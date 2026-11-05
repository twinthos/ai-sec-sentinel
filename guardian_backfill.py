"""Backfill CVE/advisory history from 2026-01-01.

NVD is queried in bounded monthly windows with pagination. GitHub advisories
are paged until the first record older than the requested start date. The
CISA KEV catalogue is a full current snapshot, not a historical event archive.
"""
import argparse, json, os, time
from datetime import datetime, timezone
import requests
from guardian_platform import db, upsert_incident, utcnow
from guardian_sources import HEADERS, TIMEOUT, severity_from_cvss, iso

def nvd_backfill(start,end):
    out=[]; cursor=start
    while cursor<end:
        # NVD date windows are kept to 30 days to stay inside API limits.
        from datetime import timedelta
        stop=min(cursor+timedelta(days=30),end)
        params={"pubStartDate":cursor.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
          "pubEndDate":stop.strftime("%Y-%m-%dT%H:%M:%S.000Z"),"resultsPerPage":2000}
        page=0
        while True:
            params["startIndex"]=page*2000
            headers=dict(HEADERS)
            if os.getenv("NVD_API_KEY"): headers["apiKey"]=os.getenv("NVD_API_KEY")
            r=requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params=params,headers=headers,timeout=TIMEOUT);r.raise_for_status()
            data=r.json(); rows=data.get("vulnerabilities",[])
            for row in rows:
                v=row["cve"]; metrics=v.get("metrics",{}); score=None
                for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if metrics.get(key): score=metrics[key][0].get("cvssData",{}).get("baseScore");break
                desc=next((x.get("value","") for x in v.get("descriptions",[]) if x.get("lang")=="en"),"")
                out.append({"id":"nvd:"+v["id"],"source":"nvd","source_id":v["id"],"cve":v["id"],
                  "published_at":iso(v.get("published")),"modified_at":iso(v.get("lastModified")),
                  "severity":severity_from_cvss(score),"title":desc[:180] or v["id"],"description":desc,
                  "references":[x.get("url") for x in v.get("references",[]) if x.get("url")],"raw":v})
            total=data.get("totalResults",0)
            if page*2000+len(rows)>=total or not rows: break
            page+=1; time.sleep(0.7 if os.getenv("NVD_API_KEY") else 6)
        cursor=stop
    return out

def github_backfill(start,end):
    out=[]; page=1; stop=False
    while page<=30 and not stop:
        r=requests.get("https://api.github.com/advisories",params={"per_page":100,"page":page,"sort":"published","direction":"desc"},
          headers={**HEADERS,"Accept":"application/vnd.github+json"},timeout=TIMEOUT);r.raise_for_status()
        rows=r.json()
        if not rows: break
        for v in rows:
            published=v.get("published_at")
            if not published: continue
            dt=datetime.fromisoformat(published.replace("Z","+00:00"))
            if dt<start: stop=True; continue
            if dt>=end: continue
            refs=[x.get("url") for x in v.get("references",[]) if x.get("url")]
            for item in v.get("vulnerabilities",[]):
                pkg=item.get("package") or {}; eco=pkg.get("ecosystem"); name=pkg.get("name")
                fix=item.get("first_patched_version") or {}; ghsa=v.get("ghsa_id")
                out.append({"id":f"github:{ghsa}:{eco}:{name}","source":"github_advisory","source_id":f"{ghsa}:{eco}:{name}",
                  "cve":v.get("cve_id"),"published_at":iso(published),"modified_at":iso(v.get("updated_at")),
                  "severity":{"moderate":"medium"}.get((v.get("severity") or "unknown").lower(),(v.get("severity") or "unknown").lower()),
                  "ecosystem":str(eco or "").lower(),"package":str(name or "").lower(),"title":v.get("summary") or ghsa,
                  "description":v.get("description") or "","affected_versions":item.get("vulnerable_version_range"),
                  "fixed_version":fix.get("identifier"),"remediation":("Upgrade to "+fix["identifier"] if fix.get("identifier") else None),
                  "references":refs,"raw":v})
        page+=1;time.sleep(0.2)
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument("--start",default="2026-01-01");p.add_argument("--end",default=datetime.now(timezone.utc).date().isoformat());a=p.parse_args()
    start=datetime.fromisoformat(a.start).replace(tzinfo=timezone.utc);end=datetime.fromisoformat(a.end).replace(tzinfo=timezone.utc)
    records=nvd_backfill(start,end)+github_backfill(start,end)
    with db() as c:
        for item in records: upsert_incident(c,item)
        c.execute("INSERT INTO source_state(source,last_success,cursor,error) VALUES('historical_backfill',?,?,NULL) ON CONFLICT(source) DO UPDATE SET last_success=excluded.last_success,cursor=excluded.cursor,error=NULL",(utcnow(),str(len(records))))
    print(json.dumps({"records_ingested":len(records),"nvd_and_github":True,"start":a.start,"end":a.end},indent=2))
if __name__=="__main__":main()
