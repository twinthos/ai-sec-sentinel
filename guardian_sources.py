"""Public vulnerability-source ingestion for the Sentinel Guardian platform.

NVD, CISA KEV and GitHub advisories are independent feeds. Source failure is
recorded and never interpreted as 'no vulnerabilities'. Run with:
python guardian_sources.py --once
"""
from __future__ import annotations
import argparse, json, os, re, time
from datetime import datetime, timedelta, timezone
import requests
from guardian_platform import db, upsert_incident, utcnow

TIMEOUT=(5,20)
HEADERS={"User-Agent":"Twinthos-Sentinel/0.1 (+https://twinthos.com/security/)"}
def iso(value):
    if not value: return utcnow()
    return value.replace("Z","+00:00")

def severity_from_cvss(score):
    try: score=float(score)
    except (TypeError,ValueError): return "unknown"
    return "critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low"

CPE_MAP={
 ("django","django"):("pypi","django"),("vercel","next.js"):("npm","next"),("vercel","nextjs"):("npm","next"),
 ("facebook","react"):("npm","react"),("axios","axios"):("npm","axios"),("vitejs","vite"):("npm","vite"),
 ("nginx","nginx"):("nginx","nginx"),("docker","docker_engine"):("docker","docker_engine"),
 ("php","php"):("php","php"),("nodejs","node.js"):("nodejs","node.js"),
 ("ruby-lang","ruby"):("rubygems","ruby"),("python","python"):("python","python"),
 ("simple-git","simple-git"):("npm","simple-git"),("npmjs","npm"):("npm","npm"),
}
def cpe_products(cve):
    found={}
    def walk(node):
        for match in node.get("cpeMatch",[]):
            if not match.get("vulnerable",True): continue
            parts=(match.get("criteria") or "").split(":")
            if len(parts)<6: continue
            vendor,product,version=parts[3].lower(),parts[4].lower(),parts[5]
            mapped=CPE_MAP.get((vendor,product))
            if not mapped: continue
            clauses=[]
            if match.get("versionStartIncluding"): clauses.append(">="+match["versionStartIncluding"])
            if match.get("versionStartExcluding"): clauses.append(">"+match["versionStartExcluding"])
            if match.get("versionEndIncluding"): clauses.append("<="+match["versionEndIncluding"])
            if match.get("versionEndExcluding"): clauses.append("<"+match["versionEndExcluding"])
            if not clauses and version not in {"*","-"}: clauses.append("=="+version)
            spec=",".join(clauses) or None
            eco,pkg=mapped
            found[(eco,pkg,spec)]=(eco,pkg,spec)
        for child in node.get("nodes",[]): walk(child)
    for config in cve.get("configurations",[]):
        walk(config)
    return list(found.values())

def nvd_fetch():
    now=datetime.now(timezone.utc); start=(now-timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    params={"lastModStartDate":start,"lastModEndDate":now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),"resultsPerPage":2000}
    key=os.getenv("NVD_API_KEY"); headers=dict(HEADERS)
    if key: headers["apiKey"]=key
    out=[]; start_index=0
    while True:
        params["startIndex"]=start_index
        response=requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params=params,headers=headers,timeout=TIMEOUT)
        response.raise_for_status(); data=response.json()
        for row in data.get("vulnerabilities",[]):
            v=row.get("cve",{}); metrics=v.get("metrics",{}); score=None
            for k in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                if metrics.get(k): score=metrics[k][0].get("cvssData",{}).get("baseScore"); break
            desc=next((x.get("value","") for x in v.get("descriptions",[]) if x.get("lang")=="en"),"")
            refs=[x.get("url") for x in v.get("references",[]) if x.get("url")]
            cve=v.get("id"); products=cpe_products(v) or [(None,None,None)]
            for ecosystem,package,affected in products:
                suffix=(":"+str(ecosystem)+":"+str(package)) if package else ""
                out.append({"id":"nvd:"+str(cve)+suffix,"source":"nvd","source_id":str(cve)+suffix,"cve":cve,
                  "published_at":iso(v.get("published")),"modified_at":iso(v.get("lastModified")),
                  "severity":severity_from_cvss(score),"title":(desc[:180] or cve),"description":desc,
                  "ecosystem":ecosystem,"package":package,"affected_versions":affected,"references":refs,"raw":v})
        count=len(data.get("vulnerabilities",[])); total=data.get("totalResults",0)
        if not count or start_index+count>=total: break
        start_index+=count
        time.sleep(0.7 if key else 6)
    return out

KEV_MAP={
 ("django","django"):("pypi","django"),("vercel","next.js"):("npm","next"),
 ("facebook","react"):("npm","react"),("axios","axios"):("npm","axios"),
 ("vite","vite"):("npm","vite"),("nginx","nginx"):("nginx","nginx"),
 ("docker","docker engine"):("docker","docker_engine"),("node.js","node.js"):("nodejs","node.js"),
 ("php","php"):("php","php"),("ruby","ruby"):("rubygems","ruby"),
 ("apache","http server"):("apache","http_server"),
}
def kev_fetch():
    r=requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",headers=HEADERS,timeout=TIMEOUT)
    r.raise_for_status(); out=[]
    for v in r.json().get("vulnerabilities",[]):
        cve=v.get("cveID")
        vendor=(v.get("vendorProject") or "").strip().lower(); product=(v.get("product") or "").strip().lower()
        mapped=KEV_MAP.get((vendor,product))
        ecosystem,package=mapped if mapped else (None,None)
        suffix=(":"+str(ecosystem)+":"+str(package)) if package else ""
        out.append({"id":"cisa-kev:"+str(cve)+suffix,"source":"cisa_kev","source_id":str(cve)+suffix,"cve":cve,
          "published_at":iso(v.get("dateAdded")),"severity":"critical","title":v.get("vulnerabilityName") or cve,
          "description":v.get("shortDescription") or "", "ecosystem":ecosystem,"package":package,"affected_versions":None,
          "remediation":v.get("requiredAction") or "Apply the vendor remediation; prioritise because exploitation is confirmed.",
          "references":[v.get("notes")] if v.get("notes") else [],"exploited":True,"raw":v})
    return out

def github_fetch():
    out=[]; since=datetime.now(timezone.utc)-timedelta(days=2); stop=False
    headers={**HEADERS,"Accept":"application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"): headers["Authorization"]="Bearer "+os.getenv("GITHUB_TOKEN")
    for page in range(1,11):
        r=requests.get("https://api.github.com/advisories",params={"per_page":100,"page":page,"sort":"published","direction":"desc"},
          headers=headers,timeout=TIMEOUT); r.raise_for_status(); rows=r.json()
        if not rows: break
        for v in rows:
            published=v.get("published_at")
            if not published: continue
            if datetime.fromisoformat(published.replace("Z","+00:00"))<since:
                stop=True; continue
            cve=v.get("cve_id"); ghsa=v.get("ghsa_id")
            refs=[x.get("url") for x in v.get("references",[]) if x.get("url")]
            for vref in v.get("vulnerabilities",[]):
                pkg=vref.get("package") or {}; rng=vref.get("vulnerable_version_range")
                fix=vref.get("first_patched_version") or {}; ecosystem=pkg.get("ecosystem"); name=pkg.get("name")
                out.append({"id":"github:"+str(ghsa)+":"+str(ecosystem)+":"+str(name),"source":"github_advisory",
                  "source_id":str(ghsa)+":"+str(ecosystem)+":"+str(name),"cve":cve,"published_at":iso(published),
                  "modified_at":iso(v.get("updated_at")),"severity":{"moderate":"medium"}.get((v.get("severity") or "unknown").lower(),(v.get("severity") or "unknown").lower()),
                  "ecosystem":str(ecosystem or "").lower(),"package":str(name or "").lower(),
                  "title":v.get("summary") or ghsa,"description":v.get("description") or "",
                  "affected_versions":rng,"fixed_version":fix.get("identifier"),
                  "remediation":("Upgrade "+str(name)+" to "+str(fix.get("identifier")) if fix.get("identifier") else "Review the linked vendor advisory and upgrade to a patched release."),
                  "references":refs,"raw":v})
        if stop: break
        time.sleep(0.2)
    return out

SOURCES={"nvd":nvd_fetch,"cisa_kev":kev_fetch,"github_advisory":github_fetch}
def run_source(name, fetcher):
    try:
        items=fetcher()
        with db() as c:
            for item in items: upsert_incident(c,item)
            c.execute("INSERT INTO source_state(source,last_success,cursor,error) VALUES(?,?,?,NULL) ON CONFLICT(source) DO UPDATE SET last_success=excluded.last_success,error=NULL",
                      (name,utcnow(),str(len(items))))
        return {"source":name,"ok":True,"received":len(items)}
    except Exception as exc:
        with db() as c:
            c.execute("INSERT INTO source_state(source,error) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET error=excluded.error",(name,str(exc)[:500]))
        return {"source":name,"ok":False,"error":str(exc)[:300]}

def run_all():
    results=[run_source(name,fn) for name,fn in SOURCES.items()]
    # Only scan after source ingestion attempts complete. Failed sources remain
    # visible in source_state; they are never reported as a clean scan.
    try:
        from guardian_platform import scan_client
        with db() as c:
            client_ids=[r["id"] for r in c.execute("SELECT id FROM clients")]
        for client_id in client_ids:
            try:
                scan_client(client_id)
            except Exception as exc:
                results.append({"client_id":client_id,"scan_ok":False,"error":str(exc)[:200]})
    except Exception as exc:
        results.append({"scan_ok":False,"error":str(exc)[:200]})
    return results

if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--once",action="store_true"); parser.add_argument("--interval",type=int,default=60)
    args=parser.parse_args()
    if args.once: print(json.dumps(run_all(),indent=2))
    else:
        while True:
            print(json.dumps(run_all()),flush=True); time.sleep(max(5,args.interval)*60)
