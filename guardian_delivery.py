"""SMTP and Slack delivery for newly discovered Guardian findings.

SMTP credentials and the operations Slack webhook are supplied only through
environment variables. Client email addresses are contact data in SQLite;
deployments must protect the database volume and backups.
"""
import json, os, smtplib, ssl
from email.message import EmailMessage
from urllib.parse import urlparse
import requests
from guardian_platform import db, utcnow

def _record(finding_id,channel,status,error=None):
    with db() as c:
        c.execute("""INSERT INTO alert_deliveries(finding_id,channel,status,attempt_count,last_attempt,error)
          VALUES(?,?,?,?,?,?) ON CONFLICT(finding_id,channel) DO UPDATE SET
          status=excluded.status,attempt_count=alert_deliveries.attempt_count+1,last_attempt=excluded.last_attempt,error=excluded.error""",
          (finding_id,channel,status,1,utcnow(),error))

def deliver_finding(finding_id):
    with db() as c:
        row=c.execute("""SELECT f.id,c.name,c.contact_email,i.cve,i.title,i.description,i.severity,
          i.package,i.affected_versions,i.fixed_version,i.remediation,i.references_json,i.exploited
          FROM findings f JOIN clients c ON c.id=f.client_id JOIN incidents i ON i.id=f.incident_id
          WHERE f.id=?""",(finding_id,)).fetchone()
    if not row: return []
    item=dict(row); refs=json.loads(item.pop("references_json")); results=[]
    with db() as c:
        sent={r["channel"] for r in c.execute("SELECT channel FROM alert_deliveries WHERE finding_id=? AND status='sent'",(finding_id,))}

    smtp_host=os.getenv("SENTINEL_SMTP_HOST")
    if item.get("contact_email") and smtp_host and "email" not in sent:
        try:
            msg=EmailMessage()
            msg["Subject"]=f"[Sentinel {item['severity'].upper()}] {item['cve'] or item['title']}"
            msg["From"]=os.environ["SENTINEL_SMTP_FROM"]; msg["To"]=item["contact_email"]
            msg.set_content(f"""Twinthos Sentinel Guardian alert

Client: {item['name']}
Severity: {item['severity']}
Incident: {item['cve'] or item['title']}
Component: {item['package'] or 'Not mapped'}
Affected versions: {item['affected_versions'] or 'Not specified'}
Fixed version: {item['fixed_version'] or 'Not specified'}

What happened:
{item['title']}

{item['description']}

Exploitation status: {'Known exploited (CISA KEV)' if item['exploited'] else 'Not confirmed by this record'}

Recommended action:
{item['remediation'] or 'Review the original vendor advisory. Do not assume a fix version where none is provided.'}

References:
{chr(10).join(refs)}

This is an automated security notification. Verify applicability against your deployed inventory before remediation.
""")
            port=int(os.getenv("SENTINEL_SMTP_PORT","587"))
            if os.getenv("SENTINEL_SMTP_SSL","").lower()=="true":
                with smtplib.SMTP_SSL(smtp_host,port,context=ssl.create_default_context(),timeout=15) as server:
                    if os.getenv("SENTINEL_SMTP_USER"): server.login(os.environ["SENTINEL_SMTP_USER"],os.environ["SENTINEL_SMTP_PASSWORD"])
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host,port,timeout=15) as server:
                    server.ehlo();server.starttls(context=ssl.create_default_context());server.ehlo()
                    if os.getenv("SENTINEL_SMTP_USER"): server.login(os.environ["SENTINEL_SMTP_USER"],os.environ["SENTINEL_SMTP_PASSWORD"])
                    server.send_message(msg)
            _record(finding_id,"email","sent");results.append({"channel":"email","status":"sent"})
        except Exception as exc:
            _record(finding_id,"email","failed",str(exc)[:300]);results.append({"channel":"email","status":"failed","error":str(exc)[:160]})
    webhook=os.getenv("SENTINEL_SLACK_WEBHOOK_URL")
    if webhook and "slack" not in sent:
        try:
            u=urlparse(webhook)
            if u.scheme!="https" or u.hostname!="hooks.slack.com" or u.port not in {None,443} or u.username or u.password or not u.path.startswith("/services/"):
                raise ValueError("Slack webhook must be an HTTPS hooks.slack.com/services URL")
            text=(f"*Twinthos Sentinel — {item['severity'].upper()}*\n"
              f"*Client:* {item['name']}\n*Incident:* {item['cve'] or item['title']}\n"
              f"*Component:* {item['package'] or 'Unmapped'}\n"
              f"*Affected versions:* {item['affected_versions'] or 'Not specified'}\n"
              f"*Fix:* {item['fixed_version'] or 'Not specified'}\n"
              f"*Exploitation:* {'Known exploited (CISA KEV)' if item['exploited'] else 'Not confirmed'}\n"
              f"*Action:* {item['remediation'] or 'Review original vendor advisory.'}")
            response=requests.post(webhook,json={"text":text},timeout=(3,10),allow_redirects=False);response.raise_for_status()
            _record(finding_id,"slack","sent");results.append({"channel":"slack","status":"sent"})
        except Exception as exc:
            _record(finding_id,"slack","failed",str(exc)[:300]);results.append({"channel":"slack","status":"failed","error":str(exc)[:160]})
    return results

def retry_pending(client_id=None):
    with db() as c:
        sql="""SELECT DISTINCT a.finding_id FROM alert_deliveries a
          JOIN findings f ON f.id=a.finding_id WHERE a.status='failed'"""
        args=[]
        if client_id: sql+=" AND f.client_id=?";args.append(client_id)
        ids=[r["finding_id"] for r in c.execute(sql,args)]
    return [{"finding_id":fid,"results":deliver_finding(fid)} for fid in ids]
