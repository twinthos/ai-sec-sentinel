"""Passive, authorisation-gated website technology fingerprinting.

Outbound requests are pinned to a resolved public IP to mitigate SSRF and
DNS-rebinding. Redirects are followed manually and revalidated. No port scan,
exploit, form submission, credential collection or code execution occurs.
"""
from __future__ import annotations
import http.client, ipaddress, re, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse
from fastapi import HTTPException

UA="Twinthos-Sentinel-Passive-Inventory/0.1"
MAX_BYTES=1_000_000
class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self,host,port,ip,timeout=6):
        super().__init__(host,port,timeout=timeout); self.ip=ip
    def connect(self):
        self.sock=socket.create_connection((self.ip,self.port),self.timeout)
class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,port,ip,timeout=6):
        super().__init__(host,port,timeout=timeout,context=ssl.create_default_context()); self.ip=ip
    def connect(self):
        raw=socket.create_connection((self.ip,self.port),self.timeout)
        self.sock=self._context.wrap_socket(raw,server_hostname=self.host)

def public_ips(host):
    try: rows=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except socket.gaierror as exc: raise HTTPException(422,"Unable to resolve target hostname") from exc
    ips=list(dict.fromkeys(x[4][0] for x in rows))
    if not ips: raise HTTPException(422,"Target hostname has no address records")
    for raw in ips:
        ip=ipaddress.ip_address(raw)
        if not ip.is_global: raise HTTPException(403,"Target resolves to a non-public IP address")
    return ips

def fetch(url,limit=MAX_BYTES):
    current=url
    for hop in range(4):
        p=urlparse(current)
        if p.scheme not in {"http","https"} or not p.hostname or p.username or p.password or p.port not in {None,80,443}:
            raise HTTPException(422,"Only public HTTP/HTTPS websites on standard ports are supported")
        ips=public_ips(p.hostname); port=p.port or (443 if p.scheme=="https" else 80)
        conn=(PinnedHTTPS if p.scheme=="https" else PinnedHTTP)(p.hostname,port,ips[0],timeout=6)
        path=urlunparse(("", "", p.path or "/", p.params, p.query, ""))
        try:
            conn.request("GET",path,headers={"Host":p.hostname,"User-Agent":UA,"Accept":"text/html,application/xhtml+xml,text/plain,*/*","Connection":"close"})
            response=conn.getresponse()
            if response.status in {301,302,303,307,308}:
                location=response.getheader("Location")
                if not location: raise HTTPException(502,"Redirect without Location")
                if hop==3: raise HTTPException(422,"Too many website redirects")
                current=urljoin(current,location); continue
            headers={k.lower():v for k,v in response.getheaders()}
            body=response.read(limit+1)
            if len(body)>limit: body=body[:limit]
            cert=conn.sock.getpeercert() if p.scheme=="https" and conn.sock else None
            return {"url":current,"status":response.status,"headers":headers,"body":body.decode("utf-8","replace"),
              "ssl":cert,"resolved_ips":ips}
        except HTTPException: raise
        except Exception as exc: raise HTTPException(502,"Website request failed: "+str(exc)[:180])
        finally: conn.close()
    raise HTTPException(422,"Redirect limit exceeded")

def detect(url):
    page=fetch(url)
    h=page["headers"]; html=page["body"]; text=(html+" "+str(h)).lower()
    components={}
    def add(ecosystem,package,version=None,evidence=""):
        components[(ecosystem,package)]={"ecosystem":ecosystem,"package":package,"version":version,"evidence":evidence}
    server=h.get("server","").lower()
    if "nginx" in server: add("nginx","nginx",None,"HTTP Server header")
    if "apache" in server: add("apache","http_server",None,"HTTP Server header")
    powered=h.get("x-powered-by","").lower()
    if "php" in powered:
        m=re.search(r"php/?([0-9]+(?:\.[0-9]+){1,2})",powered)
        add("php","php",m.group(1) if m else None,"X-Powered-By header")
    if "wp-content/" in text or "wp-includes/" in text or "wordpress" in text:
        m=re.search(r'<meta[^>]+name=["\\']generator["\\'][^>]+content=["\\']wordpress ([0-9.]+)',html,re.I)
        add("wordpress","wordpress",m.group(1) if m else None,"WordPress HTML fingerprint")
    if "/_next/" in text or "__next_data__" in text:
        add("npm","next",None,"Next.js asset / data fingerprint")
    if "react-dom" in text or "data-reactroot" in text or "__react" in text:
        add("npm","react",None,"React DOM fingerprint")
    if "/@vite/client" in text:
        add("npm","vite",None,"Vite development-client fingerprint")
    if "django" in powered or "csrftoken" in text:
        add("pypi","django",None,"Django response fingerprint")
    cert=page["ssl"]; ssl_state={"enabled":urlparse(page["url"]).scheme=="https","valid":False,"expires_at":None,"issuer":None}
    if cert:
        try:
            expires=datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),timezone.utc)
            ssl_state.update({"valid":expires>datetime.now(timezone.utc),"expires_at":expires.isoformat(),"issuer":str(cert.get("issuer"))})
        except Exception: pass
    # Probe standard public metadata paths on the same origin only.
    origin=urlparse(page["url"])
    robots=sitemap=None
    try:
        rp=fetch(urljoin(page["url"],"/robots.txt"),limit=128_000)
        if urlparse(rp["url"]).netloc==origin.netloc and rp["status"]==200: robots=rp["body"][:128_000]
    except HTTPException: pass
    try:
        sm=fetch(urljoin(page["url"],"/sitemap.xml"),limit=256_000)
        if urlparse(sm["url"]).netloc==origin.netloc and sm["status"]==200: sitemap=sm["body"][:256_000]
    except HTTPException: pass
    return {"url":page["url"],"http_status":page["status"],"server":h.get("server"),
      "powered_by":h.get("x-powered-by"),"ssl":ssl_state,"resolved_ips":page["resolved_ips"],
      "robots_txt_found":robots is not None,"sitemap_found":sitemap is not None,
      "components":list(components.values()),
      "confidence":"heuristic; verify against deployment inventory",
      "limitations":"Passive fingerprints can be hidden, spoofed, proxied or stale. Unknown versions remain unknown; absence is not proof of absence."}
