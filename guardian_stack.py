"""Authorised GitHub repository manifest inventory for Sentinel Guardians.

Only github.com repository URLs are accepted. The scanner reads repository
metadata and manifests through api.github.com; it does not clone, execute code,
or probe hosts. Private repositories require a server-side GitHub token.
"""
from __future__ import annotations
import json, os, re
from urllib.parse import urlparse
import requests
from fastapi import HTTPException
from packaging.version import Version, InvalidVersion

API="https://api.github.com"
HEAD={"Accept":"application/vnd.github+json","User-Agent":"Twinthos-Sentinel-Stack-Inventory"}
def parse_repo_url(value):
    p=urlparse(value)
    if p.scheme!="https" or p.hostname not in {"github.com","www.github.com"} or p.port or p.username or p.password:
        raise HTTPException(422,"Only HTTPS github.com repository URLs are supported")
    parts=[x for x in p.path.strip("/").split("/") if x]
    if len(parts)<2: raise HTTPException(422,"Provide a GitHub owner/repository URL")
    owner,repo=parts[:2]
    repo=re.sub(r"\.git$","",repo)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",repo):
        raise HTTPException(422,"Invalid GitHub repository path")
    return owner,repo

def request_json(url):
    headers=dict(HEAD)
    token=os.getenv("GITHUB_TOKEN")
    if token: headers["Authorization"]="Bearer "+token
    try:
        r=requests.get(url,headers=headers,timeout=(4,12),allow_redirects=False)
        if r.status_code==404: raise HTTPException(404,"Repository or manifest not found / not accessible")
        if r.status_code in (301,302,307,308): raise HTTPException(502,"Unexpected GitHub API redirect")
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        raise HTTPException(502,"GitHub API request failed: "+str(e)[:180])

def exact_version(value):
    if not isinstance(value,str): return None
    value=value.strip()
    if value.startswith(("=","==")): value=value.lstrip("=")
    if value.startswith(("^","~",">","<","*")) or " " in value or value in {"latest","*"}: return None
    value=value.removeprefix("v")
    try: Version(value); return value
    except InvalidVersion: return None

def extract_manifests(tree, get_file):
    found=[]
    def add(eco,name,raw,source):
        version=exact_version(raw)
        if eco=="docker" and isinstance(raw,str) and re.fullmatch(r"\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9._-]+)?",raw.strip()):
            version=raw.strip()
        found.append({"ecosystem":eco,"package":name.lower(),"version":version,"source":source})
    paths={x["path"] for x in tree if x.get("type")=="blob"}
    if "package.json" in paths:
        data=get_file("package.json")
        if isinstance(data,dict):
            for section in ("dependencies","devDependencies","optionalDependencies","peerDependencies"):
                for name,ver in (data.get(section) or {}).items(): add("npm",name,ver,"package.json:"+section)
    if "package-lock.json" in paths:
        lock=get_file("package-lock.json")
        if isinstance(lock,dict):
            packages=lock.get("packages") or {}
            if packages:
                for path,meta in packages.items():
                    if not path or not path.startswith("node_modules/"): continue
                    name=path.split("node_modules/")[-1]
                    if name: add("npm",name,meta.get("version"),"package-lock.json")
            else:
                def walk(deps):
                    for name,meta in (deps or {}).items():
                        add("npm",name,meta.get("version"),"package-lock.json")
                        walk(meta.get("dependencies"))
                walk(lock.get("dependencies"))
    if "Pipfile.lock" in paths:
        data=get_file("Pipfile.lock")
        if isinstance(data,dict):
            for section in ("default","develop"):
                for name,meta in (data.get(section) or {}).items():
                    raw=(meta or {}).get("version")
                    add("pypi",name,raw,"Pipfile.lock")
    if "requirements.txt" in paths:
        for line in get_file("requirements.txt").splitlines():
            line=line.strip()
            if not line or line.startswith(("#","-")): continue
            m=re.match(r"([A-Za-z0-9_.-]+)\s*==\s*([^;\s]+)",line)
            if m: add("pypi",m.group(1),m.group(2),"requirements.txt")
            else:
                m=re.match(r"([A-Za-z0-9_.-]+)",line)
                if m: add("pypi",m.group(1),None,"requirements.txt")
    if "pyproject.toml" in paths:
        # Keep parsing conservative without executing or evaluating TOML.
        import tomllib
        try:
            data=tomllib.loads(get_file("pyproject.toml"))
            deps=(data.get("project") or {}).get("dependencies",[])
            for line in deps:
                m=re.match(r"([A-Za-z0-9_.-]+)\s*==\s*([^;\s]+)",line)
                if m: add("pypi",m.group(1),m.group(2),"pyproject.toml")
                else:
                    m=re.match(r"([A-Za-z0-9_.-]+)",line)
                    if m: add("pypi",m.group(1),None,"pyproject.toml")
        except Exception: pass
    if "composer.json" in paths:
        data=get_file("composer.json")
        if isinstance(data,dict):
            for section in ("require","require-dev"):
                for name,ver in (data.get(section) or {}).items():
                    if name!="php": add("composer",name,ver,"composer.json:"+section)
    if "composer.lock" in paths:
        data=get_file("composer.lock")
        if isinstance(data,dict):
            for package in data.get("packages",[])+data.get("packages-dev",[]):
                add("composer",package.get("name",""),package.get("version"),"composer.lock")
    if "poetry.lock" in paths:
        import tomllib
        try:
            data=tomllib.loads(get_file("poetry.lock"))
            for package in data.get("package",[]):
                add("pypi",package.get("name",""),package.get("version"),"poetry.lock")
        except Exception: pass
    if "Cargo.lock" in paths:
        import tomllib
        try:
            data=tomllib.loads(get_file("Cargo.lock"))
            for package in data.get("package",[]):
                if package.get("source"):
                    add("cargo",package.get("name",""),package.get("version"),"Cargo.lock")
        except Exception: pass
    if "pom.xml" in paths:
        import xml.etree.ElementTree as ET
        try:
            root=ET.fromstring(get_file("pom.xml"))
            ns={"m":"http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//m:dependencies/m:dependency",ns):
                group=dep.findtext("m:groupId",default="",namespaces=ns)
                artifact=dep.findtext("m:artifactId",default="",namespaces=ns)
                version=dep.findtext("m:version",default="",namespaces=ns)
                if group and artifact: add("maven",group+":"+artifact,version,"pom.xml")
        except Exception: pass
    for gradle_file in ("build.gradle","build.gradle.kts"):
        if gradle_file in paths:
            for line in get_file(gradle_file).splitlines():
                match=re.search(r"""['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)['"]""",line)
                if match: add("maven",match.group(1)+":"+match.group(2),match.group(3),gradle_file)
    if "Gemfile.lock" in paths:
        section=False
        for line in get_file("Gemfile.lock").splitlines():
            if line.strip()=="specs:": section=True; continue
            if line and not line.startswith(" "): section=False
            if section:
                match=re.match(r"\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)",line)
                if match: add("rubygems",match.group(1),match.group(2),"Gemfile.lock")
    if "Dockerfile" in paths:
        for line in get_file("Dockerfile").splitlines():
            match=re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)",line,re.I)
            if not match: continue
            image=match.group(1)
            if image.lower()=="scratch" or image.startswith("$"): continue
            image=image.split("@",1)[0]
            name,sep,tag=image.rpartition(":")
            if not sep or "/" in tag: name,tag=image,None
            package=name.split("/")[-1].lower()
            if package:
                image_version=tag if tag and not tag.startswith("$") else None
                add("docker",package,image_version,"Dockerfile FROM")
                canonical={"nginx":("nginx","nginx"),"php":("php","php"),"node":("nodejs","node.js"),
                  "nodejs":("nodejs","node.js"),"python":("python","python"),"wordpress":("wordpress","wordpress")}
                if package in canonical:
                    eco,canonical_package=canonical[package]
                    add(eco,canonical_package,image_version,"Dockerfile FROM canonical runtime")
    if "go.mod" in paths:
        for line in get_file("go.mod").splitlines():
            m=re.match(r"\s*([^\s]+)\s+(v\d+\.\d+\.\d+(?:[-+][^\s]+)?)",line)
            if m: add("go",m.group(1),m.group(2),"go.mod")
    if "Cargo.toml" in paths:
        import tomllib
        try:
            data=tomllib.loads(get_file("Cargo.toml"))
            for section in ("dependencies","dev-dependencies"):
                for name,ver in (data.get(section) or {}).items():
                    if isinstance(ver,str): add("cargo",name,ver,"Cargo.toml")
                    elif isinstance(ver,dict): add("cargo",name,ver.get("version"),"Cargo.toml")
        except Exception: pass
    # Deduplicate by ecosystem/package/version, preserving source evidence.
    unique={}
    for item in found: unique[(item["ecosystem"],item["package"],item["version"])]=item
    return list(unique.values())

def inspect_github_repo(url):
    owner,repo=parse_repo_url(url)
    meta=request_json(f"{API}/repos/{owner}/{repo}")
    if meta.get("archived"): archived=True
    else: archived=False
    branch=meta.get("default_branch") or "main"
    tree=request_json(f"{API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1").get("tree",[])
    wanted={"package.json","package-lock.json","requirements.txt","Pipfile.lock","pyproject.toml","poetry.lock","composer.json","composer.lock","go.mod","Cargo.toml","Cargo.lock","pom.xml","build.gradle","build.gradle.kts","Gemfile.lock","Dockerfile"}
    paths={x["path"] for x in tree if x.get("type")=="blob"}
    # Only read known root manifests. No arbitrary paths or file execution.
    def get_file(name):
        from base64 import b64decode
        row=request_json(f"{API}/repos/{owner}/{repo}/contents/{name}?ref={branch}")
        if row.get("encoding")!="base64": return ""
        raw=b64decode(row.get("content",""))
        if len(raw)>1_000_000: return ""
        text=raw.decode("utf-8","replace")
        if name.endswith(".json"):
            try: return json.loads(text)
            except ValueError: return {}
        return text
    components=extract_manifests(tree,lambda name:get_file(name)) 
    return {"repository":meta.get("html_url"),"default_branch":branch,"private":bool(meta.get("private")),
      "archived":archived,"manifest_files":sorted(wanted & paths),"components":components,
      "versioned_components":sum(x["version"] is not None for x in components),
      "note":"Only root manifests are inspected. Unpinned ranges remain unknown; transitive lockfile dependencies and deployed runtime versions are not established."}
