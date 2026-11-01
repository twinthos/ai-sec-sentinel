#!/usr/bin/env python3
"""
Twinthos Sentinel — continuous threat intelligence for organizations.

Monitors:
- AI/agent/MCP vulnerabilities (current focus)
- Supply-chain compromises
- Brand/reputation threats
- Infrastructure threats relevant to your stack

Scrapes CVE feeds, CISA KEV, EPSS, and news sources.
Filters to YOUR stack. Alerts in real-time. Learns from feedback.

Usage:
  python3 ai_sec_sentinel.py                        # one-shot scan
  python3 ai_sec_sentinel.py --daemon                # continuous mode
  python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python
  python3 ai_sec_sentinel.py --check-only
  python3 ai_sec_sentinel.py --feedback CVE-2025-EXAMPLE ignored
"""

import argparse
import html
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\nInstall with: pip install requests")

# Risk scoring and compliance (optional)
try:
    from risk_compliance import calculate_risk_score, generate_risk_report, map_to_compliance
    RISK_AVAILABLE = True
except ImportError:
    RISK_AVAILABLE = False

def _retry(fn, max_attempts=3, delay=2):
    """Retry a function with exponential backoff."""
    import time as _t
    last_exc = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            if attempt < max_attempts - 1:
                _t.sleep(delay * (2 ** attempt))
    raise last_exc


CVE_NOW_FEED = "https://cve.now/feed?format=json"
CVE_NOW_API = "https://cve.now/api/v1/entries"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
STATE_FILE = Path(__file__).with_name("sentinel_state.json")
CONFIG_FILE = Path(__file__).with_name("sentinel_config.json")
FEEDBACK_FILE = Path(__file__).with_name("sentinel_feedback.json")

AI_KEYWORDS = [
    "langchain", "llamaindex", "openai", "anthropic", "claude", "gpt",
    "mcp", "model context protocol", "agent", "agents", "copilot",
    "cursor", "codex", "claude code", "aider", "continue",
    "prompt injection", "rag", "retrieval augmented", "embedding",
    "vllm", "ollama", "litellm", "transformers", "huggingface",
    "autogen", "crewai", "semantic kernel", "langgraph",
    "ai agent", "coding agent", "llm framework", "llm sdk",
    "ai security", "adversarial", "jailbreak",
]

# Infrastructure that commonly supports AI workloads.
# A CVE here is only flagged if an AI keyword is ALSO present,
# so we avoid pure infrastructure noise while catching the
# cases that actually matter to an AI practice.
AI_INFRA_KEYWORDS = [
    "clickhouse", "postgres", "mysql", "qdrant", "pinecone", "weaviate",
    "redis", "elasticsearch", "opensearch", "vector database",
    "mlflow", "kubeflow", "ray", "jupyter", "vllm",
]


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen": [], "last_run": None, "feedback": {}}


def atomic_write(path, data):
    """Write file atomically via temp + rename."""
    import tempfile, os
    tmp = path.parent / (path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)

def save_state(state: dict):
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    atomic_write(STATE_FILE, json.dumps(state, indent=2))


def load_feedback() -> dict:
    FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    if FEEDBACK_FILE.exists():
        try:
            return json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def record_feedback(cve_id: str, action: str):
    fb = load_feedback()
    fb[cve_id] = {"action": action, "ts": datetime.now(timezone.utc).isoformat()}
    atomic_write(FEEDBACK_FILE, json.dumps(fb, indent=2))


def _word_boundary(text: str, kw: str) -> bool:
    """Match keyword as a whole word, not a substring."""
    pattern = r"\b" + re.escape(kw) + r"\b"
    return re.search(pattern, text, re.IGNORECASE) is not None

# Synonym map: alternate spellings / product names (only non-trivial variants)
AI_SYNONYMS = {
    "langchain": ["lang chain", "langchain"],
    "llamaindex": ["llama index", "llamaindex"],
    "openai": ["open ai", "openai"],
    "anthropic": ["anthropic"],
    "claude": ["claude"],
    "gpt": ["gpt"],
    "mcp": ["model context protocol", "mcp"],
    "agent": ["agent", "agents"],
    "copilot": ["copilot"],
    "cursor": ["cursor"],
    "codex": ["codex"],
    "claude code": ["claude code"],
    "aider": ["aider"],
    "continue": ["continue"],
    "prompt injection": ["prompt injection", "prompt injection attack"],
    "rag": ["rag", "retrieval augmented generation"],
    "retrieval augmented": ["rag", "retrieval augmented generation"],
    "embedding": ["embedding", "embeddings"],
    "vllm": ["vllm"],
    "ollama": ["ollama"],
    "litellm": ["litellm"],
    "transformers": ["transformers"],
    "huggingface": ["hugging face", "huggingface"],
    "autogen": ["autogen"],
    "crewai": ["crewai"],
    "semantic kernel": ["semantic kernel"],
    "langgraph": ["langgraph"],
    "ai agent": ["ai agent", "ai agents"],
    "coding agent": ["coding agent"],
    "llm framework": ["llm framework"],
    "llm sdk": ["llm sdk"],
    "ai security": ["ai security"],
    "adversarial": ["adversarial"],
    "jailbreak": ["jailbreak"],
}

def _matches_synonyms(blob_lower: str, kw: str) -> bool:
    for syn in AI_SYNONYMS.get(kw.lower(), [kw]):
        if _word_boundary(blob_lower, syn):
            return True
    return False

def is_ai_related(entry: dict) -> bool:
    blob = (
        entry.get("title", "")
        + " "
        + entry.get("content_text", "")
        + " "
        + entry.get("summary", "")
    ).lower()
    # Tier 1: direct AI/agent/MCP keyword hit with word boundaries + synonyms
    if any(_matches_synonyms(blob, kw) for kw in AI_KEYWORDS):
        return True
    # Tier 2: AI infrastructure keyword hit, but only if an AI keyword
    # is also present in the same entry.
    if any(_word_boundary(blob, kw) for kw in AI_INFRA_KEYWORDS):
        return any(_matches_synonyms(blob, kw) for kw in AI_KEYWORDS)
    return False


def severity_rank(entry: dict) -> int:
    cvss = entry.get("cvss")
    if isinstance(cvss, str):
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = None
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return 3
        if cvss >= 7.0:
            return 2
        if cvss >= 4.0:
            return 1
        return 0

    severity = entry.get("severity") or {}
    cvss = severity.get("cvss")
    if isinstance(cvss, str):
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = None
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return 3
        if cvss >= 7.0:
            return 2
        if cvss >= 4.0:
            return 1
        return 0

    severity_text = ((severity.get("label") or severity.get("name") or "")).upper()
    if severity_text == "CRITICAL":
        return 3
    if severity_text == "HIGH":
        return 2
    if severity_text == "MEDIUM":
        return 1
    return 0


def fetch_feed(limit: int = 100) -> list[dict]:
    def _do():
        r = requests.get(CVE_NOW_FEED, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("items", [])[:limit]
    try:
        return _retry(_do)
    except Exception as e:
        print(f"Feed fetch error: {e}")
        return []


def fetch_entry(cve_id: str) -> dict | None:
    def _do():
        r = requests.get(f"{CVE_NOW_API}/{cve_id}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            severity = data.get("severity") or {}
            if data.get("cvss") is None and isinstance(severity, dict):
                data["cvss"] = severity.get("cvss")
            if not data.get("summary"):
                data["summary"] = data.get("originalDescription", "")
            return data
        return None
    try:
        return _retry(_do)
    except Exception:
        return None


def fetch_cisa_kev() -> dict:
    def _do():
        r = requests.get(CISA_KEV_URL, timeout=30)
        if r.status_code == 200:
            return r.json()
        return {}
    try:
        return _retry(_do)
    except Exception as e:
        print(f"CISA KEV fetch error: {e}")
        return {}


def fetch_epss_scores(cve_ids: list[str]) -> dict:
    scores = {}
    if not cve_ids:
        return scores
    try:
        # Batch lookup, 100 at a time
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i+100]
            query = ",".join(batch)
            r = requests.get(EPSS_API, params={"cves": query, "limit": 100}, timeout=30)
            if r.status_code == 200:
                data = r.json()
                rows = data.get("data", [])
                if not rows:
                    print("Warning: EPSS returned 0 rows — check endpoint/params")
                for item in rows:
                    cve = item.get("cve")
                    if cve:
                        scores[cve] = float(item.get("epss", 0))
    except Exception as e:
        print(f"EPSS fetch error: {e}")
    return scores


def filter_new(entries: list[dict], since: datetime) -> list[dict]:
    out = []
    for e in entries:
        ds = e.get("date_modified") or e.get("date_published")
        if not ds:
            # Include entries without dates (assume recent)
            out.append(e)
            continue
        try:
            dt = datetime.fromisoformat(ds.replace("Z", "+00:00"))
            if dt > since:
                out.append(e)
        except Exception:
            # Include on parse failure (don't silently drop)
            out.append(e)
    return out


def extract_fix_version(entry: dict) -> str | None:
    text = entry.get("content_text", "") + " " + (entry.get("summary") or "")
    # Require at least one dot in version (e.g., 1.2.3, not just "2")
    m = re.search(r"(?:fixed in|upgrade to|patched in|version)[:\s]+(\d+\.\d+(?:[\.\w-]*)?)", text, re.IGNORECASE)
    return m.group(1) if m else None


def generate_fix_command(entry: dict, ecosystem: str = "python") -> str | None:
    """Generate a fix command for a vulnerable dependency.

    NOTE: This generates a suggested command based on the CVE entry.
    Always verify the fix version is correct for your specific package
    before running. This is a suggestion, not an automated fix.
    """
    fix = extract_fix_version(entry)
    if not fix:
        return None
    raw_id = entry.get("id", "").split("#")[0].strip()
    if not raw_id:
        return None
    # Extract package name (remove CVE ID prefix if present)
    pkg_name = raw_id
    if raw_id.startswith("CVE-") or raw_id.startswith("GHSA-"):
        # Can't determine package from CVE ID alone
        return f"# Verify fix version {fix} manually for affected package"
    if ecosystem == "python":
        return f"pip install --upgrade {pkg_name}>={fix}"
    elif ecosystem == "npm":
        return f"npm install {pkg_name}@{fix}"
    elif ecosystem == "go":
        return f"go get {pkg_name}@{fix}"
    return None


def format_alert(entry: dict, epss_score: float | None = None, in_kev: bool = False,
                 cvss: float | None = None) -> str:
    raw_id = entry.get("id", "N/A")
    cve_id = raw_id.split("#")[0].strip()
    title = entry.get("title", "Unknown vulnerability")
    url = f"https://cve.now/{cve_id}"
    sev = severity_rank(entry)
    sev_emoji = {3: "🔴", 2: "🟠", 1: "🟡"}.get(sev, "⚪")
    sev_label = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}.get(sev, "UNKNOWN")

    clean_title = html.escape(title.split("#")[0].strip())
    clean_cve_id = html.escape(cve_id)
    msg = f"{sev_emoji} <b>AI Security Alert — {sev_label}</b>\n\n"
    msg += f"<b>{clean_cve_id}</b>\n"
    msg += f"{clean_title[:220]}\n\n"

    if cvss is not None:
        msg += f"CVSS: <b>{cvss}</b>  "
    if epss_score is not None:
        msg += f"EPSS: <b>{epss_score:.2f}</b>  "
    if in_kev:
        msg += "🛑 <b>CISA KEV — Actively exploited</b>  "

    msg += f"\n🔗 <a href='https://cve.now/{clean_cve_id}'>{clean_cve_id}</a>"

    fix = extract_fix_version(entry)
    if fix:
        msg += f"\n\n✅ Fix: upgrade to <b>{html.escape(fix)}</b>"

    return msg


def send_telegram(message: str, token: str, chat_id: str, cve_id: str = "") -> bool:
    if not token or not chat_id:
        print("[TELEGRAM NOT CONFIGURED]")
        print(message[:800])
        return False
    # Dry-run mode: print to stdout instead of sending
    if os.getenv("SENTINEL_DRY_RUN") == "1":
        print(f"[DRY-RUN] {message[:500]}")
        return True

    # Rate limiting: small delay between sends
    time.sleep(0.5)
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if cve_id:
            payload["reply_markup"] = {
                "inline_keyboard": [
                    [
                        {"text": "👍 Useful", "callback_data": f"feedback:{cve_id}:useful"},
                        {"text": "👎 Ignore", "callback_data": f"feedback:{cve_id}:ignored"},
                    ]
                ]
            }
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code == 429:
            retry_after = r.json().get("parameters", {}).get("retry_after", 5)
            print(f"Telegram rate limited, waiting {retry_after}s")
            time.sleep(retry_after)
            r = requests.post(url, json=payload, timeout=15)
        ok = r.status_code == 200 and r.json().get("ok")
        print(f"Telegram: {'sent' if ok else 'failed'} ({r.status_code})")
        return ok
    except Exception as e:
        print(f"Telegram error: {e}")
        return False


def check_lockfile(lockfile_path: str, ecosystem: str) -> list[dict]:
    path = Path(lockfile_path)
    if not path.exists():
        print(f"Lockfile not found: {lockfile_path}")
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    try:
        r = requests.post(
            "https://cve.now/api/stack",
            data=content.encode("utf-8"),
            headers={"X-Lockfile-Name": path.name, "Content-Type": "application/octet-stream"},
            timeout=30,
        )
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            ai_vulns = [
                v for v in vulns
                if is_ai_related({"title": v.get("id", "") + " " + v.get("summary", "")})
            ]
            return ai_vulns
    except Exception as e:
        print(f"Lockfile API error: {e}")

    # OSV.dev fallback: query OSV for known vulnerabilities
    return _osv_lockfile_check(path, content, ecosystem)


def _osv_lockfile_check(path: Path, content: str, ecosystem: str) -> list[dict]:
    """Query OSV.dev for known vulnerabilities (fallback when cve.now API is unavailable)."""
    vulns = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg = None
        version = None
        if ecosystem == "python":
            if "==" in line:
                pkg, version = line.split("==", 1)
            elif ">=" in line:
                pkg = line.split(">=", 1)[0]
        elif ecosystem == "npm":
            if ":" in line and "@" in line:
                pkg = line.split(":")[1].split("@")[0]
                version = line.split("@")[-1]
        elif ecosystem == "go":
            if " " in line:
                parts = line.split()
                if len(parts) >= 2:
                    pkg, version = parts[0], parts[1]
        if not pkg:
            continue
        if any(kw in pkg.lower() for kw in ["langchain", "openai", "anthropic", "claude", "gpt", "mcp", "agent", "crewai", "langgraph", "llamaindex", "huggingface", "transformers", "ollama", "vllm", "litellm", "semantic"]):
            # Try OSV.dev for real version data
            try:
                osv_url = "https://api.osv.dev/v1/query"
                osv_payload = {"package": {"name": pkg, "ecosystem": "PyPI" if ecosystem == "python" else ecosystem.upper()}}
                if version:
                    osv_payload["version"] = version
                osv_r = requests.post(osv_url, json=osv_payload, timeout=15)
                if osv_r.status_code == 200:
                    osv_data = osv_r.json()
                    osv_vulns = osv_data.get("vulns", [])
                    for v in osv_vulns:
                        affected = v.get("affected", [])
                        is_affected = True
                        for a in affected:
                            # Check if installed version is in affected range
                            events = a.get("ranges", [{}])[0].get("events", [])
                            introduced = None
                            fixed = None
                            for ev in events:
                                if ev.get("type") == "introduced":
                                    introduced = ev.get("introduced")
                                if ev.get("type") == "fixed":
                                    fixed = ev.get("fixed")
                            # Simple version comparison
                            if version and fixed and version >= fixed:
                                is_affected = False
                                break
                        if not is_affected:
                            continue
                        fixed_ver = None
                        for a in affected:
                            events = a.get("ranges", [{}])[0].get("events", [])
                            for ev in events:
                                if ev.get("type") == "fixed":
                                    fixed_ver = ev.get("fixed")
                        vulns.append({
                            "id": v.get("id", pkg),
                            "summary": f"OSV: {pkg} (v{version or 'unknown'}) has known vulns. Fixed in {fixed_ver or 'unknown'}.",
                            "severity": {"cvss": None},
                            "fixed_version": fixed_ver,
                            "source": "osv",
                            "affected": True,
                        })
                    if not osv_vulns:
                        vulns.append({
                            "id": pkg,
                            "summary": f"OSV: {pkg} — no known vulns found.",
                            "severity": {"cvss": None},
                            "source": "osv",
                        })
                else:
                    vulns.append({
                        "id": pkg,
                        "summary": f"Offline check: {pkg} is an AI-related dependency. OSV.dev returned {osv_r.status_code}. Verify latest version manually.",
                        "severity": {"cvss": None},
                    })
            except Exception:
                vulns.append({
                    "id": pkg,
                    "summary": f"Offline check: {pkg} is an AI-related dependency. OSV.dev unreachable. Verify latest version manually.",
                    "severity": {"cvss": None},
                })
    return vulns


def run_scan(config: dict, token: str = "", chat: str = "") -> int:
    """Run one scan cycle. Returns number of alerts sent."""
    feed_limit = config.get("feed_limit", 100)
    since_hours = config.get("since_hours", 24)
    alert_min_sev = config.get("alert_min_severity", 1)  # Default: medium and above
    if config.get("alert_on_medium"):
        alert_min_sev = 1

    state = load_state()
    seen = set(state.get("seen", []))
    feedback = load_feedback()

    # Load supplemental sources
    cisa_kev = fetch_cisa_kev()
    kev_ids = {v.get("cveID") for v in cisa_kev.get("vulnerabilities", []) if v.get("cveID")}

    alerts_sent = 0
    vulns = []

    # Lockfile scan
    lockfile = config.get("lockfile")
    ecosystem = config.get("ecosystem", "python")
    if lockfile:
        # Consent check for uploading lockfile to cve.now
        if not config.get("allow_lockfile_upload", False):
            print(f"Lockfile scan (offline only): {lockfile} — set allow_lockfile_upload=true to use cve.now API")
            vulns = _osv_lockfile_check(Path(lockfile), Path(lockfile).read_text(encoding="utf-8", errors="replace"), ecosystem)
        else:
            print(f"Scanning lockfile: {lockfile}")
            vulns = check_lockfile(lockfile, ecosystem)
        if vulns:
            msg = f"🔍 Lockfile scan: <b>{len(vulns)} AI-related vulnerabilities</b> in {Path(lockfile).name}\n"
            for v in vulns[:10]:
                msg += f"• {v.get('id', 'N/A')}\n"
                fix_cmd = generate_fix_command(v, ecosystem)
                if fix_cmd:
                    msg += f"  → Fix: <code>{html.escape(fix_cmd)}</code>\n"
            send_telegram(msg, token, chat)
        else:
            send_telegram(f"✅ Lockfile clean: {Path(lockfile).name}", token, chat)

    # Feed watch
    print("Scanning cve.now feed...")
    entries = fetch_feed(limit=feed_limit)
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    new_entries = filter_new(entries, since)
    ai_entries = [e for e in new_entries if is_ai_related(e)]

    # Supplier watch
    suppliers = [s.strip() for s in config.get("suppliers", []) if s.strip()]
    supplier_entries = []
    if suppliers:
        for entry in new_entries:
            blob = (entry.get("title", "") + " " + entry.get("content_text", "")).lower()
            if any(supplier.lower() in blob for supplier in suppliers):
                supplier_entries.append(entry)

    # News watch
    news_alerts = []
    if config.get("news", {}).get("enabled"):
        try:
            from news_scanner import scan_news
            news_alerts = scan_news()
        except Exception as e:
            print(f"News scan error: {e}")

    # Collect CVE IDs for EPSS batch lookup
    cve_ids = []
    for e in ai_entries:
        raw_id = e.get("id", "").split("#")[0].strip()
        if raw_id:
            cve_ids.append(raw_id)

    epss_scores = fetch_epss_scores(cve_ids)

    for entry in ai_entries:
        raw_id = entry.get("id", "").split("#")[0].strip()
        if raw_id in seen:
            continue

        # Check feedback — if user marked as ignored, skip for 30 days
        if raw_id in feedback and feedback[raw_id].get("action") == "ignored":
            ignored_ts = feedback[raw_id].get("ts", "")
            try:
                ignored_dt = datetime.fromisoformat(ignored_ts.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - ignored_dt < timedelta(days=30):
                    continue
                else:
                    print(f"  Re-checking previously ignored CVE (30-day expiry): {raw_id}")
            except Exception:
                continue

        sev = severity_rank(entry)
        if sev < alert_min_sev:
            continue

        # Fetch full entry for CVSS if missing
        cvss = entry.get("cvss")
        if cvss is None:
            full = fetch_entry(raw_id)
            if full:
                cvss = full.get("cvss")
                entry["cvss"] = cvss

        epss = epss_scores.get(raw_id)
        in_kev = raw_id in kev_ids
        msg = format_alert(entry, epss_score=epss, in_kev=in_kev, cvss=cvss)
        sent = send_telegram(msg, token, chat, cve_id=raw_id)
        if sent:
            seen.add(raw_id)
            alerts_sent += 1
        else:
            # Queue failed alert for retry - do NOT mark as seen
            print(f"  Alert failed for {raw_id}, will retry next scan")
        if alerts_sent >= 5:
            # Do NOT silently discard remaining - leave them for next scan
            print(f"  Alert cap reached ({alerts_sent}), remaining threats will be processed next scan")
            break

    # Run Layer 2 plugins if available
    plugin_findings = []
    try:
        from plugins.canary_prompts import run_canary_tests
        plugin_findings.extend(run_canary_tests())
    except Exception:
        pass
    try:
        from plugins.mcp_drift import scan_mcp_drift
        mcp_path = config.get("mcp_config_path")
        if mcp_path:
            plugin_findings.extend(scan_mcp_drift(mcp_path))
    except Exception:
        pass
    if plugin_findings:
        print(f"  Plugin findings: {len(plugin_findings)}")

    stats = {
        "feed_fetched": len(entries),
        "new_entries": len(new_entries),
        "ai_related": len(ai_entries),
        "supplier_related": len(supplier_entries),
        "news_alerts": len(news_alerts),
        "alerts_sent": alerts_sent,
        "cisa_kev_hits": sum(1 for e in ai_entries if e.get("id", "").split("#")[0].strip() in kev_ids),
        "high_epss": sum(1 for cid, score in epss_scores.items() if score >= 0.7),
        "lockfile_vulns": 0,
    }

    # Send supplier alerts
    for entry in supplier_entries:
        raw_id = entry.get("id", "").split("#")[0].strip()
        if raw_id in seen:
            continue
        msg = f"🏢 <b>Supplier Threat Alert</b>\n\n"
        msg += f"<b>{entry.get('title', 'Unknown')}</b>\n"
        msg += f"{entry.get('summary', entry.get('content_text', ''))[:200]}\n\n"
        msg += f"🔗 <a href='https://cve.now/{raw_id}'>{raw_id}</a>"
        sent = send_telegram(msg, token, chat)
        if sent:
            seen.add(raw_id)
            alerts_sent += 1

    # Send news alerts
    for alert in news_alerts:
        msg = f"📰 <b>News Threat Alert — {alert['severity']}</b>\n\n"
        msg += f"<b>{alert['title']}</b>\n"
        msg += f"{alert['summary']}\n\n"
        msg += f"🔗 <a href='{alert['link']}'>{alert['link']}</a>"
        sent = send_telegram(msg, token, chat)
        if sent:
            alerts_sent += 1

    if lockfile:
        stats["lockfile_vulns"] = len(vulns)

    # Send digest if in digest mode
    if os.getenv("SENTINEL_DIGEST") == "1" and (ai_entries or supplier_entries or news_alerts):
        digest = f"📋 <b>Twinthos Sentinel Digest</b>\n\n"
        digest += f"Scanned {len(entries)} CVEs, {len(new_entries)} new, {len(ai_entries)} AI-related.\n"
        digest += f"{alerts_sent} alerts sent, {stats['cisa_kev_hits']} CISA KEV hits, {stats['high_epss']} high-EPSS.\n\n"
        if ai_entries:
            digest += "<b>Top AI threats:</b>\n"
            for e in ai_entries[:5]:
                cid = e.get("id", "").split("#")[0].strip()
                sev = severity_rank(e)
                sev_label = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}.get(sev, "UNKNOWN")
                digest += f"• {cid} ({sev_label})\n"
        if supplier_entries:
            digest += f"\n<b>Supplier alerts:</b> {len(supplier_entries)}\n"
        if news_alerts:
            digest += f"\n<b>News alerts:</b> {len(news_alerts)}\n"
        send_telegram(digest, token, chat)

    # Risk report
    if RISK_AVAILABLE and ai_entries:
        findings = []
        for e in ai_entries:
            findings.append({
                "title": e.get("title", ""),
                "severity": {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}.get(severity_rank(e), "LOW"),
                "in_kev": e.get("id", "").split("#")[0].strip() in kev_ids,
                "epss": epss_scores.get(e.get("id", "").split("#")[0].strip(), 0),
                "summary": e.get("summary", e.get("content_text", "")),
            })
        risk_report = generate_risk_report(findings)
        print(risk_report)
        if os.getenv("SENTINEL_RISK_REPORT") == "1":
            send_telegram(f"<pre>{html.escape(risk_report)}</pre>", token, chat)

    print(f"  {stats['feed_fetched']} fetched, {stats['new_entries']} new, {stats['ai_related']} AI-related, {alerts_sent} alerts sent, {stats['cisa_kev_hits']} CISA KEV, {stats['high_epss']} high-EPSS")

    # Adaptive: learn from feedback — track which CVE patterns are useful vs ignored
    if config.get("learn_from_actions"):
        useful = [cid for cid, data in feedback.items() if data.get("action") == "useful"]
        ignored = [cid for cid, data in feedback.items() if data.get("action") == "ignored"]
        if len(ignored) > 5:
            print(f"  Adaptive: {len(ignored)} CVEs marked ignored, {len(useful)} marked useful")
            # Extract common keywords from ignored CVEs to reduce their weight
            ignored_keywords = set()
            for cid in ignored:
                for kw in AI_KEYWORDS:
                    if kw in cid.lower():
                        ignored_keywords.add(kw)
            if ignored_keywords:
                print(f"  Consider reducing weight for: {', '.join(sorted(ignored_keywords))}")
        # Save learned preferences to state
        state["learned"] = {
            "useful_count": len(useful),
            "ignored_count": len(ignored),
            "ignored_keywords": sorted(ignored_keywords) if ignored_keywords else [],
        }

    state["seen"] = list(seen)[-500:]
    save_state(state)
    return alerts_sent


def main():
    parser = argparse.ArgumentParser(description="Twinthos Sentinel — continuous threat intelligence")
    parser.add_argument("--version", action="version", version="Twinthos Sentinel v1.2.0")
    parser.add_argument("--lockfile", help="Path to lockfile")
    parser.add_argument("--ecosystem", choices=["python", "npm", "rust", "go", "ruby", "php", "dotnet"])
    parser.add_argument("--check-only", action="store_true", help="Lockfile only, no feed watch")
    parser.add_argument("--feed-limit", type=int, default=100)
    parser.add_argument("--since-hours", type=int, default=24)
    parser.add_argument("--daemon", action="store_true", help="Continuous daemon mode")
    parser.add_argument("--interval", type=int, default=60, help="Scan interval in minutes (daemon mode)")
    parser.add_argument("--stats", action="store_true", help="Show scan statistics and exit")
    parser.add_argument("--feedback", nargs="+", help="Mark CVE as ignored or useful, e.g. --feedback CVE-2025-EXAMPLE ignored")
    parser.add_argument("--telegram-token", default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--telegram-chat", default=os.getenv("TELEGRAM_CHAT_ID", ""))
    parser.add_argument("--webhook-port", type=int, default=0, help="Start webhook server for Telegram callback buttons")
    parser.add_argument("--dry-run", action="store_true", help="Print alerts to stdout without sending")
    parser.add_argument("--digest", action="store_true", help="Send a single digest summary instead of individual alerts")
    parser.add_argument("--risk-report", action="store_true", help="Print risk score and compliance report")
    args = parser.parse_args()

    # Load config
    config = load_config()
    if args.feed_limit:
        config["feed_limit"] = args.feed_limit
    if args.since_hours:
        config["since_hours"] = args.since_hours
    if args.lockfile:
        config["lockfile"] = args.lockfile
    if args.ecosystem:
        config["ecosystem"] = args.ecosystem

    # Check-only mode: lockfile scan only, no feed watch
    if args.check_only:
        config = load_config()
        if args.lockfile:
            config["lockfile"] = args.lockfile
        if args.ecosystem:
            config["ecosystem"] = args.ecosystem
        lockfile = config.get("lockfile")
        ecosystem = config.get("ecosystem", "python")
        if not lockfile:
            print("Error: --check-only requires --lockfile")
            return
        print(f"Checking lockfile: {lockfile} (ecosystem: {ecosystem})")
        vulns = check_lockfile(lockfile, ecosystem) if config.get("allow_lockfile_upload") else _osv_lockfile_check(Path(lockfile), Path(lockfile).read_text(encoding="utf-8", errors="replace"), ecosystem)
        if vulns:
            print(f"Found {len(vulns)} AI-related vulnerabilities:")
            for v in vulns:
                print(f"  - {v.get('id', 'N/A')}: {v.get('summary', '')[:100]}")
                fix_cmd = generate_fix_command(v, ecosystem)
                if fix_cmd:
                    print(f"    Fix: {fix_cmd}")
        else:
            print("No AI-related vulnerabilities found.")
        return

    # Stats mode
    if args.stats:
        config = load_config()
        state = load_state()
        feedback = load_feedback()
        cisa_kev = fetch_cisa_kev()
        kev_ids = {v.get("cveID") for v in cisa_kev.get("vulnerabilities", []) if v.get("cveID")}
        entries = fetch_feed(limit=config.get("feed_limit", 100))
        since = datetime.now(timezone.utc) - timedelta(hours=config.get("since_hours", 24))
        new_entries = filter_new(entries, since)
        ai_entries = [e for e in new_entries if is_ai_related(e)]
        cve_ids = [e.get("id", "").split("#")[0].strip() for e in ai_entries if e.get("id")]
        epss_scores = fetch_epss_scores(cve_ids)
        high_epss = sum(1 for s in epss_scores.values() if s >= 0.7)
        kev_hits = sum(1 for e in ai_entries if e.get("id", "").split("#")[0].strip() in kev_ids)
        lockfile_vulns = 0
        if config.get("lockfile"):
            vulns = check_lockfile(config["lockfile"], config.get("ecosystem", "python"))
            lockfile_vulns = len(vulns)
        ignored = [cid for cid, data in feedback.items() if data.get("action") == "ignored"]
        print(f"=== Sentinel Stats ===")
        print(f"Feed fetched: {len(entries)}")
        print(f"New entries: {len(new_entries)}")
        print(f"AI-related: {len(ai_entries)}")
        print(f"CISA KEV hits: {kev_hits}")
        print(f"High EPSS (>=0.7): {high_epss}")
        print(f"Lockfile vulns: {lockfile_vulns}")
        print(f"Ignored CVEs: {len(ignored)}")
        print(f"Seen CVEs (state): {len(state.get('seen', []))}")
        print(f"Last run: {state.get('last_run', 'never')}")
        return

    # Feedback mode
    if args.feedback is not None:
        if len(args.feedback) < 1:
            print("Usage: --feedback CVE-ID [useful|ignored]")
            return
        cve_id = args.feedback[0].split("#")[0].strip()
        action = args.feedback[1] if len(args.feedback) > 1 else "ignored"
        if action not in ("useful", "ignored"):
            print(f"Invalid action: {action}. Use 'useful' or 'ignored'.")
            return
        record_feedback(cve_id, action)
        print(f"Feedback recorded: {cve_id} -> {action}")
        return

    if args.dry_run:
        os.environ["SENTINEL_DRY_RUN"] = "1"
    if args.digest:
        os.environ["SENTINEL_DIGEST"] = "1"
    if args.risk_report:
        os.environ["SENTINEL_RISK_REPORT"] = "1"

    token = args.telegram_token or config.get("telegram", {}).get("token", "")
    chat = args.telegram_chat or config.get("telegram", {}).get("chat_id", "")

    if args.webhook_port:
        secret = config.get("telegram", {}).get("webhook_secret", "")
        print(f"Starting webhook server on port {args.webhook_port}...")
        _webhook_server(token, args.webhook_port, secret=secret)
        return

    if args.daemon:
        # Graceful shutdown handler
        _shutdown = {"flag": False}
        def _sig_handler(signum, frame):
            print(f"\nReceived signal {signum}, saving state and shutting down...")
            _shutdown["flag"] = True
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)

        print(f"Starting daemon mode — scanning every {args.interval} minutes...")
        while not _shutdown["flag"]:
            try:
                run_scan(config, token, chat)
            except Exception as e:
                print(f"Scan error: {e}")
            if not _shutdown["flag"]:
                time.sleep(args.interval * 60)
        print("Daemon stopped gracefully.")
    else:
        run_scan(config, token, chat)


def _handle_callback_query(update: dict, token: str):
    """Handle Telegram callback query from inline keyboard buttons."""
    callback = update.get("callback_query", {})
    data = callback.get("data", "")
    if not data.startswith("feedback:"):
        return
    _, cve_id, action = data.split(":", 2)
    record_feedback(cve_id, action)
    chat_id = callback.get("message", {}).get("chat", {}).get("id")
    if chat_id:
        send_telegram(f"✅ Feedback recorded: <b>{cve_id}</b> → {action}", token, str(chat_id))


def _webhook_server(token: str, port: int = 8080, secret: str = ""):
    """Simple HTTP server to receive Telegram webhook updates."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            # Verify secret token
            if secret:
                provided = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                if provided != secret:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"Forbidden")
                    return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                update = json.loads(body)
                _handle_callback_query(update, token)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception as e:
                print(f"Webhook error: {e}")
                self.send_response(500)
                self.end_headers()

    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Webhook server listening on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
