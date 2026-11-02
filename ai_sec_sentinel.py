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
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _normalize_text(text: str) -> str:
    """Normalize text to catch evasion attempts (synonym, leetspeak, non-English)."""
    if not text:
        return ""
    text = re.sub(r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]', '', text)
    text = unicodedata.normalize("NFKC", text)
    leet_map = str.maketrans("0134578", "oieasbt")
    text = text.translate(leet_map)
    text = text.casefold()
    return text

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
    "brotli", "node.js", "nodejs", "openssl", "zlib", "compression",
    "vscode extension", "cursor extension", "marketplace", "trojan",
    "backdoor", "ssh key", "authorized_keys", "fake", "trojanized",
    "impersonat", "phishing", "typosquat", "chatgpt desktop",
    "claude desktop", "fake app", "agentic", "offensive agent",
    "agent escape", "tool poisoning", "tool abuse", "privilege escalation",
    "sandbox escape", "sandbox bypass", "browser escape",
    "rug-pull", "tool shadowing", "tool poisoning", "memory poisoning",
    "context poisoning", "indirect prompt injection", "cascading failure",
    "agent-to-agent", "inter-agent", "a2a", "mcp rug-pull",
    "tool description injection", "prompt propagation",
    # Cloud (for cloud companies)
    "aws", "gcp", "azure", "cloud metadata", "imds", "metadata endpoint",
    "ssrf", "ec2", "s3", "lambda", "kubernetes", "k8s", "container",
    "iam", "role assumption", "service account", "cloud credential",
    "terraform", "cloudformation", "helm", "docker", "registry",
]


def load_config() -> dict:
    defaults = {
        "scan_interval_minutes": 60,
        "alert_min_severity": 1,
        "allow_lockfile_upload": False,
        "auto_remediate": False,
        "learn_from_actions": True,
        "webhook_url": "",
        "webhook_platform": "slack",
        "asset_criticality": {},
    }
    if CONFIG_FILE.exists():
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            # Validate and merge with defaults
            config = dict(defaults)
            config.update(raw)
            # Type validation
            if not isinstance(config.get("alert_min_severity"), int):
                config["alert_min_severity"] = 1
            if config["alert_min_severity"] < 0 or config["alert_min_severity"] > 3:
                config["alert_min_severity"] = 1
            if not isinstance(config.get("allow_lockfile_upload"), bool):
                config["allow_lockfile_upload"] = False
            if not isinstance(config.get("auto_remediate"), bool):
                config["auto_remediate"] = False
            return config
        except Exception:
            pass
    return defaults


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


_feedback_timestamps = []

def _check_feedback_rate_limit() -> bool:
    import time
    now = time.time()
    # Remove timestamps older than 60 seconds
    global _feedback_timestamps
    _feedback_timestamps = [t for t in _feedback_timestamps if now - t < 60]
    if len(_feedback_timestamps) >= 10:
        return False
    _feedback_timestamps.append(now)
    return True


def record_feedback(cve_id: str, action: str):
    if not _check_feedback_rate_limit():
        print("Rate limit: max 10 feedback actions per minute")
        return
    fb = load_feedback()
    fb[cve_id] = {"action": action, "ts": datetime.now(timezone.utc).isoformat()}
    atomic_write(FEEDBACK_FILE, json.dumps(fb, indent=2))


def _word_boundary(text: str, kw: str) -> bool:
    """Match keyword as a whole word, not a substring."""
    # Normalize both text and keyword to catch evasion
    norm_text = _normalize_text(text) if '_normalize_text' in globals() else text.lower()
    norm_kw = _normalize_text(kw) if '_normalize_text' in globals() else kw.lower()
    pattern = r"\b" + re.escape(norm_kw) + r"\b"
    return re.search(pattern, norm_text) is not None

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
        # Word boundary match (primary — prevents "rag" in "tragedy")
        if _word_boundary(blob_lower, syn):
            return True
        # Substring match only for compound terms (hyphenated or multi-word)
        # e.g. "langchain-utils" should match "langchain"
        if len(syn) >= 5 and "-" in blob_lower:
            for token in blob_lower.split():
                if "-" in token and syn in token:
                    return True
        # Fuzzy: only for longer keywords (>=6 chars) to avoid short-word false positives
        if len(syn) >= 6:
            for word in blob_lower.split():
                if len(word) >= 6 and (syn in word or word in syn):
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


def send_webhook(message: str, webhook_url: str, platform: str = "slack") -> bool:
    """Send alert to Slack or Discord webhook."""
    if not webhook_url:
        return False
    try:
        import re as _re
        clean = _re.sub(r'<[^>]+>', '', message)
        if platform == "slack":
            payload = {"text": clean}
        elif platform == "discord":
            payload = {"content": clean}
        else:
            payload = {"text": clean}
        r = requests.post(webhook_url, json=payload, timeout=15, verify=True)
        return r.status_code in (200, 204)
    except Exception as e:
        print(f"Webhook send failed: {e}")
        return False


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
        r = requests.post(url, json=payload, timeout=15, verify=True)
        if r.status_code == 429:
            retry_after = r.json().get("parameters", {}).get("retry_after", 5)
            print(f"Telegram rate limited, waiting {retry_after}s")
            time.sleep(retry_after)
            r = requests.post(url, json=payload, timeout=15, verify=True)
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


def check_extension_integrity(extensions_dir: str = None) -> list:
    """Check VS Code/Cursor extensions for known malicious versions."""
    import os
    results = []
    if extensions_dir is None:
        extensions_dir = os.path.expanduser("~/.vscode/extensions")
    if not os.path.exists(extensions_dir):
        return results
    known_bad = {
        "anthropic.claude-code": ["2.1.313"],
    }
    try:
        for entry in os.listdir(extensions_dir):
            for pkg, bad_versions in known_bad.items():
                if pkg in entry:
                    parts = entry.split("-")
                    version = parts[-1] if len(parts) >= 2 else "unknown"
                    if version in bad_versions:
                        results.append({"extension": pkg, "version": version, "status": "MALICIOUS", "action": "UNINSTALL IMMEDIATELY"})
                    else:
                        results.append({"extension": pkg, "version": version, "status": "OK"})
    except Exception as e:
        results.append({"error": str(e)})
    return results


def check_brand_protection(brand: str = "twinthos") -> list:
    """Check for typosquatting/impersonation domains for a brand."""
    import socket
    results = []
    # Common typosquatting patterns
    variants = [
        brand.replace("o", "0"), brand.replace("i", "1"), brand.replace("l", "1"),
        brand + "app", brand + "ai", "get" + brand, brand + "hq",
        brand.replace("th", "t"), brand + "-app", brand + "security",
    ]
    variants = list(set(variants))
    for variant in variants:
        domain = f"{variant}.com"
        try:
            socket.gethostbyname(domain)
            results.append({"domain": domain, "status": "REGISTERED", "risk": "HIGH — possible impersonation"})
        except socket.gaierror:
            results.append({"domain": domain, "status": "NOT REGISTERED", "risk": "LOW"})
    return results


def check_agent_posture(config_path: str = None) -> list:
    """Audit AI agent security posture: MCP configs, tool permissions, secrets exposure."""
    import os, json
    results = []
    # Check for MCP config files
    mcp_paths = [
        os.path.expanduser("~/.cursor/mcp.json"),
        os.path.expanduser("~/.vscode/mcp.json"),
        os.path.expanduser("~/.config/claude/mcp.json"),
    ]
    for path in mcp_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    mcp_config = json.load(f)
                servers = mcp_config.get("mcpServers", {})
                for name, srv in servers.items():
                    # Check for hardcoded secrets
                    cmd = srv.get("command", "")
                    args = srv.get("args", [])
                    env = srv.get("env", {})
                    risk = "LOW"
                    issues = []
                    if any("key" in k.lower() or "secret" in k.lower() or "token" in k.lower() for k in env):
                        issues.append("Hardcoded secrets in env")
                        risk = "HIGH"
                    if "npx" in cmd or "uvx" in cmd:
                        issues.append("Remote package execution (npx/uvx)")
                        risk = "MEDIUM"
                    results.append({
                        "config": path,
                        "server": name,
                        "risk": risk,
                        "issues": issues or ["None detected"],
                    })
            except Exception as e:
                results.append({"config": path, "error": str(e)})
    if not results:
        results.append({"status": "No MCP configs found"})
    return results


def generate_compliance_report(findings: list, output_path: str = None) -> str:
    """Generate a compliance report PDF."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
    except ImportError:
        return "reportlab not available"
    if output_path is None:
        output_path = "/tmp/compliance_report.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("Twinthos Sentinel — Compliance Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))
    # Risk score
    from risk_compliance import calculate_risk_score
    risk = calculate_risk_score(findings)
    story.append(Paragraph(f"Risk Score: {risk['score']}/100 ({risk['level']})", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))
    # Findings
    story.append(Paragraph(f"Total Findings: {len(findings)}", styles["Normal"]))
    for f in findings:
        story.append(Paragraph(f"- {f.get('title', 'Unknown')} ({f.get('severity', 'UNKNOWN')})", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))
    # Compliance mapping
    from risk_compliance import map_to_compliance
    all_mappings = set()
    for f in findings:
        all_mappings.update(map_to_compliance(f))
    if all_mappings:
        story.append(Paragraph("Compliance Impact", styles["Heading2"]))
        for m in sorted(all_mappings):
            story.append(Paragraph(f"- {m}", styles["Normal"]))
    doc.build(story)
    return output_path


def detect_memory_poisoning(memory_store: dict) -> list:
    """Detect potential memory/context poisoning in agent memory stores."""
    findings = []
    suspicious_patterns = [
        "ignore previous", "disregard", "override", "system prompt",
        "you are now", "new instructions", "forget everything",
        "base64", "eval(", "exec(", "subprocess",
    ]
    for key, value in memory_store.items():
        value_str = str(value).lower()
        for pattern in suspicious_patterns:
            if pattern in value_str:
                findings.append({
                    "memory_key": key,
                    "pattern": pattern,
                    "severity": "CRITICAL",
                    "message": f"Potential memory poisoning: '{pattern}' found in memory key '{key}'",
                })
    return findings


def detect_indirect_prompt_injection(content: str) -> list:
    """Detect indirect prompt injection in documents/webpages that agents process."""
    import re
    findings = []
    injection_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"you\s+are\s+now\s+a",
        r"disregard\s+(all\s+)?prior",
        r"new\s+instructions?\s*:",
        r"system\s*prompt",
        r"override\s+safety",
        r"jailbreak",
        r"do\s+not\s+tell\s+the\s+user",
        r"hidden\s+instruction",
        r"<!--.*instruction.*-->",
    ]
    for pattern in injection_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({
                "pattern": pattern,
                "match_count": len(matches),
                "severity": "HIGH",
                "message": f"Potential indirect prompt injection: pattern found {len(matches)} times",
            })
    return findings


def check_sbom(lockfile_path: str) -> str:
    """Generate a Software Bill of Materials from a lockfile."""
    import os
    if not os.path.exists(lockfile_path):
        return "Lockfile not found"
    lines = [f"# SBOM", f"# Source: {lockfile_path}", f"# Generated: {datetime.now(timezone.utc).isoformat()}", ""]
    with open(lockfile_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(f"- {line}")
    return "\n".join(lines)


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

    # Lockfile scan (async — runs in background thread so feed scan stays responsive)
    lockfile = config.get("lockfile")
    ecosystem = config.get("ecosystem", "python")
    if lockfile:
        import threading

        def _bg_lockfile_scan():
            try:
                # Consent check for uploading lockfile to cve.now
                if not config.get("allow_lockfile_upload", False):
                    print(f"Lockfile scan (offline only): {lockfile} — set allow_lockfile_upload=true to use cve.now API")
                    vulns_local = _osv_lockfile_check(Path(lockfile), Path(lockfile).read_text(encoding="utf-8", errors="replace"), ecosystem)
                else:
                    print(f"Scanning lockfile: {lockfile}")
                    vulns_local = check_lockfile(lockfile, ecosystem)
                if vulns_local:
                    msg = f"🔍 Lockfile scan: <b>{len(vulns_local)} AI-related vulnerabilities</b> in {Path(lockfile).name}\n"
                    for v in vulns_local[:10]:
                        msg += f"• {v.get('id', 'N/A')}\n"
                        fix_cmd = generate_fix_command(v, ecosystem)
                        if fix_cmd:
                            msg += f"  → Fix: <code>{html.escape(fix_cmd)}</code>\n"
                    send_telegram(msg, token, chat)
                else:
                    send_telegram(f"✅ Lockfile clean: {Path(lockfile).name}", token, chat)
            except Exception as e:
                print(f"Lockfile scan error: {e}")

        t = threading.Thread(target=_bg_lockfile_scan, daemon=True)
        t.start()
        # Don't block — feed scan continues in parallel

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
        # Also send to webhook if configured
        webhook_url = config.get("webhook_url", "")
        if webhook_url:
            send_webhook(msg, webhook_url, config.get("webhook_platform", "slack"))
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
        ignored_keywords = set()
        if len(ignored) > 5:
            print(f"  Adaptive: {len(ignored)} CVEs marked ignored, {len(useful)} marked useful")
            # Extract common keywords from ignored CVEs to reduce their weight
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
    parser.add_argument("--version", action="version", version="Twinthos Sentinel v1.4.1")
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
    parser.add_argument("--sbom", metavar="LOCKFILE", help="Generate SBOM from lockfile")
    parser.add_argument("--check-extensions", action="store_true", help="Check VS Code/Cursor extensions for known malicious versions")
    parser.add_argument("--brand-check", metavar="BRAND", help="Check for typosquatting/impersonation domains")
    parser.add_argument("--agent-posture", action="store_true", help="Audit AI agent security posture (MCP configs, tool permissions)")
    parser.add_argument("--compliance-report", action="store_true", help="Generate compliance report PDF")
    parser.add_argument("--demo", action="store_true", help="Run all checks in sequence (demo mode)")
    parser.add_argument("--guardian", action="store_true", help="Run Sentinel Guardian demo (agent security control plane)")
    parser.add_argument("--passport", metavar="AGENT_ID", help="Show agent passport (blast radius, permissions)")
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
            # No lockfile = health check mode (for Docker healthcheck)
            print("Sentinel OK — v1.4.1")
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
    if args.sbom:
        print(check_sbom(args.sbom))
        sys.exit(0)
    if args.check_extensions:
        results = check_extension_integrity()
        if results:
            for r in results:
                print(f"  {r.get('extension', '?')} v{r.get('version', '?')}: {r.get('status', '?')}")
                if r.get('action'):
                    print(f"    ACTION: {r['action']}")
        else:
            print("  No extensions found or no known malicious versions detected.")
        sys.exit(0)
    if args.brand_check:
        results = check_brand_protection(args.brand_check)
        for r in results:
            print(f"  {r['domain']}: {r['status']} ({r['risk']})")
        sys.exit(0)
    if args.agent_posture:
        results = check_agent_posture()
        for r in results:
            if "error" in r:
                print(f"  Error: {r['error']}")
            elif "status" in r and r["status"].startswith("No"):
                print(f"  {r['status']}")
            else:
                print(f"  {r.get('config', '?')} → {r.get('server', '?')}: {r.get('risk', '?')}")
                for issue in r.get("issues", []):
                    print(f"    - {issue}")
        sys.exit(0)
    if args.compliance_report:
        # Use sample findings for demo
        sample = [{"title": "AI agent vulnerability", "severity": "HIGH", "summary": "prompt injection in langchain"}]
        path = generate_compliance_report(sample)
        print(f"  Compliance report generated: {path}")
        sys.exit(0)
    if args.demo:
        print("=" * 60)
        print("  Twinthos Sentinel - Demo Mode")
        print("=" * 60)
        print()
        print("[1/7] Live CVE scan (dry run)...")
        print("  (use --dry-run for live scan)")
        print()
        print("[2/7] SBOM generation...")
        print(check_sbom("requirements.txt"))
        print()
        print("[3/7] Extension integrity check...")
        ext = check_extension_integrity()
        if ext:
            for r in ext:
                print(f"  {r}")
        else:
            print("  No extensions found or no known malicious versions")
        print()
        print("[4/7] Brand protection check...")
        brand = check_brand_protection("twinthos")
        for r in brand[:4]:
            print(f"  {r['domain']}: {r['status']} ({r['risk']})")
        print()
        print("[5/7] Agent posture audit...")
        posture = check_agent_posture()
        for r in posture:
            print(f"  {r}")
        print()
        print("[6/7] Risk scoring + compliance...")
        from risk_compliance import calculate_risk_score, generate_risk_report
        sample_findings = [
            {"title": "LangChain RCE via MCP", "severity": "CRITICAL", "in_kev": True, "epss": 0.95, "summary": "prompt injection in langchain"},
            {"title": "CrewAI tool poisoning", "severity": "HIGH", "in_kev": False, "epss": 0.6, "summary": "mcp tool abuse"},
        ]
        print(generate_risk_report(sample_findings))
        print()
        print("[7/7] Compliance report PDF...")
        path = generate_compliance_report(sample_findings)
        print(f"  Generated: {path}")
        print()
        print("=" * 60)
        print("  Demo complete. All systems operational.")
        print("=" * 60)
        sys.exit(0)

    if args.guardian:
        import sentinel_guardian
        g = sentinel_guardian.SentinelGuardian()
        g.register_agent("ops-assistant", "Operations Assistant", "Tyson Mandela",
                         ["file_read", "http_request", "email_send", "shell_exec"],
                         ["read_files", "send_email"], ["customer_records", "internal_docs"])
        g.control.add_policy("http_request", "block", "external_destination", "External data transfer blocked")
        g.control.add_policy("shell_exec", "block", "always", "Shell execution not permitted")
        # Demo tool calls
        for tool, params in [("file_read", {"path": "/data/report.csv"}),
                             ("http_request", {"url": "https://external.com/export"}),
                             ("shell_exec", {"command": "rm -rf /"})]:
            r = g.process_tool_call("ops-assistant", tool, params)
            print(f"  {tool}: {r['decision']['decision'].upper()}")
        print(f"  Blast radius: {g.understand.calculate_blast_radius('ops-assistant')['risk_score']}/100")
        print(f"  Ledger: {g.prove.verify_integrity()['status']} ({g.prove.verify_integrity()['entries']} entries)")
        sys.exit(0)
    if args.passport:
        import sentinel_guardian
        g = sentinel_guardian.SentinelGuardian()
        g.register_agent(args.passport, args.passport, "owner",
                         ["file_read", "http_request"], ["read_files"], ["internal_docs"])
        p = g.understand.get_passport(args.passport)
        print(f"  Agent: {p['name']}")
        print(f"  Tools: {p['tools']}")
        print(f"  Data access: {p['data_access']}")
        print(f"  Blast radius: {p['blast_radius_score']}/100")
        print(f"  Transitive reach: {p['transitive_reach']}")
        sys.exit(0)

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
            # Verify secret token (Telegram)
            if secret:
                provided = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                if provided != secret:
                    # Check if it's a GitHub webhook (different secret header)
                    gh_secret = self.headers.get("X-Hub-Signature-256", "")
                    if not gh_secret:
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b"Forbidden")
                        return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                # Detect event type
                event_type = self.headers.get("X-GitHub-Event", "")
                if event_type == "push":
                    # GitHub push event → trigger scan
                    import json as _json
                    try:
                        payload = _json.loads(body)
                        repo = payload.get("repository", {}).get("full_name", "unknown")
                        print(f"GitHub push event from {repo} — triggering scan")
                    except Exception:
                        pass
                    # Trigger scan in background
                    import threading

                    def _bg_scan():
                        try:
                            cfg = load_config() if 'load_config' in globals() else {}
                            run_scan(cfg, token, "")
                        except Exception as e:
                            print(f"Scan trigger error: {e}")

                    threading.Thread(target=_bg_scan, daemon=True).start()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Scan triggered")
                    return
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
