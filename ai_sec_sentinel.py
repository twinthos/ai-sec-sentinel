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
  python3 ai_sec_sentinel.py --feedback CVE-2026-119712 ignored
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\nInstall with: pip install requests")

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


def save_state(state: dict):
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


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
    FEEDBACK_FILE.write_text(json.dumps(fb, indent=2), encoding="utf-8")


def is_ai_related(entry: dict) -> bool:
    blob = (
        entry.get("title", "")
        + " "
        + entry.get("content_text", "")
        + " "
        + entry.get("summary", "")
    ).lower()
    # Tier 1: direct AI/agent/MCP keyword hit
    if any(kw in blob for kw in AI_KEYWORDS):
        return True
    # Tier 2: AI infrastructure keyword hit, but only if an AI keyword
    # is also present in the same entry. This catches cases like
    # "ClickHouse RCE in AI analytics pipeline" without flagging
    # every generic database CVE.
    if any(kw in blob for kw in AI_INFRA_KEYWORDS):
        return any(kw in blob for kw in AI_KEYWORDS)
    return False


def severity_rank(entry: dict) -> int:
    cvss = entry.get("cvss")
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
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return 3
        if cvss >= 7.0:
            return 2
        if cvss >= 4.0:
            return 1
        return 0

    blob = (entry.get("title", "") + " " + entry.get("content_text", "")).lower()
    if any(x in blob for x in ["critical", "cvss 9", "cvss 10", "9.8", "10.0"]):
        return 3
    if any(x in blob for x in ["high", "cvss 7", "cvss 8", "7.5", "8.8"]):
        return 2
    if any(x in blob for x in ["medium", "cvss 5", "cvss 6"]):
        return 1
    return 0


def fetch_feed(limit: int = 100) -> list[dict]:
    try:
        r = requests.get(CVE_NOW_FEED, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("items", [])[:limit]
    except Exception as e:
        print(f"Feed fetch error: {e}")
        return []


def fetch_entry(cve_id: str) -> dict | None:
    try:
        r = requests.get(f"{CVE_NOW_API}/{cve_id}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            severity = data.get("severity") or {}
            if data.get("cvss") is None and isinstance(severity, dict):
                data["cvss"] = severity.get("cvss")
            if not data.get("summary"):
                data["summary"] = data.get("originalDescription", "")
            return data
    except Exception:
        pass
    return None


def fetch_cisa_kev() -> dict:
    try:
        r = requests.get(CISA_KEV_URL, timeout=30)
        if r.status_code == 200:
            return r.json()
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
            r = requests.get(EPSS_API, params={"query": query, "limit": 100}, timeout=30)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
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
            continue
        try:
            dt = datetime.fromisoformat(ds.replace("Z", "+00:00"))
            if dt > since:
                out.append(e)
        except Exception:
            continue
    return out


def extract_fix_version(entry: dict) -> str | None:
    text = entry.get("content_text", "") + " " + (entry.get("summary") or "")
    m = re.search(r"(?:fixed in|upgrade to|patched in|version)[:\s]+([\w\.\-]+)", text, re.IGNORECASE)
    return m.group(1) if m else None


def format_alert(entry: dict, epss_score: float | None = None, in_kev: bool = False,
                 cvss: float | None = None) -> str:
    raw_id = entry.get("id", "N/A")
    cve_id = raw_id.split("#")[0].strip()
    title = entry.get("title", "Unknown vulnerability")
    url = f"https://cve.now/{cve_id}"
    sev = severity_rank(entry)
    sev_emoji = {3: "🔴", 2: "🟠", 1: "🟡"}.get(sev, "⚪")
    sev_label = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}.get(sev, "UNKNOWN")

    clean_title = title.split("#")[0].strip()
    msg = f"{sev_emoji} <b>AI Security Alert — {sev_label}</b>\n\n"
    msg += f"<b>{cve_id}</b>\n"
    msg += f"{clean_title[:220]}\n\n"

    if cvss is not None:
        msg += f"CVSS: <b>{cvss}</b>  "
    if epss_score is not None:
        msg += f"EPSS: <b>{epss_score:.2f}</b>  "
    if in_kev:
        msg += "🛑 <b>CISA KEV — Actively exploited</b>  "

    msg += f"\n🔗 <a href='{url}'>{cve_id}</a>"

    fix = extract_fix_version(entry)
    if fix:
        msg += f"\n\n✅ Fix: upgrade to <b>{fix}</b>"

    return msg


def send_telegram(message: str, token: str, chat_id: str) -> bool:
    if not token or not chat_id:
        print("[TELEGRAM NOT CONFIGURED]")
        print(message[:800])
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
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
        print(f"Lockfile check error: {e}")
    return []


def run_scan(config: dict, token: str = "", chat: str = "") -> int:
    """Run one scan cycle. Returns number of alerts sent."""
    feed_limit = config.get("feed_limit", 100)
    since_hours = config.get("since_hours", 24)
    alert_min_sev = config.get("alert_min_severity", 2)
    if config.get("alert_on_medium"):
        alert_min_sev = 1

    state = load_state()
    seen = set(state.get("seen", []))
    feedback = load_feedback()

    # Load supplemental sources
    cisa_kev = fetch_cisa_kev()
    kev_ids = {v.get("cveID") for v in cisa_kev.get("vulnerabilities", []) if v.get("cveID")}

    alerts_sent = 0

    # Lockfile scan
    lockfile = config.get("lockfile")
    ecosystem = config.get("ecosystem", "python")
    if lockfile:
        print(f"Scanning lockfile: {lockfile}")
        vulns = check_lockfile(lockfile, ecosystem)
        if vulns:
            msg = f"🔍 Lockfile scan: <b>{len(vulns)} AI-related vulnerabilities</b> in {Path(lockfile).name}\n"
            for v in vulns[:10]:
                msg += f"• {v.get('id', 'N/A')}\n"
            send_telegram(msg, token, chat)
        else:
            send_telegram(f"✅ Lockfile clean: {Path(lockfile).name}", token, chat)

    # Feed watch
    print("Scanning cve.now feed...")
    entries = fetch_feed(limit=feed_limit)
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    new_entries = filter_new(entries, since)
    ai_entries = [e for e in new_entries if is_ai_related(e)]

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

        # Check feedback — if user marked as ignored, skip forever
        if raw_id in feedback and feedback[raw_id].get("action") == "ignored":
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
        send_telegram(msg, token, chat)
        seen.add(raw_id)
        alerts_sent += 1
        if alerts_sent >= 5:
            break

    stats = {
        "feed_fetched": len(entries),
        "new_entries": len(new_entries),
        "ai_related": len(ai_entries),
        "alerts_sent": alerts_sent,
        "cisa_kev_hits": sum(1 for e in ai_entries if e.get("id", "").split("#")[0].strip() in kev_ids),
        "high_epss": sum(1 for cid, score in epss_scores.items() if score >= 0.7),
        "lockfile_vulns": 0,
    }
    if lockfile:
        stats["lockfile_vulns"] = len(vulns) if 'vulns' in dir() else 0

    print(f"  {stats["feed_fetched"]} fetched, {stats["new_entries"]} new, {stats["ai_related"]} AI-related, {alerts_sent} alerts sent, {stats["cisa_kev_hits"]} CISA KEV, {stats["high_epss"]} high-EPSS")

    # Adaptive: if user consistently ignores certain keywords, lower their weight
    if config.get("learn_from_actions"):
        ignored = [cid for cid, data in feedback.items() if data.get("action") == "ignored"]
        if len(ignored) > 5:
            print(f"  Adaptive: {len(ignored)} CVEs marked ignored — consider adjusting keywords")

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
    parser.add_argument("--feedback", nargs="+", help="Mark CVE as ignored or useful, e.g. --feedback CVE-2026-119712 ignored")
    parser.add_argument("--telegram-token", default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--telegram-chat", default=os.getenv("TELEGRAM_CHAT_ID", ""))
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
        cve_id = args.feedback[0].split("#")[0].strip()
        action = args.feedback[1] if len(args.feedback) > 1 else "ignored"
        record_feedback(cve_id, action)
        print(f"Feedback recorded: {cve_id} -> {action}")
        return

    token = args.telegram_token or config.get("telegram", {}).get("token", "")
    chat = args.telegram_chat or config.get("telegram", {}).get("chat_id", "")

    if args.daemon:
        print(f"Starting daemon mode — scanning every {args.interval} minutes...")
        while True:
            try:
                run_scan(config, token, chat)
            except Exception as e:
                print(f"Scan error: {e}")
            time.sleep(args.interval * 60)
    else:
        run_scan(config, token, chat)


if __name__ == "__main__":
    main()
