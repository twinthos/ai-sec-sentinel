#!/usr/bin/env python3
"""
Twinthos AI Security Sentinel — real-time AI vulnerability monitor.

Polls cve.now, CISA KEV, and FIRST EPSS for new AI/agent/MCP vulnerabilities.
No API key required for any source.

Usage:
  python3 ai_sec_sentinel.py                        # scan feed, alert on new AI vulns
  python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python
  python3 ai_sec_sentinel.py --check-only            # lockfile only, no feed watch
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\nInstall with: pip install requests")

CVE_NOW_FEED = "https://cve.now/feed?format=json"
CVE_NOW_API = "https://cve.now/api/v1/entries"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores.csv"
STATE_FILE = Path(__file__).with_name("sentinel_state.json")

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


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen": [], "last_run": None}


def save_state(state: dict):
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_config() -> dict:
    config_path = Path(__file__).with_name(sentinel_config.json)
    if config_path.exists():
        try:
            return json.loads(config_path.read_text(encoding=utf-8))
        except Exception:
            pass
    return {}


def is_ai_related(entry: dict) -> bool:
    blob = (
        entry.get("title", "")
        + " "
        + entry.get("content_text", "")
        + " "
        + entry.get("summary", "")
    ).lower()
    return any(kw in blob for kw in AI_KEYWORDS)


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
            # Normalize cvss from nested severity object
            severity = data.get("severity") or {}
            if data.get("cvss") is None and isinstance(severity, dict):
                data["cvss"] = severity.get("cvss")
            # Normalize summary
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


def fetch_epss_scores() -> dict:
    scores = {}
    try:
        r = requests.get(EPSS_URL, timeout=30)
        if r.status_code == 200:
            for line in r.text.splitlines()[1:]:
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    cve_id = parts[0].strip()
                    try:
                        scores[cve_id] = float(parts[1].strip())
                    except ValueError:
                        continue
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


def format_alert(entry: dict, epss_score: float | None = None, in_kev: bool = False) -> str:
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

    cvss = entry.get("cvss")
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


def main():
    parser = argparse.ArgumentParser(description="Twinthos AI Security Sentinel")
    parser.add_argument("--lockfile", help="Path to lockfile")
    parser.add_argument("--ecosystem", choices=["python", "npm", "rust", "go", "ruby", "php", "dotnet"])
    parser.add_argument("--check-only", action="store_true", help="Lockfile only, no feed watch")
    parser.add_argument("--feed-limit", type=int, default=100)
    parser.add_argument("--since-hours", type=int, default=24)
    parser.add_argument("--alert-on-everything", action="store_true", help="Alert on medium+ instead of high/critical only")
    parser.add_argument("--telegram-token", default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--telegram-chat", default=os.getenv("TELEGRAM_CHAT_ID", ""))
    args = parser.parse_args()

    token = args.telegram_token
    chat = args.telegram_chat
    state = load_state()
    seen = set(state.get("seen", []))

    # Load supplemental sources
    cisa_kev = fetch_cisa_kev()
    kev_ids = {v.get("cveID") for v in cisa_kev.get("vulnerabilities", []) if v.get("cveID")}
    epss_scores = fetch_epss_scores()

    min_sev = 1 if args.alert_on_everything else 2

    # 1. Lockfile scan
    if args.lockfile:
        print(f"Scanning lockfile: {args.lockfile}")
        vulns = check_lockfile(args.lockfile, args.ecosystem or "python")
        if vulns:
            msg = f"🔍 Lockfile scan: <b>{len(vulns)} AI-related vulnerabilities</b> in {Path(args.lockfile).name}\n"
            for v in vulns[:10]:
                msg += f"• {v.get('id', 'N/A')}\n"
            send_telegram(msg, token, chat)
        else:
            send_telegram(f"✅ Lockfile clean: {Path(args.lockfile).name}", token, chat)

    # 2. Feed watch
    if not args.check_only:
        print("Scanning cve.now feed...")
        since = datetime.now(timezone.utc) - timedelta(hours=args.since_hours)
        entries = fetch_feed(limit=args.feed_limit)
        new_entries = filter_new(entries, since)
        ai_entries = [e for e in new_entries if is_ai_related(e)]

        alerts_sent = 0
        for entry in ai_entries:
            raw_id = entry.get("id", "").split("#")[0].strip()
            if raw_id in seen:
                continue
            sev = severity_rank(entry)
            if sev < min_sev:
                continue

            # Fetch full entry for CVSS if missing from feed
            if entry.get("cvss") is None:
                full = fetch_entry(raw_id)
                if full:
                    entry["cvss"] = full.get("cvss")

            epss = epss_scores.get(raw_id)
            in_kev = raw_id in kev_ids
            msg = format_alert(entry, epss_score=epss, in_kev=in_kev)
            send_telegram(msg, token, chat)
            seen.add(raw_id)
            alerts_sent += 1
            if alerts_sent >= 5:
                break

        print(f"  {len(entries)} fetched, {len(new_entries)} new, {len(ai_entries)} AI-related, {alerts_sent} alerts sent")

    state["seen"] = list(seen)[-500:]
    save_state(state)
    print("Done.")


if __name__ == "__main__":
    main()
