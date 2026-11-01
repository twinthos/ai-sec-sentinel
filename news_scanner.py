"""
News scanner for Twinthos Sentinel.

Scrapes RSS feeds and news sources for:
- Brand/reputation threats
- Supplier incidents
- Industry-specific risks

Filters to YOUR keywords and alerts in real-time.
"""

import json
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

try:
    import feedparser
    import requests
except ImportError:
    feedparser = None
    requests = None

# Import atomic_write from main module (with fallback)
try:
    from ai_sec_sentinel import atomic_write
except ImportError:
    def atomic_write(path, data):
        path = Path(path)
        path.write_text(data, encoding="utf-8")

NEWS_SOURCES = [
    "https://feeds.bbci.co.uk/news/technology/rss.xml",
    "https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml",
    "https://www.theverge.com/rss/index.xml",
    "https://techcrunch.com/feed/",
    "https://www.wired.com/feed/rss",
]

def _load_config():
    config_path = Path(__file__).with_name("sentinel_config.json")
    if config_path.exists():
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def _load_state():
    state_path = Path(__import__("os").environ.get("SENTINEL_DATA_DIR", Path(__file__).parent)) / "sentinel_state.json"
    if state_path.exists():
        try:
            return json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen": [], "seen_news": [], "last_run": None, "last_news_run": None}

def _save_state(state: dict):
    state["last_news_run"] = datetime.now(timezone.utc).isoformat()
    state_path = Path(__file__).with_name("sentinel_state.json")
    atomic_write(state_path, json.dumps(state, indent=2))

def _matches_keywords(entry_text: str, keywords: list[str]) -> bool:
    text = entry_text.lower()
    for kw in keywords:
        pattern = r"\b" + re.escape(kw.lower()) + r"\b"
        if re.search(pattern, text):
            return True
    return False

def _is_negative_sentiment(text: str) -> bool:
    negative = [
        "breach", "leak", "attack", "vulnerability", "exploit",
        "ransomware", "malware", "compromise", "incident", "hacked",
        "phishing", "supply chain", "backdoor", "zero-day", "0day",
        "data loss", "unauthorized", "exposure", "threat", "risk",
    ]
    return any(term in text.lower() for term in negative)

def scan_news(max_items: int = 50) -> list[dict]:
    """Scan configured RSS/news sources for threats matching YOUR keywords."""
    if feedparser is None:
        raise RuntimeError("News monitoring requires feedparser; install requirements.txt")

    config = _load_config()
    news_config = config.get("news", {})
    keywords = news_config.get("keywords", [])
    sources = news_config.get("sources", NEWS_SOURCES)
    state = _load_state()
    seen = set(state.get("seen_news", []))

    alerts = []
    succeeded = 0
    failed = 0
    for source in sources:
        try:
            feed = feedparser.parse(source)
            status = getattr(feed, "status", 200)
            if isinstance(status, int) and status >= 400:
                raise RuntimeError(f"RSS source returned HTTP {status}")
            entries = feed.entries
            succeeded += 1
        except Exception as error:
            failed += 1
            print(f"RSS source unavailable: {source} ({type(error).__name__})")
            continue
        for entry in entries[:max_items]:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary = entry.get("summary", "")
            blob = f"{title} {summary}"

            if not keywords:
                continue
            if not _matches_keywords(blob, keywords):
                continue
            if not _is_negative_sentiment(blob):
                continue

            item_id = link or title
            if item_id in seen:
                continue

            severity = "HIGH" if _matches_keywords(blob, ["breach", "attack", "ransomware", "zero-day"]) else "MEDIUM"
            alerts.append({
                "id": item_id,
                "title": title,
                "link": link,
                "summary": summary[:200],
                "severity": severity,
                "source": source,
                "published": entry.get("published", datetime.now(timezone.utc).isoformat()),
            })
            seen.add(item_id)

    if sources and not succeeded:
        raise RuntimeError("Every configured RSS source failed; news coverage unavailable")
    if failed:
        print(f"NEWS COVERAGE WARNING: {failed} of {len(sources)} feeds unavailable")
    # Only the caller can mark a news alert delivered after its sink succeeds.
    # Scanning itself is read-only, including in dry-run mode.
    return alerts
