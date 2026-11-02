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
    state_path = Path(__file__).with_name("sentinel_state.json")
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

def _normalize_text(text: str) -> str:
    """Normalize text to catch evasion attempts.

    Handles:
    - Leetspeak (1->i, 0->o, 3->e, 4->a, 5->s, 7->t, 8->b)
    - Unicode normalization (non-English homoglyphs)
    - Zero-width character removal
    - Case folding
    """
    if not text:
        return ""
    # Remove zero-width and invisible characters
    text = re.sub(r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]', '', text)
    # Unicode normalization (NFKC) — catches homoglyphs
    import unicodedata
    text = unicodedata.normalize("NFKC", text)
    # Leetspeak normalization
    leet_map = str.maketrans("0134578", "oieasbt")
    text = text.translate(leet_map)
    # Case fold (handles ß -> ss, etc.)
    text = text.casefold()
    return text


def _matches_keywords(entry_text: str, keywords: list[str]) -> bool:
    text = _normalize_text(entry_text)
    for kw in keywords:
        pattern = r"\b" + re.escape(_normalize_text(kw)) + r"\b"
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
        return []

    config = _load_config()
    news_config = config.get("news", {})
    keywords = news_config.get("keywords", [])
    sources = news_config.get("sources", NEWS_SOURCES)
    state = _load_state()
    seen = set(state.get("seen_news", []))
    # Preserve main module state to avoid clobbering
    _main_seen = state.get("seen", [])
    _main_last_run = state.get("last_run")

    alerts = []
    for source in sources:
        try:
            feed = feedparser.parse(source)
        except Exception:
            continue
        for entry in feed.entries[:max_items]:
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
                "title": title,
                "link": link,
                "summary": summary[:200],
                "severity": severity,
                "source": source,
                "published": entry.get("published", datetime.now(timezone.utc).isoformat()),
            })
            seen.add(item_id)

    state["seen_news"] = list(seen)[-200:]
    # Restore main module state
    state["seen"] = _main_seen
    state["last_run"] = _main_last_run
    _save_state(state)
    return alerts
