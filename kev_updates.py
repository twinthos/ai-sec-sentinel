"""Select new, relevant additions from CISA's KEV catalog.

KEV inclusion is an independently useful exploitation-status signal. The
catalog publishes a calendar date, not a timestamp; checking the inclusive
date avoids missing entries added later on the boundary day.
"""
import re
from datetime import date, datetime
from typing import Callable


_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def select_recent_relevant_kev(
    feed: dict,
    since: datetime,
    suppliers: list[str],
    matches_ai: Callable[[dict], bool],
) -> list[dict]:
    if not isinstance(feed, dict) or not isinstance(feed.get("vulnerabilities"), list):
        raise ValueError("Invalid CISA KEV response")
    patterns = [
        re.compile(r"(?<!\w)" + re.escape(name.strip()) + r"(?!\w)", re.IGNORECASE)
        for name in suppliers
        if isinstance(name, str) and len(name.strip()) >= 3
    ]
    selected = []
    selected_ids = set()
    for item in feed["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID", "")
        if not isinstance(cve_id, str) or not _CVE.fullmatch(cve_id):
            continue
        try:
            added = date.fromisoformat(item.get("dateAdded", ""))
        except (TypeError, ValueError):
            continue
        if added < since.date():
            continue
        text = " ".join(
            str(item.get(field) or "")
            for field in ("vendorProject", "product", "vulnerabilityName", "shortDescription")
        )
        is_relevant = bool(matches_ai({"title": text, "summary": text}))
        if not is_relevant and patterns:
            is_relevant = any(p.search(text) for p in patterns)
        if is_relevant and cve_id not in selected_ids:
            selected.append(item)
            selected_ids.add(cve_id)
    return selected
