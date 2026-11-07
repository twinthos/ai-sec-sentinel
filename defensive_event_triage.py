#!/usr/bin/env python3
"""Offline defensive triage of NORMALISED cloud audit events.

NOT an ARTEX signature, network IDS, live M365 integration or proof of an attack.
This tool reads a local synthetic/redacted JSONL dataset; never reaches a network.
Reports aggregate behaviour only, never identifiers, IPs, secrets or raw events.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_FILE_BYTES = 12_000_000
MAX_EVENTS = 100_000
SIGN_IN_EVENTS = {"sign_in", "user_sign_in"}
HIGH_RISK_EVENTS = {
    "app_credential_added": "Application credential added",
    "oauth_permission_granted": "OAuth permissions granted",
    "privileged_role_granted": "Privileged role granted",
}
WINDOW = timedelta(minutes=5)


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def analyse(events, min_failures=20, min_accounts=5, min_tenants=2):
    """Return aggregate indicators, without emitting any source identifiers."""
    accepted = []
    invalid = 0
    for row in events:
        if not isinstance(row, dict) or not isinstance(row.get("event"), str):
            invalid += 1
            continue
        stamp = parse_time(row.get("timestamp"))
        if stamp is None:
            invalid += 1
            continue
        accepted.append((stamp, row))
    accepted.sort(key=lambda x: x[0])
    history = defaultdict(deque)
    # Throttle per source per window, not for the lifetime of the whole dataset.
    # Otherwise a second independent campaign from the same IP disappears.
    last_alert_at = {}
    signals = []
    for stamp, row in accepted:
        kind = row["event"]
        if kind in HIGH_RISK_EVENTS:
            signals.append({
                "type": "high_risk_change",
                "activity": HIGH_RISK_EVENTS[kind],
                "utc": stamp.isoformat(),
                "explanation": "Verify this change against approved administrators and change records."
            })
        if kind not in SIGN_IN_EVENTS or row.get("result") != "failure":
            continue
        ip = row.get("source_ip")
        principal = row.get("account_id")
        tenant = row.get("tenant_id")
        if not all(isinstance(v, str) and v for v in (ip, principal, tenant)):
            invalid += 1
            continue
        q = history[ip]
        while q and stamp - q[0][0] > WINDOW:
            q.popleft()
        q.append((stamp, principal, tenant))
        previous = last_alert_at.get(ip)
        if previous is not None and stamp - previous < WINDOW:
            continue
        users = {e[1] for e in q}
        tenants = {e[2] for e in q}
        if len(q) >= min_failures and len(users) >= min_accounts and len(tenants) >= min_tenants:
            last_alert_at[ip] = stamp
            signals.append({
                "type": "cross_tenant_signin_burst",
                "utc": stamp.isoformat(),
                "failures_in_5m": len(q),
                "unique_accounts": len(users),
                "unique_tenants": len(tenants),
                "explanation": "Investigate service principal/user sign-in logs and correlate with approved app changes. Shared NAT or data quality can produce false positives."
            })
    return {
        "purpose": "offline defensive triage; no live coverage or ARTEX attribution",
        "events_examined": len(accepted),
        "invalid_or_skipped_rows": invalid,
        "signals": sorted(signals, key=lambda s: (s["utc"], s["type"])),
        "source_identifiers_included": False,
    }


def load_jsonl(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Input must be a regular, non-symlink JSONL file of at most 12 MB")
    events = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            if len(events) >= MAX_EVENTS:
                raise ValueError("Input exceeds the 100,000-event cap")
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # Never echo untrusted event content in errors.
                raise ValueError(f"Invalid JSONL at line {number}") from None
    return events


def main():
    p = argparse.ArgumentParser(description="Defensive, offline cloud-event triage (synthetic/approved data only)")
    p.add_argument("--input", required=True, type=Path, help="Normalised local JSONL input")
    p.add_argument("--min-failures", type=int, default=20)
    args = p.parse_args()
    if not 2 <= args.min_failures <= 10000:
        p.error("Threshold must be between 2 and 10,000")
    try:
        result = analyse(load_jsonl(args.input), min_failures=args.min_failures)
    except (OSError, UnicodeError, ValueError) as exc:
        p.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
