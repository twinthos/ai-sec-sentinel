#!/usr/bin/env python3
"""Durable alert queue for Twinthos Sentinel.

SQLite-backed with WAL mode. States: discovered, pending, delivering, delivered, failed, acknowledged, resolved.
Idempotent delivery. Retry with exponential backoff + jitter. Survives restarts.
"""

import sqlite3
import json
import os
import time
import random
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Alert payloads may contain identifiers. The default is outside the source tree.
_DEFAULT_DATA_DIR = Path(os.getenv("SENTINEL_DATA_DIR") or (Path.home() / ".local" / "share" / "twinthos-sentinel"))
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH") or (_DEFAULT_DATA_DIR / "sentinel_alerts.db"))
MAX_RETRIES = 5
BASE_BACKOFF = 2  # seconds
MAX_BACKOFF = 300  # 5 minutes


def get_db():
    """Get SQLite connection with WAL mode."""
    if DB_PATH.is_symlink():
        raise RuntimeError("Refuse symlinked Sentinel alert database")
    DB_PATH.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    # SQLite's default creation mode depends on the process umask.
    if os.name == "posix":
        os.chmod(DB_PATH, 0o600)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the alert queue database."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            payload TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'discovered',
            priority INTEGER NOT NULL DEFAULT 0,
            retry_count INTEGER NOT NULL DEFAULT 0,
            next_retry TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            delivered_at TEXT,
            acknowledged_at TEXT,
            resolved_at TEXT,
            error TEXT,
            UNIQUE(finding_id, channel)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS delivery_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_state ON alerts(state)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_next_retry ON alerts(next_retry)")
    conn.commit()
    conn.close()


def enqueue(finding_id: str, channel: str, payload: dict, priority: int = 0) -> str:
    """Enqueue an alert. Idempotent — duplicate finding+channel returns existing ID."""
    alert_id = hashlib.sha256(f"{finding_id}:{channel}".encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO alerts (id, finding_id, channel, payload, state, priority, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'discovered', ?, ?, ?)
        """, (alert_id, finding_id, channel, json.dumps(payload), priority, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        # Already exists — idempotent
        pass
    conn.close()
    return alert_id


def get_pending(limit: int = 50) -> list:
    """Get pending alerts ready for delivery."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM alerts
        WHERE state IN ('discovered', 'pending', 'failed')
        AND (next_retry IS NULL OR next_retry <= ?)
        ORDER BY priority DESC, created_at ASC
        LIMIT ?
    """, (now, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_delivering(alert_id: str):
    """Mark alert as being delivered."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute("UPDATE alerts SET state='delivering', updated_at=? WHERE id=?", (now, alert_id))
    conn.commit()
    conn.close()


def mark_delivered(alert_id: str, channel: str):
    """Mark alert as successfully delivered."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute("UPDATE alerts SET state='delivered', delivered_at=?, updated_at=? WHERE id=?", (now, now, alert_id))
    conn.execute("INSERT INTO delivery_log (alert_id, channel, attempt, status, timestamp) VALUES (?, ?, (SELECT retry_count+1 FROM alerts WHERE id=?), 'delivered', ?)",
                 (alert_id, channel, alert_id, now))
    conn.commit()
    conn.close()


def mark_failed(alert_id: str, channel: str, error: str):
    """Mark alert as failed, schedule retry with backoff."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    row = conn.execute("SELECT retry_count FROM alerts WHERE id=?", (alert_id,)).fetchone()
    retry_count = (row["retry_count"] if row else 0) + 1

    if retry_count >= MAX_RETRIES:
        # Move to failed permanently
        conn.execute("UPDATE alerts SET state='failed', retry_count=?, error=?, updated_at=? WHERE id=?",
                     (retry_count, error, now, alert_id))
    else:
        # Schedule retry with backoff + jitter
        backoff = min(BASE_BACKOFF * (2 ** retry_count), MAX_BACKOFF)
        jitter = random.uniform(0, backoff * 0.1)
        next_retry = (datetime.now(timezone.utc) + timedelta(seconds=backoff + jitter)).isoformat()
        conn.execute("UPDATE alerts SET state='pending', retry_count=?, next_retry=?, error=?, updated_at=? WHERE id=?",
                     (retry_count, next_retry, error, now, alert_id))

    conn.execute("INSERT INTO delivery_log (alert_id, channel, attempt, status, error, timestamp) VALUES (?, ?, ?, 'failed', ?, ?)",
                 (alert_id, channel, retry_count, error, now))
    conn.commit()
    conn.close()


def acknowledge(alert_id: str):
    """User acknowledges an alert."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute("UPDATE alerts SET state='acknowledged', acknowledged_at=?, updated_at=? WHERE id=?", (now, now, alert_id))
    conn.commit()
    conn.close()


def resolve(alert_id: str):
    """Mark alert as resolved."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute("UPDATE alerts SET state='resolved', resolved_at=?, updated_at=? WHERE id=?", (now, now, alert_id))
    conn.commit()
    conn.close()


def get_stats() -> dict:
    """Get queue statistics."""
    conn = get_db()
    rows = conn.execute("SELECT state, COUNT(*) as count FROM alerts GROUP BY state").fetchall()
    conn.close()
    stats = {r["state"]: r["count"] for r in rows}
    return stats


def get_all(limit: int = 100) -> list:
    """Get all alerts."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print("Alert queue initialized")
    print(f"DB path: {DB_PATH}")
    # Demo
    aid = enqueue("CVE-2026-TEST", "telegram", {"title": "Test alert", "severity": "HIGH"})
    print(f"Enqueued: {aid}")
    pending = get_pending()
    print(f"Pending: {len(pending)}")
    stats = get_stats()
    print(f"Stats: {stats}")
