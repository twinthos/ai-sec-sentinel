#!/usr/bin/env python3
"""Webhook and feedback security for Twinthos Sentinel.

Constant-time secret comparison. Sender/chat validation.
CVE ID validation. Request body size limits. Suppression audit trail.
"""

import hmac
import hashlib
import re
import time
import json
from functools import wraps
from typing import Optional, Tuple

# CVE ID validation pattern
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
GHSA_PATTERN = re.compile(r'^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$')

VALID_FEEDBACK_ACTIONS = {"useful", "ignore", "suppress", "acknowledge", "resolve"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

MAX_BODY_SIZE = 65536  # 64KB
MAX_REQUESTS_PER_MINUTE = 60


class WebhookSecurity:
    def __init__(self, secret: str = None, allowed_chat_ids: list = None, allowed_user_ids: list = None):
        self.secret = secret
        self.allowed_chat_ids = set(str(x) for x in (allowed_chat_ids or []))
        self.allowed_user_ids = set(str(x) for x in (allowed_user_ids or []))
        self.request_times = []
    
    def is_enabled(self) -> bool:
        """Webhook is only enabled if secret is non-empty."""
        return bool(self.secret and len(self.secret) >= 16)
    
    def validate_secret(self, provided: str) -> bool:
        """Constant-time comparison of webhook secret."""
        if not self.secret or not provided:
            return False
        return hmac.compare_digest(self.secret.encode(), provided.encode())
    
    def validate_sender(self, chat_id: str, user_id: str) -> bool:
        """Validate that sender is authorised."""
        if self.allowed_chat_ids and str(chat_id) not in self.allowed_chat_ids:
            return False
        if self.allowed_user_ids and str(user_id) not in self.allowed_user_ids:
            return False
        return True
    
    def validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE or GHSA identifier format."""
        return bool(CVE_PATTERN.match(cve_id) or GHSA_PATTERN.match(cve_id))
    
    def validate_feedback_action(self, action: str) -> bool:
        """Validate feedback action is known."""
        return action in VALID_FEEDBACK_ACTIONS
    
    def check_rate_limit(self) -> bool:
        """Check if request rate is within limits."""
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 60]
        if len(self.request_times) >= MAX_REQUESTS_PER_MINUTE:
            return False
        self.request_times.append(now)
        return True
    
    def validate_request(self, body: bytes, secret_header: str, chat_id: str, user_id: str) -> Tuple[bool, str]:
        """Full request validation. Returns (valid, reason)."""
        # Check body size
        if len(body) > MAX_BODY_SIZE:
            return False, "Request body too large"
        
        # Check rate limit
        if not self.check_rate_limit():
            return False, "Rate limit exceeded"
        
        # Check secret
        if not self.is_enabled():
            return False, "Webhook not enabled (no secret configured)"
        if not self.validate_secret(secret_header):
            return False, "Invalid webhook secret"
        
        # Check sender
        if not self.validate_sender(chat_id, user_id):
            return False, "Unauthorised sender"
        
        return True, "OK"
    
    def parse_feedback(self, data: dict) -> Tuple[bool, str, dict]:
        """Parse and validate feedback payload. Returns (valid, reason, parsed)."""
        # Validate CVE ID
        cve_id = data.get("cve_id", "")
        if not self.validate_cve_id(cve_id):
            return False, "Invalid CVE/GHSA ID", {}
        
        # Validate action
        action = data.get("action", "")
        if not self.validate_feedback_action(action):
            return False, f"Invalid action: {action}", {}
        
        # Validate suppression requires reason
        if action == "suppress":
            reason = data.get("reason", "")
            if not reason or len(reason) < 10:
                return False, "Suppression requires a reason (min 10 chars)", {}
        
        parsed = {
            "cve_id": cve_id,
            "action": action,
            "reason": data.get("reason", ""),
            "user_id": data.get("user_id", ""),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return True, "OK", parsed


class SuppressionAudit:
    """Audit trail for suppressed findings."""
    
    def __init__(self, db_path: str = "suppression_audit.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                suppressed_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                re_evaluated INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
    
    def suppress(self, cve_id: str, user_id: str, reason: str, expiry_days: int = 30) -> int:
        """Create a suppression with expiry. Returns suppression ID."""
        import sqlite3
        from datetime import datetime, timezone, timedelta
        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(days=expiry_days)).isoformat()
        cursor = conn.execute("""
            INSERT INTO suppressions (cve_id, suppressed_by, reason, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_id, user_id, reason, now.isoformat(), expires))
        sid = cursor.lastrowid
        conn.commit()
        conn.close()
        return sid
    
    def is_suppressed(self, cve_id: str) -> bool:
        """Check if a CVE is currently suppressed (not expired)."""
        import sqlite3
        from datetime import datetime, timezone
        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc).isoformat()
        row = conn.execute("""
            SELECT COUNT(*) FROM suppressions
            WHERE cve_id=? AND active=1 AND expires_at > ?
        """, (cve_id, now)).fetchone()
        conn.close()
        return row[0] > 0
    
    def re_evaluate(self, cve_id: str, new_risk: str):
        """Re-evaluate suppressed finding if risk materially changed."""
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        if new_risk in ("CRITICAL", "HIGH"):
            # Material risk change — reactivate
            conn.execute("UPDATE suppressions SET active=0, re_evaluated=1 WHERE cve_id=? AND active=1", (cve_id,))
            conn.commit()
        conn.close()


def run_webhook_tests():
    print("=== Webhook Security Tests ===")
    
    ws = WebhookSecurity(secret="test-secret-that-is-long-enough-1234", allowed_chat_ids=["123"], allowed_user_ids=["456"])
    
    # Test 1: Enabled check
    print("\n1. Webhook enabled:")
    assert ws.is_enabled() == True
    ws2 = WebhookSecurity(secret="short")
    assert ws2.is_enabled() == False
    print("   PASS: requires 16+ char secret")
    
    # Test 2: Constant-time comparison
    print("\n2. Secret validation:")
    assert ws.validate_secret("test-secret-that-is-long-enough-1234") == True
    assert ws.validate_secret("wrong") == False
    assert ws.validate_secret("") == False
    print("   PASS: constant-time comparison works")
    
    # Test 3: Sender validation
    print("\n3. Sender validation:")
    assert ws.validate_sender("123", "456") == True
    assert ws.validate_sender("999", "456") == False
    assert ws.validate_sender("123", "999") == False
    print("   PASS: unauthorised senders rejected")
    
    # Test 4: CVE ID validation
    print("\n4. CVE ID validation:")
    assert ws.validate_cve_id("CVE-2026-12345") == True
    assert ws.validate_cve_id("CVE-2026-1234") == True
    assert ws.validate_cve_id("not-a-cve") == False
    assert ws.validate_cve_id("GHSA-aaaa-bbbb-cccc") == True
    print("   PASS: CVE/GHSA format validated")
    
    # Test 5: Feedback action validation
    print("\n5. Feedback action validation:")
    assert ws.validate_feedback_action("useful") == True
    assert ws.validate_feedback_action("hack") == False
    print("   PASS: unknown actions rejected")
    
    # Test 6: Request validation
    print("\n6. Full request validation:")
    valid, reason = ws.validate_request(b"{}", "test-secret-that-is-long-enough-1234", "123", "456")
    assert valid == True, reason
    valid, reason = ws.validate_request(b"{}", "wrong", "123", "456")
    assert valid == False
    print("   PASS: full validation works")
    
    # Test 7: Body size limit
    print("\n7. Body size limit:")
    big = b"x" * 70000
    valid, reason = ws.validate_request(big, "test-secret-that-is-long-enough-1234", "123", "456")
    assert valid == False and "too large" in reason
    print("   PASS: oversized body rejected")
    
    # Test 8: Suppression audit
    print("\n8. Suppression audit:")
    import tempfile, os
    db = tempfile.mktemp(suffix=".db")
    sa = SuppressionAudit(db_path=db)
    sid = sa.suppress("CVE-2026-12345", "user1", "False positive in test env")
    assert sid > 0
    assert sa.is_suppressed("CVE-2026-12345") == True
    # Re-evaluate on material risk change
    sa.re_evaluate("CVE-2026-12345", "CRITICAL")
    assert sa.is_suppressed("CVE-2026-12345") == False
    os.unlink(db)
    print("   PASS: suppression with expiry and re-evaluation")
    
    print("\n=== All webhook security tests passed ===")


if __name__ == "__main__":
    run_webhook_tests()
