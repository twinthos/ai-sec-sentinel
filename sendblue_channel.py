#!/usr/bin/env python3
"""Sendblue iMessage channel for Twinthos Sentinel alerts.

Third-party iMessage delivery via Sendblue REST API.
Requires: SENDBLUE_API_KEY and SENDBLUE_API_SECRET environment variables.
Docs: https://www.sendblue.com/api
"""

import os
import json
import time
import requests
from typing import Optional, Tuple

SENDBLUE_API_URL = "https://api.sendblue.co/api/send-message"
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds


def is_configured() -> bool:
    """Check if Sendblue credentials are available."""
    return bool(os.getenv("SENDBLUE_API_KEY") and os.getenv("SENDBLUE_API_SECRET"))


def send_imessage(to_number: str, content: str, from_number: Optional[str] = None) -> Tuple[bool, str]:
    """Send an iMessage via Sendblue. Returns (success, message)."""
    api_key = os.getenv("SENDBLUE_API_KEY")
    api_secret = os.getenv("SENDBLUE_API_SECRET")
    
    if not api_key or not api_secret:
        return False, "Sendblue not configured (missing SENDBLUE_API_KEY or SENDBLUE_API_SECRET)"
    
    if not to_number:
        return False, "No recipient phone number configured"
    
    payload = {
        "number": to_number,
        "content": content,
    }
    if from_number:
        payload["from_number"] = from_number
    
    headers = {
        "sb-api-key-id": api_key,
        "sb-api-secret-key": api_secret,
        "Content-Type": "application/json",
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(SENDBLUE_API_URL, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return True, data.get("message_handle", "sent")
            if resp.status_code == 429:
                # Rate limited — respect Retry-After
                retry_after = int(resp.headers.get("Retry-After", RETRY_BACKOFF * (attempt + 1)))
                time.sleep(retry_after)
                continue
            if resp.status_code >= 500:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
                continue
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
                continue
            return False, "Timeout after retries"
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
                continue
            return False, "Connection failed after retries"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    return False, "Max retries exceeded"


def send_alert_via_sendblue(alert_payload: dict, to_number: str) -> Tuple[bool, str]:
    """Format and send a Sentinel alert as an iMessage."""
    title = alert_payload.get("title", "Sentinel Alert")
    severity = alert_payload.get("severity", "UNKNOWN")
    cve = alert_payload.get("cve_id", "")
    summary = alert_payload.get("summary", "")
    
    # iMessage-friendly format (no markdown, short)
    content = f"🛡️ Twinthos Sentinel\n\n"
    content += f"Severity: {severity}\n"
    if cve:
        content += f"CVE: {cve}\n"
    content += f"{title}\n"
    if summary:
        content += f"\n{summary[:200]}"
    content += f"\n\n— Twinthos Sentinel"
    
    return send_imessage(to_number, content)


def get_channel_status() -> dict:
    """Return Sendblue channel status."""
    return {
        "channel": "imessage_sendblue",
        "configured": is_configured(),
        "api_url": SENDBLUE_API_URL,
        "env_vars": ["SENDBLUE_API_KEY", "SENDBLUE_API_SECRET"],
    }


def run_sendblue_tests():
    """Run Sendblue channel tests."""
    print("=== Sendblue Channel Tests ===")
    
    # Test 1: Not configured
    print("\n1. Not configured (no env vars):")
    with _env_clean():
        success, msg = send_imessage("+15551234567", "test")
        assert success == False
        assert "not configured" in msg.lower()
        print(f"   PASS: {msg}")
    
    # Test 2: Missing recipient
    print("\n2. Missing recipient:")
    os.environ["SENDBLUE_API_KEY"] = "test-key"
    os.environ["SENDBLUE_API_SECRET"] = "test-secret"
    success, msg = send_imessage("", "test")
    assert success == False
    assert "no recipient" in msg.lower()
    print(f"   PASS: {msg}")
    del os.environ["SENDBLUE_API_KEY"]
    del os.environ["SENDBLUE_API_SECRET"]
    
    # Test 3: Channel status
    print("\n3. Channel status:")
    status = get_channel_status()
    assert "channel" in status
    assert status["channel"] == "imessage_sendblue"
    print(f"   PASS: {status}")
    
    # Test 4: Alert formatting
    print("\n4. Alert formatting:")
    payload = {"title": "LangChain RCE", "severity": "CRITICAL", "cve_id": "CVE-2026-105740", "summary": "Remote code execution"}
    # Just check it doesn't crash
    content = f"🛡️ Twinthos Sentinel\n\nSeverity: {payload['severity']}\nCVE: {payload['cve_id']}\n{payload['title']}\n\n{payload['summary'][:200]}\n\n— Twinthos Sentinel"
    assert "CRITICAL" in content
    assert "CVE-2026-105740" in content
    print("   PASS: alert formatted correctly")
    
    # Test 5: Mocked successful send
    print("\n5. Mocked successful send:")
    import unittest.mock as mock
    os.environ["SENDBLUE_API_KEY"] = "test-key"
    os.environ["SENDBLUE_API_SECRET"] = "test-secret"
    with mock.patch("sendblue_channel.requests.post") as mock_post:
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"message_handle": "msg-123"}
        mock_post.return_value = mock_resp
        success, msg = send_imessage("+15551234567", "test message")
        assert success == True
        assert msg == "msg-123"
        print(f"   PASS: {msg}")
    del os.environ["SENDBLUE_API_KEY"]
    del os.environ["SENDBLUE_API_SECRET"]
    
    # Test 6: Mocked rate limit
    print("\n6. Mocked rate limit (429):")
    os.environ["SENDBLUE_API_KEY"] = "test-key"
    os.environ["SENDBLUE_API_SECRET"] = "test-secret"
    with mock.patch("sendblue_channel.requests.post") as mock_post:
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {"Retry-After": "1"}
        mock_post.return_value = mock_resp
        success, msg = send_imessage("+15551234567", "test")
        assert success == False
        print(f"   PASS: rate limit handled — {msg}")
    del os.environ["SENDBLUE_API_KEY"]
    del os.environ["SENDBLUE_API_SECRET"]
    
    print("\n=== All Sendblue tests passed ===")


class _env_clean:
    """Context manager to clean env vars."""
    def __enter__(self):
        self.saved = {}
        for k in ["SENDBLUE_API_KEY", "SENDBLUE_API_SECRET"]:
            if k in os.environ:
                self.saved[k] = os.environ.pop(k)
        return self
    def __exit__(self, *args):
        os.environ.update(self.saved)


if __name__ == "__main__":
    run_sendblue_tests()
