"""Regression tests for November 2026 alert and operator-boundary hardening.

All network and credential cases are mocked; no production services are contacted.
"""
import contextlib
import io
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import ai_sec_sentinel as sentinel


CVE = "CVE-2026-12345"
WEBHOOK = "https://hooks.slack.com/services/T/B/C"


def fixture():
    return {
        "id": CVE,
        "title": "LangChain agent vulnerability",
        "summary": "LangChain security issue requiring investigation",
        "date_published": datetime.now(timezone.utc).isoformat(),
    }


def callback(user="42", chat="123", data=f"feedback:{CVE}:ignored"):
    return {
        "callback_query": {
            "from": {"id": user},
            "message": {"chat": {"id": chat}},
            "data": data,
        }
    }


class NovemberSecurityRegressionTests(unittest.TestCase):
    def _run_scanner(self, *, cisa, entry_details, threshold=2):
        state = {"seen": [], "seen_news": []}
        config = {
            "news": {"enabled": False},
            "webhook_url": WEBHOOK,
            "alert_min_severity": threshold,
        }
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_state", return_value=state), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state") as save_state, \
             patch.object(sentinel, "fetch_feed", return_value=[fixture()]), \
             patch.object(sentinel, "fetch_cisa_kev", return_value=cisa), \
             patch.object(sentinel, "fetch_epss_scores", return_value={}), \
             patch.object(sentinel, "fetch_entry", return_value=entry_details) as enrich, \
             patch.object(sentinel, "send_telegram", return_value=False), \
             patch.object(sentinel, "send_webhook", return_value=True) as webhook:
            count = sentinel.run_scan(config)
        return count, enrich, webhook, save_state

    def test_unscored_critical_entry_is_enriched_before_filtering(self):
        count, enrich, webhook, save = self._run_scanner(
            cisa={"vulnerabilities": []}, entry_details={"cvss": 9.8}
        )
        self.assertEqual(count, 1)
        enrich.assert_called_once_with(CVE)
        webhook.assert_called_once()
        self.assertIn(CVE, save.call_args.args[0]["seen"])

    def test_known_exploited_entry_is_not_discarded_when_unscored(self):
        count, enrich, webhook, save = self._run_scanner(
            cisa={"vulnerabilities": [{"cveID": CVE}]},
            entry_details=None,
            threshold=3,
        )
        self.assertEqual(count, 1)
        self.assertIn("KNOWN EXPLOITED (UNSCORED)", webhook.call_args.args[0])
        self.assertIn(CVE, save.call_args.args[0]["seen"])

    def test_unknown_and_unauthorised_feedback_fail_closed(self):
        with patch.dict(os.environ, {
            "TELEGRAM_CHAT_ID": "123",
            "TELEGRAM_ALLOWED_USER_IDS": "",
        }), patch.object(sentinel, "record_feedback") as recorder:
            self.assertFalse(sentinel._handle_callback_query(callback(), "dummy"))
            self.assertFalse(sentinel._handle_callback_query(callback(data="feedback:bad:ignored"), "dummy"))
            self.assertFalse(sentinel._handle_callback_query(callback(data=f"feedback:{CVE}:suppress"), "dummy"))
            recorder.assert_not_called()

    def test_feedback_requires_both_chat_and_sender_identity(self):
        with patch.dict(os.environ, {
            "TELEGRAM_CHAT_ID": "123",
            "TELEGRAM_ALLOWED_USER_IDS": "42,43",
        }), patch.object(sentinel, "record_feedback") as recorder, \
             patch.object(sentinel, "send_telegram") as sender:
            self.assertFalse(sentinel._handle_callback_query(callback(user="99"), "dummy"))
            self.assertFalse(sentinel._handle_callback_query(callback(chat="999"), "dummy"))
            self.assertTrue(sentinel._handle_callback_query(callback(), "dummy"))
            recorder.assert_called_once_with(CVE, "ignored")
            sender.assert_called_once()

    def test_webhook_must_not_follow_redirects(self):
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel.requests, "post", return_value=Mock(status_code=307)) as post:
            self.assertFalse(sentinel.send_webhook("test", WEBHOOK, "slack"))
            self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_telegram_exception_never_logs_token(self):
        import requests
        token = "dummy-secret-never-print"
        failure = requests.RequestException(
            f"request failed: https://api.telegram.org/bot{token}/sendMessage"
        )
        output = io.StringIO()
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel.requests, "post", side_effect=failure) as post, \
             patch.object(sentinel.time, "sleep"), contextlib.redirect_stdout(output):
            self.assertFalse(sentinel.send_telegram("hello", token, "123"))
        self.assertNotIn(token, output.getvalue())
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_telegram_backoff_is_bounded(self):
        limited = Mock(status_code=429)
        limited.json.return_value = {"parameters": {"retry_after": 999999}}
        ok = Mock(status_code=200)
        ok.json.return_value = {"ok": True}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel.requests, "post", side_effect=[limited, ok]), \
             patch.object(sentinel.time, "sleep") as sleep:
            self.assertTrue(sentinel.send_telegram("hello", "dummy", "123"))
        self.assertIn(30, [call.args[0] for call in sleep.call_args_list])

    def test_ci_dry_run_receives_no_message_secrets(self):
        workflow = Path(".github/workflows/sentinel-scan.yml").read_text()
        self.assertNotIn("secrets.TELEGRAM_BOT_TOKEN", workflow)
        self.assertNotIn("secrets.TELEGRAM_CHAT_ID", workflow)
        self.assertIn("contents: read", workflow)

    def test_requests_version_contains_2026_security_fixes(self):
        self.assertIn("requests==2.34.2", Path("requirements.txt").read_text())


if __name__ == "__main__":
    unittest.main()
