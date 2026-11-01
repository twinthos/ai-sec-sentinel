"""Regression tests for real monitoring behavior, without network access."""
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, Mock

import ai_sec_sentinel as sentinel
import dashboard


def cve():
    return {
        "id": "CVE-2026-12345",
        "title": "LangChain agent prompt injection",
        "summary": "LangChain test fixture",
        "date_published": datetime.now(timezone.utc).isoformat(),
        "cvss": 9.1,
    }


def mocked_sources():
    return (
        patch.object(sentinel, "fetch_feed", return_value=[cve()]),
        patch.object(sentinel, "fetch_cisa_kev", return_value={"vulnerabilities": []}),
        patch.object(sentinel, "fetch_epss_scores", return_value={}),
        patch("news_scanner.scan_news", return_value=[
            {"id": "https://example.invalid/story", "title": "<unsafe>",
             "summary": "breach", "severity": "HIGH", "link": "https://example.invalid/story"}
        ]),
    )


class RuntimeSafetyTests(unittest.TestCase):
    def test_live_scan_requires_sink(self):
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}):
            with self.assertRaisesRegex(RuntimeError, "No alert destination"):
                sentinel.run_scan({"news": {"enabled": False}}, "", "")

    def test_preview_does_not_change_seen_or_send_network(self):
        state = {"seen": [], "seen_news": []}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "1"}), \
             patch.object(sentinel, "load_state", return_value=state), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state") as write_state, \
             patch.object(sentinel.requests, "post") as network:
            with mocked_sources()[0], mocked_sources()[1], mocked_sources()[2], mocked_sources()[3]:
                alerts = sentinel.run_scan(
                    {"news": {"enabled": True}, "webhook_url": "https://hooks.slack.com/services/T/B/C", "alert_min_severity": 1}
                )
            self.assertGreaterEqual(alerts, 1)
            self.assertEqual(state["seen"], [])
            self.assertEqual(state["seen_news"], [])
            write_state.assert_not_called()
            network.assert_not_called()

    def test_failed_notification_is_retried_not_deduplicated(self):
        state = {"seen": [], "seen_news": []}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_state", return_value=state), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state") as writer, \
             patch.object(sentinel, "send_telegram", return_value=False), \
             patch.object(sentinel, "send_webhook", return_value=False):
            with mocked_sources()[0], mocked_sources()[1], mocked_sources()[2], mocked_sources()[3]:
                sentinel.run_scan({"news": {"enabled": True}, "webhook_url": "https://hooks.slack.com/services/T/B/C"})
            saved = writer.call_args.args[0]
            self.assertEqual(saved["seen"], [])
            self.assertEqual(saved["seen_news"], [])

    def test_successful_webhook_acknowledges_cve_and_news(self):
        state = {"seen": [], "seen_news": []}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_state", return_value=state), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state") as writer, \
             patch.object(sentinel, "send_telegram", return_value=False), \
             patch.object(sentinel, "send_webhook", return_value=True) as webhook:
            with mocked_sources()[0], mocked_sources()[1], mocked_sources()[2], mocked_sources()[3]:
                sentinel.run_scan({"news": {"enabled": True}, "webhook_url": "https://hooks.slack.com/services/T/B/C"})
            saved = writer.call_args.args[0]
            self.assertIn("CVE-2026-12345", saved["seen"])
            self.assertIn("https://example.invalid/story", saved["seen_news"])
            self.assertIn("&lt;unsafe&gt;", str(webhook.call_args_list))

    def test_osv_strict_fails_on_unpinned_ai_package(self):
        with self.assertRaisesRegex(RuntimeError, "not exactly pinned"):
            sentinel._osv_lockfile_check(Path("requirements.txt"), "langchain>=0.3\n", "python", strict=True)

    def test_osv_strict_fails_on_network_problem(self):
        import requests
        with patch.object(sentinel.requests, "post", side_effect=requests.Timeout("timeout")):
            with self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
                sentinel._osv_lockfile_check(Path("requirements.txt"), "langchain==0.3.0\n", "python", strict=True)

    def test_check_only_no_lockfile_is_not_health(self):
        with patch("sys.argv", ["sentinel", "--check-only"]):
            with patch.object(sentinel, "load_config", return_value={}):
                self.assertEqual(sentinel.main(), 2)

    def test_health_rejects_missing_successful_scan(self):
        with patch("sys.argv", ["sentinel", "--health"]), \
             patch.object(sentinel, "load_config", return_value={}), \
             patch.object(sentinel, "load_state", return_value={}):
            self.assertEqual(sentinel.main(), 2)

    def test_health_accepts_recent_successful_scan(self):
        with patch("sys.argv", ["sentinel", "--health"]), \
             patch.object(sentinel, "load_config", return_value={}), \
             patch.object(sentinel, "load_state", return_value={
                 "last_successful_run": datetime.now(timezone.utc).isoformat()
             }):
            self.assertEqual(sentinel.main(), 0)

    def test_news_scanner_does_not_persist_before_delivery(self):
        import news_scanner
        feed = Mock()
        feed.entries = [{"title": "LangChain breach", "summary": "attack", "link": "https://example.invalid/news"}]
        response = Mock(status_code=200)
        response.iter_content.return_value = [b"<rss/>"]
        with patch.object(news_scanner, "_load_config", return_value={"news": {
            "keywords": ["LangChain"], "sources": ["https://example.invalid/rss"]
        }}), \
             patch.object(news_scanner, "_load_state", return_value={"seen_news": []}), \
             patch.object(news_scanner, "_save_state") as save, \
             patch.object(news_scanner.requests, "get", return_value=response), \
             patch.object(news_scanner.feedparser, "parse", return_value=feed):
            alerts = news_scanner.scan_news()
            self.assertEqual(len(alerts), 1)
            save.assert_not_called()

    def test_test_alert_returns_failure_if_destination_declines(self):
        with patch("sys.argv", ["sentinel", "--test-alert"]), \
             patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_config", return_value={"webhook_url": "https://hooks.slack.com/services/T/B/C"}), \
             patch.object(sentinel, "send_webhook", return_value=False):
            self.assertEqual(sentinel.main(), 2)

    def test_test_alert_requires_real_send_not_inherited_preview(self):
        with patch("sys.argv", ["sentinel", "--test-alert"]), \
             patch.dict(os.environ, {"SENTINEL_DRY_RUN": "1"}), \
             patch.object(sentinel, "load_config", return_value={"webhook_url": "https://hooks.slack.com/services/T/B/C"}), \
             patch.object(sentinel, "send_webhook") as webhook:
            self.assertEqual(sentinel.main(), 2)
            webhook.assert_not_called()

    def test_test_alert_success_needs_acknowledgement(self):
        with patch("sys.argv", ["sentinel", "--test-alert"]), \
             patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_config", return_value={"webhook_url": "https://hooks.slack.com/services/T/B/C"}), \
             patch.object(sentinel, "send_webhook", return_value=True) as webhook:
            self.assertEqual(sentinel.main(), 0)
            webhook.assert_called_once()

    def test_docker_compose_does_not_override_executable(self):
        compose = Path("docker-compose.yml").read_text()
        self.assertNotIn("command:", compose)
        self.assertIn("sentinel-data:/data", compose)
        self.assertIn("--health", compose)

    def test_dashboard_requires_bearer_and_disallows_scan_trigger(self):
        from dashboard import Handler
        handler = Handler.__new__(Handler)
        replies = []
        handler._respond = lambda status, body, mime: replies.append(status)
        with patch.object(dashboard, "API_KEY", "x" * 32):
            handler.headers = {"Authorization": ""}
            handler.path = "/"
            handler.do_GET()
            self.assertEqual(replies[-1], 401)
            handler.headers = {"Authorization": "Bearer " + "x" * 32}
            handler.path = "/api/scan"
            handler.do_GET()
            self.assertEqual(replies[-1], 404)

    def test_state_path_uses_persistent_data_directory(self):
        self.assertEqual(sentinel.STATE_FILE.name, "sentinel_state.json")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            sentinel.atomic_write(path, '{"hello":"world"}')
            self.assertEqual(path.read_text(), '{"hello":"world"}')


if __name__ == "__main__":
    unittest.main()
