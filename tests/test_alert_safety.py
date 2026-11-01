import os
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
import ai_sec_sentinel as sentinel
import news_scanner

class AlertSafetyTests(unittest.TestCase):
    @patch.dict(os.environ, {"SENTINEL_DRY_RUN": "1"})
    @patch("ai_sec_sentinel.requests.post")
    def test_dry_run_sends_no_messages(self, post):
        self.assertTrue(sentinel.send_telegram("hello", "token", "chat"))
        self.assertTrue(sentinel.send_webhook("hello", "https://example.com"))
        post.assert_not_called()

    @patch.dict(os.environ, {"SENTINEL_DRY_RUN": "1"})
    @patch("ai_sec_sentinel.save_state")
    @patch("ai_sec_sentinel.fetch_epss_scores", return_value={})
    @patch("ai_sec_sentinel.fetch_feed", return_value=[])
    @patch("ai_sec_sentinel.fetch_cisa_kev", return_value={})
    @patch("ai_sec_sentinel.load_feedback", return_value={})
    @patch("ai_sec_sentinel.load_state", return_value={"seen": []})
    def test_dry_run_does_not_persist_seen(self, *mocks):
        sentinel.run_scan({})
        mocks[-1].assert_not_called()

    @patch.dict(os.environ, {"SENTINEL_DRY_RUN": "1"})
    @patch("news_scanner._save_state")
    @patch("news_scanner._load_state", return_value={})
    @patch("news_scanner._load_config", return_value={"news": {"sources": []}})
    def test_dry_run_does_not_persist_news(self, config, state, save):
        with patch.object(news_scanner, 'feedparser', object()):
            news_scanner.scan_news()
        save.assert_not_called()

    @patch("ai_sec_sentinel.requests.post")
    def test_osv_event_fixed_key_and_version(self, post):
        post.return_value = Mock(status_code=200, json=lambda: {"vulns": [{"id": "OSV-1", "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.10"}]}]}]}]})
        results = sentinel._osv_lockfile_check(Path('requirements.txt'), 'langchain==1.9', 'python')
        self.assertEqual(results[0]['fixed_version'], '1.10')
        self.assertTrue(results[0]['affected'])
        self.assertEqual(post.call_args.kwargs['json']['version'], '1.9')
