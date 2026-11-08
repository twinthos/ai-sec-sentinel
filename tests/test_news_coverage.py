"""Partial feed failures must not masquerade as a complete healthy scan."""
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import ai_sec_sentinel as sentinel
import news_scanner as news
import dashboard


class NewsCoverageTests(unittest.TestCase):
    def test_mixed_feeds_keep_alerts_and_report_failed_coverage(self):
        good = Mock(status_code=200)
        good.iter_content.return_value = [b'<rss/>']
        bad = Mock(status_code=403)
        feed = Mock(bozo=False, entries=[{'title':'LangChain vulnerability',
            'summary':'A test exploit', 'link':'https://example.invalid/item'}])
        with patch.object(news, '_load_config', return_value={'news':{
            'sources':['https://example.invalid/good', 'https://example.invalid/bad'],
            'keywords':['langchain']}}), patch.object(news, '_load_state', return_value={}), \
             patch.object(news.requests, 'get', side_effect=[good, bad]), \
             patch.object(news.feedparser, 'parse', return_value=feed):
            result = news.scan_news()
        self.assertEqual(len(result), 1)
        self.assertEqual(result.checked_sources, 2)
        self.assertEqual(result.failed_sources, 1)

    def test_empty_sources_fail_visibly(self):
        with patch.object(news, '_load_config', return_value={'news': {'sources': []}}), \
             patch.object(news, '_load_state', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'at least one'):
                news.scan_news()

    def test_partial_scan_processes_available_alerts_but_fails_health(self):
        old = datetime.now(timezone.utc).isoformat()
        for dry in ('0','1'):
            state = {'last_successful_run':old,'seen':[],'seen_news':[]}
            result = news.NewsScanResult([{'id':'synthetic', 'severity':'HIGH',
                'title':'test', 'summary':'test', 'link':'https://example.invalid'}], 4, 1)
            with self.subTest(dry=dry), patch.dict(os.environ, {'SENTINEL_DRY_RUN':dry}), \
                 patch.object(sentinel, 'load_state', return_value=state), \
                 patch.object(sentinel, 'load_feedback', return_value={}), \
                 patch.object(sentinel, 'fetch_feed', return_value=[]), \
                 patch.object(sentinel, 'fetch_cisa_kev', return_value={'vulnerabilities':[]}), \
                 patch.object(sentinel, 'fetch_epss_scores', return_value={}), \
                 patch.object(news, 'scan_news', return_value=result), \
                 patch.object(sentinel, 'send_telegram', return_value=True) as send, \
                 patch.object(sentinel, 'save_state') as save:
                with self.assertRaisesRegex(RuntimeError, 'Incomplete news coverage'):
                    sentinel.run_scan({'news':{'enabled':True}}, 'synthetic', 'synthetic')
                send.assert_called_once()
                if dry == '1':
                    save.assert_not_called()
                else:
                    saved=save.call_args.args[0]
                    self.assertFalse(saved['last_scan_complete'])
                    self.assertEqual(saved['last_successful_run'], old)
                    self.assertIn('synthetic', saved['seen_news'])

    def test_health_rejects_partial_scan_even_with_recent_success(self):
        state={'last_successful_run':datetime.now(timezone.utc).isoformat(), 'last_scan_complete':False}
        with patch('sys.argv', ['sentinel','--health']), \
             patch.object(sentinel,'load_state',return_value=state), \
             patch.object(sentinel,'load_config',return_value={}):
            self.assertEqual(sentinel.main(),2)
        with patch.object(dashboard,'load_json',side_effect=[state,{}]):
            self.assertEqual(dashboard.get_status()['status'],'degraded')
