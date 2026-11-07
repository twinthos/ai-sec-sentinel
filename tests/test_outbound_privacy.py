"""Synthetic data only: exercise notification and upload privacy boundaries."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import requests
import ai_sec_sentinel as s


class OutboundPrivacyTests(unittest.TestCase):
    def test_notification_errors_do_not_log_credentials(self):
        for channel in ('telegram', 'webhook'):
            with self.subTest(channel=channel), patch.dict(os.environ, {'SENTINEL_DRY_RUN': '0'}), \
                 patch.object(s.time, 'sleep'), \
                 patch.object(s.requests, 'post', side_effect=requests.ConnectionError('private-token-in-url')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                if channel == 'telegram':
                    result = s.send_telegram('hello', 'synthetic-token', 'synthetic-chat')
                else:
                    result = s.send_webhook('hello', 'https://hooks.slack.com/services/synthetic')
                self.assertFalse(result)
                self.assertNotIn('private-token-in-url', output.getvalue())
                self.assertIn('ConnectionError', output.getvalue())

    def test_notifications_scrub_content_and_reject_redirects(self):
        for channel in ('telegram', 'webhook'):
            with self.subTest(channel=channel), patch.dict(os.environ, {'SENTINEL_DRY_RUN': '0'}), \
                 patch.object(s.time, 'sleep'), \
                 patch.object(s.requests, 'post', return_value=Mock(status_code=307)) as post:
                message = 'Contact person@example.com; password=syntheticpassword'
                if channel == 'telegram':
                    result = s.send_telegram(message, 'synthetic-token', 'synthetic-chat')
                else:
                    result = s.send_webhook(message, 'https://hooks.slack.com/services/synthetic')
                self.assertFalse(result)
                self.assertFalse(post.call_args.kwargs['allow_redirects'])
                payload = str(post.call_args.kwargs['json'])
                self.assertNotIn('person@example.com', payload)
                self.assertNotIn('syntheticpassword', payload)

    def test_upload_requires_boolean_consent_before_reading(self):
        with patch.object(Path, 'read_text', side_effect=AssertionError('file read')), \
             patch.object(s.requests, 'post') as post:
            for consent in (False, 'true', 1):
                with self.assertRaises(ValueError):
                    s.check_lockfile('private.txt', 'python', consent=consent)
            post.assert_not_called()

    def test_sensitive_file_and_symlink_upload_denied(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(s.requests, 'post') as post:
            secret = Path(tmp) / '.env.staging'
            secret.write_text('synthetic-private-content')
            link = Path(tmp) / 'requirements.txt'
            link.symlink_to(secret)
            for path in (secret, link):
                with self.assertRaises(ValueError):
                    s.check_lockfile(str(path), 'python', consent=True)
            post.assert_not_called()

    def test_consented_upload_disables_redirects(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(s.requests, 'post', return_value=Mock(status_code=200, json=lambda: {'vulnerabilities': []})) as post:
            path = Path(tmp) / 'requirements.txt'
            path.write_text('example==1.0')
            self.assertEqual(s.check_lockfile(str(path), 'python', consent=True), [])
            self.assertFalse(post.call_args.kwargs['allow_redirects'])

    def test_osv_redirect_is_incomplete_not_clean(self):
        with patch.object(s.requests, 'post', return_value=Mock(status_code=307)) as post:
            with self.assertRaises(RuntimeError):
                s._osv_lockfile_check(Path('requirements.txt'), 'langchain==1.0', 'python', strict=True)
            self.assertFalse(post.call_args.kwargs['allow_redirects'])
