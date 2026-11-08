"""Operational regressions: bounded retries and interruptible daemon shutdown."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

import alert_queue as queue
import ai_sec_sentinel as sentinel


class QueueRetryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = patch.object(queue, 'DB_PATH', Path(self.directory.name) / 'alerts.db')
        self.path.start()
        self.addCleanup(self.path.stop)
        queue.init_db()

    def test_exhausted_alert_never_becomes_pending_again(self):
        alert = queue.enqueue('CVE-test', 'test', {'title': 'synthetic'})
        for attempt in range(queue.MAX_RETRIES):
            queue.mark_delivering(alert)
            queue.mark_failed(alert, 'test', 'synthetic failure')
        self.assertEqual(queue.get_pending(), [])
        queue.init_db()  # A restart must preserve the terminal condition.
        self.assertEqual(queue.get_pending(), [])
        row = queue.get_all()[0]
        self.assertEqual(row['retry_count'], queue.MAX_RETRIES)
        self.assertEqual(row['state'], 'failed')
        self.assertIsNone(row['next_retry'])

    def test_legacy_exhausted_failure_is_excluded(self):
        alert = queue.enqueue('CVE-old', 'test', {})
        with queue.get_db() as db:
            db.execute("UPDATE alerts SET state='failed', retry_count=?, next_retry=? WHERE id=?",
                       (queue.MAX_RETRIES, '2000-01-01T00:00:00+00:00', alert))
        self.assertEqual(queue.get_pending(), [])

    def test_due_retry_is_preserved_below_limit(self):
        alert = queue.enqueue('CVE-retry', 'test', {})
        queue.mark_failed(alert, 'test', 'temporary')
        self.assertEqual(queue.get_pending(), [])
        with queue.get_db() as db:
            db.execute('UPDATE alerts SET next_retry=? WHERE id=?',
                       ('2000-01-01T00:00:00+00:00', alert))
        self.assertEqual([row['id'] for row in queue.get_pending()], [alert])


class DaemonTests(unittest.TestCase):
    def test_nonpositive_interval_rejected_before_config_or_network(self):
        for value in ('0', '-1'):
            with self.subTest(value=value), patch('sys.argv', ['sentinel', '--daemon', '--interval', value]), \
                 patch.object(sentinel, 'load_config') as config:
                with self.assertRaises(SystemExit) as raised:
                    sentinel.main()
                self.assertEqual(raised.exception.code, 2)
                config.assert_not_called()

    def test_sigterm_interrupts_idle_wait_without_second_scan(self):
        handlers = {}
        event = Mock()
        stopped = [False]
        event.is_set.side_effect = lambda: stopped[0]
        event.set.side_effect = lambda: stopped.__setitem__(0, True)
        event.wait.side_effect = lambda timeout: handlers[sentinel.signal.SIGTERM](15, None)
        with patch('sys.argv', ['sentinel', '--daemon', '--dry-run', '--interval', '60']), \
             patch.object(sentinel, 'load_config', return_value={}), \
             patch.object(sentinel, 'run_scan') as scan, \
             patch.object(sentinel.signal, 'signal', side_effect=lambda sig, fn: handlers.__setitem__(sig, fn)), \
             patch.object(sentinel.threading, 'Event', return_value=event), \
             patch.object(sentinel.time, 'sleep') as sleep:
            self.assertEqual(sentinel.main(), 0)
        scan.assert_called_once()
        event.wait.assert_called_once_with(3600)
        sleep.assert_not_called()
        self.assertTrue(stopped[0])
