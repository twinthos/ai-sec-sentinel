"""Exercise the actual offline proof without loading private runtime configuration."""
import contextlib
import io
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import ai_sec_sentinel as sentinel


class QuickstartTests(unittest.TestCase):
    def test_real_proof_never_loads_config_or_uses_http(self):
        with patch.object(sys, 'argv', ['sentinel', '--quickstart']), \
             patch.object(sentinel, 'load_config', side_effect=AssertionError('private config read')), \
             patch('requests.sessions.Session.request', side_effect=AssertionError('network used')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sentinel.main(), 0)
        self.assertIn('PASS:', output.getvalue())

    def test_failure_is_nonzero_and_does_not_print_exception_data(self):
        with patch.object(sys, 'argv', ['sentinel', '--quickstart']), \
             patch('examples.proof.prove', side_effect=RuntimeError('private-content')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sentinel.main(), 1)
        self.assertNotIn('private-content', output.getvalue())

    def test_failed_check_is_not_success(self):
        with patch.object(sys, 'argv', ['sentinel', '--quickstart']), \
             patch('examples.proof.prove', return_value={'boundary': False}), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sentinel.main(), 1)

    def test_live_options_cannot_be_combined(self):
        with patch.object(sys, 'argv', ['sentinel', '--quickstart', '--daemon']), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            sentinel.main()
        self.assertEqual(caught.exception.code, 2)

    def test_no_arguments_does_not_read_config(self):
        with patch.object(sys, 'argv', ['sentinel']), \
             patch.object(sentinel, 'load_config', side_effect=AssertionError('config read')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sentinel.main(), 0)
        self.assertIn('--quickstart', output.getvalue())

    def test_default_state_outside_checkout(self):
        environment = os.environ.copy()
        environment.pop('SENTINEL_DATA_DIR', None)
        subprocess.run([sys.executable, '-c',
            'from pathlib import Path; import ai_sec_sentinel as s; '
            'assert s.DATA_DIR == Path.home()/".local"/"share"/"twinthos-sentinel"'],
            env=environment, check=True)
