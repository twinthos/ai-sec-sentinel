"""Regression tests for Guardian's policy and evidence boundaries."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_guardian import ControlLayer, ProveLayer, SentinelGuardian, ObserveLayer


class GuardianSecurityTests(unittest.TestCase):
    def test_default_denies_unknown_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = ControlLayer(str(Path(tmp) / "missing.json"))
            self.assertEqual(control.evaluate("a", "email_send", {})["decision"], "block")

    def test_explicit_allow_for_nondangerous_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = ControlLayer(str(Path(tmp) / "policy.json"))
            control.add_policy("file_read", "allow")
            self.assertEqual(control.evaluate("a", "file_read", {})["decision"], "allow")
            self.assertEqual(control.evaluate("a", "shell_exec", {})["decision"], "block")

    def test_deny_overrides_allow_regardless_of_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = ControlLayer(str(Path(tmp) / "policy.json"))
            control.add_policy("file_read", "block")
            control.add_policy("file_read", "allow")
            self.assertEqual(control.evaluate("a", "file_read", {})["decision"], "block")

    def test_ledger_detects_content_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = ProveLayer(str(path))
            ledger.record("test", "agent", {"secret": "redacted"})
            self.assertEqual(ledger.verify_integrity()["status"], "intact")
            entry = json.loads(path.read_text())
            entry["data"]["secret"] = "modified"
            path.write_text(json.dumps(entry) + "\n")
            self.assertEqual(ledger.verify_integrity()["status"], "tampered")

    def test_tampered_ledger_cannot_be_reopened(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = ProveLayer(str(path))
            ledger.record("demo", "agent", {"marker": "original"})
            entry = json.loads(path.read_text())
            entry["data"]["marker"] = "modified"
            path.write_text(json.dumps(entry) + "\n")
            with self.assertRaisesRegex(RuntimeError, "ledger verification failed"):
                ProveLayer(str(path))

    def test_unknown_agent_cannot_use_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            guardian = SentinelGuardian.__new__(SentinelGuardian)
            from sentinel_guardian import UnderstandLayer
            guardian.understand = UnderstandLayer()
            guardian.understand.register_agent("known", "Known", "owner", ["file_read"], [], [])
            with self.assertRaises(PermissionError):
                guardian.process_tool_call("unknown", "file_read", {})
            with self.assertRaises(PermissionError):
                guardian.process_tool_call("known", "shell_exec", {})

    def test_ledger_does_not_store_raw_tool_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger_file = Path(tmp) / "ledger.jsonl"
            log_dir = Path(tmp) / "logs"
            policy = Path(tmp) / "policy.json"
            policy.write_text(json.dumps([{"tool": "file_read", "action": "allow", "condition": "always"}]))
            from sentinel_guardian import UnderstandLayer
            guardian = SentinelGuardian.__new__(SentinelGuardian)
            guardian.observe = ObserveLayer(str(log_dir))
            guardian.prove = ProveLayer(str(ledger_file))
            guardian.control = ControlLayer(str(policy))
            guardian.understand = UnderstandLayer()
            guardian.understand.register_agent("a", "A", "owner", ["file_read"], [], [])
            guardian.process_tool_call("a", "file_read", {"token": "DO_NOT_LOG_THIS_VALUE"})
            self.assertNotIn("DO_NOT_LOG_THIS_VALUE", ledger_file.read_text())
            self.assertNotIn("DO_NOT_LOG_THIS_VALUE", next(log_dir.glob("*.jsonl")).read_text())


if __name__ == "__main__":
    unittest.main()
