"""Adversarial, offline checks for host-owned task context firewall.

Only synthetic credentials and files are used. These tests do not imply that
an unmodified Hermes or Orgo runtime routes its real tools through this gate.
"""
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from task_context import ContextConfigurationError, TaskContextFirewall
import guardian_gate as gate


NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
TOKEN = "synthetic-example-task-token-123456789"
AGENT = "operator-agent"
TASK = "customer-support-1"


class TaskScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tasks.json"
        self.policy = {
            "version": 1, "tasks": [{
                "task_id": TASK,
                "agent_id": AGENT,
                "capability_sha256": hashlib.sha256(TOKEN.encode()).hexdigest(),
                "not_before": (NOW - timedelta(minutes=2)).isoformat(),
                "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
                "tools": {
                    "file_read": {"path_prefixes": ["approved/"]},
                    "http_request": {"hosts": ["api.example.com"]},
                },
            }]
        }
        self.save()

    def save(self, policy=None):
        self.path.write_text(json.dumps(self.policy if policy is None else policy))
        self.path.chmod(0o600)

    def check(self, tool="file_read", params=None, agent=AGENT, task=TASK, token=TOKEN, now=NOW):
        return TaskContextFirewall(self.path).evaluate(
            agent, task, token, tool,
            {"path": "approved/brief.txt"} if params is None else params,
            now=now,
        )

    def test_scoped_read_and_network_prechecks(self):
        self.assertEqual(self.check()["decision"], "allow")
        self.assertEqual(
            self.check("http_request", {"url": "https://api.example.com/resource"})["decision"],
            "allow",
        )

    def test_no_agent_selected_authority_or_replay_beyond_expiry(self):
        for overrides in [
            {"agent": "admin-agent"},
            {"task": "another-task"},
            {"token": "wrong-value-that-is-long-enough"},
            {"token": ""},
            {"now": NOW - timedelta(minutes=10)},
            {"now": NOW + timedelta(minutes=6)},
        ]:
            with self.subTest(overrides=overrides):
                self.assertEqual(self.check(**overrides)["decision"], "block")

    def test_only_explicit_named_tools_have_scope(self):
        for tool in ("shell_exec", "file_delete", "plugin_activate", "mcp_register"):
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool=tool)["decision"], "block")

    def test_read_directory_boundaries_and_argument_smuggling(self):
        for params in (
            {"path": "../approved/brief.txt"},
            {"path": "approved/../outside.txt"},
            {"path": "approved\\outside.txt"},
            {"path": "/approved/brief.txt"},
            {"path": "approved2/brief.txt"},
            {"path": "approved/.env"},
            {"path": "approved/%2e%2e/secret.txt"},
            {"path": "approved//brief.txt"},
            {"path": "approved/brief.txt", "write": True},
        ):
            with self.subTest(params=params):
                self.assertEqual(self.check(params=params)["decision"], "block")

    def test_exact_https_host_scoping(self):
        for url in (
            "http://api.example.com/",
            "https://api.example.com.evil.test/",
            "https://api.example.com@evil.test/",
            "https://api.example.com:8443/",
            "https://api.example.com./",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "ftp://api.example.com/",
            "https://api.example.com/#fragment",
            "https://api.example.com\\@evil.test/",
         ):
            with self.subTest(url=url):
                self.assertEqual(
                    self.check("http_request", {"url": url})["decision"], "block"
                )

    def test_policy_reload_revokes_existing_capability(self):
        self.assertEqual(self.check()["decision"], "allow")
        self.policy["tasks"] = []
        self.save()
        self.assertEqual(self.check()["decision"], "block")

    def test_untrusted_or_duplicate_policy_fails_closed(self):
        variants = [
            {"version": 1, "tasks": [self.policy["tasks"][0]] * 2},
            {"version": 1, "tasks": [{**self.policy["tasks"][0], "tools": {
                "shell_exec": {"commands": ["*"]}}}]},
            {"version": 1, "tasks": [{**self.policy["tasks"][0], "tools": {
                "http_request": {"hosts": [""]}}}]},
            {"version": 1, "tasks": [{**self.policy["tasks"][0], "expires_at": "bad"}]},
            {"version": 2, "tasks": []},
            {"version": 1, "tasks": [], "exemptions": True},
        ]
        for candidate in variants:
            with self.subTest(candidate=candidate):
                self.save(candidate)
                with self.assertRaises(ContextConfigurationError):
                    self.check()

    def test_private_regular_file_and_no_symlink_required(self):
        self.path.chmod(0o644)
        with self.assertRaises(ContextConfigurationError):
            self.check()
        self.path.chmod(0o600)
        link = Path(self.tmp.name) / "alias.json"
        link.symlink_to(self.path)
        with self.assertRaises(ContextConfigurationError):
            TaskContextFirewall(link).evaluate(
                AGENT, TASK, TOKEN, "file_read", {"path": "approved/a.txt"}, now=NOW
            )
        self.path.unlink()
        with self.assertRaises(ContextConfigurationError):
            self.check()

    def test_gateway_denies_before_guardian_and_records_minimal_evidence(self):
        fake = Mock()
        handler = object.__new__(gate.GateHandler)
        handler.path = "/evaluate"
        handler.headers = {"X-Sentinel-Task-Capability": TOKEN}
        handler._authorized = Mock(return_value=True)
        handler._bound_agent = Mock(return_value=True)
        handler._read_json = Mock(return_value={
            "agent_id": AGENT, "task_id": TASK,
            "tool": "file_read", "params": {"path": "another/data.txt"}
        })
        handler._respond = Mock()
        with patch.object(gate, "GATE_TASK_POLICY_FILE", str(self.path)), \\
             patch.object(gate, "guardian", fake):
            handler.do_POST()
        handler._respond.assert_called_once()
        self.assertEqual(handler._respond.call_args.args[0], 403)
        fake.process_tool_call.assert_not_called()
        evidence = fake.prove.record.call_args.args
        self.assertEqual(evidence[0], "task_scope_denied")
        self.assertNotIn(TOKEN, str(evidence))
        self.assertNotIn("another/data.txt", str(evidence))

    def test_gateway_proceeds_only_after_valid_task_scope_and_existing_guardian(self):
        fake = Mock()
        fake.process_tool_call.return_value = {
            "decision": {"decision": "allow", "reasons": []},
            "event": {"risk_level": "low"},
            "ledger_entry": "testhash",
            "blast_radius": {"risk_score": 0},
        }
        handler = object.__new__(gate.GateHandler)
        handler.path = "/evaluate"
        handler.headers = {"X-Sentinel-Task-Capability": TOKEN}
        handler._authorized = Mock(return_value=True)
        handler._bound_agent = Mock(return_value=True)
        handler._read_json = Mock(return_value={
            "agent_id": AGENT, "task_id": TASK,
            "tool": "file_read", "params": {"path": "approved/brief.txt"}
        })
        handler._respond = Mock()
        with patch.object(gate, "GATE_TASK_POLICY_FILE", str(self.path)), \\
             patch.object(gate, "guardian", fake), \\
             patch("task_context.datetime") as clock:
            clock.now.return_value = NOW
            clock.fromisoformat.side_effect = datetime.fromisoformat
            handler.do_POST()
        fake.process_tool_call.assert_called_once()
        self.assertEqual(handler._respond.call_args.args[0], 200)
        self.assertEqual(handler._respond.call_args.args[1]["task_scope"], "verified")

    def test_gateway_invalid_policy_never_calls_guardian(self):
        fake = Mock()
        handler = object.__new__(gate.GateHandler)
        handler.path = "/evaluate"
        handler.headers = {"X-Sentinel-Task-Capability": TOKEN}
        handler._authorized = Mock(return_value=True)
        handler._bound_agent = Mock(return_value=True)
        handler._read_json = Mock(return_value={
            "agent_id": AGENT, "task_id": TASK,
            "tool": "file_read", "params": {"path": "approved/a.txt"}
        })
        handler._respond = Mock()
        self.path.chmod(0o644)
        with patch.object(gate, "GATE_TASK_POLICY_FILE", str(self.path)), \\
             patch.object(gate, "guardian", fake):
            handler.do_POST()
        self.assertEqual(handler._respond.call_args.args[0], 503)
        fake.process_tool_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
