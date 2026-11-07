"""Adversarial review: protocol abuse, repeat detection and privacy leaks.

Perspectives:
- hostile MCP client: malformed JSON-RPC and tool requests must not crash the server
- defending SOC: a repeat burst must not be silently missed forever
- privacy reviewer: nested payloads must not bypass redaction
- auditor: no source identifiers should reach triage output
All input is local and synthetic. No network or real customer information.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defensive_event_triage import analyse
from mcp_reference_server import ReferenceMCP, safe_relative_path
from privacy import redact_dict
from reference_adapter import GuardedWorkspace


class AdversarialSwarmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "approved"
        self.root.mkdir()
        (self.root / "example.md").write_text("Synthetic harmless document", encoding="utf-8")
        self.policy = self.base / "policy.json"
        self.policy.write_text(json.dumps([
            {"tool": "file_read", "agent": "sim-agent", "action": "allow", "condition": "always"}
        ]), encoding="utf-8")
        self.ledger = self.base / "audit.jsonl"
        self.server = ReferenceMCP(GuardedWorkspace(
            self.root, self.policy, self.ledger, "sim-agent"
        ))

    def test_malformed_protocol_versions_return_error_not_exception(self):
        for value in ([], {}, {"protocol": "2025-06-18"}, ["2025-06-18"], None, 13, True):
            with self.subTest(type=type(value).__name__):
                fresh = ReferenceMCP(GuardedWorkspace(
                    self.root, self.policy, self.base / "test-ledger.jsonl", "sim-agent"
                ))
                response = fresh.handle({"jsonrpc": "2.0", "id": 10,
                    "method": "initialize", "params": {"protocolVersion": value}})
                self.assertEqual(response["error"]["code"], -32602)
                self.assertFalse(fresh.initialized)

    def test_stdio_survives_malformed_handshake_then_accepts_valid_client(self):
        server = Path(__file__).resolve().parent.parent / "mcp_reference_server.py"
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": ["2025-06-18"]}},
            {"jsonrpc": "2.0", "id": 2, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        ]
        proc = subprocess.run(
            [sys.executable, "-u", str(server), "--workspace", str(self.root),
             "--policy", str(self.policy), "--ledger", str(self.base / "stdio.jsonl"),
             "--agent-id", "sim-agent"],
            input="\n".join(json.dumps(x) for x in lines) + "\n",
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, "Malformed handshake terminated the MCP process")
        out = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual(len(out), 3)
        self.assertEqual(out[0]["error"]["code"], -32602)
        self.assertEqual(out[2]["result"]["tools"][0]["name"], "sentinel_read_workspace")

    def test_path_with_control_characters_is_not_public_document(self):
        for bad in ("x\n.md", "x\r.md", "x\t.md", "x\x01.md", "x\x7f.md"):
            with self.subTest(path=repr(bad)):
                self.assertFalse(safe_relative_path(bad))

    def test_repeated_separate_cloud_bursts_both_reported(self):
        when = datetime(2026, 11, 2, tzinfo=timezone.utc)
        rows = []
        for period in (0, 20):
            for i in range(25):
                rows.append({
                    "timestamp": (when + timedelta(minutes=period, seconds=i * 6)).isoformat(),
                    "event": "sign_in", "result": "failure",
                    "source_ip": "198.51.100.7",
                    "account_id": "account-" + str(i % 7),
                    "tenant_id": "tenant-" + str(i % 3),
                })
        report = analyse(rows)
        bursts = [x for x in report["signals"] if x["type"] == "cross_tenant_signin_burst"]
        self.assertEqual(len(bursts), 2, "Second distinct five-minute burst was suppressed")
        self.assertNotIn("198.51.100.7", json.dumps(report))
        self.assertNotIn("account-", json.dumps(report))

    def test_nested_list_tokens_redacted(self):
        secret = "Bearer " + "SYNTHETICFAKETOKEN" * 3
        data = {"events": [[{"message": secret}], [secret]]}
        cleaned = redact_dict(data)
        self.assertNotIn(secret, json.dumps(cleaned))
        self.assertIn("[REDACTED]", json.dumps(cleaned))

    def test_deeply_nested_dictionary_does_not_return_raw_secrets(self):
        secret = "Bearer " + "SYNTHETICFAKETOKEN" * 3
        payload = {"message": secret}
        for i in range(13):
            payload = {"nested": payload}
        cleaned = redact_dict(payload)
        self.assertNotIn(secret, json.dumps(cleaned))

    def test_authorized_read_does_not_return_obvious_embedded_secrets(self):
        """Path permission alone must not grant obvious secret material."""
        from reference_adapter import DeniedAction
        samples = (
            "Access token: Bearer " + "SYNTHETICONLY" * 3,
            "Synthetic AWS key: " + "AKIA" + "A" * 16,
            "Private contact: reviewer@example.test",
        )
        for content in samples:
            with self.subTest(category=content.split(":")[0]):
                (self.root / "example.md").write_text(content, encoding="utf-8")
                with self.assertRaises(DeniedAction):
                    self.server.workspace.execute("file_read", {"path": "example.md"})
                self.assertNotIn(content, self.ledger.read_text())
        self.assertEqual(self.server.workspace.ledger.verify_integrity()["status"], "intact")

    def test_ordinary_data_survives_redaction(self):
        payload = {"events": [{"score": 3, "message": "all clear"}, ["hello", 23]]}
        self.assertEqual(redact_dict(payload), payload)


if __name__ == "__main__":
    unittest.main()
