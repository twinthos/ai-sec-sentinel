"""Security regression tests for the actual read-only reference adapter."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from reference_adapter import DeniedAction, GuardedWorkspace, demo


class ReferenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "note.txt").write_text("trusted-data", encoding="utf-8")
        self.policy_path = root / "policy.json"
        self.ledger_path = root / "evidence.jsonl"
        self.policy_path.write_text(json.dumps([{
            "tool": "file_read", "action": "allow", "agent": "trusted-agent", "condition": "always"
        }]), encoding="utf-8")
        self.adapter = GuardedWorkspace(self.workspace, self.policy_path,
                                        self.ledger_path, "trusted-agent")

    def test_permitted_read_returns_exact_content(self):
        self.assertEqual(self.adapter.execute("file_read", {"path": "note.txt"}), "trusted-data")
        self.assertEqual(self.adapter.ledger.verify_integrity()["status"], "intact")
        self.assertNotIn("trusted-data", self.ledger_path.read_text())

    def test_unknown_tool_cannot_delete_file(self):
        with self.assertRaises(DeniedAction):
            self.adapter.execute("file_delete", {"path": "note.txt"})
        self.assertTrue((self.workspace / "note.txt").exists())

    def test_parent_path_traversal_is_denied(self):
        for bad in ("../outside.txt", "folder/../note.txt", "/etc/passwd", ".", "a//b",
                    "folder\\\\note.txt", ""):
            with self.subTest(path=bad), self.assertRaises(DeniedAction):
                self.adapter.execute("file_read", {"path": bad})

    def test_symlink_to_outside_is_denied(self):
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("SECRET_BEYOND_ROOT")
        (self.workspace / "link.txt").symlink_to(outside)
        with self.assertRaises(DeniedAction):
            self.adapter.execute("file_read", {"path": "link.txt"})
        self.assertNotIn("SECRET_BEYOND_ROOT", self.ledger_path.read_text())

    def test_intermediate_symlink_is_denied(self):
        outside = Path(self.tmp.name) / "private"
        outside.mkdir()
        (outside / "data.txt").write_text("private")
        (self.workspace / "folder").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(DeniedAction):
            self.adapter.execute("file_read", {"path": "folder/data.txt"})

    def test_no_policy_means_no_reads(self):
        Path(self.policy_path).unlink()
        deny = GuardedWorkspace(self.workspace, self.policy_path,
                                Path(self.tmp.name) / "empty-ledger.jsonl", "trusted-agent")
        with self.assertRaises(DeniedAction):
            deny.execute("file_read", {"path": "note.txt"})

    def test_ask_does_not_execute(self):
        self.policy_path.write_text(json.dumps([{
            "tool": "file_read", "action": "ask", "agent": "trusted-agent", "condition": "always"
        }]))
        ask = GuardedWorkspace(self.workspace, self.policy_path,
                               Path(self.tmp.name) / "ask-ledger.jsonl", "trusted-agent")
        with self.assertRaises(DeniedAction):
            ask.execute("file_read", {"path": "note.txt"})

    def test_fails_closed_when_ledger_cannot_write(self):
        self.adapter.ledger.ledger_file = Path(self.tmp.name) / "no-such-dir" / "ledger.jsonl"
        with self.assertRaises(OSError):
            self.adapter.execute("file_read", {"path": "note.txt"})

    def test_binary_or_oversized_file_denied(self):
        (self.workspace / "large.txt").write_text("x" * 70_000)
        (self.workspace / "bin").write_bytes(bytes([0xff]))
        for path in ("large.txt", "bin"):
            with self.subTest(path=path), self.assertRaises(DeniedAction):
                self.adapter.execute("file_read", {"path": path})

    def test_demo_workflow(self):
        demo()


if __name__ == "__main__":
    unittest.main()
