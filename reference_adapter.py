#!/usr/bin/env python3
"""Small, enforceable reference adapter for ONE capability: scoped file reads.

This is an executable security demonstration, NOT an integration with Hermes,
MCP, Orgo, or arbitrary host tools. A separate, unrestricted shell can bypass it.
Only this adapter's exposed operations are constrained.
"""
import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

from sentinel_guardian import ControlLayer, ObserveLayer, ProveLayer, UnderstandLayer
from privacy import redact_text


class DeniedAction(PermissionError):
    """The adapter refused a tool call before attempting an operation."""


class GuardedWorkspace:
    """Read-only operations rooted at a trusted directory file descriptor.

    Caller identity must come from trusted application configuration, never from
    an untrusted model prompt. No write, shell, network or arbitrary exec tool
    is implemented by this adapter.
    """

    def __init__(self, root: Path, policy_file: Path, ledger_file: Path,
                 agent_id: str, allowed_tools=("file_read",), max_bytes=65536):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Workspace root must be a directory")
        self.agent_id = agent_id
        self.max_bytes = max_bytes
        if not 0 < max_bytes <= 1_048_576:
            raise ValueError("max_bytes must be between 1 and 1048576")
        self.policy = ControlLayer(str(policy_file))
        self.ledger = ProveLayer(str(ledger_file))
        self.observe = ObserveLayer(str(ledger_file.parent / "observe"))
        self.understand = UnderstandLayer()
        self.understand.register_agent(agent_id, agent_id, "local owner",
                                       list(allowed_tools), ["read"], ["workspace"])

    def _record(self, tool: str, outcome: str, reason: str):
        # Never store file contents, requested paths or raw model parameters.
        self.ledger.record("enforced_tool_call", self.agent_id,
                           {"tool": tool, "outcome": outcome, "reason": reason})

    def execute(self, tool: str, params: dict) -> str:
        """Only a literal 'allow' can cause a scoped file read."""
        if not isinstance(params, dict) or not isinstance(tool, str):
            raise DeniedAction("Invalid request")
        if tool != "file_read" or tool not in self.understand.agents[self.agent_id]["tools"]:
            self._record(str(tool)[:80], "denied", "tool_not_exposed")
            raise DeniedAction("Tool not exposed by adapter")
        try:
            decision = self.policy.evaluate(self.agent_id, tool, params)["decision"]
        except Exception:
            self._record(tool, "denied", "policy_error")
            raise DeniedAction("Policy evaluation failed") from None
        if decision != "allow":
            self._record(tool, "denied", "policy_" + decision)
            raise DeniedAction("Policy did not authorize execution")
        filename = params.get("path")
        if not isinstance(filename, str) or not filename or len(filename) > 1024:
            self._record(tool, "denied", "invalid_path")
            raise DeniedAction("Invalid relative file path")
        # Do not accept absolute or backslash paths (even on POSIX).
        if filename.startswith("/") or "\\" in filename or "\x00" in filename:
            self._record(tool, "denied", "invalid_path")
            raise DeniedAction("Absolute or invalid path")
        parts = filename.split("/")
        if any(x in ("", ".", "..") for x in parts):
            self._record(tool, "denied", "path_traversal")
            raise DeniedAction("Path traversal is not allowed")
        try:
            data = self._read_with_no_symlinks(parts)
        except (OSError, UnicodeDecodeError, ValueError):
            self._record(tool, "denied", "unsafe_or_unreadable_file")
            raise DeniedAction("File not found, unsafe, oversized or unreadable") from None
        # Heuristic content screening is a second guard, not full DLP.
        # If it fails, or finds obvious secrets/PII, never return raw data.
        try:
            contains_sensitive_data = redact_text(data) != data
        except Exception:
            self._record(tool, "denied", "content_screen_error")
            raise DeniedAction("Document content could not be screened") from None
        if contains_sensitive_data:
            self._record(tool, "denied", "sensitive_content")
            raise DeniedAction("Document content is not approved for release")
        # Evidence is durable BEFORE content returns.
        self._record(tool, "allowed", "scoped_read")
        return data

    def _read_with_no_symlinks(self, parts):
        # dir_fd traversal prevents resolving through symlinks, including
        # intermediate directory symlinks; anchors all reads to a trusted fd.
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise OSError("Secure no-follow file access unsupported on this platform")
        current = os.open(self.root, flags | os.O_DIRECTORY)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, flags | nofollow | os.O_DIRECTORY, dir_fd=current)
                os.close(current)
                current = next_fd
            file_fd = os.open(parts[-1], flags | nofollow | getattr(os, "O_NONBLOCK", 0),
                              dir_fd=current)
            try:
                mode = os.fstat(file_fd).st_mode
                size = os.fstat(file_fd).st_size
                if not stat.S_ISREG(mode) or size > self.max_bytes:
                    raise ValueError("Not a bounded regular file")
                with os.fdopen(file_fd, "rb", closefd=False) as f:
                    raw = f.read(self.max_bytes + 1)
                if len(raw) > self.max_bytes:
                    raise ValueError("File exceeds limit")
                return raw.decode("utf-8")
            finally:
                os.close(file_fd)
        finally:
            os.close(current)


def demo():
    """An offline proof: permitted file read succeeds; deletion is denied."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        workspace = base / "workspace"
        workspace.mkdir()
        (workspace / "report.txt").write_text("A customer record stays unchanged.", encoding="utf-8")
        policy = base / "policy.json"
        policy.write_text(json.dumps([
            {"tool": "file_read", "action": "allow", "agent": "demo-agent", "condition": "always"}
        ]), encoding="utf-8")
        adapter = GuardedWorkspace(workspace, policy, base / "ledger.jsonl", "demo-agent")
        allowed = adapter.execute("file_read", {"path": "report.txt"})
        assert allowed == "A customer record stays unchanged."
        try:
            adapter.execute("file_delete", {"path": "report.txt"})
            raise AssertionError("Prohibited action unexpectedly passed")
        except DeniedAction:
            pass
        assert (workspace / "report.txt").exists()
        assert adapter.ledger.verify_integrity()["status"] == "intact"
        print("PASS: Scoped file read allowed.")
        print("PASS: File deletion denied before execution; file unchanged.")
        print("PASS: Evidence ledger verified; contents not logged.")
        print("Scope: this read-only adapter only; NOT a universal agent firewall.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline Guardian enforcement demonstration")
    parser.add_argument("--demo", action="store_true", help="Run isolated safe/denied test")
    args = parser.parse_args()
    if not args.demo:
        parser.error("Use --demo (no live system interaction)")
    demo()
