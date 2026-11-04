#!/usr/bin/env python3
"""Offline, reproducible evidence wrapper around Sentinel's real MCP subprocess proof.

This does NOT contact Beam, Mirror, Hermes, or Nous Portal. No model attack-success
rate is measured. Results cover only the deliberately narrow MCP read boundary.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROOF = ROOT / "examples" / "proof.py"
EXPECTED_CHECKS = frozenset({
    "mcp_stdio_handshake",
    "only_one_exposed_tool",
    "authorised_read",
    "forbidden_shell_denied",
    "path_escape_denied",
    "hidden_secret_path_denied",
    "no_private_data_returned",
    "outside_file_unchanged",
    "file_contents_not_in_evidence",
    "server_closed_cleanly",
})
SOURCES = (
    "examples/proof.py",
    "examples/reflection_boundary_evidence.py",
    "mcp_reference_server.py",
    "reference_adapter.py",
    "sentinel_guardian.py",
)


def validate_proof(result: object) -> dict:
    """Fail closed on partial or inconsistent evidence; never invent missing checks."""
    if not isinstance(result, dict) or result.get("project") != "Twinthos Sentinel":
        raise ValueError("Unexpected proof origin")
    if result.get("scope") != "synthetic, local, read-only MCP enforcement proof":
        raise ValueError("Unexpected proof scope")
    checks = result.get("checks")
    if not isinstance(checks, dict) or set(checks) != EXPECTED_CHECKS:
        raise ValueError("Missing or extra proof checks; review the contract")
    if any(type(value) is not bool for value in checks.values()):
        raise ValueError("Every proof check must be a boolean")
    if type(result.get("pass")) is not bool:
        raise ValueError("Missing boolean overall proof outcome")
    if result["pass"] != all(checks.values()):
        raise ValueError("Reported outcome contradicts checks")
    return checks


def digest_sources() -> dict:
    """SHA-256 content fingerprints enable third parties to pin what was tested."""
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def make_report(proof: dict) -> dict:
    checks = validate_proof(proof)
    passed = all(checks.values())
    return {
        "schema_version": 1,
        "study": "Twinthos Sentinel bounded tool execution — Reflection research companion",
        "status": "pass" if passed else "fail",
        "scope": "Real local MCP subprocess; synthetic data; bounded read-only tool",
        "test_count": len(checks),
        "checks_passed": sum(checks.values()),
        "checks_failed": [key for key, ok in sorted(checks.items()) if not ok],
        "checks": {key: checks[key] for key in sorted(checks)},
        "source_sha256": digest_sources(),
        "model_involved": False,
        "beam_tested": False,
        "mirror_tested": False,
        "hermes_tested": False,
        "model_attack_success_rate": None,
        "legitimate_task_completion_rate": None,
        "limitations": [
            "The proof does not evaluate Beam or any model decision.",
            "An unrestricted shell, browser, extension or other MCP tool can bypass this server.",
            "The tool cannot enforce permissions over an external Hermes or Mirror runtime.",
            "Passing these fixed checks does not establish resistance to adaptive adversaries.",
            "The hash-chained local ledger is not independently attested.",
        ],
        "reproduction": "python3 examples/reflection_boundary_evidence.py",
    }


def main() -> int:
    try:
        run = subprocess.run(
            [sys.executable, "-B", str(PROOF)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if run.returncode not in (0, 1):
            raise ValueError("Underlying MCP proof did not finish normally")
        raw = json.loads(run.stdout)
        report = make_report(raw)
        if (run.returncode == 0) != (report["status"] == "pass"):
            raise ValueError("Underlying process exit status contradicts evidence")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        # Do not echo subprocess output: it might contain unexpected private data.
        report = {
            "schema_version": 1,
            "study": "Twinthos Sentinel bounded tool execution — Reflection research companion",
            "status": "fail",
            "error": type(exc).__name__,
            "model_involved": False,
            "beam_tested": False,
            "model_attack_success_rate": None,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
