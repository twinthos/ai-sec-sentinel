#!/usr/bin/env python3
"""Fail CI for clearly dangerous files and high-confidence credential patterns.

This is a heuristic *current tracked-tree* check, NOT Git history scanning,
secret rotation, provenance attestation or a substitute for dedicated scanners.
Do not echo matched secret values.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {".py", ".md", ".json", ".txt", ".xml", ".yml", ".yaml", ".sh", ".toml", ".ini", ".cfg", ".html"}
DANGEROUS_SUFFIXES = {".pem", ".p12", ".pfx", ".p8", ".sqlite", ".sqlite3", ".db"}
FORBIDDEN_FILES = {"id_rsa", "id_ed25519", ".env", ".netrc", "service-account.json",
                   "secrets.json", "credentials.json", "guardian_ledger.jsonl",
                   "sentinel_state.json", "sentinel_feedback.json"}
CREDENTIAL_PATTERNS = [
    re.compile(r"\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"),
    re.compile(r"\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"),
    re.compile(r"\\bgithub_pat_[A-Za-z0-9_]{50,}\\b"),
    re.compile(r"\\bxox[baprs]-[A-Za-z0-9-]{24,}\\b"),
    re.compile(r"sk-proj-[A-Za-z0-9_-]{24,}"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
]


def inspect_paths(paths):
    issues = []
    for relative in paths:
        path = ROOT / relative
        parts = path.relative_to(ROOT).parts
        names = [p.casefold() for p in parts]
        base = names[-1]
        if any(p == ".env" or p.startswith(".env.") for p in names):
            issues.append(f"Forbidden environment file: {relative}")
        if base in FORBIDDEN_FILES or path.suffix.casefold() in DANGEROUS_SUFFIXES:
            issues.append(f"Forbidden credential or state file: {relative}")
        if "__pycache__" in parts or path.suffix == ".pyc":
            issues.append(f"Compiled bytecode published: {relative}")
        if path.is_symlink():
            issues.append(f"Unexpected symlink in tracked tree: {relative}")
            continue
        if not path.is_file() or (path.suffix.casefold() not in TEXT_SUFFIXES and base not in ("dockerfile", ".gitignore")):
            continue
        if path.stat().st_size > 2_000_000:
            issues.append(f"Oversized text file requires manual review: {relative}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(p.search(text) for p in CREDENTIAL_PATTERNS):
            issues.append(f"Credential-like content in tracked file: {relative}")
    return issues


def main():
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    paths = [p.decode("utf-8", "replace") for p in proc.stdout.split(b"\0") if p]
    issues = inspect_paths(paths)
    if issues:
        for issue in issues:
            print("FAIL:", issue)
        return 1
    print(f"PASS: checked {len(paths)} tracked files for high-confidence exposure patterns")
    print("LIMIT: current tracked tree only; history, caches, forks and runtime systems not scanned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
