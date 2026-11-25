#!/usr/bin/env python3
"""Read-only view of the ATT&CK / Sigma coverage index for Twinthos Sentinel.

The index in ``detection/attack-coverage.json`` is generated offline by
``tools/build_detection_coverage.py`` from a SigmaHQ checkout and the MITRE
ATT&CK STIX bundle. This module only reads and checks it: no network calls, no
third-party dependencies, no execution of Sigma rules.

What the index is:
    A reference map from a small set of ATT&CK techniques to (a) the Sentinel
    code path that reasons about the behaviour and (b) real upstream Sigma
    rules for the same technique.

What the index is not:
    A claim that Sentinel detects those techniques. ``confidence`` is either
    ``direct`` (a check inspects the behaviour) or ``partial`` (a check sees an
    adjacent signal). Sentinel never runs Sigma rules and never adjudicates an
    intrusion.

Usage:
    python3 detection_coverage.py --report
    python3 detection_coverage.py --validate
    python3 detection_coverage.py --technique T1190
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_INDEX = REPO_ROOT / "detection" / "attack-coverage.json"

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
RULE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CONFIDENCE_VALUES = {"direct", "partial"}
REQUIRED_PROVENANCE = ("attack", "sigma")

SCOPE_NOTE = (
    "Reference index only. Sentinel does not execute Sigma rules and does not "
    "claim detection coverage for these techniques."
)


class CoverageError(ValueError):
    """Raised when the coverage index cannot be read at all."""


def load_index(path: Optional[Path | str] = None) -> dict:
    """Load and shape-check the index. Raises CoverageError, never returns junk."""
    index_path = Path(path) if path is not None else DEFAULT_INDEX
    try:
        raw = index_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CoverageError(f"cannot read coverage index at {index_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CoverageError(f"coverage index is not valid JSON ({index_path}): {exc}") from exc
    if not isinstance(data, dict) or "techniques" not in data:
        raise CoverageError(f"coverage index has no 'techniques' list ({index_path})")
    if not isinstance(data["techniques"], list):
        raise CoverageError("coverage index 'techniques' is not a list")
    return data


def _finding(code: str, severity: str, detail: str) -> dict:
    return {"code": code, "severity": severity, "detail": detail}


def _resolve_check(module_name: str, check_name: Optional[str]) -> Optional[str]:
    """Return an error string when the referenced callable is not resolvable."""
    if not module_name:
        return "no module named"
    if check_name is None:
        return None
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - the import failure is the finding
        return f"cannot import {module_name}: {exc}"
    if not callable(getattr(module, check_name, None)):
        return f"{module_name}.{check_name} is not a callable in this checkout"
    return None


def validate_index(index: dict) -> list[dict]:
    """Check the index against its own contract. Returns findings, newest first.

    Errors mean the published index is wrong or stale. Warnings are honest
    limits worth showing, not failures.
    """
    findings: list[dict] = []

    if index.get("schema_version") != 1:
        findings.append(_finding("SCHEMA_VERSION", "error",
                                 f"expected schema_version 1, found {index.get('schema_version')!r}"))

    note = index.get("scope_note", "")
    if "does not" not in note:
        findings.append(_finding("SCOPE_NOTE", "error",
                                 "scope_note is missing the 'not a detection claim' wording"))

    provenance = index.get("provenance") or {}
    for key in REQUIRED_PROVENANCE:
        if not isinstance(provenance.get(key), dict) or not provenance[key]:
            findings.append(_finding("PROVENANCE", "error", f"provenance.{key} is missing"))
    attack = provenance.get("attack") or {}
    sigma = provenance.get("sigma") or {}
    if not attack.get("version"):
        findings.append(_finding("PROVENANCE", "error", "provenance.attack.version is empty"))
    if not sigma.get("licence"):
        findings.append(_finding("PROVENANCE", "error", "provenance.sigma.licence is empty"))
    if not sigma.get("rules_with_attack_tags"):
        findings.append(_finding("PROVENANCE", "error",
                                 "provenance.sigma.rules_with_attack_tags is empty"))
    if not sigma.get("commit"):
        findings.append(_finding("PROVENANCE", "warn",
                                 "provenance.sigma.commit is empty; the index cannot be traced to a revision"))

    entries = index.get("techniques") or []
    seen: set[str] = set()
    previous = ""
    rule_ids: dict[str, str] = {}
    direct = partial = sigma_refs = 0

    for entry in entries:
        tid = str(entry.get("technique", ""))
        if not TECHNIQUE_ID.match(tid):
            findings.append(_finding("TECHNIQUE_ID", "error", f"{tid!r} is not a sub/T technique id"))
            continue
        if tid in seen:
            findings.append(_finding("DUPLICATE_TECHNIQUE", "error", f"{tid} appears more than once"))
        seen.add(tid)
        if previous and tid < previous:
            findings.append(_finding("UNSORTED", "warn", f"{tid} is out of order after {previous}"))
        previous = tid

        if not str(entry.get("name", "")).strip():
            findings.append(_finding("EMPTY_NAME", "error", f"{tid} has no technique name"))
        if not entry.get("tactics"):
            findings.append(_finding("EMPTY_TACTICS", "error", f"{tid} has no tactic"))

        sentinel = entry.get("sentinel") or {}
        confidence = sentinel.get("confidence")
        if confidence not in CONFIDENCE_VALUES:
            findings.append(_finding("CONFIDENCE", "error",
                                     f"{tid} confidence {confidence!r} is not one of {sorted(CONFIDENCE_VALUES)}"))
        elif confidence == "direct":
            direct += 1
        else:
            partial += 1

        problem = _resolve_check(str(sentinel.get("module", "")), sentinel.get("check"))
        if problem:
            findings.append(_finding("UNRESOLVED_CHECK", "error", f"{tid}: {problem}"))
        control = sentinel.get("control")
        if control and not (REPO_ROOT / control).is_file():
            findings.append(_finding("MISSING_CONTROL", "error",
                                     f"{tid}: control artefact {control} is not in this checkout"))
        has_check = bool(sentinel.get("check"))
        if not has_check and not control:
            findings.append(_finding("NO_LOCAL_REFERENCE", "error",
                                     f"{tid} names neither a check nor a control artefact"))

        samples = entry.get("sigma_samples") or []
        count = entry.get("sigma_rule_count")
        if not isinstance(count, int) or count < 0:
            findings.append(_finding("SIGMA_COUNT", "error", f"{tid} sigma_rule_count is not a count"))
        else:
            sigma_refs += count
            if count and not samples:
                findings.append(_finding("SIGMA_SAMPLES", "error",
                                         f"{tid} claims {count} rules but ships no samples"))
            if len(samples) > count:
                findings.append(_finding("SIGMA_COUNT_MISMATCH", "error",
                                         f"{tid} ships {len(samples)} samples for {count} rules"))
            if count == 0:
                findings.append(_finding("NO_SIGMA_RULES", "warn",
                                         f"{tid} has no Sigma rules upstream; the entry is local-only"))
        for sample in samples:
            rule_id = str(sample.get("id", ""))
            if not RULE_ID.match(rule_id):
                findings.append(_finding("SIGMA_ID", "error", f"{tid}: {rule_id!r} is not a rule UUID"))
                continue
            if rule_id in rule_ids and rule_ids[rule_id] != tid:
                findings.append(_finding("DUPLICATE_SIGMA_ID", "warn",
                                         f"rule {rule_id} referenced by {rule_ids[rule_id]} and {tid}"))
            rule_ids[rule_id] = tid
            if not str(sample.get("title", "")).strip():
                findings.append(_finding("SIGMA_TITLE", "error", f"{tid}: rule {rule_id} has no title"))
            if not str(sample.get("path", "")).strip():
                findings.append(_finding("SIGMA_PATH", "error", f"{tid}: rule {rule_id} has no upstream path"))

    counts = index.get("counts") or {}
    recomputed = {
        "techniques_mapped": len(entries),
        "sigma_rules_referenced": sigma_refs,
        "direct": direct,
        "partial": partial,
    }
    for key, value in recomputed.items():
        if counts.get(key) != value:
            findings.append(_finding("COUNT_MISMATCH", "error",
                                     f"counts.{key} says {counts.get(key)!r}, entries give {value}"))

    return findings


def errors(findings: Iterable[dict]) -> list[dict]:
    return [f for f in findings if f.get("severity") == "error"]


def summary(index: dict) -> dict:
    """Compact numbers for a report or a test."""
    entries = index.get("techniques") or []
    return {
        "techniques_mapped": len(entries),
        "direct": sum(1 for e in entries if (e.get("sentinel") or {}).get("confidence") == "direct"),
        "partial": sum(1 for e in entries if (e.get("sentinel") or {}).get("confidence") == "partial"),
        "sigma_rules_referenced": sum(int(e.get("sigma_rule_count") or 0) for e in entries),
        "attack_version": (index.get("provenance") or {}).get("attack", {}).get("version", ""),
        "sigma_commit": (index.get("provenance") or {}).get("sigma", {}).get("commit", ""),
        "sigma_rules_with_attack_tags": (index.get("provenance") or {}).get("sigma", {}).get(
            "rules_with_attack_tags", 0),
    }


def for_technique(index: dict, technique_id: str) -> Optional[dict]:
    """Case-insensitive lookup; returns None rather than guessing."""
    wanted = str(technique_id or "").strip().upper()
    for entry in index.get("techniques") or []:
        if str(entry.get("technique", "")).upper() == wanted:
            return entry
    return None


def render_report(index: dict) -> str:
    """Human-readable table. Numbers first, no adjectives."""
    stats = summary(index)
    lines = [
        "Twinthos Sentinel - ATT&CK / Sigma coverage index",
        f"ATT&CK {stats['attack_version']} | SigmaHQ {stats['sigma_commit'] or 'unknown revision'} "
        f"({stats['sigma_rules_with_attack_tags']} rules carry ATT&CK tags)",
        f"{stats['techniques_mapped']} techniques mapped | "
        f"{stats['direct']} direct, {stats['partial']} partial | "
        f"{stats['sigma_rules_referenced']} upstream Sigma rules referenced",
        "",
        f"{'TECHNIQUE':<11}{'CONF':<9}{'LOCAL CONTROL':<46}{'SIGMA':>6}  NAME",
    ]
    for entry in index.get("techniques") or []:
        sentinel = entry.get("sentinel") or {}
        local = f"{sentinel.get('module', '')}.{sentinel.get('check') or ''}".rstrip(".") or "control only"
        if sentinel.get("control"):
            local = f"control:{sentinel['control']}"
        lines.append(
            f"{entry['technique']:<11}{sentinel.get('confidence', ''):<9}{local:<46}"
            f"{int(entry.get('sigma_rule_count') or 0):>6}  {entry.get('name', '')}"
        )
    lines += ["", SCOPE_NOTE]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read and check Sentinel's ATT&CK/Sigma coverage index.")
    parser.add_argument("--index", default=str(DEFAULT_INDEX), help="path to attack-coverage.json")
    parser.add_argument("--report", action="store_true", help="print the human-readable coverage table")
    parser.add_argument("--validate", action="store_true", help="check the index against its contract")
    parser.add_argument("--technique", metavar="TID", help="show one technique, e.g. T1190")
    parser.add_argument("--json", action="store_true", help="machine-readable output with --validate")
    args = parser.parse_args(argv)

    try:
        index = load_index(args.index)
    except CoverageError as exc:
        print(f"ERROR: {exc}")
        return 1

    if args.technique:
        entry = for_technique(index, args.technique)
        if entry is None:
            print(f"NOT MAPPED: {args.technique.upper()} is not in the index")
            return 2
        print(json.dumps(entry, indent=2))
        return 0

    if args.validate:
        findings = validate_index(index)
        problems = errors(findings)
        if args.json:
            print(json.dumps({"index": str(args.index), "errors": len(problems),
                              "warnings": len(findings) - len(problems),
                              "findings": findings}, indent=2))
        else:
            if not problems:
                stats = summary(index)
                warnings = len(findings) - len(problems)
                print(f"VALID: {stats['techniques_mapped']} techniques, "
                      f"{stats['sigma_rules_referenced']} Sigma references, "
                      f"{len(problems)} errors, {warnings} warnings")
            for finding in findings:
                print(f"{finding['severity'].upper():<5} {finding['code']:<20} {finding['detail']}")
        return 1 if problems else 0

    print(render_report(index))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
