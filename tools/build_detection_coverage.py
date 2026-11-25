#!/usr/bin/env python3
"""Generate detection/attack-coverage.json from official upstream sources.

This tool is run by a maintainer, not by Sentinel at runtime. It reads:

  * a SigmaHQ rules checkout (``--sigma``), and
  * the MITRE ATT&CK enterprise STIX bundle (``--attack``),

and writes a provenance-stamped JSON index that maps a small, curated set of
ATT&CK techniques to (a) the Sentinel code path that reasons about that
behaviour and (b) real Sigma rules that exist upstream for it.

Nothing is hand-typed that upstream can supply: technique names, tactics and
Sigma rule identifiers/titles are copied from the source files. A technique
that is absent from the ATT&CK bundle, or a Sentinel reference that does not
resolve in this checkout, aborts the build instead of producing a plausible
but unverifiable entry.

Usage:
    python3 tools/build_detection_coverage.py \
        --sigma /path/to/sigma \
        --attack /path/to/enterprise-attack.json \
        --out detection/attack-coverage.json

Sentinel does not execute Sigma rules. The index is a reference map for
analysts and for our own coverage reporting; see docs/DETECTION-COVERAGE.md.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Curated mapping. Every entry names a behaviour Sentinel actually reasons
# about. "confidence" is deliberately conservative:
#   direct  - a Sentinel check inspects this behaviour explicitly
#   partial - Sentinel inspects an adjacent signal, not the technique itself
SENTINEL_TECHNIQUES = [
    {
        "technique": "T1190",
        "module": "risk_compliance",
        "check": "check_attack_surface",
        "confidence": "partial",
        "rationale": "Flags unauthenticated internet-facing services, the precondition for exploitation, not exploit traffic itself.",
    },
    {
        "technique": "T1133",
        "module": "risk_compliance",
        "check": "check_attack_surface",
        "confidence": "partial",
        "rationale": "Same surface review covers remote-access services left reachable without authentication.",
    },
    {
        "technique": "T1595",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "direct",
        "rationale": "Classifies caller-supplied telemetry for rotating-proxy probing and page-reader scanning beside attack traffic.",
    },
    {
        "technique": "T1595.002",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "direct",
        "rationale": "Vulnerability-scanning behaviour surfaces as single-target probing spread across many source addresses.",
    },
    {
        "technique": "T1059",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "partial",
        "rationale": "Detects auto-approved agent CLIs starting attack tools; it observes the approval bypass, not the interpreter itself.",
    },
    {
        "technique": "T1059.004",
        "module": "policy_engine",
        "check": "shell_exec_is_blocked",
        "confidence": "direct",
        "rationale": "Deny-by-default tool policy: shell_exec has no allow rule, so evaluate() returns BLOCK before execution. This is an enforcement control, not a detection.",
    },
    {
        "technique": "T1071.001",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "partial",
        "rationale": "Flags production servers calling unexpected model API or gateway endpoints, a web-protocol egress anomaly.",
    },
    {
        "technique": "T1090",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "direct",
        "rationale": "Rotating-proxy probing is one of the shared agentic behaviours Sentinel classifies.",
    },
    {
        "technique": "T1105",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "partial",
        "rationale": "Callback-to-prober and worker-port traffic is a transfer path signal, not payload inspection.",
    },
    {
        "technique": "T1552.001",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "direct",
        "rationale": "Bulk reads of configuration, .env and backup files are classified as config_or_backup_theft.",
    },
    {
        "technique": "T1078.004",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "direct",
        "rationale": "machine_speed_credential_use covers cloud identities used at machine speed and off-instance role keys.",
    },
    {
        "technique": "T1110",
        "module": "defensive_event_triage",
        "check": "analyse",
        "confidence": "direct",
        "rationale": "Cross-tenant sign-in bursts are counted as aggregate failure clusters without emitting source identifiers.",
    },
    {
        "technique": "T1098",
        "module": "defensive_event_triage",
        "check": "analyse",
        "confidence": "partial",
        "rationale": "High-risk change events are surfaced for verification against approved administrators and change records.",
    },
    {
        "technique": "T1566",
        "module": "risk_compliance",
        "check": "check_email_security",
        "confidence": "partial",
        "rationale": "SPF/DMARC configuration review addresses spoofing of the sender domain, one phishing precondition.",
    },
    {
        "technique": "T1041",
        "module": "risk_compliance",
        "check": "check_agentic_attack_patterns",
        "confidence": "partial",
        "rationale": "Outbound callbacks to recent inbound probers are flagged; channel content is not inspected.",
    },
]

SIGMA_SOURCE = "https://github.com/SigmaHQ/sigma"
SIGMA_LICENCE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"
ATTACK_SOURCE = "https://github.com/mitre-attack/attack-stix-data"
MAX_SAMPLES_PER_TECHNIQUE = 5
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def parse_sigma_rule(path: Path, repo_dir: Path) -> dict | None:
    """Extract the fields we index with a small, dependency-free reader."""
    text = path.read_text(encoding="utf-8", errors="replace")
    rule_id = re.search(r"^id:\s*([0-9a-fA-F-]{36})\s*$", text, re.M)
    title = re.search(r"^title:\s*(.+?)\s*$", text, re.M)
    level = re.search(r"^level:\s*(\w+)", text, re.M)
    if not (rule_id and title):
        return None
    tags = sorted({t.lower() for t in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)\b", text, re.I)})
    if not tags:
        return None
    logsource = {}
    block = re.search(r"^logsource:\s*$(.*?)(?=^\S)", text, re.M | re.S)
    if block:
        for key in ("product", "category", "service"):
            found = re.search(rf"^\s+{key}:\s*(\S+)", block.group(1), re.M)
            if found:
                logsource[key] = found.group(1)
    return {
        "id": rule_id.group(1).lower(),
        "title": title.group(1).strip().strip('"'),
        "level": (level.group(1).lower() if level else "unknown"),
        "path": str(path.relative_to(repo_dir)).replace("\\", "/"),
        "tags": tags,
        "logsource": logsource,
    }


def load_attack(path: Path) -> tuple[dict, dict]:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    techniques: dict[str, dict] = {}
    collection = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            collection = {
                "name": obj.get("name", ""),
                "version": obj.get("x_mitre_version", ""),
                "modified": obj.get("modified", ""),
            }
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external = [e for e in obj.get("external_references", []) if e.get("source_name") == "mitre-attack"]
        if not external:
            continue
        tid = external[0].get("external_id", "")
        techniques[tid.upper()] = {
            "name": obj.get("name", ""),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("phase_name")],
            "subtechnique_of": obj.get("x_mitre_is_subtechnique") and ".".join(tid.split(".")[:-1]).upper() or None,
            "url": external[0].get("url", ""),
        }
    return techniques, collection


def children_of(tid: str, all_tids) -> list[str]:
    return sorted(t for t in all_tids if t.startswith(tid + "."))


def resolve_local_reference(module_name: str, check: str | None, control: str | None) -> None:
    """Abort if the referenced Sentinel code or artefact is missing from this checkout."""
    if module_name:
        sys.path.insert(0, str(REPO_ROOT))
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - report the real import failure
            raise SystemExit(f"ERROR: cannot import {module_name}: {exc}") from exc
        if check is not None and not callable(getattr(module, check, None)):
            raise SystemExit(f"ERROR: {module_name}.{check} is not a callable in this checkout")
    if control is not None and not (REPO_ROOT / control).is_file():
        raise SystemExit(f"ERROR: control artefact {control} does not exist in this checkout")


def build(sigma_dir: Path, attack_path: Path, sigma_commit: str = "", sigma_commit_date: str = "") -> dict:
    techniques, collection = load_attack(attack_path)
    if not techniques:
        raise SystemExit("ERROR: no ATT&CK techniques parsed from the STIX bundle")

    by_technique: dict[str, list[dict]] = {}
    rule_files = 0
    rule_count = 0
    rule_hashes = hashlib.sha256()
    for path in sorted(sigma_dir.glob("rules/**/*.yml")):
        rule_files += 1
        rule = parse_sigma_rule(path, sigma_dir)
        if not rule:
            continue
        rule_count += 1
        rule_hashes.update(rule["id"].encode())
        for tid in rule["tags"]:
            by_technique.setdefault(tid.upper(), []).append(rule)

    entries = []
    missing = []
    for spec in SENTINEL_TECHNIQUES:
        tid = spec["technique"].upper()
        meta = techniques.get(tid)
        if not meta:
            missing.append(f"{tid} is not an active technique in the supplied ATT&CK bundle")
            continue
        resolve_local_reference(spec.get("module", ""), spec.get("check"), spec.get("control"))

        scope = [tid] + children_of(tid, techniques)
        matched = {}
        for candidate in scope:
            for rule in by_technique.get(candidate, []):
                matched[rule["id"]] = rule
        ranked = sorted(
            matched.values(),
            key=lambda r: (LEVEL_ORDER.get(r["level"], 9), r["path"]),
        )
        entries.append({
            "technique": tid,
            "name": meta["name"],
            "tactics": meta["tactics"],
            "subtechnique_of": meta["subtechnique_of"],
            "attack_url": meta["url"],
            "sentinel": {
                "module": spec.get("module", ""),
                "check": spec.get("check"),
                "control": spec.get("control"),
                "confidence": spec["confidence"],
                "rationale": spec["rationale"],
            },
            "sigma_rule_count": len(matched),
            "sigma_samples": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "level": r["level"],
                    "path": r["path"],
                    "logsource": r["logsource"],
                }
                for r in ranked[:MAX_SAMPLES_PER_TECHNIQUE]
            ],
        })

    if missing:
        raise SystemExit("ERROR: " + "; ".join(missing))

    entries.sort(key=lambda e: e["technique"])
    return {
        "schema_version": 1,
        "generated_by": "tools/build_detection_coverage.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_note": (
            "Reference index only. Sentinel does not execute Sigma rules and does not "
            "claim detection coverage for these techniques. 'direct' means a Sentinel "
            "check inspects the behaviour; 'partial' means it inspects an adjacent signal."
        ),
        "provenance": {
            "attack": {
                "name": collection.get("name") or "Enterprise ATT&CK",
                "version": collection.get("version", ""),
                "modified": collection.get("modified", ""),
                "source": ATTACK_SOURCE,
                "techniques_in_bundle": len(techniques),
            },
            "sigma": {
                "repository": SIGMA_SOURCE,
                "licence": "Detection Rule License (DRL) 1.1",
                "licence_url": SIGMA_LICENCE_URL,
                "commit": sigma_commit,
                "committed_at": sigma_commit_date,
                "rule_files_scanned": rule_files,
                "rules_with_attack_tags": rule_count,
                "rules_index_sha256_prefix": rule_hashes.hexdigest()[:16],
                "techniques_tagged": len(by_technique),
            },
        },
        "counts": {
            "techniques_mapped": len(entries),
            "checks_referenced": len({(e["sentinel"]["module"], e["sentinel"]["check"]) for e in entries}),
            "sigma_rules_referenced": sum(e["sigma_rule_count"] for e in entries),
            "direct": sum(1 for e in entries if e["sentinel"]["confidence"] == "direct"),
            "partial": sum(1 for e in entries if e["sentinel"]["confidence"] == "partial"),
        },
        "techniques": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the ATT&CK/Sigma detection coverage index.")
    parser.add_argument("--sigma", required=True, help="path to a SigmaHQ/sigma checkout")
    parser.add_argument("--attack", required=True, help="path to enterprise-attack.json (STIX)")
    parser.add_argument("--out", default=str(REPO_ROOT / "detection" / "attack-coverage.json"))
    parser.add_argument("--sigma-commit", default="", help="SigmaHQ commit SHA the checkout came from")
    parser.add_argument("--sigma-commit-date", default="", help="ISO timestamp of that commit")
    args = parser.parse_args()

    index = build(
        Path(args.sigma).expanduser().resolve(),
        Path(args.attack).expanduser().resolve(),
        args.sigma_commit,
        args.sigma_commit_date,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    print(json.dumps(index["counts"], indent=2))
    print(f"ATT&CK {index['provenance']['attack']['version']}, "
          f"{index['provenance']['sigma']['rules_with_attack_tags']} of "
          f"{index['provenance']['sigma']['rule_files_scanned']} Sigma rules carry ATT&CK tags")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
