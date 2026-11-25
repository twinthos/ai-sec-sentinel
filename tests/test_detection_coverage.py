"""Tests for the ATT&CK / Sigma coverage index and its read-only checker.

The shipped index is generated offline from a SigmaHQ checkout and the MITRE
ATT&CK STIX bundle (tools/build_detection_coverage.py). CI cannot re-download
those sources, so these tests verify the published artefact against its own
contract: every technique id is shaped and unique, every Sentinel reference
resolves in this checkout, every Sigma sample is a real rule identifier with an
upstream path, and the headline counts match the entries. Several tests corrupt
a copy on purpose to prove the checker can fail.
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import detection_coverage as dc


class TestShippedIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = dc.load_index()

    def test_schema_and_provenance_present(self):
        self.assertEqual(self.index["schema_version"], 1)
        self.assertIn("attack", self.index["provenance"])
        self.assertIn("sigma", self.index["provenance"])
        self.assertTrue(self.index["provenance"]["attack"]["version"])
        self.assertTrue(self.index["provenance"]["sigma"]["licence"])

    def test_shipped_index_validates_with_no_errors(self):
        findings = dc.validate_index(self.index)
        self.assertEqual(dc.errors(findings), [], f"index has errors: {dc.errors(findings)}")

    def test_technique_ids_are_unique_and_correctly_shaped(self):
        ids = [e["technique"] for e in self.index["techniques"]]
        self.assertEqual(len(ids), len(set(ids)))
        for tid in ids:
            self.assertRegex(tid, r"^T\d{4}(?:\.\d{3})?$")

    def test_every_sentinel_check_resolves_to_real_code(self):
        for entry in self.index["techniques"]:
            sentinel = entry["sentinel"]
            if sentinel.get("check"):
                self.assertIsNone(
                    dc._resolve_check(sentinel["module"], sentinel["check"]),
                    f"{entry['technique']} points at missing code",
                )

    def test_every_control_artefact_exists(self):
        for entry in self.index["techniques"]:
            control = entry["sentinel"].get("control")
            if control:
                self.assertTrue((REPO_ROOT / control).is_file(), f"{control} missing for {entry['technique']}")

    def test_control_artefacts_are_tracked_by_git(self):
        """A locally present but gitignored policy file must not back the index.

        This exact mistake reached CI once: guardian_policy.json exists in a
        working checkout, is listed in .gitignore, and is absent from a clean
        clone, so the index validated locally and failed in CI.
        """
        controls = [e["sentinel"]["control"] for e in self.index["techniques"] if e["sentinel"].get("control")]
        if not controls:
            self.skipTest("index references no local control artefacts")
        for control in controls:
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", control],
                cwd=str(REPO_ROOT), capture_output=True, text=True,
            )
            self.assertEqual(tracked.returncode, 0,
                             f"{control} is referenced by the index but not tracked in git")

    def test_unix_shell_entry_is_backed_by_a_passing_control_probe(self):
        entry = dc.for_technique(self.index, "T1059.004")
        self.assertIsNotNone(entry)
        sentinel = entry["sentinel"]
        self.assertEqual((sentinel["module"], sentinel["check"]), ("policy_engine", "shell_exec_is_blocked"))
        module = __import__(sentinel["module"])
        self.assertTrue(getattr(module, sentinel["check"])(),
                        "the deny-by-default shell probe no longer returns blocked")

    def test_every_entry_has_a_local_basis(self):
        for entry in self.index["techniques"]:
            sentinel = entry["sentinel"]
            self.assertTrue(sentinel.get("check") or sentinel.get("control"),
                            f"{entry['technique']} has no local basis")
            self.assertIn(sentinel["confidence"], {"direct", "partial"})
            self.assertTrue(sentinel["rationale"].strip())

    def test_sigma_samples_are_real_rule_references(self):
        total_samples = 0
        for entry in self.index["techniques"]:
            for sample in entry["sigma_samples"]:
                total_samples += 1
                self.assertRegex(sample["id"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                self.assertTrue(sample["title"].strip())
                self.assertTrue(sample["path"].startswith("rules/"), sample["path"])
                self.assertTrue(sample["path"].endswith((".yml", ".yaml")), sample["path"])
        self.assertGreater(total_samples, 0, "no Sigma samples shipped; the index is unverified")

    def test_sigma_counts_cover_their_samples(self):
        for entry in self.index["techniques"]:
            self.assertGreaterEqual(entry["sigma_rule_count"], len(entry["sigma_samples"]),
                                    entry["technique"])

    def test_headline_counts_match_entries(self):
        entries = self.index["techniques"]
        counts = self.index["counts"]
        self.assertEqual(counts["techniques_mapped"], len(entries))
        self.assertEqual(counts["sigma_rules_referenced"], sum(e["sigma_rule_count"] for e in entries))
        self.assertEqual(counts["direct"], sum(1 for e in entries if e["sentinel"]["confidence"] == "direct"))
        self.assertEqual(counts["partial"], sum(1 for e in entries if e["sentinel"]["confidence"] == "partial"))
        self.assertEqual(counts["direct"] + counts["partial"], len(entries))

    def test_index_does_not_claim_detection_capability(self):
        note = self.index["scope_note"].lower()
        self.assertIn("does not execute sigma", note)
        self.assertIn("does not claim detection coverage", note)


class TestVerifierCanFail(unittest.TestCase):
    """A checker that has never gone red has proven nothing."""

    @classmethod
    def setUpClass(cls):
        cls.index = dc.load_index()

    def _codes(self, index):
        return {f["code"] for f in dc.errors(dc.validate_index(index))}

    def test_bad_technique_id_is_rejected(self):
        broken = copy.deepcopy(self.index)
        broken["techniques"][0]["technique"] = "T1059.9999"
        self.assertIn("TECHNIQUE_ID", self._codes(broken))

    def test_missing_check_is_rejected(self):
        broken = copy.deepcopy(self.index)
        for entry in broken["techniques"]:
            if entry["sentinel"].get("check"):
                entry["sentinel"]["check"] = "check_does_not_exist"
                entry["sentinel"]["control"] = None
                break
        self.assertIn("UNRESOLVED_CHECK", self._codes(broken))

    def test_entry_with_no_local_basis_is_rejected(self):
        broken = copy.deepcopy(self.index)
        broken["techniques"][0]["sentinel"] = {
            "module": "", "check": None, "control": None, "confidence": "direct",
            "rationale": "deliberately broken for this test",
        }
        self.assertIn("NO_LOCAL_REFERENCE", self._codes(broken))

    def test_stale_count_block_is_rejected(self):
        broken = copy.deepcopy(self.index)
        broken["counts"]["sigma_rules_referenced"] += 1
        self.assertIn("COUNT_MISMATCH", self._codes(broken))

    def test_missing_control_artefact_is_rejected(self):
        broken = copy.deepcopy(self.index)
        broken["techniques"][0]["sentinel"] = {
            "module": "", "check": None, "control": "guardian_policy_missing.json",
            "confidence": "direct", "rationale": "deliberately broken for this test",
        }
        self.assertIn("MISSING_CONTROL", self._codes(broken))

    def test_sigma_sample_without_upstream_path_is_rejected(self):
        broken = copy.deepcopy(self.index)
        for entry in broken["techniques"]:
            if entry["sigma_samples"]:
                entry["sigma_samples"][0]["path"] = ""
                break
        self.assertIn("SIGMA_PATH", self._codes(broken))


class TestLookupAndReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = dc.load_index()

    def test_lookup_is_case_insensitive(self):
        entry = dc.for_technique(self.index, "t1190")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["technique"], "T1190")

    def test_unknown_technique_returns_none_rather_than_guessing(self):
        self.assertIsNone(dc.for_technique(self.index, "T9999"))

    def test_report_states_the_numbers(self):
        report = dc.render_report(self.index)
        stats = dc.summary(self.index)
        self.assertIn(f"{stats['techniques_mapped']} techniques mapped", report)
        self.assertIn(str(stats["sigma_rules_referenced"]), report)
        self.assertIn("does not claim detection coverage", report)

    def test_summary_numbers_are_integers_and_non_zero(self):
        stats = dc.summary(self.index)
        for key in ("techniques_mapped", "direct", "partial", "sigma_rules_referenced"):
            self.assertIsInstance(stats[key], int)
            self.assertGreater(stats[key], 0, key)


class TestCliAndDependencies(unittest.TestCase):
    def test_cli_validate_clean_index_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-B", str(REPO_ROOT / "detection_coverage.py"), "--validate"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_cli_validate_corrupt_index_exits_one(self):
        index = dc.load_index()
        index["counts"]["techniques_mapped"] = 999
        with tempfile.TemporaryDirectory() as tmp:
            broken_path = Path(tmp) / "broken.json"
            broken_path.write_text(json.dumps(index), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-B", str(REPO_ROOT / "detection_coverage.py"),
                 "--validate", "--index", str(broken_path)],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("COUNT_MISMATCH", result.stdout)

    def test_cli_reports_unmapped_technique_with_distinct_exit_code(self):
        result = subprocess.run(
            [sys.executable, "-B", str(REPO_ROOT / "detection_coverage.py"), "--technique", "T9999"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("NOT MAPPED", result.stdout)

    def test_module_makes_no_network_calls(self):
        source = (REPO_ROOT / "detection_coverage.py").read_text(encoding="utf-8")
        for forbidden in ("import requests", "import urllib", "import socket", "import http"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
