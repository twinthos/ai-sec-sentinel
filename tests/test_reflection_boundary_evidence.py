"""Fail-closed checks for the research evidence wrapper; no model or network needed."""
import unittest

from examples.reflection_boundary_evidence import EXPECTED_CHECKS, validate_proof


def sample_proof():
    return {
        "project": "Twinthos Sentinel",
        "scope": "synthetic, local, read-only MCP enforcement proof",
        "pass": True,
        "checks": {name: True for name in EXPECTED_CHECKS},
    }


class EvidenceContractTests(unittest.TestCase):
    def test_complete_consistent_proof_accepted(self):
        result = sample_proof()
        self.assertEqual(set(validate_proof(result)), EXPECTED_CHECKS)

    def test_failed_check_is_not_misreported_as_success(self):
        result = sample_proof()
        result["checks"]["forbidden_shell_denied"] = False
        with self.assertRaises(ValueError):
            validate_proof(result)
        result["pass"] = False
        self.assertFalse(validate_proof(result)["forbidden_shell_denied"])

    def test_missing_check_rejected(self):
        result = sample_proof()
        del result["checks"]["authorised_read"]
        with self.assertRaises(ValueError):
            validate_proof(result)

    def test_extra_check_rejected_until_reviewed(self):
        result = sample_proof()
        result["checks"]["new_unreviewed_claim"] = True
        with self.assertRaises(ValueError):
            validate_proof(result)

    def test_nonboolean_check_rejected(self):
        result = sample_proof()
        result["checks"]["path_escape_denied"] = "true"
        with self.assertRaises(ValueError):
            validate_proof(result)

    def test_truthy_nonboolean_overall_rejected(self):
        result = sample_proof()
        result["pass"] = 1
        with self.assertRaises(ValueError):
            validate_proof(result)

    def test_scope_cannot_be_silently_upgraded(self):
        result = sample_proof()
        result["scope"] = "live Beam full-system security"
        with self.assertRaises(ValueError):
            validate_proof(result)

    def test_wrong_project_rejected(self):
        result = sample_proof()
        result["project"] = "Other"
        with self.assertRaises(ValueError):
            validate_proof(result)


if __name__ == "__main__":
    unittest.main()
