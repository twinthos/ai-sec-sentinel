"""Assurance-language checks: no fake attack detections or false clean-system claims."""
import json
import unittest
from pathlib import Path

from risk_compliance import check_ai_attack_tool_awareness, check_compliance_gap, AI_ATTACK_TOOLS


class TruthfulSecurityReportingTests(unittest.TestCase):
    def test_unimplemented_autoremediation_is_disabled_by_default(self):
        cfg = json.loads((Path(__file__).resolve().parents[1] / "sentinel_config.json").read_text())
        self.assertIs(cfg["auto_remediate"], False)

    def test_awareness_uses_caller_supplied_metadata_not_detection(self):
        result = check_ai_attack_tool_awareness([
            {"internet_facing": True, "authenticated": False},
            {"internet_facing": False, "authenticated": False},
        ])
        self.assertEqual(result["ai_attack_tools_tracked"], len(AI_ATTACK_TOOLS))
        self.assertEqual(result["unauthenticated_exposed"], 1)
        self.assertEqual(result["risk"], "HIGH")
        self.assertIs(result["automatic_signature_detection"], False)
        self.assertEqual(result["input_type"], "caller_supplied_service_metadata")

    def test_no_findings_cannot_claim_the_system_is_clean(self):
        result = check_compliance_gap([], ["SOC2"])
        self.assertFalse(result["gap_detected"])
        self.assertNotIn("appears clean", result["message"].lower())
        self.assertIn("not", result["message"].lower())

    def test_reference_text_makes_no_breach_cost_guarantee(self):
        from risk_compliance import AI_SECURITY_MARKET_NOTE
        self.assertNotIn("500,000", AI_SECURITY_MARKET_NOTE)
        self.assertNotIn("near-zero", AI_SECURITY_MARKET_NOTE)


if __name__ == "__main__":
    unittest.main()
