"""Tests for shared-behaviour agentic attack detection (defensive awareness)."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from risk_compliance import (
    AGENTIC_FRAMEWORKS,
    AGENTIC_SHARED_BEHAVIORS,
    check_agentic_attack_patterns,
    generate_risk_report,
)


class TestAgenticAttackPatterns(unittest.TestCase):
    def test_auto_approved_agent_cli_is_detected(self):
        events = [{"detail": "agent CLI running with auto-approve started nmap"}]
        result = check_agentic_attack_patterns(events)
        self.assertEqual(result["risk"], "HIGH")
        self.assertIn("auto_approved_agent_cli", [m["behavior"] for m in result["matched_behaviors"]])
        self.assertTrue(result["defensive_only"])
        self.assertFalse(result["automatic_signature_detection"])

    def test_oob_domain_is_detected(self):
        events = [{"dns_query": "abc.oast.fun", "source": "prod-web-01"}]
        result = check_agentic_attack_patterns(events)
        self.assertIn("oob_test_domain", [m["behavior"] for m in result["matched_behaviors"]])

    def test_explicit_behavior_key(self):
        events = [{"behavior": "rotating_proxy_probe"}]
        result = check_agentic_attack_patterns(events)
        keys = [m["behavior"] for m in result["matched_behaviors"]]
        self.assertIn("rotating_proxy_probe", keys)
        self.assertEqual(len(keys), 1)

    def test_benign_event_returns_low_and_no_verdict(self):
        result = check_agentic_attack_patterns([{"detail": "routine health check"}])
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["matched_behaviors"], [])
        self.assertIn("NOT proof of absence", result["message"])

    def test_empty_input_is_safe(self):
        result = check_agentic_attack_patterns()
        self.assertEqual(result["events_reviewed"], 0)
        self.assertEqual(result["matched_behaviors"], [])

    def test_dedupe_across_events(self):
        events = [
            {"detail": "auto-approve enabled"},
            {"detail": "approval prompts off again"},
        ]
        result = check_agentic_attack_patterns(events)
        keys = [m["behavior"] for m in result["matched_behaviors"]]
        self.assertEqual(keys.count("auto_approved_agent_cli"), 1)

    def test_catalogue_is_awareness_only(self):
        self.assertGreaterEqual(len(AGENTIC_FRAMEWORKS), 8)
        self.assertGreaterEqual(len(AGENTIC_SHARED_BEHAVIORS), 8)
        for rule in AGENTIC_SHARED_BEHAVIORS.values():
            self.assertIn("recommendation", rule)
            self.assertIn(rule["severity"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))


class TestRiskReportRegression(unittest.TestCase):
    def test_generate_risk_report_is_callable(self):
        report = generate_risk_report([
            {"title": "LangChain RCE", "severity": "CRITICAL", "in_kev": True, "epss": 0.95, "summary": "prompt injection"},
        ])
        self.assertIn("Twinthos Sentinel Risk Report", report)


if __name__ == "__main__":
    unittest.main()
