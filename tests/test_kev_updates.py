"""Tests for CISA KEV updates, independent of original CVE publication."""
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import ai_sec_sentinel as sentinel
from kev_updates import select_recent_relevant_kev


CVE = "CVE-2026-54321"
WEBHOOK = "https://hooks.slack.com/services/T/B/C"


def new_kev():
    return {
        "cveID": CVE,
        "vendorProject": "VMware",
        "product": "ESX",
        "vulnerabilityName": "VMware ESX security issue",
        "shortDescription": "Affected systems may be exploited",
        "dateAdded": datetime.now(timezone.utc).date().isoformat(),
        "requiredAction": "Apply official vendor patches",
    }


class KevUpdateTests(unittest.TestCase):
    def test_selects_recent_watched_supplier_without_ai_keyword(self):
        match = select_recent_relevant_kev(
            {"vulnerabilities": [new_kev()]},
            datetime.now(timezone.utc),
            ["VMware"],
            sentinel.is_ai_related,
        )
        self.assertEqual([item["cveID"] for item in match], [CVE])

    def test_does_not_match_substring_of_supplier(self):
        found = select_recent_relevant_kev(
            {"vulnerabilities": [new_kev()]},
            datetime.now(timezone.utc),
            ["Mware"],
            sentinel.is_ai_related,
        )
        self.assertEqual(found, [])

    def test_kevs_realert_when_original_cve_was_acknowledged(self):
        current = {"seen": [CVE], "seen_news": []}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_state", return_value=current), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state") as persist, \
             patch.object(sentinel, "fetch_feed", return_value=[]), \
             patch.object(sentinel, "fetch_cisa_kev", return_value={"vulnerabilities": [new_kev()]}), \
             patch.object(sentinel, "fetch_epss_scores", return_value={}), \
             patch.object(sentinel, "send_webhook", return_value=True) as alert, \
             patch.object(sentinel, "send_telegram", return_value=False):
            count = sentinel.run_scan({
                "suppliers": ["VMware"], "webhook_url": WEBHOOK,
                "news": {"enabled": False},
            })
        self.assertEqual(count, 1)
        self.assertEqual(alert.call_count, 1)
        self.assertIn(CVE, persist.call_args.args[0]["seen_kev"])
        self.assertIn("CISA KEV", alert.call_args.args[0])

    def test_repeated_kev_update_does_not_spam(self):
        current = {"seen": [], "seen_news": [], "seen_kev": [CVE]}
        with patch.dict(os.environ, {"SENTINEL_DRY_RUN": "0"}), \
             patch.object(sentinel, "load_state", return_value=current), \
             patch.object(sentinel, "load_feedback", return_value={}), \
             patch.object(sentinel, "save_state"), \
             patch.object(sentinel, "fetch_feed", return_value=[]), \
             patch.object(sentinel, "fetch_cisa_kev", return_value={"vulnerabilities": [new_kev()]}), \
             patch.object(sentinel, "fetch_epss_scores", return_value={}), \
             patch.object(sentinel, "send_webhook", return_value=True) as alert:
            count = sentinel.run_scan({
                "suppliers": ["VMware"], "webhook_url": WEBHOOK,
                "news": {"enabled": False},
            })
        self.assertEqual(count, 0)
        alert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
