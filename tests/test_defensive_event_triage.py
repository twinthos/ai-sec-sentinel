"""Defensive ARTEX-era behavioural triage tests; all records synthetic."""
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defensive_event_triage import analyse, load_jsonl


class CloudLogTriageTests(unittest.TestCase):
    def records(self, count=25, accounts=7, tenants=3):
        now = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
        return [{
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            "event": "sign_in", "result": "failure",
            "source_ip": "198.51.100.7",
            "account_id": f"synthetic-user-{i%accounts}",
            "tenant_id": f"synthetic-tenant-{i%tenants}",
        } for i in range(count)]

    def test_detects_cross_tenant_multi_account_burst(self):
        out = analyse(self.records())
        signals = [x for x in out["signals"] if x["type"] == "cross_tenant_signin_burst"]
        self.assertEqual(len(signals), 1)
        self.assertGreaterEqual(signals[0]["failures_in_5m"], 20)
        self.assertGreaterEqual(signals[0]["unique_accounts"], 5)
        self.assertGreaterEqual(signals[0]["unique_tenants"], 2)

    def test_one_account_with_retries_does_not_trigger_cross_tenant_alert(self):
        self.assertEqual(analyse(self.records(30, accounts=1))["signals"], [])

    def test_single_tenant_not_cross_tenant_alert(self):
        self.assertEqual(analyse(self.records(30, tenants=1))["signals"], [])

    def test_slow_spread_out_activity_does_not_trigger_burst(self):
        rows = self.records(30)
        for i, row in enumerate(rows):
            row["timestamp"] = (datetime(2026, 10, 16, tzinfo=timezone.utc)
                                + timedelta(minutes=i)).isoformat()
        self.assertEqual(analyse(rows)["signals"], [])

    def test_sensitive_credential_and_role_changes_flagged_without_identifiers(self):
        ts = datetime(2026, 10, 16, tzinfo=timezone.utc).isoformat()
        rows = [{"timestamp": ts, "event": kind, "account_id": "sensitive-user",
                 "source_ip": "198.51.100.7", "details": "PRIVATE_BEARER_TOKEN"}
                for kind in ("app_credential_added", "oauth_permission_granted",
                             "privileged_role_granted")]
        report = analyse(rows)
        self.assertEqual(len(report["signals"]), 3)
        self.assertNotIn("sensitive-user", json.dumps(report))
        self.assertNotIn("PRIVATE_BEARER_TOKEN", json.dumps(report))
        self.assertNotIn("198.51.100.7", json.dumps(report))

    def test_malformed_timestamp_and_missing_actor_treated_as_invalid(self):
        rows = [{"timestamp": "nonsense", "event": "app_credential_added"},
                {"timestamp": "2026-10-16T00:00:00+00:00", "event": "sign_in",
                 "result": "failure"}]
        report = analyse(rows)
        self.assertEqual(report["invalid_or_skipped_rows"], 2)
        self.assertEqual(report["signals"], [])

    def test_process_does_not_echo_sensitive_raw_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "synthetic.jsonl"
            rows = self.records(21)
            rows[0]["secret"] = "NO_SHOW_IN_REPORT"
            rows.append({"timestamp": "2026-10-16T00:00:00+00:00",
                         "event": "app_credential_added", "secret": "NO_SHOW_IN_REPORT"})
            file.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            script = Path(__file__).resolve().parent.parent / "defensive_event_triage.py"
            p = subprocess.run([sys.executable, str(script), "--input", str(file)],
                               capture_output=True, text=True, timeout=8)
            self.assertEqual(p.returncode, 0, p.stderr)
            result = json.loads(p.stdout)
            self.assertGreaterEqual(len(result["signals"]), 2)
            self.assertNotIn("NO_SHOW_IN_REPORT", p.stdout)
            self.assertTrue(result["source_identifiers_included"] is False)

    def test_no_external_fetch_or_active_survey(self):
        from unittest.mock import patch
        with patch("socket.create_connection", side_effect=AssertionError("Network access forbidden")):
            report = analyse(self.records())
        self.assertGreaterEqual(len(report["signals"]), 1)

    def test_jsonl_input_refuses_symlink_and_invalid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "original.jsonl"
            target.write_text('{"event":"sign_in"}')
            link = parent / "link.jsonl"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                load_jsonl(link)
            target.write_text('{"broken":\n')
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_jsonl(target)


if __name__ == "__main__":
    unittest.main()
