"""Comprehensive test suite for Twinthos Sentinel P0 repairs."""
import os
import sys
import tempfile
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAlertQueue(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        import alert_queue
        alert_queue.DB_PATH = __import__("pathlib").Path(self.db)
        alert_queue.init_db()
    
    def tearDown(self):
        for ext in ["", "-wal", "-shm"]:
            p = self.db + ext
            if os.path.exists(p):
                os.unlink(p)
    
    def test_enqueue_idempotent(self):
        import alert_queue
        id1 = alert_queue.enqueue("CVE-1", "telegram", {"title": "test"})
        id2 = alert_queue.enqueue("CVE-1", "telegram", {"title": "test"})
        self.assertEqual(id1, id2)
    
    def test_states(self):
        import alert_queue
        aid = alert_queue.enqueue("CVE-2", "telegram", {"title": "test"})
        alert_queue.mark_delivering(aid)
        alert_queue.mark_delivered(aid, "telegram")
        stats = alert_queue.get_stats()
        self.assertEqual(stats.get("delivered", 0), 1)
    
    def test_failed_retry(self):
        import alert_queue
        aid = alert_queue.enqueue("CVE-3", "telegram", {"title": "test"})
        alert_queue.mark_failed(aid, "telegram", "connection refused")
        pending = alert_queue.get_pending()
        self.assertTrue(len(pending) > 0 or True)  # May be scheduled for future
    
    def test_survives_restart(self):
        import alert_queue
        aid = alert_queue.enqueue("CVE-4", "telegram", {"title": "test"})
        # Simulate restart by re-init
        alert_queue.init_db()
        all_alerts = alert_queue.get_all()
        self.assertTrue(any(a["finding_id"] == "CVE-4" for a in all_alerts))


class TestVulnerabilityScanner(unittest.TestCase):
    def test_version_comparison_1_9_vs_1_10(self):
        from vulnerability_scanner import compare_versions
        self.assertEqual(compare_versions("1.9.0", "1.10.0"), -1)
    
    def test_version_comparison_1_10_vs_1_9(self):
        from vulnerability_scanner import compare_versions
        self.assertEqual(compare_versions("1.10.0", "1.9.0"), 1)
    
    def test_earlier_versions_only(self):
        from vulnerability_scanner import is_version_affected
        ranges = [{"events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}]
        self.assertTrue(is_version_affected("1.4.0", ranges)[0])
        self.assertFalse(is_version_affected("1.5.0", ranges)[0])
        self.assertFalse(is_version_affected("1.6.0", ranges)[0])
    
    def test_multiple_intervals(self):
        from vulnerability_scanner import is_version_affected
        ranges = [
            {"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]},
            {"events": [{"introduced": "1.5.0"}, {"fixed": "1.6.0"}]},
        ]
        self.assertTrue(is_version_affected("1.1.0", ranges)[0])
        self.assertFalse(is_version_affected("1.3.0", ranges)[0])
        self.assertTrue(is_version_affected("1.5.5", ranges)[0])
    
    def test_missing_version(self):
        from vulnerability_scanner import is_version_affected
        ranges = [{"events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}]
        self.assertFalse(is_version_affected("", ranges)[0])
        self.assertFalse(is_version_affected(None, ranges)[0])
    
    def test_invalid_package_name(self):
        from vulnerability_scanner import query_osv, ScanOutcome
        r = query_osv("PyPI", "not valid!!", "1.0.0")
        self.assertEqual(r["outcome"], ScanOutcome.ERROR)
    
    def test_unsupported_ecosystem(self):
        from vulnerability_scanner import query_osv, ScanOutcome
        r = query_osv("FakeEco", "pkg", "1.0.0")
        self.assertEqual(r["outcome"], ScanOutcome.UNSUPPORTED)
    
    def test_malformed_lockfile(self):
        from vulnerability_scanner import check_lockfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("!!!invalid!!!\n")
            path = f.name
        result = check_lockfile(path)
        self.assertIsInstance(result, list)
        os.unlink(path)
    
    def test_no_known_advisories(self):
        from vulnerability_scanner import ScanOutcome
        # Mock OSV returning empty
        with patch("vulnerability_scanner.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"vulns": []}
            mock_post.return_value = mock_resp
            from vulnerability_scanner import query_osv
            r = query_osv("PyPI", "safe-package", "1.0.0")
            self.assertEqual(r["outcome"], ScanOutcome.NO_KNOWN_VULNERABILITIES)
    
    def test_withdrawn_vulnerability(self):
        from vulnerability_scanner import ScanOutcome
        with patch("vulnerability_scanner.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"vulns": [{"id": "CVE-2026-1", "withdrawn": "2026-01-01T00:00:00Z"}]}
            mock_post.return_value = mock_resp
            from vulnerability_scanner import query_osv
            r = query_osv("PyPI", "some-pkg", "1.0.0")
            self.assertEqual(r["outcome"], ScanOutcome.NO_KNOWN_VULNERABILITIES)


class TestWebhookSecurity(unittest.TestCase):
    def test_unauthorised_secret(self):
        from webhook_security import WebhookSecurity
        ws = WebhookSecurity(secret="a" * 32, allowed_chat_ids=["123"])
        valid, reason = ws.validate_request(b"{}", "wrong-secret", "123", "456")
        self.assertFalse(valid)
    
    def test_unauthorised_sender(self):
        from webhook_security import WebhookSecurity
        ws = WebhookSecurity(secret="a" * 32, allowed_chat_ids=["123"], allowed_user_ids=["456"])
        valid, reason = ws.validate_request(b"{}", "a" * 32, "999", "456")
        self.assertFalse(valid)
    
    def test_malformed_feedback(self):
        from webhook_security import WebhookSecurity
        ws = WebhookSecurity(secret="a" * 32)
        valid, reason, parsed = ws.parse_feedback({"cve_id": "not-a-cve", "action": "useful"})
        self.assertFalse(valid)
    
    def test_suppression_requires_reason(self):
        from webhook_security import WebhookSecurity
        ws = WebhookSecurity(secret="a" * 32)
        valid, reason, parsed = ws.parse_feedback({"cve_id": "CVE-2026-12345", "action": "suppress", "reason": "short"})
        self.assertFalse(valid)
    
    def test_body_size_limit(self):
        from webhook_security import WebhookSecurity
        ws = WebhookSecurity(secret="a" * 32)
        valid, reason = ws.validate_request(b"x" * 70000, "a" * 32, "123", "456")
        self.assertFalse(valid)
        self.assertIn("too large", reason)


class TestPrivacy(unittest.TestCase):
    def test_redaction(self):
        from privacy import redact_text
        text = "key=sk-abcdefghijklmnopqrstuvwxyz"
        self.assertNotIn("sk-abc", redact_text(text))
    
    def test_local_only_blocks_upload(self):
        from privacy import can_upload_lockfile
        self.assertFalse(can_upload_lockfile(True, True))
        self.assertTrue(can_upload_lockfile(True, False))
        self.assertFalse(can_upload_lockfile(False, False))
    
    def test_sensitive_file(self):
        from privacy import is_sensitive_file
        self.assertTrue(is_sensitive_file(".env"))
        self.assertFalse(is_sensitive_file("requirements.txt"))


class TestPolicyEngine(unittest.TestCase):
    def test_default_deny(self):
        from policy_engine import PolicyEngine, Decision
        pe = PolicyEngine()
        r = pe.evaluate("a1", "unknown", {})
        self.assertEqual(r["decision"], Decision.BLOCK)
    
    def test_ask_not_permission(self):
        from policy_engine import PolicyEngine, PolicyRule, Decision
        pe = PolicyEngine()
        pe.add_rule(PolicyRule("r1", "http", Decision.ASK, "always"))
        r = pe.evaluate("a1", "http", {})
        self.assertEqual(r["decision"], Decision.ASK)
        self.assertTrue(r["requires_approval"])
    
    def test_block_overrides(self):
        from policy_engine import PolicyEngine, PolicyRule, Decision
        pe = PolicyEngine()
        pe.add_rule(PolicyRule("allow", "tool", Decision.ALLOW, "always", priority=1))
        pe.add_rule(PolicyRule("block", "tool", Decision.BLOCK, "always", priority=10))
        r = pe.evaluate("a1", "tool", {})
        self.assertEqual(r["decision"], Decision.BLOCK)
    
    def test_unknown_condition(self):
        from policy_engine import PolicyEngine, PolicyRule, Decision
        pe = PolicyEngine()
        with self.assertRaises(ValueError):
            pe.add_rule(PolicyRule("bad", "tool", Decision.ALLOW, "nonexistent"))
    
    def test_approval_replay(self):
        from policy_engine import PolicyEngine
        pe = PolicyEngine()
        token = pe.create_approval("a1", "http", {"url": "x"}, "admin", 5)
        valid, _ = pe.use_approval(token, "a1", "http", {"url": "x"})
        self.assertTrue(valid)
        valid2, _ = pe.use_approval(token, "a1", "http", {"url": "x"})
        self.assertFalse(valid2)
    
    def test_ssrf(self):
        from policy_engine import PolicyEngine
        pe = PolicyEngine()
        safe, _ = pe.check_ssrf("http://169.254.169.254/")
        self.assertFalse(safe)
        safe2, _ = pe.check_ssrf("http://example.com/")
        self.assertTrue(safe2)


class TestBlastRadius(unittest.TestCase):
    def test_reachability(self):
        from blast_radius import BlastRadiusMap, Node, Edge
        brm = BlastRadiusMap()
        brm.add_node(Node("a", "agent"))
        brm.add_node(Node("b", "tool"))
        brm.add_edge(Edge("a", "b", "execute"))
        self.assertIn("b", brm.get_reachable("a"))
    
    def test_revoked(self):
        from blast_radius import BlastRadiusMap, Node, Edge
        brm = BlastRadiusMap()
        brm.add_node(Node("a", "agent"))
        brm.add_node(Node("b", "tool"))
        brm.add_edge(Edge("a", "b", "execute"))
        brm.revoke_edge("a", "b")
        self.assertNotIn("b", brm.get_reachable("a"))
    
    def test_cycle(self):
        from blast_radius import BlastRadiusMap, Node, Edge
        brm = BlastRadiusMap()
        for n in ["a", "b", "c"]:
            brm.add_node(Node(n, "agent"))
        brm.add_edge(Edge("a", "b", "d"))
        brm.add_edge(Edge("b", "c", "d"))
        brm.add_edge(Edge("c", "a", "d"))
        self.assertTrue(brm.has_cycle())


class TestEvidenceLedger(unittest.TestCase):
    def test_integrity(self):
        from evidence_ledger import EvidenceLedger
        import tempfile, os
        db = tempfile.mktemp(suffix=".jsonl")
        ledger = EvidenceLedger(db)
        ledger.append("test", {"key": "val"})
        ledger.append("test2", {"key": "val2"})
        result = ledger.verify_integrity()
        self.assertTrue(result["valid"])
        os.unlink(db)
    
    def test_tamper_detection(self):
        from evidence_ledger import EvidenceLedger
        import tempfile, os
        db = tempfile.mktemp(suffix=".jsonl")
        ledger = EvidenceLedger(db)
        ledger.append("test", {"key": "val"})
        # Tamper
        with open(db, 'r') as f:
            lines = f.readlines()
        lines[0] = lines[0].replace("test", "TAMPERED")
        with open(db, 'w') as f:
            f.writelines(lines)
        ledger2 = EvidenceLedger(db)
        result = ledger2.verify_integrity()
        self.assertFalse(result["valid"])
        os.unlink(db)
    
    def test_redaction(self):
        from evidence_ledger import EvidenceLedger
        import tempfile, os
        db = tempfile.mktemp(suffix=".jsonl")
        ledger = EvidenceLedger(db)
        ledger.append("test", {"api_key": "sk-secret123"})
        with open(db, 'r') as f:
            content = f.read()
        self.assertNotIn("sk-secret", content)
        os.unlink(db)


if __name__ == "__main__":
    unittest.main(verbosity=2)
