"""Fail-closed policy and approval regression tests for agent runtime boundaries.

These tests cover the reference policy engine, not arbitrary deployed agents.
"""
import datetime
import threading
import unittest

from policy_engine import Decision, PolicyEngine, PolicyRule


class PolicyEngineHardeningTests(unittest.TestCase):
    def test_time_condition_never_grants_without_window_verification(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule("time-allow", "file_delete", Decision.ALLOW, "time"))
        self.assertEqual(engine.evaluate("agent", "file_delete", {})["decision"], Decision.BLOCK)
        engine.add_rule(PolicyRule("always-allow", "file_delete", Decision.ALLOW, "always"))
        engine.add_rule(PolicyRule("time-block", "file_delete", Decision.BLOCK, "time"))
        self.assertEqual(engine.evaluate("agent", "file_delete", {})["decision"], Decision.BLOCK)

    def test_resource_block_list_cannot_be_reinterpreted_as_permission(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule("mistaken-allow", "file_read", Decision.ALLOW,
                                   "resource", {"blocked": ["secrets"]}))
        self.assertEqual(engine.evaluate("agent", "file_read", {"path": "secrets.txt"})["decision"],
                         Decision.BLOCK)
        engine.add_rule(PolicyRule("safe-general-allow", "file_read", Decision.ALLOW, "always"))
        engine.add_rule(PolicyRule("block-sensitive", "file_read", Decision.BLOCK,
                                   "resource", {"blocked": ["secrets"]}))
        self.assertEqual(engine.evaluate("agent", "file_read", {"path": "secrets.txt"})["decision"],
                         Decision.BLOCK)
        self.assertEqual(engine.evaluate("agent", "file_read", {"path": "readme.txt"})["decision"],
                         Decision.ALLOW)

    def test_invalid_expiry_cannot_disable_prohibitions_or_grant_access(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule("broken-allow", "read", Decision.ALLOW, "always", expires="bad date"))
        self.assertEqual(engine.evaluate("agent", "read", {})["decision"], Decision.BLOCK)
        engine.add_rule(PolicyRule("valid-allow", "read", Decision.ALLOW, "always"))
        engine.add_rule(PolicyRule("broken-block", "read", Decision.BLOCK, "always", expires="bad date"))
        self.assertEqual(engine.evaluate("agent", "read", {})["decision"], Decision.BLOCK)

    def test_expiry_with_non_utc_timezone_is_normalised(self):
        engine = PolicyEngine()
        past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        tz = datetime.timezone(datetime.timedelta(hours=5))
        engine.add_rule(PolicyRule("expired-block", "read", Decision.BLOCK, "always",
                                   expires=past.astimezone(tz).isoformat()))
        engine.add_rule(PolicyRule("valid-allow", "read", Decision.ALLOW, "always",
                                   expires=future.isoformat()))
        self.assertEqual(engine.evaluate("agent", "read", {})["decision"], Decision.ALLOW)

    def test_approval_tokens_are_long_random_and_one_time(self):
        engine = PolicyEngine()
        args = {"path": "report.txt"}
        tokens = {engine.create_approval("a", "file_read", args, "verified-reviewer")
                  for _ in range(50)}
        self.assertEqual(len(tokens), 50)
        self.assertTrue(all(len(token) >= 40 for token in tokens))
        token = next(iter(tokens))
        self.assertEqual(engine.use_approval(token, "a", "file_read", args)[0], True)
        self.assertEqual(engine.use_approval(token, "a", "file_read", args)[0], False)
        self.assertEqual(engine.use_approval(next(iter(tokens - {token})), "b", "file_read", args)[0], False)

    def test_approval_lifetime_and_identity_must_be_valid(self):
        engine = PolicyEngine()
        for lifetime in (0, -1, 61, 0.5, True):
            with self.subTest(lifetime=lifetime), self.assertRaises(ValueError):
                engine.create_approval("a", "file_read", {}, "reviewer", lifetime)
        with self.assertRaises(ValueError):
            engine.create_approval("a", "file_read", {}, "  ")

    def test_same_token_cannot_be_redeemed_concurrently(self):
        engine = PolicyEngine()
        args = {"path": "report.txt"}
        token = engine.create_approval("a", "file_read", args, "reviewer")
        barrier = threading.Barrier(8)
        results = []
        lock = threading.Lock()
        def claim():
            barrier.wait(timeout=3)
            result = engine.use_approval(token, "a", "file_read", args)[0]
            with lock:
                results.append(result)
        jobs = [threading.Thread(target=claim) for _ in range(8)]
        for job in jobs: job.start()
        for job in jobs: job.join(timeout=4)
        self.assertEqual(len(results), 8)
        self.assertEqual(results.count(True), 1)


if __name__ == "__main__":
    unittest.main()
