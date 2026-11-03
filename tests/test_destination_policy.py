"""Synthetic, network-free checks for destination policy fail-closed behavior."""
import unittest

from policy_engine import Decision, PolicyEngine, PolicyRule


class DestinationPolicyTests(unittest.TestCase):
    def test_empty_destination_rule_cannot_grant_network_access(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule("allow-destination", "http_request", Decision.ALLOW, "destination"))
        self.assertEqual(
            engine.evaluate("agent", "http_request", {"url": "https://example.com"})["decision"],
            Decision.BLOCK,
        )

    def test_exact_host_only_and_no_url_smuggling(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule("allowed", "http_request", Decision.ALLOW, "destination",
                                   {"allowed": ["api.example.com"]}))
        for url in (
            "https://api.example.com.evil.org/data",
            "https://api.example.com@evil.org/data",
            "https://evil.org/?redirect=https://api.example.com",
            "https://sub.api.example.com/",
            "https://api.example.com:444/",
            "file:///etc/passwd",
            "https://api.example.com/#fragment",
            "https://api.example.com./",
            "http://127.0.0.1/",
        ):
            with self.subTest(url=url):
                self.assertEqual(engine.evaluate("agent", "http_request", {"url": url})["decision"],
                                 Decision.BLOCK)
        self.assertEqual(engine.evaluate("agent", "http_request",
                                        {"url": "https://api.example.com/resource"})["decision"],
                         Decision.ALLOW)

    def test_block_domain_matches_subdomains_not_lookalikes(self):
        engine = PolicyEngine()
        engine.blocked_destinations.add("evil.org")
        engine.add_rule(PolicyRule("block-destination", "http_request", Decision.BLOCK, "destination"))
        engine.add_rule(PolicyRule("allow", "http_request", Decision.ALLOW, "always"))
        for url in ("https://evil.org/", "https://sub.evil.org/"):
            with self.subTest(url=url):
                self.assertEqual(engine.evaluate("agent", "http_request", {"url": url})["decision"],
                                 Decision.BLOCK)
        self.assertEqual(engine.evaluate("agent", "http_request",
                                        {"url": "https://not-evil.org/"})["decision"], Decision.ALLOW)

    def test_ssrf_precheck_denies_unapproved_and_unsafe_destinations(self):
        engine = PolicyEngine()
        approved = {"api.example.com"}
        for url in (
            "https://api.example.com/", "HTTPS://api.example.com/"
        ):
            with self.subTest(url=url):
                self.assertTrue(engine.check_ssrf(url, approved)[0])
        bad = (
            "https://api.example.com/",  # No allowlist
            "http://api.example.com/",   # Plain HTTP not allowed
            "https://api.example.com.evil.org/",
            "https://api.example.com@evil.org/",
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://0x7f000001/",
            "https://localhost/",
            "https://metadata.google.internal/",
            "https://api.example.com:8000/",
            "ftp://api.example.com/",
            "https://api.example.com\\@evil.org/",
            "https://api.example.com\n.evil.org/",
        )
        for url in bad:
            with self.subTest(url=url):
                self.assertFalse(engine.check_ssrf(url, () if url == "https://api.example.com/" else approved)[0])

    def test_https_allowlist_does_not_imply_safe_network_request(self):
        engine = PolicyEngine()
        allowed, reason = engine.check_ssrf("https://api.example.com/", {"api.example.com"})
        self.assertTrue(allowed)
        self.assertIn("network enforcement", reason.lower())


if __name__ == "__main__":
    unittest.main()
