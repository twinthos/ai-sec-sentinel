"""Offline OSV regression checks: no false vulnerabilities from clean or unpinned packages."""
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from ai_sec_sentinel import _osv_lockfile_check


class OsVTests(unittest.TestCase):
    @patch("ai_sec_sentinel.requests.post")
    def test_clean_osv_response_produces_no_findings(self, post):
        response = Mock()
        response.json.return_value = {"vulns": []}
        post.return_value = response
        findings = _osv_lockfile_check(Path("requirements.txt"), "langchain==2.10.0\n", "python")
        self.assertEqual(findings, [])
        self.assertEqual(post.call_args.kwargs["json"]["version"], "2.10.0")

    @patch("ai_sec_sentinel.requests.post")
    def test_unpinned_dependency_not_marked_vulnerable(self, post):
        findings = _osv_lockfile_check(Path("requirements.txt"), "langchain>=1.0\n", "python")
        self.assertEqual(findings, [])
        post.assert_not_called()

    @patch("ai_sec_sentinel.requests.post")
    def test_api_reported_vulnerability_is_retained(self, post):
        response = Mock()
        response.json.return_value = {"vulns": [{
            "id": "GHSA-example",
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
        }]}
        post.return_value = response
        findings = _osv_lockfile_check(Path("requirements.txt"), "langchain==2.10.0\n", "python")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fixed_version"], "2.10.1")
        self.assertTrue(findings[0]["affected"])

    @patch("ai_sec_sentinel.requests.post")
    def test_npm_v3_lockfile(self, post):
        response = Mock()
        response.json.return_value = {"vulns": []}
        post.return_value = response
        payload = json.dumps({"packages": {"node_modules/@langchain/core": {"version": "1.2.3"}}})
        self.assertEqual(_osv_lockfile_check(Path("package-lock.json"), payload, "npm"), [])
        self.assertEqual(post.call_args.kwargs["json"]["package"]["name"], "@langchain/core")

    @patch("ai_sec_sentinel.requests.post")
    def test_network_failure_not_counted_as_vulnerability(self, post):
        import requests
        post.side_effect = requests.Timeout("offline")
        findings = _osv_lockfile_check(Path("requirements.txt"), "langchain==2.10.0\n", "python")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
