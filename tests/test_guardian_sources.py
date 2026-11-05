import unittest\nfrom unittest.mock import patch\nfrom types import SimpleNamespace
from guardian_sources import cpe_products, KEV_MAP, rss_fetch

class CPEMappingTests(unittest.TestCase):
    def test_supported_framework_cpe_mapping_and_range(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[
          {"vulnerable":True,"criteria":"cpe:2.3:a:django:django:*:*:*:*:*:*:*:*","versionStartIncluding":"4.2","versionEndExcluding":"4.2.9"},
          {"vulnerable":False,"criteria":"cpe:2.3:a:django:django:4.1:*:*:*:*:*:*:*"}
        ]}]}]}
        self.assertEqual(cpe_products(cve),[("pypi","django",">=4.2,<4.2.9")])
    def test_cisa_mapping_is_allowlisted(self):
        self.assertEqual(KEV_MAP.get(("django","django")),("pypi","django"))
        self.assertIsNone(KEV_MAP.get(("unknown vendor","unknown product")))
    def test_rss_security_advisory_is_normalised(self):
        xml=b'''<?xml version="1.0"?><rss version="2.0"><channel><item><title>Django security advisory CVE-2026-1234 High</title><link>https://example.test/advisory</link><description>Django remote code vulnerability. High severity.</description><pubDate>Wed, 04 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>'''
        fake=SimpleNamespace(content=xml,raise_for_status=lambda:None)
        with patch("guardian_sources.requests.get",return_value=fake):
            rows=rss_fetch("test","https://feeds.example.test/rss")
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["package"],"django")
        self.assertEqual(rows[0]["ecosystem"],"pypi")
        self.assertEqual(rows[0]["cve"],"CVE-2026-1234")
        self.assertEqual(rows[0]["severity"],"high")
    def test_unknown_cpe_not_guessed(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:unknown:product:*:*:*:*:*:*:*:*"}]}]}]}
        self.assertEqual(cpe_products(cve),[])
if __name__=="__main__":unittest.main()
