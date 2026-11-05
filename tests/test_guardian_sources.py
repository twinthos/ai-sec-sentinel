import unittest
from guardian_sources import cpe_products

class CPEMappingTests(unittest.TestCase):
    def test_supported_framework_cpe_mapping_and_range(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[
          {"vulnerable":True,"criteria":"cpe:2.3:a:django:django:*:*:*:*:*:*:*:*","versionStartIncluding":"4.2","versionEndExcluding":"4.2.9"},
          {"vulnerable":False,"criteria":"cpe:2.3:a:django:django:4.1:*:*:*:*:*:*:*"}
        ]}]}]}
        self.assertEqual(cpe_products(cve),[("pypi","django",">=4.2,<4.2.9")])
    def test_unknown_cpe_not_guessed(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:unknown:product:*:*:*:*:*:*:*:*"}]}]}]}
        self.assertEqual(cpe_products(cve),[])
if __name__=="__main__":unittest.main()
