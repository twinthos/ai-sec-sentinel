import unittest
from unittest.mock import patch
from fastapi import HTTPException
import guardian_website as web

class WebsiteScannerTests(unittest.TestCase):
    def test_rejects_private_and_loopback_dns(self):
        with patch.object(web.socket,"getaddrinfo",return_value=[(2,1,6,"",("127.0.0.1",0))]):
            with self.assertRaises(HTTPException) as ctx: web.public_ips("internal.example")
            self.assertEqual(ctx.exception.status_code,403)
    def test_rejects_unsupported_scheme_before_network(self):
        with self.assertRaises(HTTPException) as ctx: web.fetch("file:///etc/passwd")
        self.assertEqual(ctx.exception.status_code,422)
    def test_passive_fingerprints_are_version_unknown_without_evidence(self):
        response={"url":"https://example.com/","status":200,
          "headers":{"server":"nginx","x-powered-by":"PHP/8.2"},
          "body":"<html><meta name='generator' content='WordPress 6.5.1'><script src='/_next/static/app.js'></script></html>",
          "ssl":None,"resolved_ips":["93.184.216.34"]}
        with patch.object(web,"fetch",return_value=response):
            result=web.detect("https://example.com")
        by={(x["ecosystem"],x["package"]):x["version"] for x in result["components"]}
        self.assertEqual(by[("nginx","nginx")],None)
        self.assertEqual(by[("php","php")],"8.2")
        self.assertEqual(by[("wordpress","wordpress")],"6.5.1")
        self.assertEqual(by[("npm","next")],None)
if __name__=="__main__":unittest.main()
