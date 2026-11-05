import unittest
from fastapi import HTTPException
from guardian_stack import parse_repo_url, extract_manifests

class StackScannerTests(unittest.TestCase):
    def test_java_ruby_and_docker_manifests(self):
        tree=[{"path":"pom.xml","type":"blob"},{"path":"Gemfile.lock","type":"blob"},{"path":"Dockerfile","type":"blob"}]
        contents={
          "pom.xml":'<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-core</artifactId><version>6.3.1</version></dependency></dependencies></project>',
          "Gemfile.lock":"GEM\n  specs:\n    rails (7.1.0)\n    rack (3.0.8)\n",
          "Dockerfile":"FROM nginx:1.25\nFROM python:3.12-slim\n"
        }
        rows=extract_manifests(tree,lambda name:contents[name])
        by={(x["ecosystem"],x["package"],x["version"]) for x in rows}
        self.assertIn(("maven","org.springframework.security:spring-security-core","6.3.1"),by)
        self.assertIn(("rubygems","rails","7.1.0"),by)
        self.assertIn(("docker","nginx","1.25"),by)
        self.assertIn(("nginx","nginx","1.25"),by)
        self.assertIn(("docker","python","3.12-slim"),by)
    def test_only_github_https_urls(self):
        self.assertEqual(parse_repo_url("https://github.com/django/django.git"),("django","django"))
        for url in ("http://github.com/a/b","https://evil.example/a/b","https://github.com.evil.example/a/b","https://127.0.0.1/a/b"):
            with self.assertRaises(HTTPException): parse_repo_url(url)
    def test_extract_exact_and_unknown_package_versions(self):
        tree=[{"path":"package.json","type":"blob"},{"path":"package-lock.json","type":"blob"},{"path":"requirements.txt","type":"blob"}]
        contents={
          "package.json":{"dependencies":{"react":"^18.2.0","axios":"1.6.2"}},
          "package-lock.json":{"packages":{"":{"name":"demo"},"node_modules/next":{"version":"14.1.0"},"node_modules/@scope/pkg":{"version":"2.0.0"}}},
          "requirements.txt":"Django==4.2.8\nrequests>=2.0\n"
        }
        rows=extract_manifests(tree,lambda name:contents[name])
        by={(x["ecosystem"],x["package"],x["version"]) for x in rows}
        self.assertIn(("npm","axios","1.6.2"),by)
        self.assertIn(("npm","react",None),by)
        self.assertIn(("npm","next","14.1.0"),by)
        self.assertIn(("npm","@scope/pkg","2.0.0"),by)
        self.assertIn(("pypi","django","4.2.8"),by)
        self.assertIn(("pypi","requests",None),by)
if __name__=="__main__": unittest.main()
