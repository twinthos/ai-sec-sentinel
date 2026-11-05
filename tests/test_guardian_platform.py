import os, tempfile, unittest
from fastapi.testclient import TestClient
import guardian_platform as gp

class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        gp.DB_PATH=os.path.join(self.tmp.name,"test.sqlite")
        gp.API_KEY="test-key"
        gp.init_db()
        self.client=TestClient(gp.app)
        self.h={"X-API-Key":"test-key"}
    def tearDown(self): self.tmp.cleanup()
    def test_console_is_served_and_client_contact_is_saved(self):
        self.assertEqual(self.client.get("/console").status_code,200)
        client=self.client.post("/v1/clients",headers=self.h,json={"name":"Contact Ltd","contact_email":"security@example.com"}).json()
        self.assertEqual(client["contact_email"],"security@example.com")
    def test_website_scan_requires_explicit_authorisation(self):
        client=self.client.post("/v1/clients",headers=self.h,json={"name":"Site owner"}).json()
        response=self.client.post(f"/v1/clients/{client['id']}/scan-website",headers=self.h,json={"url":"https://example.com","authorised":False})
        self.assertEqual(response.status_code,400)
    def test_api_key_required(self):
        self.assertEqual(self.client.get("/v1/clients").status_code,401)
    def test_confirmed_and_unknown_version_matching(self):
        self.assertEqual(gp.version_matches("4.2.1",">=4.0,<4.3"),"confirmed")
        self.assertEqual(gp.version_matches(None,">=4.0,<4.3"),"potential")
        self.assertEqual(gp.version_matches("4.3.0",">=4.0,<4.3"),"not_affected")
        self.assertEqual(gp.version_matches("unknown","not a spec"),"potential")
    def test_client_incident_scan_and_status(self):
        client=self.client.post("/v1/clients",headers=self.h,json={"name":"Example Ltd"}).json()
        cid=client["id"]
        self.client.post(f"/v1/clients/{cid}/components",headers=self.h,json={"ecosystem":"pypi","package":"django","version":"4.2.1"})
        incident={"id":"ghsa:test:django","source":"github_advisory","source_id":"GHSA-test","published_at":"2026-11-05T00:00:00Z","severity":"high","ecosystem":"pypi","package":"django","title":"Test advisory","description":"Synthetic test","affected_versions":">=4.0,<4.3","fixed_version":"4.2.2","remediation":"Upgrade to 4.2.2"}
        self.assertEqual(self.client.post("/v1/incidents",headers=self.h,json=incident).status_code,202)
        scan=self.client.post(f"/v1/clients/{cid}/scan",headers=self.h).json()
        self.assertEqual(scan["new_findings"],1)
        rows=self.client.get(f"/v1/clients/{cid}/findings",headers=self.h).json()
        self.assertEqual(rows[0]["match_state"],"confirmed")
        self.assertEqual(rows[0]["urgency"],"patch this week")
        fid=rows[0]["id"]
        self.assertEqual(self.client.patch(f"/v1/findings/{fid}",headers=self.h,json={"status":"resolved","owner":"Ops"}).status_code,200)
        self.assertEqual(self.client.get(f"/v1/clients/{cid}/dashboard",headers=self.h).json()["resolved_threats"],1)
    def test_patched_component_auto_resolves_matching_finding(self):
        client=self.client.post("/v1/clients",headers=self.h,json={"name":"Patched Ltd"}).json()
        cid=client["id"]
        component=self.client.post(f"/v1/clients/{cid}/components",headers=self.h,json={"ecosystem":"pypi","package":"django","version":"4.2.1"}).json()
        self.client.post("/v1/incidents",headers=self.h,json={"id":"ghsa:patch:django","source":"github_advisory","source_id":"GHSA-patch-django","published_at":"2026-11-05T00:00:00Z","severity":"high","ecosystem":"pypi","package":"django","title":"Patch test","affected_versions":"<4.2.2","fixed_version":"4.2.2"})
        self.client.post(f"/v1/clients/{cid}/scan",headers=self.h)
        self.assertEqual(self.client.get(f"/v1/clients/{cid}/dashboard",headers=self.h).json()["active_threats"],1)
        self.client.patch(f"/v1/clients/{cid}/components/{component['id']}",headers=self.h,json={"version":"4.2.2"})
        self.client.post(f"/v1/clients/{cid}/scan",headers=self.h)
        self.assertEqual(self.client.get(f"/v1/clients/{cid}/dashboard",headers=self.h).json()["active_threats"],0)
        self.assertEqual(self.client.get(f"/v1/clients/{cid}/dashboard",headers=self.h).json()["resolved_threats"],1)
    def test_unmapped_kev_does_not_match_every_component(self):
        client=self.client.post("/v1/clients",headers=self.h,json={"name":"No false positives"}).json()
        cid=client["id"]
        self.client.post(f"/v1/clients/{cid}/components",headers=self.h,json={"ecosystem":"npm","package":"react","version":"18.2.0"})
        self.client.post("/v1/incidents",headers=self.h,json={"id":"cisa-kev:CVE-2026-0001","source":"cisa_kev","source_id":"CVE-2026-0001","published_at":"2026-11-05T00:00:00Z","severity":"critical","cve":"CVE-2026-0001","title":"Unmapped KEV"})
        scan=self.client.post(f"/v1/clients/{cid}/scan",headers=self.h).json()
        self.assertEqual(scan["new_findings"],0)
    def test_incident_filter(self):
        self.client.post("/v1/incidents",headers=self.h,json={"id":"test:1","source":"test","published_at":"2026-11-05T00:00:00Z","severity":"critical","title":"Test"})
        self.assertEqual(len(self.client.get("/v1/incidents?severity=critical",headers=self.h).json()),1)
if __name__=="__main__": unittest.main()
