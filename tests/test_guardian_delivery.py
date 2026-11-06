import os, unittest
from unittest.mock import patch, Mock
import guardian_platform as gp
from guardian_delivery import deliver_finding

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp=tempfile.TemporaryDirectory()
        gp.DB_PATH=os.path.join(self.tmp.name,"delivery.sqlite")
        gp.API_KEY="test"
        gp.init_db()
        with gp.db() as c:
            c.execute("INSERT INTO clients(id,name,region,contact_email,created_at) VALUES(?,?,?,?,?)",("client1","Delivery Ltd","global",None,gp.utcnow()))
            c.execute("""INSERT INTO incidents(id,source,source_id,published_at,severity,ecosystem,package,title,description,affected_versions,remediation,exploited)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",("incident1","test","incident1","2026-11-06T00:00:00+00:00","high","npm","axios","Axios advisory","Test evidence","<1.2.0","Upgrade to fixed release",0))
            c.execute("""INSERT INTO findings(client_id,incident_id,match_state,status,first_seen,last_seen)
              VALUES(?,?,?,?,?,?)""",("client1","incident1","confirmed","open",gp.utcnow(),gp.utcnow()))
            self.finding_id=c.execute("SELECT id FROM findings").fetchone()[0]
    def tearDown(self):
        self.tmp.cleanup()
    @patch.dict(os.environ,{"SENTINEL_SLACK_WEBHOOK_URL":"https://hooks.slack.com/services/T000/B000/secret"},clear=True)
    @patch("guardian_delivery.requests.post")
    def test_successful_delivery_is_not_duplicated_on_retry(self,post):
        response=Mock();response.raise_for_status.return_value=None;post.return_value=response
        first=deliver_finding(self.finding_id)
        second=deliver_finding(self.finding_id)
        self.assertEqual(first,[{"channel":"slack","status":"sent"}])
        self.assertEqual(second,[])
        self.assertEqual(post.call_count,1)
        self.assertFalse(post.call_args.kwargs.get("allow_redirects",True))
    @patch.dict(os.environ,{"SENTINEL_SLACK_WEBHOOK_URL":"https://evil.example/services/secret"},clear=True)
    @patch("guardian_delivery.requests.post")
    def test_non_slack_webhook_is_rejected_without_network(self,post):
        result=deliver_finding(self.finding_id)
        self.assertEqual(result[0]["status"],"failed")
        post.assert_not_called()

if __name__=="__main__": unittest.main()
