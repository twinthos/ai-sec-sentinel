import unittest
import guardian_mcp

class MCPTests(unittest.TestCase):
    def test_initialize_and_tools(self):
        init=guardian_mcp.handle({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})
        self.assertEqual(init["result"]["serverInfo"]["name"],"twinthos-sentinel-guardian")
        tools=guardian_mcp.handle({"jsonrpc":"2.0","id":2,"method":"tools/list"})
        self.assertEqual({x["name"] for x in tools["result"]["tools"]},{"sentinel_list_incidents","sentinel_client_dashboard","sentinel_client_findings"})
    def test_unknown_method(self):
        out=guardian_mcp.handle({"jsonrpc":"2.0","id":3,"method":"tools/execute"})
        self.assertEqual(out["error"]["code"],-32601)
if __name__=="__main__": unittest.main()
