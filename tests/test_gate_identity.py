"""The policy API must not trust a caller-supplied agent identity."""
import unittest
from unittest.mock import Mock, patch
import guardian_gate as gate


class GateIdentityTests(unittest.TestCase):
    def handler(self):
        # Unit-test the policy branch without opening an HTTP listener.
        obj = object.__new__(gate.GateHandler)
        obj._respond = Mock()
        return obj

    def test_unconfigured_binding_denies_even_known_identity(self):
        h = self.handler()
        with patch.object(gate, "GATE_AGENT_ID", ""):
            self.assertFalse(h._bound_agent("known"))
        h._respond.assert_called_once()
        self.assertEqual(h._respond.call_args.args[0], 403)

    def test_other_registered_agent_cannot_be_impersonated(self):
        h = self.handler()
        with patch.object(gate, "GATE_AGENT_ID", "owned-agent"):
            self.assertFalse(h._bound_agent("admin-agent"))
        self.assertEqual(h._respond.call_args.args[0], 403)

    def test_exact_identity_matches_trusted_host_config(self):
        h = self.handler()
        with patch.object(gate, "GATE_AGENT_ID", "owned-agent"):
            self.assertTrue(h._bound_agent("owned-agent"))
            self.assertFalse(h._bound_agent("Owned-Agent"))
        self.assertEqual(h._respond.call_count, 1)

    def test_status_requires_separate_administrator_key(self):
        h = self.handler()
        h.path = "/status"
        h._authorized = Mock(return_value=False)
        h.do_GET()
        h._authorized.assert_called_once_with(admin=True)

    def test_health_uses_read_key(self):
        h = self.handler()
        h.path = "/health"
        h._authorized = Mock(return_value=False)
        h.do_GET()
        h._authorized.assert_called_once_with(admin=False)

    def test_remote_or_missing_identity_fails_before_bind(self):
        with patch.object(gate, "HOST", "0.0.0.0"), \
             patch.object(gate, "GATE_AGENT_ID", "owned-agent"):
            with self.assertRaisesRegex(SystemExit, "loopback"):
                gate.validate_configuration()
        with patch.object(gate, "HOST", "127.0.0.1"), \
             patch.object(gate, "GATE_AGENT_ID", ""):
            with self.assertRaisesRegex(SystemExit, "GUARDIAN_AGENT_ID"):
                gate.validate_configuration()

    def test_valid_separate_keys_and_binding_pass_validation(self):
        with patch.object(gate, "HOST", "127.0.0.1"), \
             patch.object(gate, "GATE_AGENT_ID", "owned-agent"), \
             patch.object(gate, "GATE_API_KEY", "x" * 32), \
             patch.object(gate, "ADMIN_API_KEY", "y" * 32):
            self.assertIsNone(gate.validate_configuration())

    def test_identical_admin_and_read_keys_rejected(self):
        with patch.object(gate, "HOST", "127.0.0.1"), \
             patch.object(gate, "GATE_AGENT_ID", "owned-agent"), \
             patch.object(gate, "GATE_API_KEY", "x" * 32), \
             patch.object(gate, "ADMIN_API_KEY", "x" * 32):
            with self.assertRaisesRegex(SystemExit, "distinct"):
                gate.validate_configuration()


if __name__ == "__main__":
    unittest.main()
