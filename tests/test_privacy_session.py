import unittest

from pps_privacy_session import PrivacySession, SessionState


class FakeBackend:
    def __init__(self, fail=None, pre_guard=False, pre_up=False):
        self.fail = fail
        self.guard = pre_guard
        self.up = pre_up
        self.calls = []

    def call(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("injected " + name)

    def guard_exists(self): self.calls.append("guard_exists"); return self.guard
    def install_guard(self): self.call("install_guard"); self.guard = True
    def interface_is_up(self): self.calls.append("interface_is_up"); return self.up
    def bring_interface_up(self): self.call("bring_interface_up"); self.up = True
    def verify_handshake(self): self.call("verify_handshake"); return self.fail != "handshake_false"
    def verify_full_tunnel_routes(self): self.call("verify_full_tunnel_routes"); return self.fail != "routes_false"
    def verify_egress(self): self.call("verify_egress"); return self.fail != "egress_false"
    def bring_interface_down(self): self.call("bring_interface_down"); self.up = False
    def remove_owned_guard(self): self.call("remove_owned_guard"); self.guard = False


class PrivacySessionTests(unittest.TestCase):
    def test_enable_order_and_success(self):
        b = FakeBackend()
        result = PrivacySession(b).enable()
        self.assertTrue(result.ok)
        self.assertEqual(result.state, SessionState.ACTIVE)
        self.assertLess(b.calls.index("install_guard"), b.calls.index("bring_interface_up"))
        self.assertLess(b.calls.index("bring_interface_up"), b.calls.index("verify_handshake"))
        self.assertLess(b.calls.index("verify_handshake"), b.calls.index("verify_full_tunnel_routes"))
        self.assertLess(b.calls.index("verify_full_tunnel_routes"), b.calls.index("verify_egress"))

    def test_refuses_preexisting_guard(self):
        b = FakeBackend(pre_guard=True)
        result = PrivacySession(b).enable()
        self.assertFalse(result.ok)
        self.assertNotIn("install_guard", b.calls)
        self.assertNotIn("bring_interface_up", b.calls)

    def test_refuses_preexisting_interface(self):
        b = FakeBackend(pre_up=True)
        result = PrivacySession(b).enable()
        self.assertFalse(result.ok)
        self.assertNotIn("install_guard", b.calls)

    def test_failed_verification_rolls_back_tunnel_before_guard(self):
        b = FakeBackend(fail="egress_false")
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.OFF)
        self.assertLess(b.calls.index("bring_interface_down"), b.calls.index("remove_owned_guard"))
        self.assertFalse(b.guard)
        self.assertFalse(b.up)

    def test_failed_down_keeps_guard(self):
        b = FakeBackend(fail="bring_interface_down", pre_guard=True, pre_up=True)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertTrue(b.guard)

    def test_disable_removes_guard_only_after_interface_down(self):
        b = FakeBackend(pre_guard=True, pre_up=True)
        result = PrivacySession(b).disable()
        self.assertTrue(result.ok)
        self.assertLess(b.calls.index("bring_interface_down"), b.calls.index("remove_owned_guard"))
        self.assertFalse(b.guard)

    def test_disable_without_guard_does_not_touch_active_interface(self):
        b = FakeBackend(pre_up=True)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertTrue(b.up)
        self.assertNotIn("bring_interface_down", b.calls)

    def test_install_failure_never_bring_up_interface(self):
        b = FakeBackend(fail="install_guard")
        result = PrivacySession(b).enable()
        self.assertNotIn("bring_interface_up", b.calls)
        self.assertEqual(result.state, SessionState.OFF)


if __name__ == "__main__":
    unittest.main()
