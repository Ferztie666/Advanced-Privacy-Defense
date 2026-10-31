import unittest

from pps_privacy_session import GuardStatus, PrivacySession, SessionState


class FakeBackend:
    def __init__(self, fail=None, pre_guard=GuardStatus.ABSENT, pre_up=False, owned=True):
        self.fail = fail
        self.guard = pre_guard
        self.up = pre_up
        self.owned = owned
        self.calls = []

    def call(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("injected " + name)

    def inspect_guard(self):
        self.calls.append("inspect_guard")
        if self.guard == GuardStatus.ABSENT:
            return GuardStatus.ABSENT
        if not self.owned:
            return GuardStatus.FOREIGN_OR_MODIFIED
        return self.guard

    def install_guard(self):
        self.call("install_guard")
        if self.fail == "install_after_create":
            self.guard = GuardStatus.OWNED
            raise RuntimeError("partial install")
        self.guard = GuardStatus.OWNED

    def interface_is_up(self):
        self.calls.append("interface_is_up")
        return self.up

    def bring_interface_up(self):
        self.call("bring_interface_up")
        self.up = True

    def verify_handshake(self):
        self.call("verify_handshake")
        return self.fail != "handshake_false"

    def verify_full_tunnel_routes(self):
        self.call("verify_full_tunnel_routes")
        return self.fail != "routes_false"

    def verify_egress(self):
        self.call("verify_egress")
        return self.fail != "egress_false"

    def bring_interface_down(self):
        self.call("bring_interface_down")
        self.up = False

    def remove_owned_guard(self):
        self.call("remove_owned_guard")
        if not self.owned:
            raise RuntimeError("ownership not proven")
        self.guard = GuardStatus.ABSENT


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
        b = FakeBackend(pre_guard=GuardStatus.OWNED)
        result = PrivacySession(b).enable()
        self.assertFalse(result.ok)
        self.assertNotIn("install_guard", b.calls)
        self.assertNotIn("bring_interface_up", b.calls)

    def test_refuses_unknown_guard_state(self):
        b = FakeBackend(pre_guard=GuardStatus.UNKNOWN)
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertNotIn("install_guard", b.calls)
        self.assertNotIn("bring_interface_up", b.calls)

    def test_refuses_foreign_guard_state(self):
        b = FakeBackend(pre_guard=GuardStatus.FOREIGN_OR_MODIFIED)
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertNotIn("install_guard", b.calls)

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
        self.assertEqual(b.guard, GuardStatus.ABSENT)
        self.assertFalse(b.up)

    def test_failed_down_keeps_guard(self):
        b = FakeBackend(fail="bring_interface_down", pre_guard=GuardStatus.OWNED, pre_up=True)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertEqual(b.guard, GuardStatus.OWNED)

    def test_disable_removes_guard_only_after_interface_down(self):
        b = FakeBackend(pre_guard=GuardStatus.OWNED, pre_up=True)
        result = PrivacySession(b).disable()
        self.assertTrue(result.ok)
        self.assertLess(b.calls.index("bring_interface_down"), b.calls.index("remove_owned_guard"))
        self.assertEqual(b.guard, GuardStatus.ABSENT)

    def test_disable_without_guard_does_not_touch_active_interface(self):
        b = FakeBackend(pre_up=True)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertTrue(b.up)
        self.assertNotIn("bring_interface_down", b.calls)

    def test_disable_unknown_inspection_never_removes_guard(self):
        b = FakeBackend(pre_guard=GuardStatus.UNKNOWN)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertNotIn("remove_owned_guard", b.calls)

    def test_install_failure_never_bring_up_interface(self):
        b = FakeBackend(fail="install_guard")
        result = PrivacySession(b).enable()
        self.assertNotIn("bring_interface_up", b.calls)
        self.assertEqual(result.state, SessionState.OFF)

    def test_partial_install_cleanup_requires_exact_ownership(self):
        b = FakeBackend(fail="install_after_create")
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.OFF)
        self.assertEqual(b.guard, GuardStatus.ABSENT)

    def test_partial_install_with_unknown_owner_is_preserved(self):
        b = FakeBackend(fail="install_after_create", owned=False)
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertEqual(b.guard, GuardStatus.OWNED)
        self.assertNotIn("remove_owned_guard", b.calls)

    def test_disable_refuses_foreign_or_modified_guard(self):
        b = FakeBackend(pre_guard=GuardStatus.FOREIGN_OR_MODIFIED)
        result = PrivacySession(b).disable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertNotIn("remove_owned_guard", b.calls)

    def test_enable_refuses_guard_with_unexpected_structure(self):
        b = FakeBackend(fail="install_after_create", owned=False)
        result = PrivacySession(b).enable()
        self.assertEqual(result.state, SessionState.GUARDED_RECOVERY)
        self.assertNotIn("bring_interface_up", b.calls)
        self.assertNotIn("remove_owned_guard", b.calls)


if __name__ == "__main__":
    unittest.main()
