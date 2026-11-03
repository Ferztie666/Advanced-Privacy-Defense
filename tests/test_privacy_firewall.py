import unittest

from pps_privacy_firewall import (
    FirewallPolicy,
    render_nftables,
    render_owned_table_delete,
    validate_policy,
)


class FirewallPolicyTests(unittest.TestCase):
    def test_renders_ipv4_endpoint_and_fail_closed_output_chain(self):
        rules = render_nftables(FirewallPolicy("198.51.100.10", 51820))
        self.assertIn("add table inet pps_guard", rules)
        self.assertIn("hook output priority -150; policy drop", rules)
        self.assertIn("ip daddr 198.51.100.10 udp dport 51820 accept", rules)
        self.assertIn("udp sport 68 udp dport 67 accept", rules)
        self.assertIn('oifname "wg-pps" accept', rules)

    def test_renders_ipv6_endpoint(self):
        rules = render_nftables(FirewallPolicy("2001:db8::10", 51820))
        self.assertIn("ip6 daddr 2001:db8::10 udp dport 51820 accept", rules)

    def test_custom_wireguard_interface_is_quoted(self):
        rules = render_nftables(FirewallPolicy("198.51.100.10", 51820, "wg-test"))
        self.assertIn('oifname "wg-test" accept', rules)

    def test_rejects_invalid_interface_injection(self):
        for name in ("wg0; flush ruleset", "wg/0", "interface name that is too long"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    render_nftables(FirewallPolicy("198.51.100.10", 51820, name))

    def test_rejects_unsafe_endpoint_addresses(self):
        for address in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "169.254.1.1", "::1", "fe80::1"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    render_nftables(FirewallPolicy(address, 51820))

    def test_rejects_bad_ports_and_boolean_port(self):
        for port in (0, 65536, -1, True, "51820"):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    render_nftables(FirewallPolicy("198.51.100.10", port))

    def test_does_not_flush_or_replace_global_ruleset(self):
        rules = render_nftables(FirewallPolicy("198.51.100.10", 51820))
        self.assertNotIn("flush ruleset", rules)
        self.assertNotIn("delete table", rules)
        self.assertNotIn("flush table", rules)
        self.assertNotIn("add chain inet filter", rules)

    def test_does_not_allow_generic_established_output(self):
        rules = render_nftables(FirewallPolicy("198.51.100.10", 51820))
        self.assertNotIn("ct state established", rules)
        self.assertNotIn("ct state related", rules)

    def test_dhcp_exception_can_be_disabled(self):
        rules = render_nftables(FirewallPolicy("198.51.100.10", 51820, allow_dhcpv4=False))
        self.assertNotIn("udp sport 68 udp dport 67", rules)

    def test_delete_plan_targets_only_pps_owned_table(self):
        self.assertEqual(render_owned_table_delete(), "delete table inet pps_guard\n")
        self.assertNotIn("flush ruleset", render_owned_table_delete())


if __name__ == "__main__":
    unittest.main()
