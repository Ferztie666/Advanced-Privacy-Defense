import json
import unittest

from pps_privacy_firewall import FirewallPolicy
from pps_privacy_ownership import OwnershipVerificationError, verify_owned_table


def fixture(policy):
    from pps_privacy_ownership import _expected_rules
    items = [
        {"metainfo": {"version": "1.0.9", "release_name": "test"}},
        {"table": {"family": "inet", "name": "pps_guard", "handle": 1}},
        {"chain": {
            "family": "inet", "table": "pps_guard", "name": "output",
            "type": "filter", "hook": "output", "prio": -150,
            "policy": "drop", "handle": 2,
        }},
    ]
    for i, expr in enumerate(_expected_rules(policy), 3):
        items.append({"rule": {
            "family": "inet", "table": "pps_guard", "chain": "output",
            "expr": expr, "handle": i,
        }})
    return {"nftables": items}


class OwnershipVerifierTests(unittest.TestCase):
    def setUp(self):
        self.policy = FirewallPolicy("198.51.100.10", 51820)

    def test_accepts_exact_generated_table(self):
        self.assertTrue(verify_owned_table(fixture(self.policy), self.policy))

    def test_accepts_json_text(self):
        self.assertTrue(verify_owned_table(json.dumps(fixture(self.policy)), self.policy))

    def test_rejects_extra_rule(self):
        data = fixture(self.policy)
        data["nftables"].append({"rule": {
            "family": "inet", "table": "pps_guard", "chain": "output",
            "expr": [{"accept": None}],
        }})
        with self.assertRaises(OwnershipVerificationError):
            verify_owned_table(data, self.policy)

    def test_rejects_modified_chain_policy(self):
        data = fixture(self.policy)
        data["nftables"][2]["chain"]["policy"] = "accept"
        with self.assertRaises(OwnershipVerificationError):
            verify_owned_table(data, self.policy)

    def test_rejects_extra_chain(self):
        data = fixture(self.policy)
        data["nftables"].append({"chain": {
            "family": "inet", "table": "pps_guard", "name": "input",
            "type": "filter", "hook": "input", "prio": 0, "policy": "accept",
        }})
        with self.assertRaises(OwnershipVerificationError):
            verify_owned_table(data, self.policy)

    def test_rejects_foreign_table_object(self):
        data = fixture(self.policy)
        data["nftables"].append({"table": {"family": "ip", "name": "other"}})
        with self.assertRaises(OwnershipVerificationError):
            verify_owned_table(data, self.policy)

    def test_rejects_malformed_or_incomplete_output(self):
        for raw in ("{", "{}", {"nftables": [{"metainfo": {}}]}):
            with self.subTest(raw=raw):
                with self.assertRaises(OwnershipVerificationError):
                    verify_owned_table(raw, self.policy)

    def test_rejects_rule_for_different_policy(self):
        with self.assertRaises(OwnershipVerificationError):
            verify_owned_table(fixture(self.policy), FirewallPolicy("198.51.100.11", 51820))

    def test_ipv6_and_dhcp_disabled_shape(self):
        policy = FirewallPolicy("2001:db8::10", 51821, allow_dhcpv4=False)
        self.assertTrue(verify_owned_table(fixture(policy), policy))


if __name__ == "__main__":
    unittest.main()
