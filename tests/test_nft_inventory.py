import json
import subprocess
import unittest
from unittest.mock import Mock

from pps_privacy_firewall import FirewallPolicy
from pps_privacy_session import GuardStatus
from pps_nft_inventory import _target_table_present, inspect_guard_inventory
from tests.test_nft_inspect import nft_json


def inventory(*tables):
    items = [{"metainfo": {"version": "1.0.9"}}]
    items.extend({"table": t} for t in tables)
    return json.dumps({"nftables": items})


class NftInventoryTests(unittest.TestCase):
    def setUp(self):
        self.policy = FirewallPolicy("198.51.100.10", 51820)

    def runner_for(self, responses):
        runner = Mock()
        runner.side_effect = [
            subprocess.CompletedProcess([], 0, out, "") for out in responses
        ]
        return runner

    def test_complete_inventory_proves_absent(self):
        runner = self.runner_for([inventory({"family": "inet", "name": "filter"})])
        result = inspect_guard_inventory(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        self.assertEqual(result.status, GuardStatus.ABSENT)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(runner.call_args.args[0], ["/usr/sbin/nft", "-j", "list", "tables"])

    def test_empty_complete_inventory_proves_absent(self):
        result = inspect_guard_inventory(
            self.policy, nft_path="/usr/sbin/nft",
            runner=self.runner_for([inventory()]),
        )
        self.assertEqual(result.status, GuardStatus.ABSENT)

    def test_present_exact_table_is_verified_with_second_read(self):
        runner = self.runner_for([inventory(
            {"family": "inet", "name": "pps_guard", "handle": 4}
        ), nft_json(self.policy)])
        result = inspect_guard_inventory(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        self.assertEqual(result.status, GuardStatus.OWNED)
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(runner.call_args.args[0][-4:], ["table", "inet", "pps_guard"])

    def test_present_but_unverifiable_table_is_unknown(self):
        runner = self.runner_for([inventory(
            {"family": "inet", "name": "pps_guard"}
        ), "{"])
        result = inspect_guard_inventory(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        self.assertEqual(result.status, GuardStatus.UNKNOWN)

    def test_nonzero_inventory_exit_is_unknown(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 1, "", "error"))
        result = inspect_guard_inventory(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        self.assertEqual(result.status, GuardStatus.UNKNOWN)

    def test_malformed_or_unknown_inventory_never_proves_absence(self):
        fixtures = [
            "{", json.dumps({"nftables": [{"rule": {}}]}),
            json.dumps({"nftables": [{"table": {"family": "inet"}}]}),
            json.dumps({"nftables": [{"table": {"family": "inet", "name": "filter", "unexpected": 1}}]}),
            inventory(
                {"family": "inet", "name": "pps_guard"},
                {"family": "inet", "name": "pps_guard"},
            ),
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assertIsNone(_target_table_present(fixture))
                result = inspect_guard_inventory(
                    self.policy, nft_path="/usr/sbin/nft",
                    runner=self.runner_for([fixture]),
                )
                self.assertEqual(result.status, GuardStatus.UNKNOWN)

    def test_timeout_is_unknown(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("nft", 3))
        result = inspect_guard_inventory(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        self.assertEqual(result.status, GuardStatus.UNKNOWN)

    def test_target_in_other_family_does_not_count(self):
        self.assertFalse(_target_table_present(inventory(
            {"family": "ip", "name": "pps_guard"}
        )))


if __name__ == "__main__":
    unittest.main()
