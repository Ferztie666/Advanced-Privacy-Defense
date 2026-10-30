import subprocess
import unittest
from unittest.mock import Mock

from pps_privacy_firewall import FirewallPolicy
from pps_privacy_ownership import _expected_rules
from pps_nft_inspect import InspectionStatus, inspect_pps_table


def nft_json(policy):
    items = [
        {"metainfo": {"version": "1.0.9"}},
        {"table": {"family": "inet", "name": "pps_guard", "handle": 1}},
        {"chain": {
            "family": "inet", "table": "pps_guard", "name": "output",
            "type": "filter", "hook": "output", "prio": -150, "policy": "drop",
        }},
    ]
    for expr in _expected_rules(policy):
        items.append({"rule": {
            "family": "inet", "table": "pps_guard", "chain": "output", "expr": expr,
        }})
    import json
    return json.dumps({"nftables": items})


class NftInspectionTests(unittest.TestCase):
    def setUp(self):
        self.policy = FirewallPolicy("198.51.100.10", 51820)

    def run_with(self, *, stdout="", returncode=0, side_effect=None):
        runner = Mock()
        if side_effect is not None:
            runner.side_effect = side_effect
        else:
            runner.return_value = subprocess.CompletedProcess([], returncode, stdout, "")
        result = inspect_pps_table(self.policy, nft_path="/usr/sbin/nft", runner=runner)
        return result, runner

    def test_exact_table_is_owned(self):
        result, runner = self.run_with(stdout=nft_json(self.policy))
        self.assertEqual(result.status, InspectionStatus.OWNED)
        args, kwargs = runner.call_args
        self.assertEqual(args[0], ["/usr/sbin/nft", "-j", "list", "table", "inet", "pps_guard"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_nonzero_exit_is_unknown_not_absent(self):
        result, _ = self.run_with(returncode=1, stdout="")
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_malformed_json_is_unknown(self):
        result, _ = self.run_with(stdout="{")
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_extra_rule_is_foreign_or_modified(self):
        import json
        data = json.loads(nft_json(self.policy))
        data["nftables"].append({"rule": {
            "family": "inet", "table": "pps_guard", "chain": "output", "expr": [{"accept": None}],
        }})
        result, _ = self.run_with(stdout=json.dumps(data))
        self.assertEqual(result.status, InspectionStatus.FOREIGN_OR_MODIFIED)

    def test_timeout_is_unknown(self):
        result, _ = self.run_with(side_effect=subprocess.TimeoutExpired("nft", 3))
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_missing_executable_is_unknown(self):
        result = inspect_pps_table(self.policy, nft_path="/missing/nft")
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_rejects_non_absolute_executable_path(self):
        result = inspect_pps_table(self.policy, nft_path="nft")
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_output_size_limit(self):
        result, _ = self.run_with(stdout=" " * (256 * 1024 + 1))
        self.assertEqual(result.status, InspectionStatus.UNKNOWN)

    def test_timeout_bounds(self):
        with self.assertRaises(ValueError):
            inspect_pps_table(self.policy, timeout=0)


if __name__ == "__main__":
    unittest.main()
