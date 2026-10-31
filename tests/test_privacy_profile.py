import base64
import os
import tempfile
import unittest
from pathlib import Path

from pps_privacy import parse_wireguard_profile


KEY = base64.b64encode(bytes(range(32))).decode()


def profile(extra_interface="", extra_peer="", endpoint="198.51.100.10:51820",
            allowed="0.0.0.0/0, ::/0", address="10.8.0.2/32, fd00::2/128"):
    return f"""[Interface]
PrivateKey = {KEY}
Address = {address}
{extra_interface}
[Peer]
PublicKey = {KEY}
Endpoint = {endpoint}
AllowedIPs = {allowed}
{extra_peer}
"""


class ProfileValidationTests(unittest.TestCase):
    def parse(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wg-test.conf"
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            return parse_wireguard_profile(path)

    def test_accepts_numeric_ipv4_endpoint_and_dual_stack(self):
        result = self.parse(profile())
        self.assertEqual(result.endpoint_ip, "198.51.100.10")
        self.assertEqual(result.endpoint_port, 51820)
        self.assertTrue(result.ipv4_full_tunnel)
        self.assertTrue(result.ipv6_full_tunnel)
        self.assertEqual(result.ipv6_policy, "tunnel")

    def test_accepts_bracketed_ipv6_endpoint(self):
        result = self.parse(profile(endpoint="[2001:db8::10]:51820"))
        self.assertEqual(result.endpoint_ip, "2001:db8::10")

    def test_accepts_ipv4_only_provider_and_requires_ipv6_block_policy(self):
        result = self.parse(profile(allowed="0.0.0.0/0", address="10.8.0.2/32"))
        self.assertTrue(result.ipv4_full_tunnel)
        self.assertFalse(result.ipv6_full_tunnel)
        self.assertEqual(result.ipv6_policy, "block-outside-tunnel")

    def test_rejects_hostname_endpoint(self):
        with self.assertRaisesRegex(ValueError, "numerik"):
            self.parse(profile(endpoint="vpn.example.test:51820"))

    def test_rejects_missing_ipv4_full_tunnel(self):
        with self.assertRaisesRegex(ValueError, "IPv4"):
            self.parse(profile(allowed="::/0"))

    def test_rejects_split_tunnel_routes(self):
        for allowed in ("10.0.0.0/8", "0.0.0.0/0, 2001:db8::/32"):
            with self.subTest(allowed=allowed):
                with self.assertRaisesRegex(ValueError, "Split-tunnel"):
                    self.parse(profile(allowed=allowed))

    def test_rejects_ipv6_default_without_ipv6_interface_address(self):
        with self.assertRaisesRegex(ValueError, "Address IPv6"):
            self.parse(profile(address="10.8.0.2/32"))

    def test_rejects_unsafe_endpoint_classes(self):
        for endpoint in ("0.0.0.0:51820", "127.0.0.1:51820", "224.0.0.1:51820",
                         "169.254.1.1:51820", "[fe80::1]:51820"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    self.parse(profile(endpoint=endpoint))

    def test_rejects_dns_and_hook_directives(self):
        for directive in ("DNS = 1.1.1.1", "PostUp = iptables -F", "Table = off"):
            with self.subTest(directive=directive):
                with self.assertRaises(ValueError):
                    self.parse(profile(extra_interface=directive))

    def test_rejects_duplicate_keys(self):
        with self.assertRaises(ValueError):
            self.parse(profile(extra_peer=f"PublicKey = {KEY}"))

    def test_rejects_multiple_peers(self):
        with self.assertRaises(ValueError):
            self.parse(profile() + f"\n[Peer]\nPublicKey = {KEY}\n")

    def test_rejects_invalid_key(self):
        content = profile().replace(KEY, "not-a-key", 1)
        with self.assertRaises(ValueError):
            self.parse(content)

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual.conf"
            actual.write_text(profile(), encoding="utf-8")
            actual.chmod(0o600)
            link = root / "link.conf"
            link.symlink_to(actual)
            with self.assertRaises(ValueError):
                parse_wireguard_profile(link)

    def test_rejects_group_or_world_readable_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wg-test.conf"
            path.write_text(profile(), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "chmod 600"):
                parse_wireguard_profile(path)


if __name__ == "__main__":
    unittest.main()
