import base64
import tempfile
import unittest
from pathlib import Path

from pps_privacy import parse_wireguard_profile


KEY = base64.b64encode(bytes(range(32))).decode()


def profile(extra_interface="", extra_peer="", endpoint="198.51.100.10:51820",
            allowed="0.0.0.0/0, ::/0"):
    return f"""[Interface]
PrivateKey = {KEY}
Address = 10.8.0.2/32, fd00::2/128
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
            return parse_wireguard_profile(path)

    def test_accepts_numeric_ipv4_endpoint_and_dual_stack(self):
        result = self.parse(profile())
        self.assertEqual(result.endpoint_ip, "198.51.100.10")
        self.assertEqual(result.endpoint_port, 51820)
        self.assertTrue(result.ipv4_full_tunnel)
        self.assertTrue(result.ipv6_full_tunnel)

    def test_accepts_bracketed_ipv6_endpoint(self):
        result = self.parse(profile(endpoint="[2001:db8::10]:51820"))
        self.assertEqual(result.endpoint_ip, "2001:db8::10")

    def test_rejects_hostname_endpoint(self):
        with self.assertRaisesRegex(ValueError, "numerik"):
            self.parse(profile(endpoint="vpn.example.test:51820"))

    def test_rejects_ipv4_only_profile(self):
        with self.assertRaisesRegex(ValueError, "dual-stack"):
            self.parse(profile(allowed="0.0.0.0/0"))

    def test_rejects_missing_full_tunnel(self):
        with self.assertRaises(ValueError):
            self.parse(profile(allowed="10.0.0.0/8"))

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
            link = root / "link.conf"
            link.symlink_to(actual)
            with self.assertRaises(ValueError):
                parse_wireguard_profile(link)


if __name__ == "__main__":
    unittest.main()
