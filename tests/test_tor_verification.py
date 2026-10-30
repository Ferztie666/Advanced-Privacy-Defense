import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pps


class TorVerificationTests(unittest.TestCase):
    @patch("pps.run_cmd")
    @patch("pps.shutil.which", return_value="/usr/bin/curl")
    def test_accepts_verified_tor_exit(self, _which, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout='{"IsTor":true,"IP":"185.220.101.1"}',
            stderr="",
        )
        ok, message = pps.tor_check("socks5h://127.0.0.1:9050")
        self.assertTrue(ok)
        self.assertIn("Tor terverifikasi", message)
        self.assertIn("185.220.101.1", message)

    @patch("pps.run_cmd")
    @patch("pps.shutil.which", return_value="/usr/bin/curl")
    def test_rejects_non_tor_proxy_exit(self, _which, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout='{"IsTor":false,"IP":"203.0.113.8"}',
            stderr="",
        )
        ok, message = pps.tor_check("socks5h://127.0.0.1:9050")
        self.assertFalse(ok)
        self.assertIn("tidak terverifikasi", message)

    @patch("pps.run_cmd")
    @patch("pps.shutil.which", return_value="/usr/bin/curl")
    def test_rejects_malformed_api_response(self, _which, run):
        run.return_value = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
        ok, message = pps.tor_check("socks5h://127.0.0.1:9050")
        self.assertFalse(ok)
        self.assertIn("tidak valid", message)

    def test_rejects_invalid_proxy_before_network(self):
        with self.assertRaises(ValueError):
            pps.tor_check("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
