import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("pps", Path(__file__).resolve().parents[1] / "pps.py")
pps = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pps)

class ProxyTests(unittest.TestCase):
    def test_socks5h(self): self.assertEqual(pps.validate_proxy("socks5h://127.0.0.1:9050").port, 9050)
    def test_http(self): self.assertEqual(pps.validate_proxy("http://localhost:8080").scheme, "http")
    def test_reject_scheme(self):
        with self.assertRaises(ValueError): pps.validate_proxy("file:///etc/passwd")
    def test_reject_credentials(self):
        with self.assertRaises(ValueError): pps.validate_proxy("socks5h://user:secret@localhost:9050")
    def test_reject_path(self):
        with self.assertRaises(ValueError): pps.validate_proxy("socks5h://localhost:9050/private")
    def test_reject_bad_port(self):
        with self.assertRaises(ValueError): pps.validate_proxy("socks5h://localhost:99999")
    def test_safe_wg_profile(self): self.assertEqual(pps.safe_profile("wg-home_1"), "wg-home_1")
    def test_reject_wg_path_traversal(self):
        with self.assertRaises(ValueError): pps.safe_profile("../bad")
    def test_reject_wg_option_like_name(self):
        with self.assertRaises(ValueError): pps.safe_profile("--help")
    def test_config_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"nested"/"config.json"
            pps.save_config(pps.defaults(),path)
            self.assertEqual(pps.load_config(path)["mode"],"balanced")
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_reject_unsupported_mode(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                pps.save_config({"proxy":pps.DEFAULT_PROXY,"mode":"maximum","scope":"both"},Path(d)/"config.json")

if __name__=="__main__": unittest.main()
