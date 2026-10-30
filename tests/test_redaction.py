import tempfile
import unittest
from pathlib import Path
import pps


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secrets_and_identity(self):
        source = "Authorization: Bearer abc123\napi_key=secret123\nuser@example.com\n/home/alice/report"
        result = pps.redact_text(source)
        for secret in ("abc123", "secret123", "user@example.com", "/home/alice"):
            self.assertNotIn(secret, result)

    def test_redact_file_preserves_original_and_restricts_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "pentest.log"
            source.write_text("token=topsecret\n", encoding="utf-8")
            output = pps.redact_file(source)
            self.assertEqual(source.read_text(encoding="utf-8"), "token=topsecret\n")
            self.assertNotIn("topsecret", output.read_text(encoding="utf-8"))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "log.txt"
            source.write_text("safe", encoding="utf-8")
            with self.assertRaises(ValueError):
                pps.redact_file(source, source)

    def test_refuses_to_overwrite_existing_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.log"
            output = Path(folder) / "existing.txt"
            source.write_text("token=secret", encoding="utf-8")
            output.write_text("keep-me", encoding="utf-8")
            with self.assertRaises(ValueError):
                pps.redact_file(source, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep-me")

    def test_rejects_symlink_source(self):
        with tempfile.TemporaryDirectory() as folder:
            real = Path(folder) / "real.log"
            link = Path(folder) / "link.log"
            real.write_text("token=secret", encoding="utf-8")
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                pps.redact_file(link)

    def test_rejects_large_file(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "large.log"
            source.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                pps.redact_file(source)


if __name__ == "__main__":
    unittest.main()
