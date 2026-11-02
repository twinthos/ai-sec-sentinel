"""No real secrets: verify the repository leak guard on synthetic examples."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import check_repo_exposure as scan


class ExposureGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_clean_public_code_passes(self):
        (self.root / "README.md").write_text("Synthetic security demo, no credentials.")
        with patch.object(scan, "ROOT", self.root):
            self.assertEqual(scan.inspect_paths(["README.md"]), [])

    def test_detects_fake_aws_key_without_disclosing_it(self):
        raw = "AKIA" + "A" * 16  # synthetic, deliberately unusable
        (self.root / "example.md").write_text(raw)
        with patch.object(scan, "ROOT", self.root):
            issues = scan.inspect_paths(["example.md"])
        self.assertEqual(len(issues), 1)
        self.assertNotIn(raw, issues[0])

    def test_env_and_private_key_files_not_tracked(self):
        for f in (".env.production", "backup.pem", "id_ed25519", "secrets.json"):
            (self.root / f).write_text("not real")
        with patch.object(scan, "ROOT", self.root):
            issues = scan.inspect_paths([".env.production", "backup.pem", "id_ed25519", "secrets.json"])
        self.assertGreaterEqual(len(issues), 4)

    def test_symlink_and_bytecode_rejected(self):
        (self.root / "target.md").write_text("ok")
        (self.root / "external.md").symlink_to(self.root / "target.md")
        (self.root / "mod.pyc").write_text("compiled sample")
        with patch.object(scan, "ROOT", self.root):
            issues = scan.inspect_paths(["external.md", "mod.pyc"])
        self.assertEqual(len(issues), 2)


if __name__ == "__main__":
    unittest.main()
