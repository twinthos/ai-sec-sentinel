"""Runtime SQLite alert data stays outside source and has restricted POSIX permissions."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import alert_queue as queue


class AlertDataPathTests(unittest.TestCase):
    def test_new_alert_db_created_with_restricted_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "private-data" / "alerts.db"
            with patch.object(queue, "DB_PATH", db):
                queue.init_db()
                self.assertTrue(db.exists())
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(db.stat().st_mode), 0o600)

    def test_symlinked_database_path_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "data.db"
            target.write_text("not sqlite")
            link = base / "link.db"
            link.symlink_to(target)
            with patch.object(queue, "DB_PATH", link):
                with self.assertRaisesRegex(RuntimeError, "symlink"):
                    queue.get_db()

    def test_documented_default_not_in_source_repo(self):
        # Code must never revert to an unignored database in the checkout root.
        src = (Path(__file__).resolve().parent.parent / "alert_queue.py").read_text()
        self.assertIn('Path.home() / ".local" / "share" / "twinthos-sentinel"', src)
        ignore = (Path(__file__).resolve().parent.parent / ".gitignore").read_text()
        self.assertIn("*.db", ignore)


if __name__ == "__main__":
    unittest.main()
