from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from elitech_history import HistoryStore
from elitech_settings import open_history, load_settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        patcher = patch("elitech_settings.SCRIPT_DIR", self.root)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_relative_override_uses_start_in_directory(self):
        store = open_history({"database_path":"database/custom.sqlite3"}, self.root)
        self.assertEqual(store.path, self.root / "database/custom.sqlite3")

    def test_unwritable_default_falls_back_to_start_in_directory(self):
        blocker = self.root / "not-a-directory"; blocker.write_text("test")
        store = open_history({}, self.root, blocker / "database.sqlite3")
        self.assertEqual(store.path, self.root / "elitech-history.sqlite3")

    def test_explicit_bad_override_reports_error_instead_of_selecting_another_database(self):
        blocker = self.root / "not-a-directory"; blocker.write_text("test")
        with self.assertRaises(RuntimeError):
            open_history({"database_path":str(blocker / "database.sqlite3")}, self.root)

    def test_existing_database_is_migrated_with_names_and_records(self):
        old = HistoryStore(self.root / "data/elitech-history.sqlite3")
        old.remember_sensor("A", {"model":"RC-4 Pro"})
        old.rename_sensor("A", "Freezer")
        with patch("elitech_settings.SCRIPT_DIR", self.root):
            store = open_history({}, self.root, self.root / "service/database.sqlite3")
        self.assertEqual(store.sensors()[0]["name"], "Freezer")

    def test_config_does_not_open_browser_by_default(self):
        settings = load_settings(self.root / "absent.json")
        self.assertFalse(settings["open_browser"])


if __name__ == "__main__": unittest.main()
