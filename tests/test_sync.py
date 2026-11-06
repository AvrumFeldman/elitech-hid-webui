from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from elitech_history import HistoryStore
from elitech_sync import SensorSync


def info(serial="A", count=1):
    return {"serial_number": serial, "session_id": "session-" + serial, "record_count": count,
            "model": "RC-4 Pro", "probe": "internal", "interval_seconds": 10,
            "temperature_unit": "C", "configuration_time": "2026-11-03 12:00:00"}


def download(serial="A", count=1):
    return {"session_id": "session-" + serial, "serial_number": serial,
            "stored_count": count, "probe": "internal", "interval_seconds": 10,
            "records": [{"index": i+1, "timestamp": f"2026-11-03 12:00:{i:02d}",
                         "temperature": 20, "probe": "internal", "status": "Measurement", "flags": []}
                        for i in range(count)]}


class SyncTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.store = HistoryStore(Path(temp.name) / "test.sqlite3")
        self.discover = Mock(return_value=[{"path":"usb"}])
        self.inspect = Mock(return_value=info())
        self.download = Mock(return_value=download())
        self.identify = Mock(return_value="A")
        self.manager = SensorSync(self.store, self.discover, self.inspect, self.download, identify=self.identify)

    def test_connection_downloads_without_browser_and_offline_sensor_keeps_name_and_history(self):
        self.manager.poll_once()
        self.download.assert_called_once_with("usb", 0)
        self.assertTrue(self.manager.snapshot()[0]["connected"])
        self.store.rename_sensor("A", "Freezer")
        self.discover.return_value = []
        self.manager.poll_once()
        offline = self.manager.snapshot()[0]
        self.assertFalse(offline["connected"])
        self.assertEqual(offline["name"], "Freezer")
        self.assertEqual(self.store.sensor_recording("A")["loaded_count"], 1)
        self.discover.return_value = [{"path":"usb"}]
        self.manager.poll_once()
        self.assertEqual(self.download.call_count, 2)

    def test_swap_in_same_usb_port_uses_real_logger_serial_and_keeps_data_separate(self):
        self.manager.poll_once()
        self.identify.return_value = "B"
        self.inspect.return_value = info("B")
        self.download.return_value = download("B")
        self.manager.poll_once()
        sensors = {sensor["serial_number"]:sensor for sensor in self.manager.snapshot()}
        self.assertFalse(sensors["A"]["connected"])
        self.assertTrue(sensors["B"]["connected"])
        for serial in ("A", "B"):
            rows = self.store.sensor_recording(serial)["records"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["session_id"], "session-" + serial)
        with self.assertRaises(ValueError):
            self.store.sensor_recording("A", "session-B")

    def test_periodic_sync_skips_unchanged_records_and_adds_new_samples(self):
        with patch("elitech_sync.time.monotonic", return_value=0): self.manager.poll_once()
        with patch("elitech_sync.time.monotonic", return_value=11): self.manager.poll_once()
        self.assertEqual(self.download.call_count, 1)
        self.inspect.return_value = info(count=2)
        self.download.return_value = download(count=2)
        with patch("elitech_sync.time.monotonic", return_value=22): self.manager.poll_once()
        self.assertEqual(self.store.sensor_recording("A")["loaded_count"], 2)


if __name__ == "__main__": unittest.main()
