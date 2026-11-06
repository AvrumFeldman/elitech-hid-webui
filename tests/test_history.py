import tempfile
from pathlib import Path
import unittest

from elitech_history import HistoryStore


def recording(session_id="recording-a", probe="internal", count=2):
    return {
        "session_id": session_id, "serial_number": "TEST12345678",
        "started_at": "2026-11-03 13:47:59", "configuration_time": "2026-11-03 13:47:37",
        "probe": probe, "interval_seconds": 10, "logger_temperature_unit": "F",
        "stored_count": count,
        "records": [{"index": i + 1, "timestamp": f"2026-11-03 13:48:{i:02}",
                     "temperature": 26 + i / 10, "humidity": None,
                     "probe": probe, "status": "Measurement", "flags": [], "raw_hex": "03 14 00 00"}
                    for i in range(count)],
    }


class HistoryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "history.sqlite3"
        self.store = HistoryStore(self.path)

    def test_old_recording_survives_restart_and_new_session_after_device_reset(self):
        self.store.save(recording())
        reopened = HistoryStore(self.path)
        reopened.save(recording("recording-b", "external", 1))
        self.assertEqual(len(reopened.sessions()), 2)
        self.assertEqual(reopened.recording("recording-a")["loaded_count"], 2)
        self.assertEqual(reopened.recording("recording-b")["records"][0]["probe"], "external")

    def test_redownload_is_deduplicated_and_never_relabels_historical_probe(self):
        self.store.save(recording())
        self.store.save(recording(probe="external", count=3))
        rows = self.store.recording("recording-a")["records"]
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["probe"] for row in rows], ["internal", "internal", "external"])

    def test_partial_downloads_backfill_and_preserve_original_indices(self):
        late = recording(count=3)
        late["records"] = late["records"][-1:]
        self.store.save(late)
        self.store.save(recording(count=2))
        data = self.store.recording("recording-a", limit=1)
        self.assertEqual(data["records"][0]["index"], 3)
        self.assertEqual(self.store.sessions()[0]["saved_count"], 3)

    def test_time_range_has_inclusive_start_exclusive_end_across_sessions(self):
        first = recording(count=3)
        first["records"][0]["timestamp"] = "2026-11-03 23:59:59"
        first["records"][1]["timestamp"] = "2026-11-04 00:00:00"
        first["records"][2]["timestamp"] = "2026-11-04 12:00:00"
        self.store.save(first)
        second = recording("recording-b", "external", 2)
        second["records"][0]["timestamp"] = "2026-11-04 23:59:59"
        second["records"][1]["timestamp"] = "2026-11-05 00:00:00"
        self.store.save(second)
        other = recording("other-logger", count=1)
        other["serial_number"] = "OTHER"
        other["records"][0]["timestamp"] = "2026-11-04 12:00:00"
        self.store.save(other)
        data = self.store.sensor_recording("TEST12345678", start="2026-11-04 00:00:00", end="2026-11-05 00:00:00")
        self.assertEqual(data["stored_count"], 5)
        self.assertEqual(data["matched_count"], 3)
        self.assertEqual([r["timestamp"] for r in data["records"]],
                         ["2026-11-04 00:00:00", "2026-11-04 12:00:00", "2026-11-04 23:59:59"])
        self.assertEqual([r["probe"] for r in data["records"]], ["internal", "internal", "external"])
        self.assertEqual(self.store.sensor_recording("TEST12345678")["loaded_count"], 5)
        empty = self.store.sensor_recording("TEST12345678", start="2026-12-01 00:00:00")
        self.assertEqual(empty["loaded_count"], 0)

    def test_time_range_validation(self):
        for start, end in [("bad", None), ("2026-02-30 00:00:00", None),
                           ("2026-11-04 00:00:00", "2026-11-03 00:00:00"),
                           ("2026-11-04 00:00:00", "2026-11-04 00:00:00")]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                self.store.sensor_recording("TEST12345678", start=start, end=end)


if __name__ == "__main__":
    unittest.main()
