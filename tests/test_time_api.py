"""Exercise time bounds through HTTP without opening HID or a browser."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen
from unittest.mock import patch

from elitech_history import HistoryStore


class TimeAPITests(unittest.TestCase):
    def test_range_query_and_invalid_bounds(self):
        spec = importlib.util.spec_from_file_location("time_api_app", Path(__file__).parents[1] / "elitech-webui.py")
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)
        with tempfile.TemporaryDirectory() as folder:
            app.HISTORY = HistoryStore(Path(folder) / "history.sqlite3")
            app.HISTORY.save({"session_id": "session", "serial_number": "A", "stored_count": 3,
                "records": [{"index": index, "timestamp": timestamp, "temperature": 20,
                             "status": "Measurement"} for index, timestamp in enumerate([
                    "2026-11-03 23:59:59", "2026-11-04 00:00:00", "2026-11-05 00:00:00"]) ]})
            server = app.LocalHTTPServer(("127.0.0.1", 0), app.Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}/api/sensor-records?"
                params = {"serial": "A", "start": "2026-11-04 00:00:00", "end": "2026-11-05 00:00:00"}
                with urlopen(base + urlencode(params), timeout=3) as response:
                    data = json.load(response)
                self.assertEqual(data["loaded_count"], 1)
                self.assertEqual(data["stored_count"], 3)
                self.assertEqual(data["records"][0]["timestamp"], params["start"])
                with patch.object(app.LOGGER, "exception"), self.assertRaises(HTTPError) as failed:
                    urlopen(base + urlencode({**params, "end": "bad"}), timeout=3)
                self.assertEqual(failed.exception.code, 400)
                failed.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
