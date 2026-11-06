import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class FakeLogger:
    def __init__(self):
        self.requests = []
        self.pending = None

    def write(self, request):
        self.requests.append(request)
        offset = (request[9] << 16) | (request[7] << 8) | request[8]
        records = [bytes.fromhex("00fe0000")] * 12
        if offset == 0:
            records[-1] = bytes.fromhex("00032000")  # pause for 3 intervals
        else:
            records[1:] = [b"\xff" * 4] * 11
        frame = bytearray(request[:11])
        frame[3] = 60
        frame.extend(b"".join(records))
        frame.append(sum(frame) & 0xFF)
        self.pending = bytes(frame) + bytes(4)
        return len(request)

    def wait_readable(self, timeout):
        return self.pending is not None

    def read(self, size):
        result, self.pending = self.pending, None
        return result


class NativeDownloadTests(unittest.TestCase):
    def test_limited_download_still_accounts_for_pause_in_earlier_packet(self):
        spec = importlib.util.spec_from_file_location("app", Path(__file__).parents[1] / "elitech-webui.py")
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)
        def parameter(fd, address, size, **kwargs):
            if address == 0x21:
                return b"\x02"  # external probe, Celsius
            if address == 0x4C:
                return b"\0\1"  # ten seconds
            trip = bytearray(32)
            trip[8:15] = bytes([26, 11, 0, 3, 13, 47, 59])
            return trip
        fake = FakeLogger()
        with patch.object(app, "hid_get_parameter", side_effect=parameter):
            result = app.read_rc4_pro_records(fake, b"\0DTEST12345678", 13, 64000, 1)
        self.assertEqual(result["source"], "hid")
        self.assertEqual(result["probe"], "external")
        self.assertEqual(result["loaded_count"], 1)
        self.assertEqual(result["records"][0]["index"], 13)
        self.assertEqual(result["records"][0]["timestamp"], "2026-11-03 13:50:19")
        self.assertEqual([request[8] for request in fake.requests], [0, 12])
        self.assertEqual([request[10] for request in fake.requests], [12, 12])


if __name__ == "__main__":
    unittest.main()
