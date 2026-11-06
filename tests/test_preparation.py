from contextlib import ExitStack
from datetime import datetime
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("app", Path(__file__).parents[1] / "elitech-webui.py")
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

    def setUp(self):
        self.identity = b"\x00\x44TEST12345678"
        self.blocks = {offset: bytes(size) for offset, size in self.app.ELITECH_CONFIG_WRITE_RANGES}
        first = bytearray(self.blocks[0])
        first[:14] = self.identity
        first[0x20] = 0x19
        first[0x21] = 0x5A  # external / Fahrenheit
        first[0x28:0x2F] = self.app.encode_official_elitech_datetime(datetime.now())
        self.blocks[0] = bytes(first)
        second = bytearray(self.blocks[0x30])
        second[0x1C:0x1E] = b"\0\1"
        self.blocks[0x30] = bytes(second)
        self.state = {"identity": self.identity, "record_count": 0, "capacity": 64000,
                      "state": 4, "start": 0x19, "unit_probe": 0x5A,
                      "alarm": bytes(4), "interval": 1,
                      "configuration_time": first[0x28:0x2F], "device_time": first[0x28:0x2F]}

    def test_success_requires_ready_empty_device_and_matching_settings(self):
        self.app.check_preparation_state(self.state, self.identity, self.blocks, True)
        for field, wrong in [("record_count", 1917), ("state", 7), ("interval", 30),
                             ("unit_probe", 0x58), ("device_time", bytes(7)),
                             ("identity", b"another logger")]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.app.check_preparation_state({**self.state, field: wrong}, self.identity, self.blocks, True)

    def test_busy_device_is_read_again_without_resending_preparation(self):
        conn = Mock()
        with (
            patch.object(self.app, "open_device", return_value=conn),
            patch.object(self.app, "read_preparation_state", side_effect=[OSError("USB restarting"), self.state]),
            patch.object(self.app.time, "sleep"),
            patch.object(self.app, "hid_format_command") as reset,
        ):
            result = self.app.verify_preparation_readback("test", self.identity, self.blocks, True)
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(conn.close.call_count, 2)
        reset.assert_not_called()

    def test_missing_ack_is_success_only_when_readback_verifies_reset(self):
        for verification_fails in (False, True):
            with self.subTest(verification_fails=verification_fails), ExitStack() as stack:
                temporary = stack.enter_context(tempfile.TemporaryDirectory())
                stack.enter_context(patch.object(self.app, "__file__", str(Path(temporary) / "app.py")))
                stack.enter_context(patch.object(self.app, "open_device", return_value=Mock()))
                stack.enter_context(patch.object(self.app, "prime_parameter_session", return_value=(self.identity, b"\x40\x54")))
                stack.enter_context(patch.object(self.app, "read_record_count_from_fd", return_value=(0x54, 64000, 1917)))
                stack.enter_context(patch.object(self.app, "recording_session_id", return_value="same-session"))
                stack.enter_context(patch.object(self.app, "read_rc4_pro_records", return_value={}))
                archive = stack.enter_context(patch.object(self.app, "save_recording_history"))
                def get_parameter(fd, offset, length):
                    return self.blocks[0][0x28:0x2F] if offset == 0x28 else self.blocks[offset][:length]
                stack.enter_context(patch.object(self.app, "hid_get_parameter", side_effect=get_parameter))
                writes = stack.enter_context(patch.object(self.app, "hid_set_parameter_official"))
                reset = stack.enter_context(patch.object(self.app, "hid_format_command", side_effect=TimeoutError("reply missing")))
                stack.enter_context(patch.object(self.app.time, "sleep"))
                verify = stack.enter_context(patch.object(self.app, "verify_preparation_readback", return_value=self.state))
                if verification_fails:
                    verify.side_effect = RuntimeError("1917 records remain")
                    with self.assertRaisesRegex(RuntimeError, "records remain"):
                        self.app.apply_device_config("test", interval_seconds=10, sync_clock=False,
                            button_stop=True, software_stop=True, temperature_unit="F", probe="external",
                            expected_record_count=1916, expected_session_id="same-session", allow_data_loss=True)
                else:
                    result = self.app.apply_device_config("test", interval_seconds=10, sync_clock=False,
                        button_stop=True, software_stop=True, temperature_unit="F", probe="external",
                        expected_record_count=1916, expected_session_id="same-session", allow_data_loss=True)
                    self.assertTrue(result["ok"])
                    self.assertFalse(result["preparation_acknowledged"])
                    self.assertEqual(result["record_count_after_save"], 0)
                archive.assert_called_once()
                self.assertEqual(writes.call_count, 6)
                reset.assert_called_once()
                verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
