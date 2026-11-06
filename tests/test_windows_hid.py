import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import elitech_hid


class WindowsHIDTests(unittest.TestCase):
    def setUp(self):
        self.raw = Mock()
        api = Mock()
        api.device.return_value = self.raw
        self.loader = patch.object(elitech_hid, "load_hidapi", return_value=api)
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.conn = elitech_hid.WindowsHID(r"\\?\HID#test")

    def test_report_id_is_added_only_on_write(self):
        report = bytes(range(64))
        self.raw.write.return_value = 65
        self.assertEqual(self.conn.write(report), 64)
        self.raw.write.assert_called_once_with(b"\0" + report)

    def test_pending_report_survives_repeated_waits(self):
        report = bytes(range(64))
        self.raw.read.return_value = list(report)
        self.assertTrue(self.conn.wait_readable(0.25))
        self.assertTrue(self.conn.wait_readable(0))
        self.assertEqual(self.conn.read(64), report)
        self.raw.read.assert_called_once_with(64, 250)

    def test_drain_is_nonblocking_and_timeout_is_not_disconnect(self):
        self.raw.set_nonblocking.assert_called_once_with(1)
        self.raw.read.return_value = []
        self.assertFalse(self.conn.wait_readable(0))
        with self.assertRaises(BlockingIOError):
            self.conn.read(64)
        self.assertFalse(self.conn.wait_readable(0.0011))
        self.raw.read.assert_called_with(64, 2)

    def test_short_and_failed_writes_are_not_success(self):
        self.raw.write.return_value = 12
        self.assertEqual(self.conn.write(bytes(64)), 11)
        self.raw.write.return_value = -1
        with self.assertRaises(OSError):
            self.conn.write(bytes(64))

    def test_disconnect_during_read_is_reported(self):
        self.raw.read.side_effect = OSError("device disconnected")
        with self.assertRaisesRegex(OSError, "disconnected"):
            self.conn.wait_readable(0.5)

    def test_failed_open_closes_handle(self):
        self.raw.open_path.side_effect = OSError("open failed")
        with self.assertRaises(OSError):
            elitech_hid.WindowsHID("missing")
        self.raw.close.assert_called_once()


class AppRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "elitech_webui", Path(__file__).parents[1] / "elitech-webui.py"
        )
        cls.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app)

    def test_rc4_pro_capacity(self):
        self.assertEqual(
            self.app.decode_capacity_record_count(bytes.fromhex("0000fa00000000000000"), 0x54),
            (64000, 0),
        )

    def test_interval_and_unit_patch_preserves_other_settings(self):
        blocks = {offset: bytes([0xA5] * size)
                  for offset, size in self.app.ELITECH_CONFIG_WRITE_RANGES}
        changed = self.app._patch_compat_config_blocks(blocks,
            interval_minutes=0, interval_seconds=10, temperature_unit="F",
            sync_clock=False, button_stop=True, software_stop=True)
        self.assertEqual(changed[0][0x21], 0xAD)
        self.assertEqual(changed[0x30][0x1C:0x1E], b"\0\1")
        self.assertEqual(changed[0][0x28:0x2F], blocks[0][0x28:0x2F])
        changed_c = self.app._patch_compat_config_blocks(changed,
            interval_minutes=0, interval_seconds=86400, temperature_unit="C",
            sync_clock=False, button_stop=True, software_stop=True)
        self.assertEqual(changed_c[0][0x21], 0xA5)
        self.assertEqual(changed_c[0x30][0x1C:0x1E], (8640).to_bytes(2, "big"))

    def test_invalid_interval_or_unit_never_opens_logger(self):
        with patch.object(self.app, "open_device") as open_device:
            for interval, unit in [(0,"C"), (11,"C"), (86410,"C"), (float("nan"),"C"), (10,"K")]:
                with self.subTest(interval=interval, unit=unit), self.assertRaises(ValueError):
                    self.app.apply_device_config("test", interval_seconds=interval,
                        temperature_unit=unit, sync_clock=True, button_stop=True,
                        software_stop=True)
            open_device.assert_not_called()

    def test_preparation_must_receive_success_acknowledgment(self):
        valid = bytes.fromhex("33cc000dc002000000000101d0") + bytes(51)
        with patch.object(self.app, "hid_generic_command", return_value=valid):
            self.assertEqual(self.app.hid_format_command(Mock()), valid)
        for invalid in [b"", bytes(64), valid[:11] + b"\0" + valid[12:]]:
            with patch.object(self.app, "hid_generic_command", return_value=invalid):
                with self.assertRaises((ValueError, TimeoutError)):
                    self.app.hid_format_command(Mock())

    def test_existing_measurements_block_configuration_before_any_write(self):
        conn = Mock()
        with (
            patch.object(self.app, "open_device", return_value=conn),
            patch.object(self.app, "prime_parameter_session", return_value=(bytes(14), bytes(2))),
            patch.object(self.app, "recording_session_id", return_value="session-a"),
            patch.object(self.app, "hid_get_parameter", return_value=bytes(7)),
            patch.object(self.app, "read_record_count_from_fd", return_value=(0x54, 64000, 7)),
            patch.object(self.app, "hid_set_parameter_official") as write,
            patch.object(self.app, "hid_format_command") as erase,
        ):
            with self.assertRaises(RuntimeError):
                self.app.apply_device_config("test", interval_minutes=5,
                    sync_clock=True, button_stop=True, software_stop=True)
            write.assert_not_called()
            erase.assert_not_called()
            conn.close.assert_called_once()

    def test_different_session_invalidates_confirmation_before_any_write(self):
        conn = Mock()
        with (
            patch.object(self.app, "open_device", return_value=conn),
            patch.object(self.app, "prime_parameter_session", return_value=(bytes(14), bytes(2))),
            patch.object(self.app, "recording_session_id", return_value="session-a"),
            patch.object(self.app, "hid_get_parameter", return_value=bytes(7)),
            patch.object(self.app, "read_record_count_from_fd", return_value=(0x54, 64000, 8)),
            patch.object(self.app, "hid_set_parameter_official") as write,
        ):
            with self.assertRaises(RuntimeError):
                self.app.apply_device_config("test", interval_minutes=5,
                    sync_clock=True, button_stop=True, software_stop=True,
                    allow_data_loss=True, expected_record_count=7, expected_session_id="session-b")
            write.assert_not_called()


    def test_growing_count_in_same_session_is_allowed(self):
        self.app.validate_configuration_confirmation(1831, 1828, "session-a", "session-a", True)

    def test_reset_changed_or_unconfirmed_session_is_rejected(self):
        cases = [(10, 1828, "a", "a", True), (1831, 1828, "b", "a", True),
                 (1831, 1828, "a", None, True), (1831, 1828, "a", "a", False),
                 (1831, None, "a", "a", True)]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                self.app.validate_configuration_confirmation(*args)

    def test_session_identity_tracks_trip_and_configuration_not_record_count(self):
        identity = bytes.fromhex("0044") + b"TEST12345678"
        trip = bytes(range(32))
        config_time = bytes([26, 11, 2, 3, 13, 44, 44])
        with patch.object(self.app, "hid_get_parameter", return_value=trip):
            first = self.app.recording_session_id(None, identity, config_time)
            self.assertEqual(first, self.app.recording_session_id(None, identity, config_time))
            self.assertNotEqual(first, self.app.recording_session_id(None, identity, bytes(7)))
        with patch.object(self.app, "hid_get_parameter", return_value=bytes(32)):
            self.assertNotEqual(first, self.app.recording_session_id(None, identity, config_time))


if __name__ == "__main__":
    unittest.main()
