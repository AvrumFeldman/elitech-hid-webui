from datetime import datetime
import unittest

from elitech_rc4 import RC4ProSession, RC4ProDecoder, parse_compact_report, convert_alarm_units


def session(unit="C", probe="internal"):
    return RC4ProSession("TEST12345678", datetime(2026, 11, 3, 13, 47, 59),
                         10, unit, probe, 35, 64000)


class CompactRecordTests(unittest.TestCase):
    def test_real_hardware_record_and_fahrenheit_normalization(self):
        record = RC4ProDecoder(session("F")).decode(bytes.fromhex("03140000"))
        self.assertEqual(record.temperature_c, 26)
        self.assertEqual(record.as_dict()["raw_hex"], "03 14 00 00")
        self.assertEqual(record.as_dict()["timestamp"], "2026-11-03 13:47:59")

    def test_negative_uses_bit_12_not_bit_15(self):
        record = RC4ProDecoder(session()).decode(bytes.fromhex("10bc0000"))
        self.assertEqual(record.temperature_c, -18.8)

    def test_pause_changes_following_timestamp_across_packets(self):
        decoder = RC4ProDecoder(session())
        decoder.decode(bytes.fromhex("00fe0000"))
        pause = decoder.decode(bytes.fromhex("00032000"))
        following = decoder.decode(bytes.fromhex("00ff0000"))
        self.assertEqual(pause.pause_intervals, 3)
        self.assertEqual(pause.status, "Paused")
        self.assertIsNone(pause.temperature_c)
        self.assertEqual(following.timestamp, datetime(2026, 11, 3, 13, 48, 39))

    def test_stop_and_sensor_error_do_not_become_measurements(self):
        decoder = RC4ProDecoder(session(probe="external"))
        stop = decoder.decode(bytes.fromhex("20fe0000"))
        error = decoder.decode(bytes.fromhex("53e80000"))
        self.assertEqual(stop.status, "Stopped")
        self.assertEqual(error.status, "Sensor error")
        self.assertEqual(error.probe, "external")
        self.assertIsNone(error.temperature_c)

    def test_response_checksum_offset_and_payload_length(self):
        # Captured model 0x44/protocol 0x54 packet, with six compact records.
        frame = bytes.fromhex("33cc002401000000000006031400000314000003160000031600000318000003180000c0")
        report = frame + bytes(64 - len(frame))
        records = parse_compact_report(report, 0, 6)
        self.assertEqual(len(records), 6)
        self.assertEqual(records[0], bytes.fromhex("03140000"))
        with self.assertRaises(ValueError):
            parse_compact_report(report, 6, 6)
        with self.assertRaises(ValueError):
            parse_compact_report(report, 0, 12)
        with self.assertRaises(ValueError):
            parse_compact_report(report[:20] + b"\xFF" + report[21:], 0, 6)

    def test_unused_record_cannot_become_a_fake_measurement(self):
        with self.assertRaises(ValueError):
            RC4ProDecoder(session()).decode(b"\xff" * 4)

    def test_unit_change_keeps_alarm_limits_and_calibration(self):
        block = bytearray(48)
        block[0x1E:0x20] = bytes.fromhex("000a")  # calibration +1 degree C
        block[0x20:0x2A] = bytes.fromhex("0fa00fa00258812c8fa0")
        convert_alarm_units(block, "C", "F")
        self.assertEqual(block[0x1E:0x20], bytes.fromhex("0012"))  # +1.8 F difference
        self.assertEqual(block[0x24:0x26], bytes.fromhex("0578"))  # 140 F
        self.assertEqual(block[0x26:0x28], bytes.fromhex("80dc"))  # -22 F
        self.assertEqual(block[0x20:0x24], bytes.fromhex("0fa00fa0"))
        self.assertEqual(block[0x28:0x2A], bytes.fromhex("8fa0"))


if __name__ == "__main__":
    unittest.main()
