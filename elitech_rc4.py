"""RC-4 Pro compact HID records and session metadata.

Protocol facts checked against ElitechLog Win 8.0.5.0 DataFactory's
ParseRecord4RC4Pro, USBParameters.IsRC4Pro and real model 0x0044 / protocol
0x54 responses. This module is our own implementation; it needs no vendor
runtime, USB drive, generated report, or non-standard Python dependency.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class RC4ProSession:
    serial: str
    started_at: datetime
    interval_seconds: int
    temperature_unit: str
    probe: str
    record_count: int
    capacity: int

    def __post_init__(self):
        if self.temperature_unit not in ("C", "F"):
            raise ValueError("Unknown logger temperature unit.")
        if self.probe not in ("internal", "external"):
            raise ValueError("Unknown temperature probe.")
        if not 10 <= self.interval_seconds <= 86400 or self.interval_seconds % 10:
            raise ValueError("Invalid logger sampling interval.")
        if not 0 <= self.record_count <= self.capacity <= 64000:
            raise ValueError("Invalid RC-4 Pro record count/capacity.")


@dataclass(frozen=True)
class RC4ProRecord:
    index: int
    timestamp: datetime
    temperature_c: float | None
    probe: str
    status: str
    flags: tuple[str, ...]
    pause_intervals: int
    raw: bytes

    def as_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            # All API temperatures are Celsius. Only the presentation converts.
            "temperature": self.temperature_c,
            "humidity": None,
            "probe": self.probe,
            "status": self.status,
            "flags": list(self.flags),
            "pause_intervals": self.pause_intervals,
            "raw_hex": self.raw.hex(" "),
            "flags_raw": self.raw[0],
        }


class RC4ProDecoder:
    """Stateful across packets because pause records advance the clock."""

    def __init__(self, session):
        self.session = session
        self.next_time = session.started_at
        self.next_index = 1

    def decode(self, raw):
        if len(raw) != 4 or raw == b"\xff" * 4:
            raise ValueError("Missing or invalid RC-4 Pro compact record.")
        magnitude = ((raw[0] & 0x0F) << 8) | raw[1]
        secondary = ((raw[2] & 0x0F) << 8) | raw[3]
        value = magnitude / 10
        if raw[0] & 0x10:
            value = -value
        paused = bool(raw[2] & 0x20)
        stopped = bool(raw[0] & 0x20)
        # Vendor error sentinels are qualified by the sensor error flag.
        sensor_error = bool(raw[0] & 0x40) and value in (-100, -409.5, -101, -111)
        flags = []
        pause_intervals = (secondary << 12) | magnitude if paused else 0
        if sensor_error:
            flags.append("Sensor error")
        if stopped:
            flags.append("Stopped")
        if paused:
            flags.append(f"Paused for {pause_intervals} sampling intervals")
        status = "Paused" if paused else "Stopped" if stopped else "Sensor error" if sensor_error else "Measurement"
        temperature_c = None
        if status == "Measurement":
            temperature_c = (value - 32) * 5 / 9 if self.session.temperature_unit == "F" else value
        record = RC4ProRecord(self.next_index, self.next_time, temperature_c,
                             self.session.probe, status, tuple(flags), pause_intervals, raw)
        self.next_time += timedelta(seconds=self.session.interval_seconds * (pause_intervals if paused else 1))
        self.next_index += 1
        return record


def parse_compact_report(report, expected_offset, requested_count):
    """Validate a GetRecord reply before exposing its four-byte records.

    A separate, valid ACK has no payload and returns None. Corrupt replies,
    wrong offsets and truncated payloads are errors, not apparent successes.
    """
    if len(report) != 64 or report[:3] != b"\x33\xcc\x00" or report[4:6] != b"\x01\x00":
        raise ValueError("Invalid RC-4 Pro record response header.")
    frame_length = report[3]
    if not 12 <= frame_length <= 64:
        raise ValueError("Invalid RC-4 Pro response length.")
    if report[frame_length - 1] != sum(report[:frame_length - 1]) & 0xFF:
        raise ValueError("Invalid RC-4 Pro response checksum.")
    offset = (report[9] << 16) | (report[7] << 8) | report[8]
    if offset != expected_offset:
        raise ValueError("The logger returned a different record offset.")
    count = report[10]
    if frame_length == 12 and count == 0:
        return None
    if count != requested_count or frame_length != 12 + count * 4:
        raise ValueError("Incomplete RC-4 Pro compact record response.")
    return [report[11 + i * 4:15 + i * 4] for i in range(count)]


def decode_parameter_temperature(raw):
    value = int.from_bytes(raw, "big")
    return -(value & 0x7FFF) / 10 if value & 0x8000 else value / 10


def encode_parameter_temperature(value):
    magnitude = round(abs(value) * 10)
    if magnitude > 0x7FFF:
        raise ValueError("Temperature parameter is out of range.")
    return (magnitude | (0x8000 if value < 0 else 0)).to_bytes(2, "big")


def convert_alarm_units(block, old_unit, new_unit):
    """Keep physical alarm limits and calibration when changing logger units.

    block covers parameter 0x30..0x5f. +/-400 means unused alarm and must not
    be converted. Calibration is a difference, so it never receives +32.
    """
    if old_unit == new_unit:
        return
    for address in (0x4E, 0x50, 0x52, 0x54, 0x56, 0x58):
        position = address - 0x30
        value = decode_parameter_temperature(block[position:position + 2])
        if address != 0x4E and abs(value) == 400:
            continue
        if address == 0x4E:
            value = value * 9 / 5 if new_unit == "F" else value * 5 / 9
        else:
            value = value * 9 / 5 + 32 if new_unit == "F" else (value - 32) * 5 / 9
        block[position:position + 2] = encode_parameter_temperature(value)
