#!/usr/bin/env python3

import json
import hashlib
import hmac
import logging
import math
import os
import argparse
import sys
import secrets
import socket
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser

from elitech_history import HistoryStore
from elitech_settings import load_settings, open_history, configured_path
from elitech_sync import SensorSync
from elitech_hid import open_device, windows_devices, load_hidapi
from elitech_rc4 import RC4ProSession, RC4ProDecoder, parse_compact_report, convert_alarm_units, decode_parameter_temperature, encode_parameter_temperature

from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen


APP_VERSION = "v27-time-range"

HOST = "127.0.0.1"
PORT = 8765

ELITECH_VENDOR_ID = "246C"
ELITECH_PRODUCT_ID = "9001"

HISTORY = None
SYNC_MANAGER = None


def get_history():
    global HISTORY
    if HISTORY is None:
        HISTORY = open_history(load_settings())
    return HISTORY

HID_LOCK = threading.Lock()
APP_TOKEN = secrets.token_urlsafe(32)

DEBUG_LOG_PATH = Path.cwd() / "elitech-debug.log"

LOGGER = logging.getLogger("elitech_rc5")
LOGGER.setLevel(logging.DEBUG)

if not LOGGER.handlers:
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    LOGGER.addHandler(console_handler)


def frame_hex(data: bytes, frame_length=None) -> str:
    if frame_length is None:
        frame_length = len(data)

    frame_length = max(
        0,
        min(int(frame_length), len(data)),
    )

    return data[:frame_length].hex(" ")


# ============================================================
# Linux HID eszközkeresés
# ============================================================

def parse_uevent(path: Path) -> dict:
    data = {}

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    data[key] = value
    except OSError:
        pass

    return data


def parse_hid_id(hid_id: str):
    parts = hid_id.split(":")
    if len(parts) != 3:
        return None, None

    vendor_id = parts[1][-4:].upper()
    product_id = parts[2][-4:].upper()
    return vendor_id, product_id


def scan_devices():
    if sys.platform == "win32":
        return windows_devices(ELITECH_VENDOR_ID, ELITECH_PRODUCT_ID)

    devices = []
    root = Path("/sys/class/hidraw")

    if not root.exists():
        return devices

    for item in sorted(root.glob("hidraw*")):
        info = parse_uevent(item / "device" / "uevent")
        vendor_id, product_id = parse_hid_id(info.get("HID_ID", ""))

        if not vendor_id or not product_id:
            continue

        if vendor_id != ELITECH_VENDOR_ID or product_id != ELITECH_PRODUCT_ID:
            continue

        device_path = f"/dev/{item.name}"
        name = info.get("HID_NAME", "") or "Elitech RC-5"

        devices.append(
            {
                "path": device_path,
                "vendor_id": vendor_id,
                "product_id": product_id,
                "name": name,
                "serial": info.get("HID_UNIQ", ""),
                "physical_path": info.get("HID_PHYS", ""),
                "display_name": name,
                "can_readwrite": os.access(device_path, os.R_OK | os.W_OK),
            }
        )

    return devices


def find_device(device_path: str):
    for device in scan_devices():
        if device["path"] == device_path:
            return device
    return None


# ============================================================
# Elitech HID protokoll
# ============================================================

def build_get_parameter_frame(offset: int, length: int) -> bytes:
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid parameter address.")

    if not 1 <= length <= 52:
        raise ValueError("Invalid request length.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        0x03,  # GetParameter
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        length & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)
    return packet + bytes(64 - len(packet))


def drain_hid(fd):
    while True:
        try:
            data = fd.read(64)
            if not data:
                return
        except BlockingIOError:
            return


def parse_response(response: bytes, operation=0x03):
    if len(response) < 12:
        raise ValueError("HID response is too short.")

    if response[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError("Invalid Elitech response header.")

    if response[4] != operation:
        raise ValueError(
            f"Unexpected Elitech operation code: 0x{response[4]:02X}"
        )

    frame_length = response[3]

    if frame_length < 12:
        raise ValueError("Invalid response size.")

    if frame_length > len(response):
        raise ValueError("Incomplete HID response.")

    frame = response[:frame_length]

    expected_checksum = sum(frame[:-1]) & 0xFF
    actual_checksum = frame[-1]

    if actual_checksum != expected_checksum:
        raise ValueError(
            f"Invalid response checksum: "
            f"0x{actual_checksum:02X} != 0x{expected_checksum:02X}"
        )

    offset = (frame[9] << 16) | (frame[7] << 8) | frame[8]
    data_length = frame[10]

    if 11 + data_length > frame_length - 1:
        raise ValueError("Truncated Elitech payload.")

    data = frame[11 : 11 + data_length]
    return offset, data


def hid_get_parameter(
    fd,
    offset: int,
    length: int,
    timeout: float = 1.0,
    operation: int = 0x03,
) -> bytes:
    drain_hid(fd)

    packet = (build_get_parameter_frame(offset, length) if operation == 0x03
              else build_official_read_frame(operation, offset, length))

    LOGGER.debug(
        "HID GET TX | offset=0x%06X | len=%d | frame=%s",
        offset,
        length,
        frame_hex(packet, 12),
    )

    written = fd.write(packet)

    if written != len(packet):
        raise OSError("Could not send the complete HID report.")

    readable = fd.wait_readable(timeout)

    if not readable:
        LOGGER.error(
            "HID GET TIMEOUT | offset=0x%06X | len=%d",
            offset,
            length,
        )
        raise TimeoutError(
            f"The logger did not answer the request at 0x{offset:02X}."
        )

    response = fd.read(64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.debug(
        "HID GET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    response_offset, data = parse_response(response, operation)

    requested_start = offset
    requested_end = offset + length
    response_start = response_offset
    response_end = response_offset + len(data)

    if requested_start < response_start or requested_end > response_end:
        raise ValueError(
            "The logger returned a different parameter range."
        )

    start = requested_start - response_start
    result = data[start : start + length]

    LOGGER.debug(
        "HID GET DATA | requested=0x%06X..0x%06X | "
        "response_offset=0x%06X | data=%s",
        requested_start,
        requested_end - 1,
        response_offset,
        result.hex(" "),
    )

    return result


def prime_parameter_session(
    fd,
    context: str,
    timeout: float = 1.0,
):
    """
    Visszaállítja / inicializálja az RC-5 normál 0x03 paraméterolvasási
    munkamenetét.

    A 246c:9001 / protocol 0x35 eszközön a GetRecord letöltési flow
    után megfigyeltük, hogy a rövid GetParameter olvasások egy része
    átmenetileg kizárólag 0xFF sentinel adatot ad vissza.

    Az "Device information" tab ezt következetesen helyreállítja,
    mert az első két lekérdezése:
        0x000000 / 14 byte  -- identity
        0x000094 / 2 byte   -- protocol

    A v21 ugyanezt explicit session-prime-ként használja, így a
    konfiguráció, rekordolvasás és mentés nem függ attól, melyik
    UI tabot nyitotta meg előtte a felhasználó.

    Ez kizárólag READ művelet.
    """
    identity = hid_get_parameter(
        fd,
        0x00,
        14,
        timeout=timeout,
    )

    protocol_data = hid_get_parameter(
        fd,
        0x94,
        2,
        timeout=timeout,
    )

    model = int.from_bytes(
        identity[0:2],
        byteorder="big",
    )

    serial = (
        identity[2:14]
        .decode("ascii", errors="replace")
        .replace("\x00", "")
        .strip()
    )

    protocol_version = (
        protocol_data[1]
        if len(protocol_data) >= 2
        else None
    )

    LOGGER.info(
        "PARAMETER SESSION PRIME | context=%s | model=0x%04X | "
        "serial=%s | protocol=%s",
        context,
        model,
        serial or "-",
        (
            f"0x{protocol_version:02X}"
            if protocol_version is not None
            else "-"
        ),
    )

    return identity, protocol_data


# ============================================================
# Adatdekódolás
# ============================================================

def decode_datetime(data: bytes) -> str:
    """
    Elitech 7-byte dátum/idő mező.

    Az új 246c:9001 RC-5 leállított állapotban több runtime mezőt
    0xFF sentinel értékekkel tölt ki. Ezeket nem szabad valódi
    dátumként megjeleníteni.

    A 3. byte .NET DayOfWeek; azt a dátum összeállításánál nem
    használjuk, így önmagában 0xFF lehet anélkül, hogy a dátum hibás lenne.
    """
    if len(data) != 7:
        return "-"

    if all(byte == 0 for byte in data):
        return "-"

    if all(byte == 0xFF for byte in data):
        return "-"

    # A tényleges datetime mezők: YY, MM, DD, hh, mm, ss.
    relevant = (
        data[0],
        data[1],
        data[3],
        data[4],
        data[5],
        data[6],
    )

    if any(byte == 0xFF for byte in relevant):
        return "-"

    try:
        dt = datetime(
            year=2000 + data[0],
            month=data[1],
            day=data[3],
            hour=data[4],
            minute=data[5],
            second=data[6],
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "-"


def decode_capacity_record_count(
    capacity_data: bytes,
    protocol_version: int,
) -> tuple[int | None, int | None]:
    """
    A 0x42 blokk kapacitás/rekordszám értelmezése.

    A normál 246c:9001 állapotban:
        00 00 7d 00 00 00 00 1b 00 00
        -> capacity 32000, records 27

    Stopped után ugyanez megfigyelten:
        ff ff 7d 00 00 00 00 1b ff ff

    A felső FF FF ebben az állapotban sentinel/állapotkitöltés,
    nem a kapacitás része. Ezért az új hardvernél az FF FF xxxx
    mintát a megmaradó alsó 16 bitből normalizáljuk.

    Ha a szükséges mező teljesen FF, nem gyártunk belőle
    4 294 967 295-ös "adatot": None lesz, és a szigorú olvasó
    újrapróbálja / biztonságosan leáll.
    """
    if len(capacity_data) != 10:
        raise ValueError(
            f"Invalid capacity block length: {len(capacity_data)}."
        )

    capacity_bytes = capacity_data[0:4]

    if capacity_bytes == b"\xFF\xFF\xFF\xFF":
        capacity = None
    elif (
        capacity_bytes[0:2] == b"\xFF\xFF"
        and capacity_bytes[2:4] != b"\xFF\xFF"
    ):
        capacity = int.from_bytes(
            capacity_bytes[2:4],
            byteorder="big",
        )

        LOGGER.debug(
            "CAPACITY STOP-STATE NORMALIZE | raw=%s | normalized=%d",
            capacity_bytes.hex(" "),
            capacity,
        )
    else:
        capacity = int.from_bytes(
            capacity_bytes,
            byteorder="big",
        )

    if protocol_version >= 0x24:
        record_bytes = capacity_data[4:8]
    else:
        record_bytes = capacity_data[6:8]

    if all(byte == 0xFF for byte in record_bytes):
        record_count = None
    else:
        record_count = int.from_bytes(
            record_bytes,
            byteorder="big",
        )

    # Lehetetlen kombinációt ne mutassunk felhasználói adatként.
    if (
        capacity is not None
        and record_count is not None
        and record_count > capacity
    ):
        LOGGER.warning(
            "CAPACITY/COUNT INCONSISTENT | raw=%s | "
            "capacity=%s | record_count=%s",
            capacity_data.hex(" "),
            capacity,
            record_count,
        )
        return None, None

    return capacity, record_count


def decode_interval_seconds(data: bytes) -> int | None:
    """
    2-byte mintavételi intervallum; 10 secondses egység.

    FF FF runtime sentinelként nem valódi 10922,5 minutes.
    """
    if len(data) != 2:
        return None

    if data == b"\xFF\xFF":
        return None

    raw = int.from_bytes(
        data,
        byteorder="big",
    )

    if raw == 0:
        return None

    return raw * 10


def format_optional_count(
    value: int | None,
    suffix: str = "",
) -> str:
    if value is None:
        return "-"

    formatted = f"{value:,}".replace(",", " ")

    return formatted + suffix


def decode_start_mode(byte: int) -> str:
    value = byte & 0b111
    modes = {
        0b000: "Azonnali",
        0b001: "Manual",
        0b010: "Scheduled",
        0b111: "Ismeretlen / MAX",
    }
    return modes.get(value, f"Ismeretlen (0b{value:03b})")


def decode_stop_mode(byte: int) -> str:
    value = byte & 0b111
    modes = {
        0b000: "Manual",
        0b011: "Temporarily stopped",
        0b111: "No valid stop / MAX",
    }
    return modes.get(value, f"Ismeretlen (0b{value:03b})")


def format_interval(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600} hours"

    if seconds % 60 == 0:
        return f"{seconds // 60} minutes"

    return f"{seconds} seconds"


# ============================================================
# Device information
# ============================================================

def read_device_info(device_path: str):
    with HID_LOCK:
        fd = open_device(device_path)

        try:
            identity = hid_get_parameter(fd, 0x00, 14)
            model = int.from_bytes(identity[:2], "big")
            trip_data = hid_get_parameter(fd, 0x00, 32, operation=0x05) if model == 0x0044 else None
            protocol_data = hid_get_parameter(fd, 0x94, 2)
            start_mode_data = hid_get_parameter(fd, 0x20, 1)
            unit_probe_data = hid_get_parameter(fd, 0x21, 1)
            device_state_data = hid_get_parameter(fd, 0x25, 1)
            stop_battery_data = hid_get_parameter(fd, 0x26, 2)
            configuration_time_data = hid_get_parameter(fd, 0x28, 7)
            start_stop_data = hid_get_parameter(fd, 0x30, 15)
            capacity_data = hid_get_parameter(fd, 0x42, 10)
            interval_data = hid_get_parameter(fd, 0x4C, 2)
            device_time_data = hid_get_parameter(fd, 0x88, 7)
        finally:
            fd.close()

    model = int.from_bytes(identity[0:2], byteorder="big")

    serial_number = (
        identity[2:14]
        .decode("ascii", errors="replace")
        .replace("\x00", "")
        .strip()
    )

    protocol_version = protocol_data[1]

    capacity, record_count = decode_capacity_record_count(
        capacity_data,
        protocol_version,
    )

    interval_seconds = decode_interval_seconds(
        interval_data
    )

    start_mode_byte = start_mode_data[0]
    device_state = device_state_data[0]
    actual_stop_byte = stop_battery_data[0]

    battery_byte = stop_battery_data[1]

    battery_raw = (
        None
        if battery_byte == 0xFF
        else battery_byte & 0x0F
    )

    configuration_time = decode_datetime(configuration_time_data)
    start_time = decode_datetime(trip_data[8:15]) if trip_data is not None else decode_datetime(start_stop_data[0:7])
    stop_time = "-" if trip_data is not None else decode_datetime(start_stop_data[8:15])
    device_time = decode_datetime(device_time_data)

    fields = [
        {"label": "Serial number", "value": serial_number or "No data"},
        {"label": "Model", "value": "RC-4 Pro" if model == 0x0044 else f"0x{model:04X}"},
        {"label": "Temperature probe", "value": "External" if unit_probe_data[0] & 0x02 else "Internal"},
        {"label": "Logger temperature unit", "value": "°F" if unit_probe_data[0] & 0x08 else "°C"},
        {"label": "Protocol version", "value": f"0x{protocol_version:02X}"},
        {
            "label": "Logger capacity",
            "value": format_optional_count(
                capacity,
                " measurements",
            ),
        },
        {
            "label": "Stored measurements",
            "value": format_optional_count(
                record_count,
            ),
        },
        {"label": "Recording started", "value": start_time},
        {"label": "Recording stopped", "value": stop_time},
        {"label": "Configuration saved", "value": configuration_time},
        {"label": "Logger time", "value": device_time},
        {
            "label": "Logging interval",
            "value": (
                "-"
                if interval_seconds is None
                else (
                    f"{format_interval(interval_seconds)} "
                    f"({interval_seconds} s)"
                )
            ),
        },
        {"label": "Start mode", "value": decode_start_mode(start_mode_byte)},
        {
            "label": "Button stop",
            "value": "Enabled"
            if start_mode_byte & (1 << 3)
            else "Disabled",
        },
        {
            "label": "Software stop",
            "value": "Enabled"
            if start_mode_byte & (1 << 4)
            else "Disabled",
        },
        {
            "label": "Device state",
            "value": f"0x{device_state:02X} (raw value)",
        },
        {
            "label": "Actual stop mode",
            "value": decode_stop_mode(actual_stop_byte),
        },
        {
            "label": "Battery level",
            "value": (
                "-"
                if battery_raw is None
                else f"{battery_raw} / 15 (raw value)"
            ),
        },
    ]

    return {
        "path": device_path,
        "serial_number": serial_number,
        "capacity": capacity,
        "record_count": record_count,
        "fields": fields,
    }



# ============================================================
# Konfiguráció írás / olvasás
# ============================================================

def build_set_parameter_frame(offset: int, data: bytes) -> bytes:
    """
    Elitech SetParameter (0x0004) HID frame.
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid parameter address.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Configuration data must be bytes.")

    if not 1 <= len(data) <= 52:
        raise ValueError("Invalid configuration data length.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x00,  # frame length, alább kitöltjük
        0x04,  # SetParameter
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        len(data) & 0xFF,
    ]

    frame.extend(data)
    frame[3] = len(frame) + 1
    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)

    if len(packet) > 64:
        raise ValueError("HID report is too large.")

    return packet + bytes(64 - len(packet))


def parse_set_response(response: bytes, requested_offset: int):
    """
    SetParameter válasz ellenőrzése.
    Az ismert Elitech protokollban a válasz egyetlen státuszbájtot
    tartalmaz; 1 = siker.
    """
    if len(response) < 13:
        raise ValueError("SetParameter response is too short.")

    if response[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError("Invalid Elitech response header.")

    if response[4] != 0x04:
        raise ValueError(
            f"Unexpected Elitech operation code: 0x{response[4]:02X}"
        )

    frame_length = response[3]

    if frame_length < 13 or frame_length > len(response):
        raise ValueError("Invalid SetParameter response size.")

    frame = response[:frame_length]

    expected_checksum = sum(frame[:-1]) & 0xFF
    actual_checksum = frame[-1]

    if actual_checksum != expected_checksum:
        raise ValueError(
            f"Invalid SetParameter checksum: "
            f"0x{actual_checksum:02X} != 0x{expected_checksum:02X}"
        )

    response_offset = (
        (frame[9] << 16)
        | (frame[7] << 8)
        | frame[8]
    )

    if response_offset != requested_offset:
        raise ValueError(
            f"Response address differs from request: "
            f"0x{response_offset:06X} != 0x{requested_offset:06X}"
        )

    if frame[10] != 1:
        raise ValueError(
            f"Unexpected SetParameter status length: {frame[10]}"
        )

    if frame[11] != 1:
        raise RuntimeError(
            f"The logger rejected the settings "
            f"(status: 0x{frame[11]:02X})."
        )



def build_official_set_packet(
    offset: int,
    data: bytes,
    *,
    declared_length: int | None = None,
    frame_length: int | None = None,
) -> bytes:
    """
    ElitechLog Win V8.0.5.0 DataFactory.GetListForSet() packet layout.

    Normally:
        frame_length = 11 + len(data) + 1
        declared_length = len(data)

    One factory packet is intentionally odd:
        offset 0x60:
          declared length = 0x30 (48)
          actual payload bytes = 47 (0x60..0x8E)
          frame length = 0x3B (59)
          checksum at byte 58

    We reproduce that byte-for-byte instead of "fixing" it.
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid parameter address.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Configuration data must be bytes.")

    if declared_length is None:
        declared_length = len(data)

    if frame_length is None:
        frame_length = 11 + len(data) + 1

    if not 0 <= declared_length <= 0xFF:
        raise ValueError("Invalid declared payload length.")

    if frame_length != 11 + len(data) + 1:
        raise ValueError(
            "frame_length does not match the actual Elitech frame size."
        )

    frame = [
        0x33,
        0xCC,
        0x00,
        frame_length & 0xFF,
        0x04,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        declared_length & 0xFF,
    ]

    frame.extend(data)
    frame.append(sum(frame) & 0xFF)

    if len(frame) != frame_length:
        raise RuntimeError("Internal error: incorrect Elitech frame length.")

    if len(frame) > 64:
        raise ValueError("HID report is too large.")

    return bytes(frame) + bytes(64 - len(frame))


def hid_set_parameter_official(
    fd,
    offset: int,
    data: bytes,
    *,
    declared_length: int | None = None,
    frame_length: int | None = None,
    timeout: float = 1.0,
):
    """
    ElitechLog V8.0.5.0 által generált SetParameter frame elküldése.
    """
    drain_hid(fd)

    packet = build_official_set_packet(
        offset,
        data,
        declared_length=declared_length,
        frame_length=frame_length,
    )

    LOGGER.info(
        "FACTORY SET TX | offset=0x%06X | declared_len=%d | "
        "actual_data_len=%d | frame_len=%d | data=%s",
        offset,
        packet[10],
        len(data),
        packet[3],
        data.hex(" "),
    )

    LOGGER.debug(
        "FACTORY SET TX FRAME | offset=0x%06X | frame=%s",
        offset,
        frame_hex(packet, packet[3]),
    )

    written = fd.write(packet)

    if written != len(packet):
        raise OSError("Could not send the complete HID report.")

    readable = fd.wait_readable(timeout)

    if not readable:
        raise TimeoutError(
            f"The logger did not acknowledge settings at 0x{offset:02X}."
        )

    response = fd.read(64)

    response_len = response[3] if len(response) >= 4 else len(response)

    LOGGER.info(
        "FACTORY SET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    parse_set_response(response, offset)

    LOGGER.info(
        "FACTORY SET ACK OK | offset=0x%06X",
        offset,
    )


def encode_official_elitech_datetime(value: datetime) -> bytes:
    """
    ElitechLog V8.0.5.0 DataFactory.GetListForSet() formátuma.

    A 3. byte NEM reserved:
    a gyári program System.DateTime.DayOfWeek értékét írja ide
    (Sunday=0 ... Saturday=6).

    A korábbi saját kódunk itt 0-t írt, ami eltért a gyári programtól.
    """
    if value.year < 2000 or value.year > 2255:
        raise ValueError("The year cannot be represented in the logger date format.")

    # Python weekday(): Monday=0 ... Sunday=6
    # .NET DayOfWeek: Sunday=0 ... Saturday=6
    dotnet_day_of_week = (value.weekday() + 1) % 7

    return bytes(
        [
            value.year - 2000,
            value.month,
            dotnet_day_of_week,
            value.day,
            value.hour,
            value.minute,
            value.second,
        ]
    )


def hid_set_parameter(
    fd,
    offset: int,
    data: bytes,
    timeout: float = 1.0,
):
    drain_hid(fd)

    packet = build_set_parameter_frame(offset, data)

    LOGGER.info(
        "HID SET TX | offset=0x%06X | len=%d | data=%s",
        offset,
        len(data),
        data.hex(" "),
    )

    LOGGER.debug(
        "HID SET TX FRAME | offset=0x%06X | frame=%s",
        offset,
        frame_hex(packet, packet[3]),
    )

    written = fd.write(packet)

    if written != len(packet):
        raise OSError("Could not send the complete HID report.")

    readable = fd.wait_readable(timeout)

    if not readable:
        LOGGER.error(
            "HID SET TIMEOUT | offset=0x%06X | len=%d",
            offset,
            len(data),
        )
        raise TimeoutError(
            f"The logger did not acknowledge settings at 0x{offset:02X}."
        )

    response = fd.read(64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.info(
        "HID SET RX | offset=0x%06X | raw=%s",
        offset,
        frame_hex(response, response_len),
    )

    parse_set_response(response, offset)

    LOGGER.info(
        "HID SET ACK OK | offset=0x%06X",
        offset,
    )



def build_generic_command_frame(
    operation: int,
    offset: int = 0,
    data: bytes = b"\x00",
) -> bytes:
    """
    Generic Elitech command frame.

    The public python-elitech reverse engineering lists:
      0x02C0 = FormatCommand
      0x03C0 = StopCommand

    The operation is encoded little-endian in bytes 4..5.
    """
    if not 0 <= operation <= 0xFFFF:
        raise ValueError("Invalid Elitech operation code.")

    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid Elitech address.")

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Command data must be bytes.")

    if len(data) > 52:
        raise ValueError("Elitech command data is too long.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x00,
        operation & 0xFF,
        (operation >> 8) & 0xFF,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        len(data) & 0xFF,
    ]

    frame.extend(data)
    frame[3] = len(frame) + 1
    frame.append(sum(frame) & 0xFF)

    packet = bytes(frame)

    if len(packet) > 64:
        raise ValueError("HID report is too large.")

    return packet + bytes(64 - len(packet))


def hid_generic_command(
    fd,
    operation: int,
    *,
    offset: int = 0,
    data: bytes = b"\x00",
    timeout: float = 2.0,
) -> bytes:
    """
    Küld egy nem-SetParameter Elitech parancsot és a nyers választ adja vissza.
    """
    drain_hid(fd)

    packet = build_generic_command_frame(
        operation,
        offset,
        data,
    )

    LOGGER.warning(
        "HID GENERIC TX | op=0x%04X | offset=0x%06X | frame=%s",
        operation,
        offset,
        frame_hex(packet, packet[3]),
    )

    written = fd.write(packet)

    if written != len(packet):
        raise OSError(
            "Could not send the complete Elitech command."
        )

    readable = fd.wait_readable(timeout)

    if not readable:
        LOGGER.warning(
            "HID GENERIC NO RESPONSE | op=0x%04X",
            operation,
        )
        return b""

    response = fd.read(64)

    response_len = (
        response[3]
        if len(response) >= 4
        else len(response)
    )

    LOGGER.warning(
        "HID GENERIC RX | op=0x%04X | raw=%s",
        operation,
        frame_hex(response, response_len),
    )

    return response


def hid_format_command(fd) -> bytes:
    """Prepare a new session after the caller has checked data-loss consent."""
    response = hid_generic_command(fd, 0x02C0, offset=0, data=b"\x00", timeout=2.0)
    if not response:
        raise TimeoutError("The logger did not acknowledge preparation of the new session.")
    if (len(response) < 13 or response[:3] != b"\x33\xcc\x00"
            or response[3] != 13 or response[4:6] != b"\xc0\x02"
            or response[10] != 1 or response[11] != 1
            or response[12] != sum(response[:12]) & 0xFF):
        raise ValueError("The logger rejected preparation of the new recording session.")
    return response



def encode_device_datetime(value: datetime) -> bytes:
    if value.year < 2000 or value.year > 2255:
        raise ValueError("The year cannot be represented in the logger date format.")

    return bytes(
        [
            value.year - 2000,
            value.month,
            0x00,
            value.day,
            value.hour,
            value.minute,
            value.second,
        ]
    )


def read_record_count_from_fd(fd: int):
    """
    Biztonsági szempontból kritikus olvasás.

    A stopped RC-5 0xFF sentineljeit normalizáljuk. Ha három
    egymást követő olvasásból sem kapunk hihető capacity/count
    párost, inkább hibát adunk, mint hogy 0xFFFFFFFF-et valódi
    rekordszámként használjunk egy destruktív mentés előtt.
    """
    protocol_data = hid_get_parameter(
        fd,
        0x94,
        2,
    )

    protocol_version = protocol_data[1]

    last_raw = None

    for attempt in range(1, 4):
        capacity_data = hid_get_parameter(
            fd,
            0x42,
            10,
        )

        last_raw = capacity_data

        capacity, record_count = (
            decode_capacity_record_count(
                capacity_data,
                protocol_version,
            )
        )

        if (
            capacity is not None
            and record_count is not None
        ):
            if attempt > 1:
                LOGGER.info(
                    "RECORD COUNT RETRY RECOVERED | attempt=%d | "
                    "capacity=%d | records=%d",
                    attempt,
                    capacity,
                    record_count,
                )

            return (
                protocol_version,
                capacity,
                record_count,
            )

        LOGGER.warning(
            "RECORD COUNT INVALID/SENTINEL | attempt=%d/3 | raw=%s",
            attempt,
            capacity_data.hex(" "),
        )

        time.sleep(0.06)

    raise RuntimeError(
        "The logger capacity/record count currently "
        "cannot be read reliably "
        f"(last raw capacity block: "
        f"{last_raw.hex(' ') if last_raw else '-'}). "
        "Saving settings is unavailable until the count can be read."
    )



# ============================================================
# Measurementi rekordok kiolvasása
# ============================================================

RECORD_LENGTH = 8
RECORDS_PER_PACKET = 6
RECORD_RESPONSE_DATA_OFFSET = 11

RECORD_FLAG_MARK = 0x01
RECORD_FLAG_PAUSE = 0x02
RECORD_FLAG_STOP = 0x04
RECORD_FLAG_SIGN1 = 0x08
RECORD_FLAG_LIGHT = 0x10
RECORD_FLAG_VIBRATION = 0x20
RECORD_FLAG_SIGN2 = 0x40
RECORD_FLAG_ERROR = 0x80


# ElitechLog Win V8.0.5.0 DataFactory.GetListForParameter()
# pontos, statikusan visszafejtett 17 darabos kapcsolódási/read preamble.
#
# A gyári program nem csak a régi 0x0003 GetParameter műveletet használja,
# hanem több 0x0005 read packetet is elküld minden első csatlakozáskor.
# Ezek olvasási műveletek; a v16 a rekordletöltés előtt reprodukálja őket.
OFFICIAL_PARAMETER_PREAMBLE = (
    (0x03, 0x000000, 0x30),
    (0x03, 0x000030, 0x30),
    (0x03, 0x000060, 0x30),
    (0x03, 0x000090, 0x08),
    (0x03, 0x000098, 0x34),
    (0x03, 0x0000CC, 0x30),

    (0x05, 0x000000, 0x20),
    (0x05, 0x000070, 0x10),
    (0x05, 0x000080, 0x30),
    (0x05, 0x0000B0, 0x30),
    (0x05, 0x0000E0, 0x30),
    (0x05, 0x000110, 0x30),
    (0x05, 0x000140, 0x30),
    (0x05, 0x000020, 0x30),
    (0x05, 0x000050, 0x20),

    (0x03, 0x00012C, 0x30),
    (0x03, 0x0000FD, 0x30),
)


def build_official_read_frame(
    operation: int,
    offset: int,
    length: int,
) -> bytes:
    """
    ElitechLog GetListForParameter()-kompatibilis 12-byte request,
    64 byte-ra nullával feltöltve.

    operation jelenleg 0x03 vagy 0x05.
    """
    if operation not in (0x03, 0x05):
        raise ValueError("Unsupported read operation.")

    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid read offset.")

    if not 1 <= length <= 0xFF:
        raise ValueError("Invalid read length.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        operation,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        length & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    return bytes(frame) + bytes(64 - len(frame))


def run_official_parameter_preamble(
    fd,
    timeout: float = 1.0,
) -> None:
    """
    A gyári ElitechLog első kapcsolódáskor végrehajtott 17 read packetes
    paraméterpreambluma.

    Fontos:
      - nincs write/config módosítás;
      - minden packet után megvárjuk a választ;
      - a gyári kód 80 ms szünetet tart a packetek között, ezt megtartjuk.
    """
    LOGGER.info(
        "FACTORY READ PREAMBLE START | packets=%d",
        len(OFFICIAL_PARAMETER_PREAMBLE),
    )

    # A korábbi API GET-ekből esetleg bent maradt reportokat egyszer,
    # dokumentáltan kiürítjük. Rekordpacketek között már NEM drainelünk.
    drained = 0

    while True:
        readable = fd.wait_readable(0)

        if not readable:
            break

        try:
            old = fd.read(64)
        except BlockingIOError:
            break

        if not old:
            break

        drained += 1

        LOGGER.debug(
            "FACTORY READ PREAMBLE DRAIN | raw=%s",
            old.hex(" "),
        )

    LOGGER.debug(
        "FACTORY READ PREAMBLE DRAINED | reports=%d",
        drained,
    )

    for index, (
        operation,
        offset,
        length,
    ) in enumerate(
        OFFICIAL_PARAMETER_PREAMBLE,
        start=1,
    ):
        packet = build_official_read_frame(
            operation,
            offset,
            length,
        )

        LOGGER.debug(
            "FACTORY READ TX | n=%d/%d | op=0x%02X | "
            "offset=0x%06X | len=%d | frame=%s",
            index,
            len(OFFICIAL_PARAMETER_PREAMBLE),
            operation,
            offset,
            length,
            frame_hex(packet, packet[3]),
        )

        written = fd.write(packet)

        if written != len(packet):
            raise OSError(
                "Could not send the connection initialization request."
            )

        readable = fd.wait_readable(timeout)

        if not readable:
            raise TimeoutError(
                "The logger did not answer connection initialization "
                f"request {index} "
                f"(op=0x{operation:02X}, offset=0x{offset:06X})."
            )

        response = fd.read(64)

        LOGGER.debug(
            "FACTORY READ RX | n=%d/%d | op=0x%02X | "
            "offset=0x%06X | raw=%s",
            index,
            len(OFFICIAL_PARAMETER_PREAMBLE),
            operation,
            offset,
            response.hex(" "),
        )

        # A gyári UsbCommand.GetParameter() Thread.Sleep(80)-at használ.
        time.sleep(0.08)

    LOGGER.info("FACTORY READ PREAMBLE COMPLETE")


def build_get_record_frame(
    offset: int,
    count: int = RECORDS_PER_PACKET,
) -> bytes:
    """
    ElitechLog Win V8.0.5.0 DataFactory.GetListForRecord() request.

    A gyári kliensnél:
      - offset = rekordsorszám (0, 6, 12, ...)
      - standard 8-byte rekordnál count = 6
      - operation = 0x0001
      - byte[5] = 0 a normál rekordtárhoz
    """
    if not 0 <= offset <= 0xFFFFFF:
        raise ValueError("Invalid record offset.")

    if not 1 <= count <= 0xFF:
        raise ValueError("Invalid record count.")

    frame = [
        0x33,
        0xCC,
        0x00,
        0x0C,
        0x01,
        0x00,
        0x00,
        (offset >> 8) & 0xFF,
        offset & 0xFF,
        (offset >> 16) & 0xFF,
        count & 0xFF,
    ]

    frame.append(sum(frame) & 0xFF)

    return bytes(frame) + bytes(64 - len(frame))


def is_record_ack_only(
    report: bytes,
) -> bool:
    """
    Az új 246c:9001 eszközön megfigyelt azonnali GetRecord ACK:

      33 cc 00 0c 01 00 00 00 00 00 00 0c 00 00 ...

    Ez nem measurementsi adat. A v15 tévesen rekordpacketként próbálta parse-olni.
    """
    if len(report) < 12:
        return False

    if report[0:5] != bytes(
        [0x33, 0xCC, 0x00, 0x0C, 0x01]
    ):
        return False

    checksum_ok = (
        report[11]
        == (sum(report[:11]) & 0xFF)
    )

    no_payload = all(
        value == 0
        for value in report[12:]
    )

    return checksum_ok and no_payload


def validate_record_report_header(
    report: bytes,
) -> None:
    if len(report) != 64:
        raise ValueError(
            f"A HID report nem 64 byte: {len(report)}."
        )

    if report[0:3] != bytes([0x33, 0xCC, 0x00]):
        raise ValueError(
            "Invalid GetRecord report header."
        )

    if report[4] != 0x01:
        raise ValueError(
            "A GetRecord report operation byte-ja nem 0x01."
        )


def parse_elitech_record(
    raw: bytes,
    protocol_version: int,
) -> dict | None:
    """
    Elitech 8-byte standard rekord dekódolás.

    Az új 246c:9001 / protocol 0x35 RC-5 hardveren a szabályos
    measurementsi rekordok byte0 értéke következetesen 0xC0.

    A régi flag-térkép ezt 0x80=Error + 0x40=Sign2 kombinációnak
    értelmezte, ezért a v16 minden normál rekordot tévesen
    "Error" állapotúnak mutatott.

    Protocol >= 0x35 esetén ezért a felső két bitet az új
    rekordformátum markerének kezeljük; az alsó 6 bit esemény/sign
    flagjeit továbbra is megtartjuk.

    Az RC-5 hőmérséklet-only modellnél a humidity bitek nem
    szenzoradatok, ezért páratartalmat nem jelenítünk meg.
    """
    if len(raw) != RECORD_LENGTH:
        raise ValueError(
            f"Invalid record length: {len(raw)}."
        )

    if raw == bytes([0xFF]) * RECORD_LENGTH:
        return None

    flags_raw = raw[0]

    if protocol_version >= 0x35:
        flags = flags_raw & 0x3F
        format_marker = flags_raw & 0xC0
    else:
        flags = flags_raw
        format_marker = 0

    second = (raw[1] >> 2) & 0x3F
    year = 2000 + (raw[2] & 0x7F)

    month = (
        ((raw[3] & 0x07) << 1)
        + ((raw[2] >> 7) & 0x01)
    )

    day = (raw[3] >> 3) & 0x1F
    hour = raw[4] & 0x1F
    minute = raw[6] & 0x3F

    if protocol_version >= 0x23:
        temperature_raw = (
            (((raw[1] >> 1) & 0x01) << 11)
            + (raw[5] << 3)
            + (raw[4] >> 5)
        )
    else:
        temperature_raw = (
            (raw[5] << 3)
            + (raw[4] >> 5)
        )

    temperature = temperature_raw / 10.0

    if flags & RECORD_FLAG_SIGN1:
        temperature = -temperature

    timestamp = datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
    )

    flag_labels = []

    if flags & RECORD_FLAG_MARK:
        flag_labels.append("Marked")

    if flags & RECORD_FLAG_LIGHT:
        flag_labels.append("Light")

    if flags & RECORD_FLAG_VIBRATION:
        flag_labels.append("Vibration")

    if flags & RECORD_FLAG_PAUSE:
        status = "Paused"
    elif flags & RECORD_FLAG_STOP:
        status = "Stopped"
    elif (
        protocol_version < 0x35
        and flags & RECORD_FLAG_ERROR
    ):
        status = "Error"
    else:
        status = "Measurement"

    temperature_value = (
        temperature
        if status == "Measurement"
        else None
    )

    humidity_value = None

    return {
        "timestamp": timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "temperature": temperature_value,
        "humidity": humidity_value,
        "status": status,
        "flags": flag_labels,
        "flags_raw": flags_raw,
        "flags_effective": flags,
        "record_format_marker": format_marker,
        "raw_hex": raw.hex(" "),
    }


def count_plausible_records(
    report: bytes,
    protocol_version: int,
) -> int:
    """
    Diagnosztikai klasszifikáció: hány 8-byte rekord parse-olható
    érvényes dátummal a report byte 11-től?
    """
    plausible = 0

    for local_index in range(RECORDS_PER_PACKET):
        start = (
            RECORD_RESPONSE_DATA_OFFSET
            + local_index * RECORD_LENGTH
        )
        end = start + RECORD_LENGTH

        raw = report[start:end]

        try:
            parsed = parse_elitech_record(
                raw,
                protocol_version,
            )
        except (
            ValueError,
            OverflowError,
        ):
            continue

        if parsed is not None:
            plausible += 1

    return plausible


def read_one_hid_report(
    fd,
    timeout: float,
) -> bytes | None:
    readable = fd.wait_readable(timeout)

    if not readable:
        return None

    response = fd.read(64)

    if not response:
        return None

    return response


def get_record_data_report(
    fd,
    offset: int,
    protocol_version: int,
    timeout: float = 1.5,
) -> bytes:
    """
    GetRecord kérés + az új hardveren megfigyelt ACK/data szétválasztás.

    A v15 minden rekordkérés elején drain_hid()-ot hívott. Ha az eszköz
    az azonnali ACK után néhány ms-mal küldi a tényleges adatreportot,
    a következő packet előtti drain ezt észrevétlenül eldobhatta.

    A v16 ezért:
      1. nem drainel packetek között;
      2. ACK után még vár ugyanazon kéréshez tartozó új reportot;
      3. minden beérkező 64 byte-ot teljesen naplóz.
    """
    packet = build_get_record_frame(
        offset,
        RECORDS_PER_PACKET,
    )

    LOGGER.debug(
        "HID RECORD GET TX | offset=%d | count=%d | frame=%s",
        offset,
        RECORDS_PER_PACKET,
        frame_hex(packet, packet[3]),
    )

    written = fd.write(packet)

    if written != len(packet):
        raise OSError(
            "Could not send the complete record request."
        )

    deadline = time.monotonic() + timeout
    report_number = 0
    saw_ack = False

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            break

        response = read_one_hid_report(
            fd,
            min(remaining, 0.35),
        )

        if response is None:
            if saw_ack:
                # ACK után rövid ideig nincs új report; folytatjuk a
                # teljes timeout végéig, nem küldünk közben új offsetet.
                continue
            continue

        report_number += 1

        LOGGER.debug(
            "HID RECORD RX STREAM | offset=%d | report_no=%d | "
            "len=%d | raw=%s",
            offset,
            report_number,
            len(response),
            response.hex(" "),
        )

        try:
            validate_record_report_header(response)
        except ValueError as error:
            LOGGER.warning(
                "HID RECORD NONSTANDARD REPORT | offset=%d | "
                "report_no=%d | error=%s",
                offset,
                report_number,
                error,
            )
            continue

        if is_record_ack_only(response):
            saw_ack = True

            LOGGER.info(
                "HID RECORD ACK ONLY | offset=%d | "
                "waiting for data report without draining",
                offset,
            )

            continue

        plausible = count_plausible_records(
            response,
            protocol_version,
        )

        LOGGER.debug(
            "HID RECORD DATA CANDIDATE | offset=%d | "
            "plausible_records=%d",
            offset,
            plausible,
        )

        if plausible > 0:
            return response

        LOGGER.warning(
            "HID RECORD REPORT WITHOUT PLAUSIBLE DATA | "
            "offset=%d | raw=%s",
            offset,
            response.hex(" "),
        )

    if saw_ack:
        raise TimeoutError(
            "The record request was acknowledged but no "
            "measurement data followed. The debug log includes the connection "
            "initialization and subsequent reports."
        )

    raise TimeoutError(
        "The logger did not answer the measurement request."
    )


def read_rc4_pro_records(fd, identity, record_count, capacity, limit):
    unit_probe = hid_get_parameter(fd, 0x21, 1)[0]
    interval = decode_interval_seconds(hid_get_parameter(fd, 0x4C, 2))
    trip = hid_get_parameter(fd, 0, 32, operation=0x05)
    start_text = decode_datetime(trip[8:15])
    if start_text == "-":
        raise ValueError("The RC-4 Pro did not provide a valid recording start time.")
    session = RC4ProSession(
        serial=identity[2:14].decode("ascii").strip("\x00 "),
        started_at=datetime.strptime(start_text, "%Y-%m-%d %H:%M:%S"),
        interval_seconds=interval,
        temperature_unit="F" if unit_probe & 0x08 else "C",
        probe="external" if unit_probe & 0x02 else "internal",
        record_count=record_count,
        capacity=capacity,
    )
    decoder = RC4ProDecoder(session)
    first_wanted = max(0, record_count - limit) if limit else 0
    records = []
    # Read preceding packets as well: pause records change the timestamp of
    # later measurements, so index * interval alone is not sufficient.
    for offset in range(0, record_count, 12):
        packet = build_get_record_frame(offset, 12)
        if fd.write(packet) != len(packet):
            raise OSError("Could not send the complete RC-4 Pro record request.")
        deadline = time.monotonic() + 2.0
        raw_records = None
        while time.monotonic() < deadline:
            if not fd.wait_readable(max(0, deadline - time.monotonic())):
                break
            response = fd.read(64)
            LOGGER.debug("RC4 COMPACT RX | offset=%d | raw=%s", offset, response.hex(" "))
            raw_records = parse_compact_report(response, offset, 12)
            if raw_records is not None:
                break
        if raw_records is None:
            raise TimeoutError("The RC-4 Pro did not return its compact measurement records.")
        for index, raw in enumerate(raw_records[:min(12, record_count - offset)]):
            record = decoder.decode(raw)
            if offset + index >= first_wanted:
                records.append(record.as_dict())
    return {
        "protocol_version": 0x54,
        "capacity": capacity,
        "stored_count": record_count,
        "loaded_count": len(records),
        "start_index": records[0]["index"] if records else None,
        "end_index": records[-1]["index"] if records else None,
        "records": records,
        "source": "hid",
        "record_format": "rc4-pro-compact-4-byte",
        "probe": session.probe,
        "started_at": session.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "logger_temperature_unit": session.temperature_unit,
        "interval_seconds": session.interval_seconds,
    }


def read_device_records(
    device_path: str,
    limit: int = 500,
):
    """
    Measurementi rekordok read-only kiolvasása.

    A v16 két, az ElitechLog V8.0.5.0-ból visszafejtett részt
    reprodukál:
      - teljes 17-packetes kapcsolódási paraméter-read preamble;
      - 6 rekord / GetRecord packet.

    Emellett kezeli az új 246c:9001 hardveren megfigyelt külön
    ACK-only reportot anélkül, hogy a késve érkező reportot drainelné.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValueError(
            "Record limit must be an integer."
        )

    if limit < 0 or limit > 64000:
        raise ValueError(
            "Record limit must be between 0 and 64000; 0 means all."
        )

    LOGGER.info(
        "RECORD READ REQUEST | version=%s | device=%s | limit=%d",
        APP_VERSION,
        device_path,
        limit,
    )

    with HID_LOCK:
        fd = open_device(device_path)

        try:
            identity, _ = prime_parameter_session(
                fd,
                context="record-read-precheck",
            )

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            if record_count > capacity:
                raise RuntimeError(
                    "The reported record count exceeds the logger capacity."
                )

            if record_count == 0:
                return {
                    "protocol_version": protocol_version,
                    "capacity": capacity,
                    "stored_count": 0,
                    "loaded_count": 0,
                    "start_index": None,
                    "end_index": None,
                    "records": [],
                }

            if int.from_bytes(identity[:2], "big") == 0x0044 and protocol_version == 0x54:
                data = read_rc4_pro_records(fd, identity, record_count, capacity, limit)
                return save_recording_history(fd, identity, data)

            if limit == 0:
                wanted_start = 0
            else:
                wanted_start = max(
                    0,
                    record_count - limit,
                )

            first_packet_offset = (
                wanted_start // RECORDS_PER_PACKET
            ) * RECORDS_PER_PACKET

            LOGGER.info(
                "RECORD READ PRECHECK | protocol=0x%02X | "
                "capacity=%d | stored=%d | wanted_start=%d | "
                "first_packet_offset=%d",
                protocol_version,
                capacity,
                record_count,
                wanted_start,
                first_packet_offset,
            )

            # A gyári ElitechLog kapcsolódási read sorozata.
            run_official_parameter_preamble(fd)

            parsed_records = []
            packet_offset = first_packet_offset

            while packet_offset < record_count:
                response = get_record_data_report(
                    fd,
                    packet_offset,
                    protocol_version,
                )

                valid_in_packet = min(
                    RECORDS_PER_PACKET,
                    record_count - packet_offset,
                )

                for local_index in range(valid_in_packet):
                    record_index = (
                        packet_offset + local_index
                    )

                    raw_start = (
                        RECORD_RESPONSE_DATA_OFFSET
                        + local_index * RECORD_LENGTH
                    )

                    raw_end = raw_start + RECORD_LENGTH

                    raw = response[raw_start:raw_end]

                    LOGGER.debug(
                        "RECORD RAW | index=%d | packet_offset=%d | "
                        "local=%d | raw=%s",
                        record_index + 1,
                        packet_offset,
                        local_index,
                        raw.hex(" "),
                    )

                    try:
                        parsed = parse_elitech_record(
                            raw,
                            protocol_version,
                        )

                        if parsed is None:
                            item = {
                                "index": record_index + 1,
                                "timestamp": None,
                                "temperature": None,
                                "humidity": None,
                                "status": "No data",
                                "flags": [],
                                "flags_raw": 0,
                                "raw_hex": raw.hex(" "),
                            }
                        else:
                            parsed["index"] = record_index + 1
                            item = parsed

                    except (
                        ValueError,
                        OverflowError,
                    ) as error:
                        LOGGER.warning(
                            "RECORD PARSE ERROR | index=%d | "
                            "raw=%s | error=%s",
                            record_index + 1,
                            raw.hex(" "),
                            error,
                        )

                        item = {
                            "index": record_index + 1,
                            "timestamp": None,
                            "temperature": None,
                            "humidity": None,
                            "status": "Parse error",
                            "flags": [],
                            "flags_raw": None,
                            "raw_hex": raw.hex(" "),
                            "parse_error": str(error),
                        }

                    if record_index >= wanted_start:
                        parsed_records.append(item)

                packet_offset += RECORDS_PER_PACKET

        finally:
            # A GetRecord flow után a firmware paraméterolvasási állapota
            # ezen az új hardveren nem mindig tér vissza magától.
            # Még ugyanazon HID handle-en visszaprime-oljuk, így a
            # következő tabváltás nem kap FF sentinel blokkokat.
            try:
                time.sleep(0.05)

                prime_parameter_session(
                    fd,
                    context="record-read-cleanup",
                    timeout=0.75,
                )

                LOGGER.info(
                    "RECORD SESSION CLEANUP COMPLETE"
                )
            except Exception as cleanup_error:
                # A rekordok sikeres kiolvasását ne veszítsük el csak azért,
                # mert pl. a felhasználó közben kihúzta az USB-t. A következő
                # high-level művelet saját prime-mal indul.
                LOGGER.warning(
                    "RECORD SESSION CLEANUP FAILED | %s: %s",
                    cleanup_error.__class__.__name__,
                    cleanup_error,
                )
            finally:
                fd.close()

    valid_measurements = sum(
        1
        for record in parsed_records
        if (
            record.get("status") == "Measurement"
            and record.get("temperature") is not None
        )
    )

    LOGGER.info(
        "RECORD READ RESULT | version=%s | stored=%d | loaded=%d | "
        "valid_measurements=%d | first_index=%s | last_index=%s",
        APP_VERSION,
        record_count,
        len(parsed_records),
        valid_measurements,
        (
            parsed_records[0]["index"]
            if parsed_records
            else "-"
        ),
        (
            parsed_records[-1]["index"]
            if parsed_records
            else "-"
        ),
    )

    return {
        "protocol_version": protocol_version,
        "capacity": capacity,
        "stored_count": record_count,
        "loaded_count": len(parsed_records),
        "start_index": (
            parsed_records[0]["index"]
            if parsed_records
            else None
        ),
        "end_index": (
            parsed_records[-1]["index"]
            if parsed_records
            else None
        ),
        "records": parsed_records,
    }


def save_recording_history(fd, identity, data):
    configuration_time = hid_get_parameter(fd, 0x28, 7)
    data["session_id"] = recording_session_id(fd, identity, configuration_time)
    data["serial_number"] = identity[2:14].decode("ascii").strip("\x00 ")
    data["configuration_time"] = decode_datetime(configuration_time)
    data["saved_count"] = get_history().save(data)
    return data


def recording_session_id(fd, identity, configuration_time):
    """Identify the recording without including its growing record count."""
    model = int.from_bytes(identity[:2], "big")
    if model == 0x0044:
        trip = hid_get_parameter(fd, 0, 32, operation=0x05)
        marker = trip[:15]  # trip ID and recording start, not live readings
    else:
        marker = hid_get_parameter(fd, 0x30, 7)
    return hashlib.sha256(identity + configuration_time + marker).hexdigest()


def validate_configuration_confirmation(record_count, expected_record_count,
                                        session_id, expected_session_id, allow_data_loss):
    """Consent covers this session, including samples arriving before Save."""
    if expected_session_id is not None:
        if not isinstance(expected_session_id, str) or not hmac.compare_digest(session_id, expected_session_id):
            raise RuntimeError("The recording session changed. Reload the settings and confirm the new session.")
    if expected_record_count is not None:
        if isinstance(expected_record_count, bool) or not isinstance(expected_record_count, int) or expected_record_count < 0:
            raise ValueError("Invalid expected record count.")
        if record_count < expected_record_count:
            raise RuntimeError("The logger's record count decreased; it may have been reset. Reload the settings and confirm again.")
    if record_count and not allow_data_loss:
        raise RuntimeError(f"The logger contains {record_count} measurements. Confirm erasing this recording session before saving.")
    if record_count and allow_data_loss:
        if expected_session_id is None or expected_record_count is None:
            raise RuntimeError("Reload the page and confirm erasing the current recording session before saving.")


def read_device_config(device_path: str):
    """
    A jelenleg támogatott konfigurációs mezők beolvasása.

    Nincs periodikus háttérlekérdezés: ezt az API-t a UI csak a tab
    megnyitásakor vagy kézi újraolvasáskor hívja.
    """
    LOGGER.info(
        "CONFIG READ REQUEST | device=%s",
        device_path,
    )

    with HID_LOCK:
        fd = open_device(device_path)

        try:
            identity, _ = prime_parameter_session(
                fd,
                context="config-read",
            )

            start_mode_data = hid_get_parameter(fd, 0x20, 1)
            unit_data = hid_get_parameter(fd, 0x21, 1)
            alarm_data = hid_get_parameter(fd, 0x54, 4)
            configuration_time_data = hid_get_parameter(fd, 0x28, 7)
            session_id = recording_session_id(fd, identity, configuration_time_data)
            interval_data = hid_get_parameter(fd, 0x4C, 2)
            device_time_data = hid_get_parameter(fd, 0x88, 7)

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            interval_seconds = decode_interval_seconds(
                interval_data
            )

            if interval_seconds is None:
                LOGGER.warning(
                    "CONFIG INTERVAL SENTINEL | direct=%s | "
                    "trying 0x30 full-block fallback",
                    interval_data.hex(" "),
                )

                block_30 = hid_get_parameter(
                    fd,
                    0x30,
                    0x30,
                )

                # 0x4C - 0x30 = 0x1C
                fallback_interval = block_30[
                    0x1C:0x1E
                ]

                interval_seconds = decode_interval_seconds(
                    fallback_interval
                )

                LOGGER.info(
                    "CONFIG INTERVAL FALLBACK | raw=%s | seconds=%s",
                    fallback_interval.hex(" "),
                    interval_seconds,
                )
        finally:
            fd.close()

    start_byte = start_mode_data[0]
    if interval_seconds is None:
        raise RuntimeError(
            "The logging interval cannot currently be read "
            "reliably. Read the configuration again before saving."
        )

    LOGGER.info(
        "CONFIG READ RESULT | device=%s | protocol=0x%02X | "
        "records=%d | interval_seconds=%d | start_byte=0x%02X | "
        "device_time=%s | configuration_time=%s",
        device_path,
        protocol_version,
        record_count,
        interval_seconds,
        start_byte,
        decode_datetime(device_time_data),
        decode_datetime(configuration_time_data),
    )

    return {
        "path": device_path,
        "serial_number": identity[2:14].decode("ascii").strip("\x00 "),
        "model": "RC-4 Pro" if int.from_bytes(identity[:2], "big") == 0x0044 else "Elitech logger",
        "protocol_version": protocol_version,
        "capacity": capacity,
        "record_count": record_count,
        "interval_seconds": interval_seconds,
        "interval_minutes": interval_seconds / 60.0,
        "temperature_unit": "F" if unit_data[0] & 0x08 else "C",
        "probe": "external" if unit_data[0] & 0x02 else "internal",
        "alarm_high": decode_parameter_temperature(alarm_data[:2]),
        "alarm_low": decode_parameter_temperature(alarm_data[2:]),
        "start_mode_raw": start_byte & 0b111,
        "start_mode": decode_start_mode(start_byte),
        "button_stop": bool(start_byte & (1 << 3)),
        "software_stop": bool(start_byte & (1 << 4)),
        "configuration_time": decode_datetime(configuration_time_data),
        "device_time": decode_datetime(device_time_data),
        "session_id": session_id,
        "can_configure": True,
        "requires_data_loss_confirmation": record_count > 0,
        "blocked_reason": (
            ""
            if record_count == 0
            else (
                f"The logger contains {record_count} measurements. "
                "Saving settings will "
                "erase them. Two confirmations are "
                "required before saving."
            )
        ),
    }



ELITECH_COMPAT_RANGES = [
    (0x00, 0x30),
    (0x30, 0x30),
    (0x60, 0x30),
    (0x98, 0x34),
    (0xCC, 0x30),
    (0xFD, 0x2F),
]

# ElitechLog Win V8.0.5.0:
# UsbCommand.Initval() protocol >= 0x16 esetén 6 SetParameter packetet
# küld, majd FormatCommand-ot. A 7. (device-name) packet csak az arra
# képes modelleknél kerül sorra.
ELITECH_CONFIG_WRITE_RANGES = [
    (0x00, 0x30),
    (0x30, 0x30),
    (0x60, 0x30),
    (0x98, 0x34),
    (0xCC, 0x30),
    (0xFD, 0x2F),
]


def _patch_compat_config_blocks(
    blocks,
    *,
    interval_minutes: int,
    button_stop: bool,
    software_stop: bool,
    sync_clock: bool,
    interval_seconds: int | None = None,
    temperature_unit: str | None = None,
    probe: str | None = None,
    alarm_high: float | None = None,
    alarm_low: float | None = None,
):
    """
    A gyári ElitechLog save-flow alapján készítjük elő a hat blokkot.

    A már érvényes eszközkonfigurációt alapnak használjuk, és csak:
      - 0x20 start/stop bitek,
      - 0x28..0x2E konfigurációs idő,
      - 0x4C..0x4D mintavételi intervallum,
      - 0x88..0x8E device-time staging mező
    változik.

    A gyári ElitechLog a 0x88..0x8E mezőt NULLÁZZA SetParameter során.
    """
    by_start = {
        start: bytearray(data)
        for start, data in blocks.items()
    }

    if interval_seconds is None:
        interval_seconds = interval_minutes * 60
    interval_raw = interval_seconds // 10

    block0 = by_start[0x00]

    old_start = block0[0x20]
    new_start = old_start & 0b11100000
    new_start |= 0b001  # Manual

    if button_stop:
        new_start |= 1 << 3

    if software_stop:
        new_start |= 1 << 4

    block0[0x20] = new_start

    if probe is not None:
        block0[0x21] = (block0[0x21] & ~0x02) | (0x02 if probe == "external" else 0)

    old_unit = "F" if block0[0x21] & 0x08 else "C"
    if temperature_unit is not None:
        # Temperature unit is bit 3 at parameter 0x21. Preserve sensor bits.
        block0[0x21] = (block0[0x21] & ~0x08) | (0x08 if temperature_unit == "F" else 0)

    if sync_clock:
        now = datetime.now().replace(microsecond=0)
        encoded = encode_official_elitech_datetime(now)
        block0[0x28:0x2F] = encoded

    block1 = by_start[0x30]
    if temperature_unit is not None:
        convert_alarm_units(block1, old_unit, temperature_unit)
    if alarm_high is not None:
        block1[0x24:0x26] = encode_parameter_temperature(alarm_high)
        block1[0x26:0x28] = encode_parameter_temperature(alarm_low)
    interval_pos = 0x4C - 0x30
    block1[
        interval_pos : interval_pos + 2
    ] = int(interval_raw).to_bytes(
        2,
        byteorder="big",
    )

    # A gyári GetListForSet() packet 0x60 ezt explicit nullázza.
    block2 = by_start[0x60]
    device_time_pos = 0x88 - 0x60
    block2[
        device_time_pos : device_time_pos + 7
    ] = bytes(7)

    return {
        start: bytes(data)
        for start, data in by_start.items()
    }


def read_preparation_state(fd):
    identity, _ = prime_parameter_session(fd, context="preparation-readback")
    _, capacity, record_count = read_record_count_from_fd(fd)
    return {
        "identity": identity,
        "capacity": capacity,
        "record_count": record_count,
        "state": hid_get_parameter(fd, 0x25, 1)[0] & 0x3F,
        "start": hid_get_parameter(fd, 0x20, 1)[0],
        "unit_probe": hid_get_parameter(fd, 0x21, 1)[0],
        "alarm": hid_get_parameter(fd, 0x54, 4),
        "interval": int.from_bytes(hid_get_parameter(fd, 0x4C, 2), "big"),
        "configuration_time": hid_get_parameter(fd, 0x28, 7),
        "device_time": hid_get_parameter(fd, 0x88, 7),
    }


def check_preparation_state(state, identity, blocks, sync_clock):
    problems = []
    if state["identity"] != identity:
        problems.append("a different logger was found")
    if state["record_count"] != 0:
        problems.append(f"the previous recording has not cleared ({state['record_count']} records remain)")
    if int.from_bytes(identity[:2], "big") == 0x0044 and state["state"] != 4:
        problems.append("the logger is not ready for a new manual recording")
    if state["start"] & 0x1F != blocks[0][0x20] & 0x1F:
        problems.append("the start/stop settings do not match")
    if state["unit_probe"] & 0x0A != blocks[0][0x21] & 0x0A:
        problems.append("the temperature unit/probe does not match")
    if state["interval"] != int.from_bytes(blocks[0x30][0x1C:0x1E], "big"):
        problems.append("the logging interval does not match")
    if state["alarm"] != blocks[0x30][0x24:0x28]:
        problems.append("the alarm limits do not match")
    if state["configuration_time"] != blocks[0][0x28:0x2F]:
        problems.append("the configuration time does not match")
    clock_text = decode_datetime(state["device_time"])
    if clock_text == "-":
        problems.append("the logger clock has not restarted")
    elif sync_clock:
        requested_text = decode_datetime(blocks[0][0x28:0x2F])
        if requested_text == "-":
            problems.append("the requested clock time is invalid")
        else:
            requested = datetime.strptime(requested_text, "%Y-%m-%d %H:%M:%S")
            actual = datetime.strptime(clock_text, "%Y-%m-%d %H:%M:%S")
            if not -2 <= (actual - requested).total_seconds() <= max(10, (datetime.now() - requested).total_seconds() + 10):
                problems.append("the logger clock does not match the requested time")
    if problems:
        raise RuntimeError("; ".join(problems))


def verify_preparation_readback(device_path, identity, blocks, sync_clock, timeout=8.0):
    """Only retry reads. Never repeat parameter writes or FormatCommand."""
    deadline = time.monotonic() + timeout
    while True:
        fd = None
        try:
            fd = open_device(device_path)
            state = read_preparation_state(fd)
            check_preparation_state(state, identity, blocks, sync_clock)
            LOGGER.info("PREPARATION VERIFIED | records=%d | state=0x%02X | unit_probe=0x%02X | interval_raw=%d",
                        state["record_count"], state["state"], state["unit_probe"], state["interval"])
            return state
        except (OSError, ValueError, RuntimeError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "The preparation command was sent, but its result could not be verified. "
                    "Reload device information before trying again. Details: " + str(error)
                ) from error
            LOGGER.info("PREPARATION READBACK WAIT | %s", error)
        finally:
            if fd is not None:
                fd.close()
        time.sleep(0.2)


def apply_device_config(
    device_path: str,
    *,
    interval_minutes: int | None = None,
    interval_seconds: int | None = None,
    temperature_unit: str | None = None,
    probe: str | None = None,
    alarm_high: float | None = None,
    alarm_low: float | None = None,
    sync_clock: bool,
    button_stop: bool,
    software_stop: bool,
    allow_data_loss: bool = False,
    expected_record_count: int | None = None,
    expected_session_id: str | None = None,
):
    """
    ElitechLog Win V8.0.5.0 save-flow rekonstrukció.

    A statikus .NET visszafejtés alapján a gyári program:
      1. 6 db SetParameter packetet küld,
      2. a dátum 3. byte-jába DayOfWeek értéket ír,
      3. a 0x60 packetben nullázza 0x88..0x8E-t,
      4. a harmadik SetParameter packetnek van egy gyári off-by-one
         framing sajátossága,
      5. elküldi a 0x02C0 FormatCommand-ot,
      6. kb. 500 ms-ig nyitva hagyja az eszközt,
      7. csak utána zárja a HID kapcsolatot.

    Ezt a sorrendet reprodukáljuk.
    """
    if interval_seconds is None:
        try:
            interval_seconds = float(interval_minutes) * 60
        except (TypeError, ValueError):
            raise ValueError("Choose a logging interval.")
    if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float)):
        raise ValueError("The logging interval must be a number of seconds.")
    if not 10 <= interval_seconds <= 86400 or interval_seconds % 10 != 0:
        raise ValueError("Use an interval from 10 seconds to 24 hours, in steps of 10 seconds.")
    interval_seconds = int(interval_seconds)
    interval_minutes = interval_seconds / 60
    interval_raw = interval_seconds // 10
    if alarm_high is not None or alarm_low is not None:
        if (isinstance(alarm_high, bool) or isinstance(alarm_low, bool)
                or not isinstance(alarm_high, (int, float)) or not isinstance(alarm_low, (int, float))
                or not math.isfinite(alarm_high) or not math.isfinite(alarm_low)
                or not -399.9 <= alarm_low < alarm_high <= 399.9):
            raise ValueError("Choose valid low/high alarm limits, with the low limit below the high limit.")
    if probe not in (None, "internal", "external"):
        raise ValueError("Probe must be internal or external.")
    if temperature_unit not in (None, "C", "F"):
        raise ValueError("Temperature unit must be C or F.")

    LOGGER.info(
        "FACTORY FLOW START | version=%s | device=%s | interval_minutes=%.3f | "
        "sync_clock=%s | button_stop=%s | software_stop=%s | "
        "allow_data_loss=%s | expected_record_count=%s",
        APP_VERSION,
        device_path,
        interval_minutes,
        sync_clock,
        button_stop,
        software_stop,
        allow_data_loss,
        expected_record_count,
    )

    with HID_LOCK:
        fd = open_device(device_path)

        try:
            identity, _ = prime_parameter_session(
                fd,
                context="factory-save-precheck",
            )

            protocol_version, capacity, record_count = (
                read_record_count_from_fd(fd)
            )

            LOGGER.info(
                "FACTORY PRECHECK | protocol=0x%02X | "
                "capacity=%d | records=%d",
                protocol_version,
                capacity,
                record_count,
            )

            current_session_id = recording_session_id(
                fd, identity, hid_get_parameter(fd, 0x28, 7)
            )
            validate_configuration_confirmation(
                record_count, expected_record_count, current_session_id,
                expected_session_id, allow_data_loss,
            )

            if record_count != 0:
                LOGGER.warning(
                    "DESTRUCTIVE CONFIG CONFIRMED | records_to_erase=%d | "
                    "expected_record_count=%s",
                    record_count,
                    expected_record_count,
                )

            if protocol_version < 0x16:
                raise RuntimeError(
                    "Saving settings requires "
                    "protocol version 0x16 or later."
                )

            if record_count and int.from_bytes(identity[:2], "big") == 0x0044 and protocol_version == 0x54:
                archive = read_rc4_pro_records(fd, identity, record_count, capacity, 0)
                save_recording_history(fd, identity, archive)
                prime_parameter_session(fd, context="after-history-save")

            original_blocks = {}

            for start, length in ELITECH_CONFIG_WRITE_RANGES:
                original_blocks[start] = hid_get_parameter(
                    fd,
                    start,
                    length,
                )

            backup_dir = Path(__file__).resolve().parent / ".device-backups"
            backup_dir.mkdir(exist_ok=True)
            backup_path = backup_dir / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json")
            backup_path.write_text(json.dumps({
                "device_path": device_path,
                "protocol_version": protocol_version,
                "record_count": record_count,
                "parameters": {f"0x{start:04X}": data.hex() for start, data in original_blocks.items()},
            }, indent=2), encoding="utf-8")

            patched_blocks = _patch_compat_config_blocks(
                original_blocks,
                interval_minutes=interval_minutes,
                interval_seconds=interval_seconds,
                temperature_unit=temperature_unit,
                probe=probe,
                alarm_high=alarm_high,
                alarm_low=alarm_low,
                button_stop=button_stop,
                software_stop=software_stop,
                sync_clock=sync_clock,
            )

            for start, length in ELITECH_CONFIG_WRITE_RANGES:
                old_data = original_blocks[start]
                new_data = patched_blocks[start]

                diffs = []

                for index, (old_byte, new_byte) in enumerate(
                    zip(old_data, new_data)
                ):
                    if old_byte != new_byte:
                        diffs.append(
                            f"0x{start + index:02X}:"
                            f"{old_byte:02X}->{new_byte:02X}"
                        )

                LOGGER.info(
                    "FACTORY BLOCK DIFF | start=0x%02X | "
                    "len=%d | changes=%s",
                    start,
                    length,
                    ", ".join(diffs) if diffs else "(none)",
                )

            # ------------------------------------------------
            # Exact factory packet order.
            # ------------------------------------------------

            hid_set_parameter_official(
                fd,
                0x00,
                patched_blocks[0x00],
            )

            hid_set_parameter_official(
                fd,
                0x30,
                patched_blocks[0x30],
            )

            # ElitechLog V8.0.5.0 DataFactory.GetListForSet():
            # byte[3] = 0x3B, byte[10] = 0x30, but checksum is at 58.
            # Therefore only addresses 0x60..0x8E (47 bytes) are in frame.
            hid_set_parameter_official(
                fd,
                0x60,
                patched_blocks[0x60][:47],
                declared_length=48,
                frame_length=59,
            )

            hid_set_parameter_official(
                fd,
                0x98,
                patched_blocks[0x98],
            )

            hid_set_parameter_official(
                fd,
                0xCC,
                patched_blocks[0xCC],
            )

            hid_set_parameter_official(
                fd,
                0xFD,
                patched_blocks[0xFD],
            )

            LOGGER.warning(
                "FACTORY FORMAT TX | op=0x02C0"
            )

            format_response = b""
            try:
                format_response = hid_format_command(fd)
            except OSError as response_error:
                # A flash erase/restart can finish without an input report.
                # Preserve the settle/reopen sequence and verify the outcome;
                # sending FormatCommand again could clear a newly started run.
                LOGGER.warning("PREPARATION REPLY MISSING | verifying device state | %s", response_error)

            LOGGER.warning(
                "FACTORY FORMAT RX | response_len=%d",
                len(format_response),
            )

            # CUSB.setParameters(): success után Thread.Sleep(500),
            # majd Dispose/CloseDevice. Eddig mi túl korán zártunk.
            LOGGER.info(
                "FACTORY POST-FORMAT HOLD | keeping HID open for 550 ms"
            )
            time.sleep(0.55)

        finally:
            fd.close()

        LOGGER.info(
            "FACTORY HID CLOSED | waiting 1 second before reopen"
        )
        time.sleep(1.0)

        readback = verify_preparation_readback(device_path, identity, patched_blocks, sync_clock)
        verify_unit = "F" if readback["unit_probe"] & 0x08 else "C"
        verify_probe = "external" if readback["unit_probe"] & 0x02 else "internal"
        verify_device_time = readback["device_time"]
        verify_config_time = readback["configuration_time"]

    return {
        "ok": True,
        "message": (
            "Settings saved and verified after reopening USB. "
            "Unplug the logger, wait 3 seconds, then hold its button for 5 seconds "
            "until the recording symbol appears."
        ),
        "write_mode": "elitechlog-v8.0.5.0-factory-flow",
        "preparation_acknowledged": bool(format_response),
        "verification": "device-readback",
        "record_count_after_save": readback["record_count"],
        "protocol_version": protocol_version,
        "capacity": capacity,
        "record_count_before_save": record_count,
        "data_loss_confirmed": bool(record_count != 0 and allow_data_loss),
        "interval_minutes": interval_minutes,
        "interval_seconds": interval_seconds,
        "temperature_unit": verify_unit,
        "probe": verify_probe,
        "start_mode": "Manual",
        "button_stop": bool(button_stop),
        "software_stop": bool(software_stop),
        "clock_sync_requested": bool(sync_clock),
        "device_time": decode_datetime(verify_device_time),
        "configuration_time": decode_datetime(verify_config_time),
        "persistence_note": "Reconnect USB later to download measurements.",
    }


# ============================================================
# udev jogosultság beállítása
# ============================================================

UDEV_RULE = (
    'KERNEL=="hidraw*", '
    'ATTRS{idVendor}=="246c", '
    'ATTRS{idProduct}=="9001", '
    'MODE="0660", '
    'TAG+="uaccess"\n'
)


def install_udev_rule():
    if sys.platform == "win32":
        raise RuntimeError("Windows uses its built-in HID driver; no udev rule is needed.")

    pkexec = shutil.which("pkexec")
    udevadm = shutil.which("udevadm")
    install_cmd = shutil.which("install")

    if not pkexec:
        raise RuntimeError(
            "pkexec was not found. Install policykit-1 "
            "or configure a udev rule manually."
        )

    if not udevadm:
        raise RuntimeError("udevadm was not found.")

    if not install_cmd:
        raise RuntimeError("The install command was not found.")

    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="99-elitech-rc5-",
            suffix=".rules",
            delete=False,
        ) as handle:
            handle.write(UDEV_RULE)
            tmp_path = handle.name

        command = (
            f"{shlex.quote(install_cmd)} -m 0644 "
            f"{shlex.quote(tmp_path)} "
            f"/etc/udev/rules.d/99-elitech-rc5.rules"
            " && "
            f"{shlex.quote(udevadm)} control --reload-rules"
            " && "
            f"{shlex.quote(udevadm)} trigger --subsystem-match=hidraw"
        )

        result = subprocess.run(
            [pkexec, "/bin/sh", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            if not message:
                message = (
                    "USB access setup was cancelled or failed."
                )
            raise RuntimeError(message)

        return {
            "ok": True,
            "message": (
                "USB access rule installed. "
                "If the logger is still unavailable, unplug and reconnect it."
            ),
        }

    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ============================================================
# Web UI
# ============================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Elitech USB Logger Manager</title>

<style>
* { box-sizing: border-box; }

html, body { height: 100%; }

body {
    margin: 0;
    background: #f3f4f6;
    color: #172033;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

button, input { font: inherit; }

.app {
    min-height: 100vh;
    padding: 18px;
}

.header { margin-bottom: 16px; }

.header h1 {
    margin: 0;
    font-size: 28px;
}

.subtitle {
    margin-top: 3px;
    color: #667085;
    font-size: 14px;
}

.layout {
    display: grid;
    grid-template-columns: minmax(220px, 1fr) minmax(0, 5fr);
    gap: 16px;
    align-items: start;
}

.sidebar, .main-panel { min-width: 0; }

.panel {
    background: white;
    border: 1px solid #d8dce3;
    border-radius: 10px;
}

.sidebar-panel { padding: 12px; }

.sidebar-title {
    margin: 0 0 10px;
    font-size: 14px;
}

.device-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
    max-height: 520px;
    overflow-y: auto;
}

.device-list-empty {
    padding: 12px 10px;
    border: 1px dashed #cfd4dc;
    border-radius: 7px;
    color: #7b8491;
    font-size: 13px;
    text-align: center;
}

.device-item {
    width: 100%;
    padding: 10px;
    border: 1px solid #cfd4dc;
    border-radius: 7px;
    background: #fff;
    color: #172033;
    text-align: left;
    cursor: pointer;
}

.device-item:hover {
    background: #f6f8fb;
    border-color: #aeb8c7;
}

.device-item.selected {
    border-color: #2457d6;
    background: #eef3ff;
    box-shadow: inset 3px 0 0 #2457d6;
}

.device-item-name {
    display: block;
    margin-bottom: 4px;
    font-size: 13px;
    font-weight: 700;
    overflow-wrap: anywhere;
}

.device-item-meta {
    display: block;
    color: #6f7783;
    font-family: monospace;
    font-size: 11px;
    overflow-wrap: anywhere;
}

.device-status {
    margin-top: 10px;
    font-size: 12px;
    line-height: 1.4;
}

.device-status.online { color: #16823b; }
.device-status.offline { color: #a43737; }

.tabs {
    display: flex;
    gap: 4px;
    padding: 0 14px;
    border-bottom: 1px solid #d8dce3;
}

.tab-button {
    padding: 14px 10px 11px;
    border: 0;
    border-bottom: 3px solid transparent;
    background: transparent;
    color: #596274;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
}

.tab-button.active {
    border-bottom-color: #2457d6;
    color: #172033;
}

.tab-content {
    min-height: 480px;
    padding: 18px;
}

.tab-page { display: none; }
.tab-page.active { display: block; }

.empty-state {
    display: flex;
    min-height: 420px;
    align-items: center;
    justify-content: center;
    color: #747b86;
    text-align: center;
}

.content-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
}

.content-title { min-width: 0; }

.content-title h2 {
    margin: 0 0 3px;
    font-size: 19px;
}

.device-path {
    color: #737b87;
    font-family: monospace;
    font-size: 12px;
}

.action-button {
    padding: 8px 12px;
    border: 1px solid #aeb4bf;
    border-radius: 6px;
    background: white;
    cursor: pointer;
}

.action-button:hover { background: #f5f6f8; }

.action-button:disabled {
    color: #999;
    cursor: default;
}

.loading {
    display: none;
    margin-bottom: 12px;
    color: #69717c;
    font-size: 13px;
}

.error-box,
.permission-box,
.success-box,
.warning-box {
    display: none;
    margin-bottom: 12px;
    padding: 12px;
    border-radius: 8px;
    line-height: 1.45;
}

.error-box {
    border: 1px solid #e0a3a3;
    background: #fff4f4;
    color: #8b2222;
    white-space: pre-wrap;
}

.permission-box {
    border: 1px solid #e2c06d;
    background: #fff9e8;
    color: #6a5111;
}

.success-box {
    border: 1px solid #9ac7a7;
    background: #f1fbf4;
    color: #245f34;
}

.warning-box {
    border: 1px solid #e2c06d;
    background: #fff9e8;
    color: #6a5111;
}

.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
}

.info-item {
    min-width: 0;
    padding: 12px;
    border: 1px solid #e0e3e8;
    border-radius: 8px;
    background: #fafbfc;
}

.info-label {
    margin-bottom: 5px;
    color: #667085;
    font-size: 12px;
}

.info-value {
    overflow-wrap: anywhere;
    font-family: monospace;
    font-size: 14px;
    font-weight: 650;
}

/* konfiguráció */
.config-intro {
    margin-bottom: 14px;
    padding: 12px;
    border: 1px solid #cbd7ef;
    border-radius: 8px;
    background: #f5f8ff;
    color: #39465f;
    font-size: 13px;
    line-height: 1.5;
}

.config-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.config-section {
    min-width: 0;
    padding: 14px;
    border: 1px solid #e0e3e8;
    border-radius: 8px;
    background: #fafbfc;
}

.config-section.full-width {
    grid-column: 1 / -1;
}

.config-section h3 {
    margin: 0 0 12px;
    font-size: 15px;
}

.form-row {
    display: grid;
    grid-template-columns: minmax(150px, 0.8fr) minmax(180px, 1.2fr);
    gap: 12px;
    align-items: center;
    margin-bottom: 11px;
}

.form-row:last-child { margin-bottom: 0; }

.form-row label {
    color: #4f5968;
    font-size: 13px;
}

.form-control {
    width: 100%;
    min-width: 0;
    height: 38px;
    padding: 0 9px;
    border: 1px solid #b8bec8;
    border-radius: 6px;
    background: white;
    color: #172033;
}

.form-control:disabled {
    background: #eef0f3;
    color: #707783;
}

.inline-unit {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 8px;
    align-items: center;
}

.checkbox-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 34px;
    color: #394150;
    font-size: 13px;
}

.checkbox-row input {
    width: 16px;
    height: 16px;
}

.hint {
    margin-top: 5px;
    color: #7a828d;
    font-size: 11px;
    line-height: 1.4;
}

.preview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 9px;
}

.preview-item {
    padding: 10px;
    border: 1px solid #e1e5eb;
    border-radius: 7px;
    background: white;
}

.preview-label {
    margin-bottom: 4px;
    color: #6f7783;
    font-size: 11px;
}

.preview-value {
    font-family: monospace;
    font-size: 14px;
    font-weight: 700;
}

.config-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
}

.config-footer-text {
    max-width: 760px;
    color: #5e6673;
    font-size: 12px;
    line-height: 1.5;
}

.save-button {
    flex: 0 0 auto;
    padding: 10px 15px;
    border: 1px solid #2457d6;
    border-radius: 6px;
    background: #2457d6;
    color: white;
    font-weight: 700;
    cursor: pointer;
}

.save-button:hover { background: #1d48b4; }

.save-button:disabled {
    border-color: #c7ccd4;
    background: #eceef1;
    color: #8a919c;
    cursor: not-allowed;
}

.status-value-ok { color: #167c3b; }
.status-value-blocked { color: #a43737; }


.measurement-toolbar {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
    margin-bottom: 16px;
}

.measurement-toolbar-group {
    display: flex;
    align-items: end;
    gap: 10px;
    flex-wrap: wrap;
}

.measurement-control {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.measurement-control label {
    color: #5e6673;
    font-size: 12px;
    font-weight: 700;
}

.measurement-summary {
    margin: 14px 0;
}

.measurement-chart-wrap {
    display: none;
    margin: 16px 0;
    padding: 12px;
    border: 1px solid #e1e4e9;
    border-radius: 7px;
    background: #fff;
}

.measurement-chart-title {
    margin: 0 0 8px 0;
    font-size: 14px;
    font-weight: 700;
}

.measurement-chart {
    width: 100%;
    min-height: 260px;
}

.measurement-chart svg {
    display: block;
    width: 100%;
    height: auto;
    cursor: crosshair;
    user-select: none;
}

.measurement-chart-help {
    margin-top: 6px;
    color: #69717c;
    font-size: 12px;
}

.measurement-table-wrap {
    margin-top: 14px;
    overflow: auto;
    max-height: 560px;
    border: 1px solid #e1e4e9;
    border-radius: 7px;
}

.measurement-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    background: #fff;
}

.measurement-table th,
.measurement-table td {
    padding: 8px 10px;
    border-bottom: 1px solid #eceef2;
    text-align: left;
    white-space: nowrap;
}

.measurement-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: #f4f6f8;
    color: #3d4652;
    font-size: 12px;
}

.measurement-table td.numeric {
    text-align: right;
    font-variant-numeric: tabular-nums;
}

.measurement-table tr:last-child td {
    border-bottom: none;
}

.measurement-table tr.event-row td {
    background: #fff9ec;
}

.measurement-table tr.error-row td {
    background: #fff0f0;
}

.measurement-empty {
    padding: 28px 12px;
    color: #69717c;
    text-align: center;
}

.measurement-note {
    color: #69717c;
    font-size: 12px;
    line-height: 1.45;
    margin-top: 9px;
}


.safety-modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: rgba(17, 24, 39, 0.58);
}

.safety-modal-backdrop.open {
    display: flex;
}

.safety-modal {
    width: min(620px, 100%);
    background: #fff;
    border: 1px solid #cfd4dc;
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);
    overflow: hidden;
}

.safety-modal-header {
    padding: 18px 20px 10px;
    font-size: 18px;
    font-weight: 750;
    color: #172033;
}

.safety-modal-body {
    padding: 0 20px 18px;
    color: #3e4857;
    line-height: 1.5;
    white-space: pre-line;
}

.safety-modal-actions {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 20px;
    border-top: 1px solid #e5e7eb;
    background: #f7f8fa;
}

.safety-modal-button {
    min-width: 116px;
    padding: 9px 16px;
    border: 1px solid #b9c0ca;
    border-radius: 7px;
    background: #fff;
    color: #172033;
    cursor: pointer;
    font-weight: 650;
}

.safety-modal-button:hover {
    background: #f2f4f7;
}

.safety-modal-button.danger {
    border-color: #b42318;
    background: #b42318;
    color: #fff;
}

.safety-modal-button.danger:hover {
    background: #912018;
}

@media (max-width: 1000px) {
    .config-grid { grid-template-columns: 1fr; }
    .config-section.full-width { grid-column: auto; }
}

@media (max-width: 850px) {
    .layout { grid-template-columns: 1fr; }
    .device-list { max-height: 220px; }
    .form-row { grid-template-columns: 1fr; gap: 5px; }
    .config-footer { align-items: stretch; flex-direction: column; }
}
.content-title { display:none; }
.sensor-dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; background:#9ca3af; }
.sensor-dot.connected { background:#16a34a; }
.device-item.offline { color:#6b7280; }
</style>
</head>

<body>
<div class="app">

    <div class="header">
        <h1>Elitech USB Logger Manager <span style="font-size:13px;font-weight:600;opacity:.65;">v26-sensor-library</span></h1>
        <div class="subtitle">USB temperature logger</div>
        <label for="displayUnit">Charts and CSV:
            <select id="displayUnit" aria-label="Temperature display unit">
                <option value="C">Celsius (°C)</option>
                <option value="F">Fahrenheit (°F)</option>
            </select>
        </label>
    </div>

    <div class="layout">

        <aside class="sidebar">
            <div class="panel sidebar-panel">
                <h2 class="sidebar-title">Sensors</h2>

                <div id="deviceList" class="device-list">
                    <div class="device-list-empty">Loading sensors...</div>
                </div>

                <label for="sensorNameInput">Sensor name</label>
                <input id="sensorNameInput" class="form-control" placeholder="Select a sensor" maxlength="100" disabled>
                <button id="saveSensorName" type="button" class="action-button" disabled>Save name</button>
                <details style="margin-top:12px;"><summary>Database location</summary><code id="databaseLocation" style="display:block;overflow-wrap:anywhere;font-size:11px;"></code></details>
                <div id="deviceStatus" class="device-status offline">
                    Loading sensors...
                </div>
            </div>
        </aside>

        <main class="main-panel">
            <div class="panel">

                <div class="tabs">
                    <button id="infoTabButton" type="button" class="tab-button">
                        Device information
                    </button>

                    <button id="configTabButton" type="button" class="tab-button">
                        Prepare logging
                    </button>

                    <button id="measurementsTabButton" type="button" class="tab-button active">
                        Measurements
                    </button>
                </div>

                <div class="tab-content">

                    <section id="infoTabPage" class="tab-page">
                        <div id="infoEmptyState" class="empty-state">
                            Select an Elitech logger from the list on the left.
                        </div>

                        <div id="infoContent" style="display:none;">
                            <div class="content-header">

                                <button
                                    id="refreshInfoButton"
                                    type="button"
                                    class="action-button"
                                >
                                    Refresh
                                </button>
                            </div>

                            <div id="infoLoading" class="loading">
                                Reading device information...
                            </div>

                            <div id="infoErrorBox" class="error-box"></div>

                            <div id="permissionBox" class="permission-box">
                                The logger was found but requires
                                USB access permission.
                                <br><br>
                                <button
                                    id="permissionButton"
                                    type="button"
                                    class="action-button"
                                >
                                    Set up USB access
                                </button>
                            </div>

                            <div id="infoSuccessBox" class="success-box"></div>
                            <div id="infoGrid" class="info-grid"></div>
                        </div>
                    </section>


                    <section id="configTabPage" class="tab-page">

                        <div id="configEmptyState" class="empty-state">
                            Select an Elitech logger from the list on the left.
                        </div>

                        <div id="configContent" style="display:none;">
                            <div class="content-header">

                                <button
                                    id="reloadConfigButton"
                                    type="button"
                                    class="action-button"
                                >
                                    Reload settings
                                </button>
                            </div>

                            <div class="config-intro">
                                <strong>Prepare the logger for a new recording session.</strong>
                                Choose an interval and temperature unit, then save.
                                After saving, unplug USB and hold the logger's button for 5 seconds
                                until the recording symbol appears. A flashing symbol means a start delay.
                            </div>

                            <div id="configLoading" class="loading">
                                Reading settings...
                            </div>

                            <div id="configErrorBox" class="error-box"></div>
                            <div id="configSuccessBox" class="success-box"></div>
                            <div id="configWarningBox" class="warning-box"></div>

                            <div id="configForm">

                                <div class="config-grid">

                                    <section class="config-section">
                                        <h3>Logging interval</h3>

                                        <div class="form-row">
                                            <label for="sampleInterval">
                                                Logging interval
                                            </label>

                                            <div>
                                                <div class="inline-unit">
                                                    <input
                                                        id="sampleInterval"
                                                        class="form-control"
                                                        type="number"
                                                        min="0.01"
                                                        max="86400"
                                                        step="any"
                                                        value="5"
                                                    >
                                                    <select id="intervalUnit" class="form-control" aria-label="Interval unit">
                                                        <option value="1">seconds</option>
                                                        <option value="60" selected>minutes</option>
                                                        <option value="3600">hours</option>
                                                    </select>
                                                </div>

                                                <div class="hint">
                                                    From 10 seconds to 24 hours, in 10-second steps.
                                                </div>
                                            </div>
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Start recording</h3>
                                        <div class="form-row">
                                            <label for="probeSelection">Temperature probe</label>
                                            <div>
                                                <input id="probeSelection" type="hidden" value="internal">
                                                <label style="color:#2563eb;margin-right:12px;"><input id="probeInternal" type="radio" name="probe" value="internal" checked> Internal</label>
                                                <label style="color:#ea580c;"><input id="probeExternal" type="radio" name="probe" value="external"> External</label>
                                            </div>
                                        </div>
                                        <div class="hint">RC-4 Pro records one selected temperature probe per session.</div>
                                        <div class="form-row">
                                            <label for="temperatureUnit">Logger temperature unit</label>
                                            <select id="temperatureUnit" class="form-control">
                                                <option value="C">Celsius (°C)</option>
                                                <option value="F">Fahrenheit (°F)</option>
                                            </select>
                                        </div>

                                        <div class="form-row">
                                            <label>
                                                Start mode
                                            </label>

                                            <input
                                                class="form-control"
                                                value="Manual — hold the logger button for 5 seconds"
                                                disabled
                                            >
                                        </div>

                                        <div class="hint">
                                            After saving, unplug USB and hold the button for 5 seconds. Confirm the recording symbol on the logger.
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Temperature alarms</h3>
                                        <div class="form-row"><label for="alarmHigh">High limit</label><input id="alarmHigh" class="form-control" type="number" step="0.1"></div>
                                        <div class="form-row"><label for="alarmLow">Low limit</label><input id="alarmLow" class="form-control" type="number" step="0.1"></div>
                                        <div class="hint">Limits use the logger temperature unit above. Changing units converts the limits.</div>
                                        <button id="resetAlarmLimits" type="button" class="action-button">Use default limits</button>
                                    </section>
                                    <section class="config-section">
                                        <h3>Logger clock</h3>

                                        <div class="checkbox-row">
                                            <input
                                                id="syncClock"
                                                type="checkbox"
                                                checked
                                            >

                                            <label for="syncClock">
                                                Synchronize the logger clock with this computer
                                                when saving
                                            </label>
                                        </div>

                                        <div class="form-row">
                                            <label>
                                                Current logger time
                                            </label>

                                            <input
                                                id="currentDeviceTime"
                                                class="form-control"
                                                type="text"
                                                readonly
                                            >
                                        </div>

                                        <div class="form-row">
                                            <label>
                                                Computer time
                                            </label>

                                            <input
                                                id="computerTime"
                                                class="form-control"
                                                type="text"
                                                readonly
                                            >
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Stopping options</h3>

                                        <div class="checkbox-row">
                                            <input
                                                id="allowButtonStop"
                                                type="checkbox"
                                            >

                                            <label for="allowButtonStop">
                                                Allow stopping with the logger button
                                            </label>
                                        </div>

                                        <div class="checkbox-row">
                                            <input
                                                id="allowSoftwareStop"
                                                type="checkbox"
                                            >

                                            <label for="allowSoftwareStop">
                                                Allow stopping from software
                                            </label>
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Memory</h3>

                                        <div class="preview-grid">
                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Logger capacity
                                                </div>
                                                <div id="configCapacity" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Stored measurements
                                                </div>
                                                <div id="configRecordCount" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Ready to configure
                                                </div>
                                                <div id="configAllowed" class="preview-value">
                                                    —
                                                </div>
                                            </div>
                                        </div>

                                        <div class="hint">
                                            Export any measurements before preparing a new session. Saving settings clears the stored measurements.
                                        </div>
                                    </section>


                                    <section class="config-section">
                                        <h3>Recording capacity</h3>

                                        <div class="preview-grid">
                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Days
                                                </div>
                                                <div id="durationDays" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Months
                                                </div>
                                                <div id="durationMonths" class="preview-value">
                                                    —
                                                </div>
                                            </div>

                                            <div class="preview-item">
                                                <div class="preview-label">
                                                    Years
                                                </div>
                                                <div id="durationYears" class="preview-value">
                                                    —
                                                </div>
                                            </div>
                                        </div>
                                    </section>


                                    <section class="config-section full-width">
                                        <h3>Prepare a new session</h3>

                                        <div class="config-footer">
                                            <div class="config-footer-text">
                                                Saving synchronizes the clock (if selected) and prepares a new session.
                                                Existing measurements will be erased; export them first.
                                                Start recording with the device button after unplugging USB.
                                            </div>

                                            <button
                                                id="saveConfigButton"
                                                type="button"
                                                class="save-button"
                                                disabled
                                            >
                                                Save and prepare logging
                                            </button>
                                        </div>
                                    </section>

                                </div>
                            </div>
                        </div>
                    </section>


                    <section id="measurementsTabPage" class="tab-page active">

                        <div id="measurementsEmptyState" class="empty-state">
                            Select an Elitech logger from the list on the left.
                        </div>

                        <div id="measurementsContent" style="display:none;">
                            <div class="config-intro">
                                Measurements are shown from the local database. Connecting USB automatically downloads new readings. Internal and external readings are color coded.
                            </div>

                            <div class="measurement-toolbar">
                                <div class="measurement-toolbar-group">
                                    <div class="measurement-control">
                                        <label for="measurementRangePreset">Time range</label>
                                        <select id="measurementRangePreset" class="form-control">
                                            <option value="today" selected>Today</option>
                                            <option value="yesterday">Yesterday</option>
                                            <option value="week">Last 7 days</option>
                                            <option value="month">Last 30 days</option>
                                            <option value="all">All history</option>
                                            <option value="custom">Custom</option>
                                        </select>
                                    </div>
                                    <div class="measurement-control">
                                        <label for="measurementStart">From (local time)</label>
                                        <input id="measurementStart" type="datetime-local" step="1" class="form-control">
                                    </div>
                                    <div class="measurement-control">
                                        <label for="measurementEnd">To (exclusive)</label>
                                        <input id="measurementEnd" type="datetime-local" step="1" class="form-control">
                                    </div>
                                    <button id="applyMeasurementRange" type="button" class="action-button">Apply range</button>
                                    <button
                                        id="reloadMeasurementsButton"
                                        type="button"
                                        class="action-button"
                                    >
                                        Sync now
                                    </button>
                                </div>

                                <button
                                    id="exportCsvButton"
                                    type="button"
                                    class="action-button"
                                    disabled
                                >
                                    Export CSV
                                </button>
                            </div>

                            <div id="measurementsLoading" class="loading">
                                Loading saved measurements...
                            </div>

                            <div id="measurementsErrorBox" class="error-box"></div>
                            <div id="measurementsSuccessBox" class="success-box"></div>

                            <div
                                id="measurementSummary"
                                class="preview-grid measurement-summary"
                            >
                                <div class="preview-item">
                                    <div class="preview-label">Stored records</div>
                                    <div id="measurementStoredCount" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">In time range</div>
                                    <div id="measurementLoadedCount" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Period</div>
                                    <div id="measurementPeriod" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Minimum</div>
                                    <div id="measurementMin" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Average</div>
                                    <div id="measurementAvg" class="preview-value">—</div>
                                </div>

                                <div class="preview-item">
                                    <div class="preview-label">Maximum</div>
                                    <div id="measurementMax" class="preview-value">—</div>
                                </div>
                            </div>

                            <div id="measurementChartWrap" class="measurement-chart-wrap">
                                <div class="measurement-chart-title">
                                    Temperature over time
                                    <span style="color:#2563eb;margin-left:16px;">● Internal</span>
                                    <span style="color:#ea580c;margin-left:10px;">● External</span>
                                </div>
                                <div class="measurement-toolbar-group" style="margin-bottom:10px;">
                                    <button id="measurementZoomIn" type="button" class="action-button" aria-label="Zoom in on time">Zoom in (+)</button>
                                    <button id="measurementZoomOut" type="button" class="action-button" aria-label="Zoom out on time">Zoom out (−)</button>
                                    <button id="measurementToday" type="button" class="action-button">Today</button>
                                </div>
                                <div id="measurementChart" class="measurement-chart"></div>
                                <div class="measurement-chart-help">
                                    Hover to inspect. Drag across the chart to zoom into a time range. Double-click to zoom out.
                                </div>
                            </div>

                            <div class="measurement-table-wrap">
                                <table class="measurement-table">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>Time</th>
                                            <th>Temperature</th>
                                            <th>Humidity</th>
                                            <th>Probe</th>
                                            <th>Status</th>
                                            <th>Flags</th>
                                        </tr>
                                    </thead>

                                    <tbody id="measurementTableBody">
                                        <tr>
                                            <td colspan="7" class="measurement-empty">
                                                No measurements in this time range.
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div class="measurement-note">
                                Measurements are downloaded directly over USB HID. RC-4 Pro records the selected internal or external temperature probe. Humidity is unavailable on this temperature-only model.
                            </div>
                        </div>
                    </section>

                </div>
            </div>
        </main>
    </div>
</div>

<div
    id="safetyModalBackdrop"
    class="safety-modal-backdrop"
    aria-hidden="true"
>
    <div
        class="safety-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="safetyModalTitle"
    >
        <div
            id="safetyModalTitle"
            class="safety-modal-header"
        ></div>

        <div
            id="safetyModalBody"
            class="safety-modal-body"
        ></div>

        <div
            id="safetyModalActions"
            class="safety-modal-actions"
        ></div>
    </div>
</div>

<script>
const APP_TOKEN = "__APP_TOKEN__";
const IS_WINDOWS = __IS_WINDOWS__;

let devices = [];
let selectedSerial = "";
let activeTab = "measurements";

let infoBusy = false;
let configBusy = false;
let measurementsBusy = false;
let permissionBusy = false;

let currentCapacity = 32000;
let currentRecordCount = null;
let currentSessionId = null;
let configLoaded = false;
let measurementsLoaded = false;
let loadedMeasurementRecords = [];


const deviceList = document.getElementById("deviceList");
const deviceStatus = document.getElementById("deviceStatus");

const infoTabButton = document.getElementById("infoTabButton");
const configTabButton = document.getElementById("configTabButton");
const measurementsTabButton = document.getElementById("measurementsTabButton");
const infoTabPage = document.getElementById("infoTabPage");
const configTabPage = document.getElementById("configTabPage");
const measurementsTabPage = document.getElementById("measurementsTabPage");

const infoEmptyState = document.getElementById("infoEmptyState");
const infoContent = document.getElementById("infoContent");
const refreshInfoButton = document.getElementById("refreshInfoButton");
const infoLoading = document.getElementById("infoLoading");
const infoErrorBox = document.getElementById("infoErrorBox");
const permissionBox = document.getElementById("permissionBox");
const permissionButton = document.getElementById("permissionButton");
const infoSuccessBox = document.getElementById("infoSuccessBox");
const infoGrid = document.getElementById("infoGrid");

const configEmptyState = document.getElementById("configEmptyState");
const configContent = document.getElementById("configContent");
const reloadConfigButton = document.getElementById("reloadConfigButton");
const configLoading = document.getElementById("configLoading");
const configErrorBox = document.getElementById("configErrorBox");
const configSuccessBox = document.getElementById("configSuccessBox");
const configWarningBox = document.getElementById("configWarningBox");

const sampleInterval = document.getElementById("sampleInterval");
const intervalUnit = document.getElementById("intervalUnit");
const temperatureUnit = document.getElementById("temperatureUnit");
const probeSelection = document.getElementById("probeSelection");
const probeInternal = document.getElementById("probeInternal");
const probeExternal = document.getElementById("probeExternal");
const sensorNameInput = document.getElementById("sensorNameInput");
const saveSensorName = document.getElementById("saveSensorName");
const alarmHigh = document.getElementById("alarmHigh");
const alarmLow = document.getElementById("alarmLow");
const displayUnit = document.getElementById("displayUnit");
try { displayUnit.value = localStorage.getItem("elitechTemperatureUnit") === "F" ? "F" : "C"; } catch (_) {}
let lastMeasurementData = null;
let measurementRequestSequence = 0;
function intervalSeconds() { return Number(sampleInterval.value) * Number(intervalUnit.value); }
function probeColor(probe) { return probe === "internal" ? "#2563eb" : probe === "external" ? "#ea580c" : "#6b7280"; }
function displayTemperature(celsius) { return displayUnit.value === "F" ? celsius * 9 / 5 + 32 : celsius; }
const syncClock = document.getElementById("syncClock");
const currentDeviceTime = document.getElementById("currentDeviceTime");
const computerTime = document.getElementById("computerTime");
const allowButtonStop = document.getElementById("allowButtonStop");
const allowSoftwareStop = document.getElementById("allowSoftwareStop");
const configCapacity = document.getElementById("configCapacity");
const configRecordCount = document.getElementById("configRecordCount");
const configAllowed = document.getElementById("configAllowed");
const durationDays = document.getElementById("durationDays");
const durationMonths = document.getElementById("durationMonths");
const durationYears = document.getElementById("durationYears");
const saveConfigButton = document.getElementById("saveConfigButton");

const safetyModalBackdrop = document.getElementById("safetyModalBackdrop");
const safetyModalTitle = document.getElementById("safetyModalTitle");
const safetyModalBody = document.getElementById("safetyModalBody");
const safetyModalActions = document.getElementById("safetyModalActions");

const measurementsEmptyState = document.getElementById("measurementsEmptyState");
const measurementsContent = document.getElementById("measurementsContent");
const measurementRangePreset = document.getElementById("measurementRangePreset");
const measurementStart = document.getElementById("measurementStart");
const measurementEnd = document.getElementById("measurementEnd");
let measurementRange = null;
const reloadMeasurementsButton = document.getElementById("reloadMeasurementsButton");
const exportCsvButton = document.getElementById("exportCsvButton");
const measurementsLoading = document.getElementById("measurementsLoading");
const measurementsErrorBox = document.getElementById("measurementsErrorBox");
const measurementsSuccessBox = document.getElementById("measurementsSuccessBox");
const measurementStoredCount = document.getElementById("measurementStoredCount");
const measurementLoadedCount = document.getElementById("measurementLoadedCount");
const measurementPeriod = document.getElementById("measurementPeriod");
const measurementMin = document.getElementById("measurementMin");
const measurementAvg = document.getElementById("measurementAvg");
const measurementMax = document.getElementById("measurementMax");
const measurementChartWrap = document.getElementById("measurementChartWrap");
const measurementChart = document.getElementById("measurementChart");
const measurementTableBody = document.getElementById("measurementTableBody");


function currentDevice() {
    return devices.find(device => device.serial_number === selectedSerial);
}


function clearInfoMessages() {
    infoErrorBox.style.display = "none";
    permissionBox.style.display = "none";
    infoSuccessBox.style.display = "none";
}


function clearConfigMessages() {
    configErrorBox.style.display = "none";
    configSuccessBox.style.display = "none";
    configWarningBox.style.display = "none";
}


function clearMeasurementMessages() {
    measurementsErrorBox.style.display = "none";
    measurementsSuccessBox.style.display = "none";
}


function resetMeasurementView() {
    measurementRequestSequence++;
    lastMeasurementData = null;
    measurementsLoaded = false;
    loadedMeasurementRecords = [];

    measurementStoredCount.textContent = "—";
    measurementLoadedCount.textContent = "—";
    measurementPeriod.textContent = "—";
    measurementMin.textContent = "—";
    measurementAvg.textContent = "—";
    measurementMax.textContent = "—";

    measurementChartWrap.style.display = "none";
    measurementChart.innerHTML = "";

    measurementTableBody.innerHTML = "";

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = 7;
    cell.className = "measurement-empty";
    cell.textContent = "No measurements in this time range.";

    row.appendChild(cell);
    measurementTableBody.appendChild(row);

    exportCsvButton.disabled = true;
}


function updateDeviceHeaders() {
    const device = currentDevice();
    infoEmptyState.style.display = device ? "none" : "flex";
    infoContent.style.display = device ? "block" : "none";
    configEmptyState.style.display = device?.connected ? "none" : "flex";
    configEmptyState.textContent = device ? "Reconnect this sensor to change its settings." : "Select a sensor.";
    configContent.style.display = device?.connected ? "block" : "none";
    measurementsEmptyState.style.display = device ? "none" : "flex";
    measurementsEmptyState.textContent = "Select a sensor to view its saved measurements.";
    measurementsContent.style.display = device ? "block" : "none";
    sensorNameInput.disabled = !device;
    saveSensorName.disabled = !device;
    if (device && document.activeElement !== sensorNameInput) sensorNameInput.value = device.name;
    reloadMeasurementsButton.textContent = device?.syncing ? "Syncing…" : "Sync now";
    reloadMeasurementsButton.disabled = !device?.connected || device?.syncing;
}

function sensorFingerprint(device) {
    return device ? `${device.serial_number}:${device.saved_count}:${device.recording_count}:${device.data_updated}` : "";
}

function selectDevice(serial) {
    if (selectedSerial === serial) { renderDeviceList(); updateDeviceHeaders(); return; }
    selectedSerial = serial;
    configLoaded = false;
    currentRecordCount = null;
    currentSessionId = null;
    resetMeasurementView();
    clearInfoMessages(); clearConfigMessages(); clearMeasurementMessages();
    renderDeviceList(); updateDeviceHeaders();
    const device = currentDevice();
    if (!device) return;
    currentCapacity = device.metadata?.capacity || 64000;
    updateConfigPreview();
    if (activeTab === "info") refreshDeviceInfo();
    else if (activeTab === "config" && device.connected) loadDeviceConfig();
    else if (activeTab === "measurements") loadDeviceMeasurements();
}

function renderDeviceList() {
    deviceList.replaceChildren();
    for (const device of devices) {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "device-item" + (device.serial_number === selectedSerial ? " selected" : "") + (!device.connected ? " offline" : "");
        const name = document.createElement("span");
        name.className = "device-item-name";
        const dot = document.createElement("span");
        dot.className = "sensor-dot" + (device.connected ? " connected" : "");
        dot.setAttribute("aria-label", device.connected ? "Connected" : "Offline");
        const label = document.createElement("span");
        label.textContent = device.name;
        name.appendChild(dot); name.appendChild(label);
        const meta = document.createElement("span");
        meta.className = "device-item-meta";
        meta.textContent = `${device.serial_number} · ${device.syncing ? "Syncing…" : device.connected ? "Connected" : "Offline"} · ${device.saved_count} saved`;
        if (device.error) meta.title = device.error;
        item.appendChild(name); item.appendChild(meta);
        item.addEventListener("click", () => selectDevice(device.serial_number));
        deviceList.appendChild(item);
    }
    if (!devices.length) {
        const empty = document.createElement("div");
        empty.className = "device-list-empty"; empty.textContent = "Connect a logger to add it.";
        deviceList.appendChild(empty);
    }
    deviceStatus.textContent = `${devices.filter(item => item.connected).length} connected · ${devices.length} known sensors`;
}

async function refreshDevices() {
    try {
        const response = await fetch("/api/sensors");
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Could not load sensors.");
        const previous = devices;
        const oldDevice = currentDevice();
        const before = sensorFingerprint(oldDevice);
        devices = payload.sensors;
        document.getElementById("databaseLocation").textContent = payload.database_path;
        const newlyConnected = devices.find(item => item.connected && !previous.some(old => old.serial_number === item.serial_number && old.connected));
        if (!currentDevice() || (!currentDevice().connected && newlyConnected)) {
            selectDevice(newlyConnected?.serial_number || devices.find(item => item.connected)?.serial_number || devices[0]?.serial_number || "");
        } else {
            renderDeviceList(); updateDeviceHeaders();
            if (activeTab === "measurements" && before !== sensorFingerprint(currentDevice())) loadDeviceMeasurements();
            if (activeTab === "info") refreshDeviceInfo();
            if (activeTab === "config" && !oldDevice?.connected && currentDevice()?.connected) loadDeviceConfig();
        }
    } catch (error) {
        deviceStatus.textContent = error.message;
    }
}

async function renameSelectedSensor() {
    if (!selectedSerial) return;
    const response = await fetch("/api/sensor-name", {method:"POST",
        headers:{"Content-Type":"application/json", "X-Elitech-Token":APP_TOKEN},
        body:JSON.stringify({serial:selectedSerial, name:sensorNameInput.value})});
    const data = await response.json();
    if (!response.ok) { deviceStatus.textContent = data.error; return; }
    await refreshDevices();
}

async function syncSelectedSensor() {
    if (!currentDevice()?.connected) return;
    await fetch("/api/sync", {method:"POST", headers:{"Content-Type":"application/json", "X-Elitech-Token":APP_TOKEN},
        body:JSON.stringify({serial:selectedSerial})});
    await refreshDevices();
}

function renderInfoFields(fields) {
    infoGrid.innerHTML = "";

    for (const field of fields) {
        const item = document.createElement("div");
        item.className = "info-item";

        const label = document.createElement("div");
        label.className = "info-label";
        label.textContent = field.label;

        const value = document.createElement("div");
        value.className = "info-value";
        value.textContent = field.value;

        item.appendChild(label);
        item.appendChild(value);
        infoGrid.appendChild(item);
    }
}


function refreshDeviceInfo() {
    const device = currentDevice();
    if (!device) return;
    const fields = device.metadata?.fields || [{label:"Serial number", value:device.serial_number}];
    renderInfoFields([{label:"Connection", value:device.connected ? "Connected" : "Offline"},
                      {label:"Saved measurements", value:String(device.saved_count)}, ...fields]);
}

function updateConfigPreview() {
    const seconds = intervalSeconds();
    if (!Number.isFinite(seconds) || seconds <= 0) {
        durationDays.textContent = durationMonths.textContent = durationYears.textContent = "—";
        return;
    }
    const days = currentCapacity * seconds / 86400;
    durationDays.textContent = days.toLocaleString("en-US", {maximumFractionDigits:2});
    durationMonths.textContent = (days / 30.4375).toLocaleString("en-US", {maximumFractionDigits:2});
    durationYears.textContent = (days / 365.25).toLocaleString("en-US", {maximumFractionDigits:2});
}

function showSafetyConfirm({
    title,
    message,
    okSide = "right",
    okLabel = "OK",
    cancelLabel = "Cancel",
    danger = false
}) {
    return new Promise(resolve => {
        let settled = false;

        safetyModalTitle.textContent = title;
        safetyModalBody.textContent = message;
        safetyModalActions.innerHTML = "";

        const cancelButton = document.createElement("button");
        cancelButton.type = "button";
        cancelButton.className = "safety-modal-button";
        cancelButton.textContent = cancelLabel;

        const okButton = document.createElement("button");
        okButton.type = "button";
        okButton.className =
            "safety-modal-button"
            + (danger ? " danger" : "");
        okButton.textContent = okLabel;

        const finish = value => {
            if (settled) {
                return;
            }

            settled = true;

            document.removeEventListener(
                "keydown",
                onKeyDown
            );

            safetyModalBackdrop.classList.remove(
                "open"
            );

            safetyModalBackdrop.setAttribute(
                "aria-hidden",
                "true"
            );

            safetyModalActions.innerHTML = "";

            resolve(value);
        };

        const onKeyDown = event => {
            if (event.key === "Escape") {
                event.preventDefault();
                finish(false);
            }

            // Szándékosan nincs Enter=OK gyorsbillentyű.
            // A jóváhagyáshoz tényleges kattintás kell.
        };

        cancelButton.addEventListener(
            "click",
            () => finish(false)
        );

        okButton.addEventListener(
            "click",
            () => finish(true)
        );

        if (okSide === "left") {
            safetyModalActions.appendChild(okButton);
            safetyModalActions.appendChild(cancelButton);
        } else {
            safetyModalActions.appendChild(cancelButton);
            safetyModalActions.appendChild(okButton);
        }

        safetyModalBackdrop.classList.add(
            "open"
        );

        safetyModalBackdrop.setAttribute(
            "aria-hidden",
            "false"
        );

        document.addEventListener(
            "keydown",
            onKeyDown
        );

        // Mindkét ablaknál a Cancel kap fókuszt.
        // Így véletlen Enter sem tud destruktív műveletet indítani.
        cancelButton.focus();
    });
}


function updateConfigSaveState() {
    const seconds = intervalSeconds();

    const intervalValid =
        Number.isInteger(seconds) && seconds >= 10 && seconds <= 86400 && seconds % 10 === 0;

    saveConfigButton.disabled =
        !configLoaded ||
        !currentDevice()?.connected ||
        !intervalValid ||
        configBusy;
}


function renderConfig(data) {
    currentCapacity = data.capacity;
    currentRecordCount = data.record_count;
    currentSessionId = data.session_id;

    const seconds = Number(data.interval_seconds);
    intervalUnit.value = seconds % 3600 === 0 ? "3600" : seconds % 60 === 0 ? "60" : "1";
    sampleInterval.value = String(seconds / Number(intervalUnit.value));
    temperatureUnit.value = data.temperature_unit === "F" ? "F" : "C";
    probeSelection.value = data.probe === "external" ? "external" : "internal";
    probeInternal.checked = probeSelection.value === "internal";
    probeExternal.checked = probeSelection.value === "external";
    temperatureUnit.dataset.previousUnit = temperatureUnit.value;
    alarmHigh.value = data.alarm_high;
    alarmLow.value = data.alarm_low;

    allowButtonStop.checked = Boolean(data.button_stop);
    allowSoftwareStop.checked = Boolean(data.software_stop);

    currentDeviceTime.value = data.device_time || "—";

    configCapacity.textContent =
        (
            data.capacity === null
            || data.capacity === undefined
        )
        ? "-"
        : Number(data.capacity).toLocaleString("en-US") + " measurements";

    configRecordCount.textContent =
        (
            data.record_count === null
            || data.record_count === undefined
        )
        ? "-"
        : Number(data.record_count).toLocaleString("en-US");

    if (Number(data.record_count) === 0) {
        configAllowed.textContent = "Yes";
        configAllowed.className = "preview-value status-value-ok";
        configWarningBox.style.display = "none";
    } else {
        configAllowed.textContent = "Yes, with confirmation";
        configAllowed.className = "preview-value status-value-blocked";

        configWarningBox.textContent = data.blocked_reason;
        configWarningBox.style.display = "block";
    }

    configLoaded = true;
    updateConfigPreview();
    updateConfigSaveState();
}


async function loadDeviceConfig() {
    if (!currentDevice()?.connected || configBusy) {
        return;
    }

    configBusy = true;
    configLoaded = false;

    const requestedSerial = selectedSerial;
    const requestedPath = currentDevice()?.path;

    configLoading.style.display = "block";
    reloadConfigButton.disabled = true;
    saveConfigButton.disabled = true;
    clearConfigMessages();

    try {
        const response = await fetch(
            "/api/device-config?path=" +
            encodeURIComponent(requestedPath) +
            "&t=" +
            Date.now()
        );

        const data = await response.json();

        if (requestedSerial !== selectedSerial) {
            return;
        }

        if (!response.ok) {
            if (
                response.status === 403 &&
                data.code === "permission_denied"
            ) {
                throw new Error(
                    "Cannot access the logger settings. "
                    + "Open the Device information tab "
                    + "and check USB access."
                );
            }

            throw new Error(data.error || ("HTTP " + response.status));
        }

        renderConfig(data);
    } catch (error) {
        configErrorBox.textContent =
            "Could not read the settings:\n" +
            error.message;
        configErrorBox.style.display = "block";
    } finally {
        if (requestedSerial === selectedSerial) {
            configLoading.style.display = "none";
            reloadConfigButton.disabled = false;
        }

        configBusy = false;
        updateConfigSaveState();
    }
}


async function saveDeviceConfig() {
    if (
        !selectedSerial
        || configBusy
        || !configLoaded
    ) {
        return;
    }

    const seconds = intervalSeconds();
    if (!Number.isInteger(seconds) || seconds < 10 || seconds > 86400 || seconds % 10 !== 0) {
        configErrorBox.textContent = "Choose 10 seconds to 24 hours, in steps of 10 seconds.";
        configErrorBox.style.display = "block";
        return;
    }

    const requestedSerial = selectedSerial;
    const requestedPath = currentDevice()?.path;
    const confirmedRecordCount = Number(currentRecordCount);
    const confirmedSessionId = currentSessionId;
    const destructive = confirmedRecordCount > 0;

    const configSummary =
        `Logging interval: ${seconds} seconds
Logger unit: °${temperatureUnit.value}
Probe: ${probeSelection.value}
Alarm limits: ${alarmLow.value} to ${alarmHigh.value} °${temperatureUnit.value}
Start: hold the logger button after unplugging USB
Button stop: ${allowButtonStop.checked ? "enabled" : "disabled"}
Software stop: ${allowSoftwareStop.checked ? "enabled" : "disabled"}
Synchronize clock: ${syncClock.checked ? "yes" : "no"}`;

    if (destructive) {
        const firstConfirmed =
            await showSafetyConfirm({
                title: "1/2 — Existing measurements will be erased",
                message:
                    `The logger currently has at least ${confirmedRecordCount.toLocaleString("en-US")} stored measurements.

Preparing a new session erases all measurements in this recording session, including new samples collected before saving.

Download your measurements and export CSV before continuing.

${configSummary}`,
                okSide: "left",
                okLabel: "OK",
                cancelLabel: "Cancel",
                danger: false
            });

        if (!firstConfirmed) {
            return;
        }

        const secondConfirmed =
            await showSafetyConfirm({
                title: "2/2 — Confirm erasing measurements",
                message:
                    `This is the final confirmation.

Clicking OK will save settings and erase all measurements in this recording session, including samples collected while you configure it.

After saving, unplug USB and hold the logger button for 5 seconds to begin recording.`,
                okSide: "right",
                okLabel: "OK",
                cancelLabel: "Cancel",
                danger: true
            });

        if (!secondConfirmed) {
            return;
        }
    } else {
        const confirmed =
            await showSafetyConfirm({
                title: "Save and prepare logging",
                message:
                    `${configSummary}

After saving, unplug USB and hold the logger button for 5 seconds to begin recording.

Settings and the clock will be saved before preparing the logger.`,
                okSide: "right",
                okLabel: "OK",
                cancelLabel: "Cancel",
                danger: false
            });

        if (!confirmed) {
            return;
        }
    }

    if (selectedSerial !== requestedSerial || currentSessionId !== confirmedSessionId) {
        configErrorBox.textContent = "The selected recording session changed. Reload the settings and confirm again.";
        configErrorBox.style.display = "block";
        return;
    }
    configBusy = true;
    saveConfigButton.disabled = true;
    reloadConfigButton.disabled = true;
    clearConfigMessages();

    try {
        const response = await fetch(
            "/api/device-config",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Elitech-Token": APP_TOKEN
                },
                body: JSON.stringify({
                    path: requestedPath,
                    interval_seconds: seconds,
                    temperature_unit: temperatureUnit.value,
                    probe: probeSelection.value,
                    alarm_high: Number(alarmHigh.value),
                    alarm_low: Number(alarmLow.value),
                    sync_clock: syncClock.checked,
                    button_stop: allowButtonStop.checked,
                    software_stop: allowSoftwareStop.checked,
                    allow_data_loss: destructive,
                    expected_record_count: confirmedRecordCount,
                    expected_session_id: confirmedSessionId
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error
                || ("HTTP " + response.status)
            );
        }

        configSuccessBox.textContent =
            (
                destructive
                ? `${Number(data.record_count_before_save).toLocaleString("en-US")} measurements were erased from the confirmed session. `
                : ""
            )
            + data.message
            + " Logger time: "
            + data.device_time
            + " "
            + (data.persistence_note || "");

        configSuccessBox.style.display = "block";

        resetMeasurementView();
        displayUnit.value = temperatureUnit.value;
        try { localStorage.setItem("elitechTemperatureUnit", displayUnit.value); } catch (_) {}
        // Read back the complete configuration after preparing the logger.
        configBusy = false;
        await loadDeviceConfig();

        // A sikerüzenetet a load ne takarja el.
        configSuccessBox.textContent =
            (
                destructive
                ? `${Number(data.record_count_before_save).toLocaleString("en-US")} measurements were erased from the confirmed session. `
                : ""
            )
            + data.message
            + " Logger time: "
            + data.device_time
            + " "
            + (data.persistence_note || "");

        configSuccessBox.style.display = "block";

    } catch (error) {
        configErrorBox.textContent =
            "Could not prepare logging:\n"
            + error.message;
        configErrorBox.style.display = "block";
    } finally {
        configBusy = false;
        reloadConfigButton.disabled = false;
        updateConfigSaveState();
    }
}



function formatTemperature(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) {
        return "—";
    }

    return displayTemperature(Number(value)).toLocaleString(
        "en-US",
        {
            minimumFractionDigits: 1,
            maximumFractionDigits: 1
        }
    ) + " °" + displayUnit.value;
}


function formatHumidity(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) {
        return "-";
    }

    return Number(value).toLocaleString(
        "en-US",
        {
            minimumFractionDigits: 1,
            maximumFractionDigits: 1
        }
    ) + " %";
}


function renderMeasurementTable(records) {
    measurementTableBody.innerHTML = "";

    if (records.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 7;
        cell.className = "measurement-empty";
        cell.textContent = "No measurements in this time range.";

        row.appendChild(cell);
        measurementTableBody.appendChild(row);
        return;
    }

    for (const record of records) {
        const row = document.createElement("tr");

        if (record.status === "Parse error") {
            row.className = "error-row";
        } else if (record.status !== "Measurement") {
            row.className = "event-row";
        }

        const values = [
            record.index,
            record.timestamp || "—",
            formatTemperature(record.temperature),
            formatHumidity(record.humidity),
            record.probe || "unknown",
            record.status || "—",
            (
                Array.isArray(record.flags) && record.flags.length
                ? record.flags.join(", ")
                : "—"
            )
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = String(value);
            if (index === 4) { cell.style.color = probeColor(record.probe); cell.style.fontWeight = "600"; }

            if (index === 0 || index === 2 || index === 3) {
                cell.className = "numeric";
            }

            if (
                record.status === "Parse error"
                && index === 6
                && record.raw_hex
            ) {
                cell.textContent =
                    "raw: " + record.raw_hex;
                cell.title = record.parse_error || "";
            }

            row.appendChild(cell);
        });

        measurementTableBody.appendChild(row);
    }
}


function parseMeasurementTimestamp(timestamp) {
    const match = String(timestamp || "").match(
        /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/
    );

    if (!match) {
        return NaN;
    }

    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);

    return new Date(
        year,
        month - 1,
        day,
        hour,
        minute,
        second
    ).getTime();
}


function formatChartAxisLabel(timeMs, spanMs) {
    const date = new Date(timeMs);
    if (spanMs <= 5 * 60 * 1000) {
        return new Intl.DateTimeFormat("en-US", {
            hour: "2-digit", minute: "2-digit", second: "2-digit"
        }).format(date);
    }

    if (spanMs <= 36 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "en-US",
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 10 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "en-US",
            {
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 90 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "en-US",
            {
                month: "short",
                day: "2-digit"
            }
        ).format(date);
    }

    if (spanMs <= 550 * 24 * 60 * 60 * 1000) {
        return new Intl.DateTimeFormat(
            "en-US",
            {
                year: "numeric",
                month: "short"
            }
        ).format(date);
    }

    return new Intl.DateTimeFormat(
        "en-US",
        {
            year: "numeric"
        }
    ).format(date);
}


function formatChartTooltipTime(timeMs) {
    return new Intl.DateTimeFormat(
        "en-US",
        {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    ).format(new Date(timeMs));
}


function findNearestMeasurementByTime(points, targetTime) {
    if (points.length === 0) {
        return null;
    }

    let low = 0;
    let high = points.length - 1;

    while (low < high) {
        const middle = Math.floor(
            (low + high) / 2
        );

        if (points[middle].time < targetTime) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if (low === 0) {
        return points[0];
    }

    const current = points[low];
    const previous = points[low - 1];

    return (
        Math.abs(current.time - targetTime)
        < Math.abs(previous.time - targetTime)
        ? current
        : previous
    );
}


function renderMeasurementChart(records) {
    const chartData = records
        .filter(
            record =>
                record.status === "Measurement"
                && record.timestamp
                && record.temperature !== null
                && Number.isFinite(Number(record.temperature))
        )
        .map(
            record => ({
                ...record,
                time: parseMeasurementTimestamp(record.timestamp),
                temperatureNumber: displayTemperature(Number(record.temperature))
            })
        )
        .filter(
            record => Number.isFinite(record.time)
        )
        .sort(
            (a, b) => a.time - b.time
        );

    const minTime = measurementRange?.start ?? chartData[0]?.time ?? Date.now() - 3600000;
    const maxTime = measurementRange?.end ?? Math.max(minTime + 1000, (chartData[chartData.length - 1]?.time ?? Date.now()) + 1000);
    const timeSpan = Math.max(1, maxTime - minTime);

    const temperatures = chartData.map(
        record => record.temperatureNumber
    );

    let minTemp = temperatures.reduce((a, b) => Math.min(a, b), Infinity);
    let maxTemp = temperatures.reduce((a, b) => Math.max(a, b), -Infinity);

    if (!temperatures.length) { minTemp = 0; maxTemp = 1; }
    if (minTemp === maxTemp) {
        minTemp -= 0.5;
        maxTemp += 0.5;
    }

    const width = 1000;
    const height = 300;
    const left = 68;
    const right = 22;
    const top = 18;
    const bottom = 62;

    const plotWidth = width - left - right;
    const plotHeight = height - top - bottom;

    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute(
        "aria-label",
        "Interactive temperature chart"
    );

    const xForTime = time =>
        left
        + ((time - minTime) / timeSpan) * plotWidth;

    const yForTemperature = temperature =>
        top
        + (
            (maxTemp - temperature)
            / (maxTemp - minTemp)
        ) * plotHeight;

    const addLine = (
        x1,
        y1,
        x2,
        y2,
        stroke,
        dash = "",
        widthValue = "1"
    ) => {
        const line = document.createElementNS(ns, "line");
        line.setAttribute("x1", x1);
        line.setAttribute("y1", y1);
        line.setAttribute("x2", x2);
        line.setAttribute("y2", y2);
        line.setAttribute("stroke", stroke);
        line.setAttribute("stroke-width", widthValue);

        if (dash) {
            line.setAttribute("stroke-dasharray", dash);
        }

        svg.appendChild(line);
        return line;
    };

    const addText = (
        x,
        y,
        value,
        anchor = "start",
        fontSize = "12"
    ) => {
        const node = document.createElementNS(ns, "text");
        node.setAttribute("x", x);
        node.setAttribute("y", y);
        node.setAttribute("text-anchor", anchor);
        node.setAttribute("font-size", fontSize);
        node.setAttribute("fill", "#5e6673");
        node.textContent = value;
        svg.appendChild(node);
        return node;
    };

    // Y grid + labels.
    for (let gridIndex = 0; gridIndex <= 4; gridIndex++) {
        const ratio = gridIndex / 4;
        const y = top + ratio * plotHeight;
        const value =
            maxTemp - ratio * (maxTemp - minTemp);

        addLine(
            left,
            y,
            width - right,
            y,
            "#e2e6eb"
        );

        addText(
            left - 9,
            y + 4,
            value.toLocaleString(
                "en-US",
                {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1
                }
            ) + " °" + displayUnit.value,
            "end"
        );
    }

    // Adaptive X axis.
    const tickCount = 7;

    for (let tickIndex = 0; tickIndex < tickCount; tickIndex++) {
        const ratio =
            tickIndex / (tickCount - 1);

        const tickTime =
            minTime + ratio * timeSpan;

        const x =
            left + ratio * plotWidth;

        addLine(
            x,
            top,
            x,
            top + plotHeight,
            "#eef0f3",
            "3 5"
        );

        addText(
            x,
            height - 22,
            formatChartAxisLabel(
                tickTime,
                timeSpan
            ),
            (
                tickIndex === 0
                ? "start"
                : (
                    tickIndex === tickCount - 1
                    ? "end"
                    : "middle"
                )
            ),
            "11"
        );
    }

    if (!chartData.length) addText(width / 2, height / 2, "No measurements in this time range", "middle", "14");

    // Temperature line.
    const groups = new Map();
    for (const record of chartData) {
        const key = `${record.session_id || "recording"}:${record.probe || "unknown"}`;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(record);
    }
    const stride = Math.max(1, Math.ceil(chartData.length / 1500));
    for (const records of groups.values()) {
        const points = records.filter((_, i) => i === 0 || i % stride === 0 || i === records.length - 1);
        const polyline = document.createElementNS(ns, "polyline");
        polyline.setAttribute("points", points.map(record => `${xForTime(record.time).toFixed(2)},${yForTemperature(record.temperatureNumber).toFixed(2)}`).join(" "));
        polyline.setAttribute("fill", "none");
        polyline.setAttribute("stroke", probeColor(records[0].probe));
        polyline.setAttribute("stroke-width", "2");
        polyline.setAttribute("vector-effect", "non-scaling-stroke");
        svg.appendChild(polyline);
        if (records.length === 1) {
            const point = document.createElementNS(ns, "circle");
            point.setAttribute("cx", xForTime(records[0].time));
            point.setAttribute("cy", yForTemperature(records[0].temperatureNumber));
            point.setAttribute("r", "4"); point.setAttribute("fill", probeColor(records[0].probe));
            svg.appendChild(point);
        }
    }

    const hoverLine = document.createElementNS(ns, "line");
    hoverLine.setAttribute("stroke", "#5d6570");
    hoverLine.setAttribute("stroke-width", "1");
    hoverLine.setAttribute("stroke-dasharray", "4 4");
    hoverLine.style.display = "none";
    svg.appendChild(hoverLine);

    // Hover point.
    const hoverCircle = document.createElementNS(ns, "circle");
    hoverCircle.setAttribute("r", "5");
    hoverCircle.setAttribute("fill", "#2457d6");
    hoverCircle.setAttribute("stroke", "#ffffff");
    hoverCircle.setAttribute("stroke-width", "2");
    hoverCircle.style.display = "none";
    svg.appendChild(hoverCircle);

    // Tooltip.
    const tooltipGroup = document.createElementNS(ns, "g");
    tooltipGroup.style.display = "none";
    tooltipGroup.style.pointerEvents = "none";

    const tooltipRect = document.createElementNS(ns, "rect");
    tooltipRect.setAttribute("width", "210");
    tooltipRect.setAttribute("height", "70");
    tooltipRect.setAttribute("rx", "6");
    tooltipRect.setAttribute("fill", "#ffffff");
    tooltipRect.setAttribute("stroke", "#b9c0c9");
    tooltipGroup.appendChild(tooltipRect);

    const tooltipTime = document.createElementNS(ns, "text");
    tooltipTime.setAttribute("x", "10");
    tooltipTime.setAttribute("y", "20");
    tooltipTime.setAttribute("font-size", "12");
    tooltipTime.setAttribute("fill", "#3d4652");
    tooltipGroup.appendChild(tooltipTime);

    const tooltipTemperature = document.createElementNS(ns, "text");
    tooltipTemperature.setAttribute("x", "10");
    tooltipTemperature.setAttribute("y", "41");
    tooltipTemperature.setAttribute("font-size", "14");
    tooltipTemperature.setAttribute("font-weight", "700");
    tooltipTemperature.setAttribute("fill", "#2457d6");
    tooltipGroup.appendChild(tooltipTemperature);

    const tooltipIndex = document.createElementNS(ns, "text");
    tooltipIndex.setAttribute("x", "10");
    tooltipIndex.setAttribute("y", "60");
    tooltipIndex.setAttribute("font-size", "11");
    tooltipIndex.setAttribute("fill", "#69717c");
    tooltipGroup.appendChild(tooltipIndex);

    svg.appendChild(tooltipGroup);

    // Transparent interaction layer over the plot.
    const hoverOverlay = document.createElementNS(ns, "rect");
    hoverOverlay.setAttribute("x", left);
    hoverOverlay.setAttribute("y", top);
    hoverOverlay.setAttribute("width", plotWidth);
    hoverOverlay.setAttribute("height", plotHeight);
    hoverOverlay.setAttribute("fill", "transparent");
    hoverOverlay.style.pointerEvents = "all";
    hoverOverlay.style.touchAction = "none";
    const selection = document.createElementNS(ns, "rect");
    selection.setAttribute("y", top);
    selection.setAttribute("height", plotHeight);
    selection.setAttribute("fill", "#2563eb");
    selection.setAttribute("fill-opacity", "0.18");
    selection.setAttribute("stroke", "#2563eb");
    selection.style.pointerEvents = "none";
    selection.style.display = "none";
    svg.appendChild(selection);
    let dragStart = null;
    const plotX = event => {
        const bounds = svg.getBoundingClientRect();
        return Math.max(left, Math.min(width - right, (event.clientX - bounds.left) / bounds.width * width));
    };
    const timeAtX = x => minTime + (x - left) / plotWidth * timeSpan;
    hoverOverlay.addEventListener("pointerdown", event => {
        if (event.button !== undefined && event.button !== 0) return;
        event.preventDefault();
        dragStart = plotX(event);
        hoverOverlay.setPointerCapture(event.pointerId);
        selection.setAttribute("x", dragStart);
        selection.setAttribute("width", 0);
        selection.style.display = "";
    });
    hoverOverlay.addEventListener("pointermove", event => {
        if (dragStart === null) return;
        const x = plotX(event);
        selection.setAttribute("x", Math.min(dragStart, x));
        selection.setAttribute("width", Math.abs(x - dragStart));
        hoverLine.style.display = hoverCircle.style.display = tooltipGroup.style.display = "none";
    });
    hoverOverlay.addEventListener("pointerup", event => {
        if (dragStart === null) return;
        const x = plotX(event), first = dragStart;
        dragStart = null;
        selection.style.display = "none";
        hoverOverlay.releasePointerCapture(event.pointerId);
        if (Math.abs(x - first) >= 6) {
            setMeasurementRange(timeAtX(Math.min(x, first)), timeAtX(Math.max(x, first)));
        }
    });
    hoverOverlay.addEventListener("pointercancel", () => {
        dragStart = null;
        selection.style.display = "none";
    });
    hoverOverlay.addEventListener("dblclick", () => zoomMeasurementTime(2));

    hoverOverlay.addEventListener(
        "mousemove",
        event => {
            if (dragStart !== null) return;
            const bounds = svg.getBoundingClientRect();

            const mouseX =
                ((event.clientX - bounds.left) / bounds.width)
                * width;

            const clampedX = Math.max(
                left,
                Math.min(width - right, mouseX)
            );

            const targetTime =
                minTime
                + ((clampedX - left) / plotWidth) * timeSpan;

            const nearest =
                findNearestMeasurementByTime(
                    chartData,
                    targetTime
                );

            if (!nearest) {
                return;
            }

            const pointX = xForTime(nearest.time);
            const pointY =
                yForTemperature(nearest.temperatureNumber);

            hoverLine.setAttribute("x1", pointX);
            hoverLine.setAttribute("x2", pointX);
            hoverLine.setAttribute("y1", top);
            hoverLine.setAttribute("y2", top + plotHeight);
            hoverLine.style.display = "";

            hoverCircle.setAttribute("fill", probeColor(nearest.probe));
            hoverCircle.setAttribute("cx", pointX);
            hoverCircle.setAttribute("cy", pointY);
            hoverCircle.style.display = "";

            tooltipTime.textContent =
                formatChartTooltipTime(nearest.time);

            tooltipTemperature.textContent =
                formatTemperature(
                    nearest.temperature
                );

            tooltipIndex.textContent =
                (nearest.probe || "unknown") + " probe · #" + nearest.index;

            const tooltipWidth = 210;
            const tooltipHeight = 70;

            let tooltipX = pointX + 12;

            if (
                tooltipX + tooltipWidth
                > width - right
            ) {
                tooltipX =
                    pointX - tooltipWidth - 12;
            }

            let tooltipY =
                pointY - tooltipHeight - 10;

            if (tooltipY < top) {
                tooltipY = pointY + 12;
            }

            tooltipGroup.setAttribute(
                "transform",
                `translate(${tooltipX}, ${tooltipY})`
            );

            tooltipGroup.style.display = "";
        }
    );

    hoverOverlay.addEventListener(
        "mouseleave",
        () => {
            hoverLine.style.display = "none";
            hoverCircle.style.display = "none";
            tooltipGroup.style.display = "none";
        }
    );

    svg.appendChild(hoverOverlay);

    measurementChart.replaceChildren(svg);
    measurementChartWrap.style.display = "block";
}


function renderMeasurementSummary(data) {
    const records = data.records || [];

    measurementStoredCount.textContent =
        Number(data.stored_count || 0).toLocaleString("en-US");

    measurementLoadedCount.textContent =
        Number(data.loaded_count || 0).toLocaleString("en-US");

    const timedRecords = records.filter(
        record => Boolean(record.timestamp)
    );

    if (measurementRange) {
        measurementPeriod.textContent = localDateTime(measurementRange.start).replace("T", " ")
            + " → " + localDateTime(measurementRange.end).replace("T", " ");
    } else if (timedRecords.length > 0) {
        measurementPeriod.textContent =
            timedRecords[0].timestamp
            + " → "
            + timedRecords[timedRecords.length - 1].timestamp;
    } else {
        measurementPeriod.textContent = "—";
    }

    const temperatures = records
        .filter(
            record =>
                record.status === "Measurement"
                && record.temperature !== null
                && Number.isFinite(Number(record.temperature))
        )
        .map(
            record => Number(record.temperature)
        );

    if (temperatures.length === 0) {
        measurementMin.textContent = "—";
        measurementAvg.textContent = "—";
        measurementMax.textContent = "—";
        return;
    }

    const minimum = temperatures.reduce((a, b) => Math.min(a, b), Infinity);
    const maximum = temperatures.reduce((a, b) => Math.max(a, b), -Infinity);
    const average =
        temperatures.reduce((sum, value) => sum + value, 0)
        / temperatures.length;

    measurementMin.textContent = formatTemperature(minimum);
    measurementAvg.textContent = formatTemperature(average);
    measurementMax.textContent = formatTemperature(maximum);
}


function renderMeasurements(data) {
    lastMeasurementData = data;
    loadedMeasurementRecords = Array.isArray(data.records)
        ? data.records
        : [];

    measurementsLoaded = true;

    renderMeasurementSummary(data);
    renderMeasurementTable(loadedMeasurementRecords);
    renderMeasurementChart(loadedMeasurementRecords);

    exportCsvButton.disabled =
        loadedMeasurementRecords.length === 0;
}


// Bounds use local wall time, matching timestamps saved from the logger.
function localDateTime(time) {
    const d = new Date(time), pad = n => String(n).padStart(2, "0");
    return `${String(d.getFullYear()).padStart(4, "0")}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function setMeasurementRange(start, end, preset = "custom", reload = true) {
    start = Math.floor(start / 1000) * 1000;
    end = Math.ceil(end / 1000) * 1000;
    if (!Number.isFinite(start) || !Number.isFinite(end) || end - start < 1000
        || new Date(start).getFullYear() < 1 || new Date(end).getFullYear() > 9999) {
        measurementsErrorBox.textContent = "Choose a valid start and end time, with the end after the start.";
        measurementsErrorBox.style.display = "block";
        return false;
    }
    measurementRange = {start, end};
    measurementRangePreset.value = preset;
    measurementStart.value = localDateTime(start);
    measurementEnd.value = localDateTime(end);
    clearMeasurementMessages();
    if (reload) { resetMeasurementView(); loadDeviceMeasurements(); }
    return true;
}

function useMeasurementPreset(preset, reload = true) {
    if (preset === "custom") return;
    if (preset === "all") {
        measurementRange = null;
        measurementStart.value = measurementEnd.value = "";
        measurementRangePreset.value = "all";
        if (reload) { resetMeasurementView(); loadDeviceMeasurements(); }
        return;
    }
    const start = new Date(), end = new Date();
    start.setHours(0, 0, 0, 0);
    end.setHours(0, 0, 0, 0);
    if (preset === "yesterday") start.setDate(start.getDate() - 1);
    else {
        end.setDate(end.getDate() + 1);
        if (preset === "week") start.setDate(start.getDate() - 6);
        if (preset === "month") start.setDate(start.getDate() - 29);
    }
    setMeasurementRange(start.getTime(), end.getTime(), preset, reload);
}

function applyMeasurementRange() {
    setMeasurementRange(parseMeasurementTimestamp(measurementStart.value.replace("T", " ").padEnd(19, ":00")),
        parseMeasurementTimestamp(measurementEnd.value.replace("T", " ").padEnd(19, ":00")));
}

function zoomMeasurementTime(factor) {
    let range = measurementRange;
    if (!range) {
        const times = loadedMeasurementRecords.map(r => parseMeasurementTimestamp(r.timestamp)).filter(Number.isFinite);
        if (times.length) range = {start: times.reduce((a,b) => Math.min(a,b), Infinity), end: times.reduce((a,b) => Math.max(a,b), -Infinity) + 1000};
        else { useMeasurementPreset("today"); return; }
    }
    const middle = (range.start + range.end) / 2;
    const span = Math.max(1000, (range.end - range.start) * factor);
    setMeasurementRange(middle - span / 2, middle + span / 2);
}

async function loadDeviceMeasurements() {
    if (!selectedSerial) return;
    const serial = selectedSerial;
    const request = ++measurementRequestSequence;
    measurementsBusy = true;
    clearMeasurementMessages();
    measurementsLoading.style.display = "block";
    try {
        let url = "/api/sensor-records?serial=" + encodeURIComponent(serial);
        if (measurementRange) {
            url += "&start=" + encodeURIComponent(localDateTime(measurementRange.start).replace("T", " "))
                + "&end=" + encodeURIComponent(localDateTime(measurementRange.end).replace("T", " "));
        }
        const response = await fetch(url);
        const data = await response.json();
        if (request !== measurementRequestSequence || serial !== selectedSerial) return;
        if (!response.ok) throw new Error(data.error || "Could not load saved measurements.");
        if (data.serial_number !== serial) throw new Error("The response belongs to another sensor.");
        renderMeasurements(data);
        measurementsSuccessBox.textContent = `${data.loaded_count} measurements in the selected time range (${data.stored_count} saved for this sensor).`;
        measurementsSuccessBox.style.display = "block";
    } catch (error) {
        if (request === measurementRequestSequence) {
            measurementsErrorBox.textContent = error.message;
            measurementsErrorBox.style.display = "block";
        }
    } finally {
        if (request === measurementRequestSequence) {
            measurementsBusy = false;
            measurementsLoading.style.display = "none";
            updateDeviceHeaders();
        }
    }
}

function csvEscape(value) {
    const text = String(
        value === null || value === undefined
        ? ""
        : value
    );

    if (
        text.includes(";")
        || text.includes('"')
        || text.includes("\n")
        || text.includes("\r")
    ) {
        return '"'
            + text.replaceAll('"', '""')
            + '"';
    }

    return text;
}


function exportMeasurementsCsv() {
    if (loadedMeasurementRecords.length === 0) {
        return;
    }

    const rows = [
        [
            "Logger serial",
            "Index",
            "Time",
            `Temperature (°${displayUnit.value})`,
            "Humidity (%)",
            "Probe",
            "Status",
            "Flags",
            "Raw record"
        ]
    ];

    for (const record of loadedMeasurementRecords) {
        rows.push(
            [
                lastMeasurementData?.serial_number || selectedSerial,
                record.index,
                record.timestamp || "",
                (
                    record.temperature === null
                    || record.temperature === undefined
                    ? ""
                    : displayTemperature(Number(record.temperature)).toFixed(1)
                ),
                (
                    record.humidity === null
                    || record.humidity === undefined
                    ? ""
                    : Number(record.humidity).toFixed(1)
                ),
                record.probe || "unknown",
                record.status || "",
                (
                    Array.isArray(record.flags)
                    ? record.flags.join(", ")
                    : ""
                ),
                record.raw_hex || ""
            ]
        );
    }

    const csv =
        "\uFEFF"
        + rows
            .map(
                row =>
                    row
                        .map(csvEscape)
                        .join(";")
            )
            .join("\r\n");

    const blob = new Blob(
        [csv],
        {
            type: "text/csv;charset=utf-8"
        }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    const now = new Date();
    const datePart =
        now.getFullYear()
        + "-"
        + String(now.getMonth() + 1).padStart(2, "0")
        + "-"
        + String(now.getDate()).padStart(2, "0");

    link.href = url;
    link.download =
        "elitech-" + (lastMeasurementData?.serial_number || selectedSerial) + "-measurements-"
        + datePart
        + ".csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}


async function installPermissionRule() {
    if (permissionBusy) {
        return;
    }

    permissionBusy = true;
    permissionButton.disabled = true;

    try {
        const response = await fetch(
            "/api/install-udev",
            {
                method: "POST",
                headers: {
                    "X-Elitech-Token": APP_TOKEN
                }
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || ("HTTP " + response.status));
        }

        infoSuccessBox.textContent = data.message;
        infoSuccessBox.style.display = "block";

        await new Promise(resolve => setTimeout(resolve, 700));
        await refreshDevices();

        if (activeTab === "info") {
            await refreshDeviceInfo();
        }
    } catch (error) {
        infoErrorBox.textContent =
            "Could not set up USB access:\n"
            + error.message;
        infoErrorBox.style.display = "block";
    } finally {
        permissionBusy = false;
        permissionButton.disabled = false;
    }
}


function openTab(tabName) {
    activeTab = tabName;
    for (const [name, button, page] of [["info",infoTabButton,infoTabPage], ["config",configTabButton,configTabPage], ["measurements",measurementsTabButton,measurementsTabPage]]) {
        button.classList.toggle("active", tabName === name);
        page.classList.toggle("active", tabName === name);
    }
    updateDeviceHeaders();
    if (tabName === "measurements") loadDeviceMeasurements();
    else if (tabName === "config" && currentDevice()?.connected) loadDeviceConfig();
    else if (tabName === "info") refreshDeviceInfo();
}

function updateComputerTime() {
    computerTime.value =
        new Intl.DateTimeFormat(
            "en-US",
            {
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        ).format(new Date());
}


infoTabButton.addEventListener(
    "click",
    () => openTab("info")
);

configTabButton.addEventListener(
    "click",
    () => openTab("config")
);

measurementsTabButton.addEventListener(
    "click",
    () => openTab("measurements")
);

refreshInfoButton.addEventListener(
    "click",
    refreshDeviceInfo
);

reloadConfigButton.addEventListener(
    "click",
    loadDeviceConfig
);

saveConfigButton.addEventListener(
    "click",
    saveDeviceConfig
);

reloadMeasurementsButton.addEventListener(
    "click",
    syncSelectedSensor
);

exportCsvButton.addEventListener(
    "click",
    exportMeasurementsCsv
);

permissionButton.addEventListener(
    "click",
    installPermissionRule
);

sampleInterval.addEventListener(
    "input",
    () => {
        updateConfigPreview();
        updateConfigSaveState();
    }
);


saveSensorName.addEventListener("click", renameSelectedSensor);
probeInternal.addEventListener("change", () => { if (probeInternal.checked) probeSelection.value = "internal"; });
probeExternal.addEventListener("change", () => { if (probeExternal.checked) probeSelection.value = "external"; });
measurementRangePreset.addEventListener("change", () => useMeasurementPreset(measurementRangePreset.value));
for (const input of [measurementStart, measurementEnd]) {
    input.addEventListener("input", () => { measurementRangePreset.value = "custom"; });
    input.addEventListener("keydown", event => { if (event.key === "Enter") applyMeasurementRange(); });
}
document.getElementById("applyMeasurementRange").addEventListener("click", applyMeasurementRange);
document.getElementById("measurementZoomIn").addEventListener("click", () => zoomMeasurementTime(0.5));
document.getElementById("measurementZoomOut").addEventListener("click", () => zoomMeasurementTime(2));
document.getElementById("measurementToday").addEventListener("click", () => useMeasurementPreset("today"));
temperatureUnit.addEventListener("change", () => {
    const oldUnit = temperatureUnit.dataset.previousUnit || "C";
    if (oldUnit !== temperatureUnit.value) {
        for (const field of [alarmHigh, alarmLow]) {
            const value = Number(field.value);
            if (Number.isFinite(value)) field.value = (temperatureUnit.value === "F" ? value * 9 / 5 + 32 : (value - 32) * 5 / 9).toFixed(1);
        }
    }
    temperatureUnit.dataset.previousUnit = temperatureUnit.value;
});
document.getElementById("resetAlarmLimits").addEventListener("click", () => {
    alarmHigh.value = temperatureUnit.value === "F" ? "140" : "60";
    alarmLow.value = temperatureUnit.value === "F" ? "-22" : "-30";
});
intervalUnit.addEventListener("change", () => { updateConfigPreview(); updateConfigSaveState(); });
displayUnit.addEventListener("change", () => {
    try { localStorage.setItem("elitechTemperatureUnit", displayUnit.value); } catch (_) {}
    if (lastMeasurementData) renderMeasurements(lastMeasurementData);
});

async function start() {
    useMeasurementPreset("today", false);
    updateComputerTime();
    updateConfigPreview();

    // Ez csak a helyi számítógép kijelzett óráját frissíti.
    setInterval(updateComputerTime, 1000);

    await refreshDevices();

    // Csak az eszközlista frissül automatikusan.
    // A HID-adatok csak tab megnyitáskor vagy gombnyomásra frissülnek.
    setInterval(refreshDevices, 1000);
}


start();
</script>
</body>
</html>
"""


# ============================================================
# HTTP szerver
# ============================================================

def identify_sensor(path):
    with HID_LOCK:
        fd = open_device(path)
        try:
            return hid_get_parameter(fd, 0, 14)[2:14].decode("ascii").strip("\x00 ")
        finally:
            fd.close()


def inspect_sensor(path):
    config = read_device_config(path)
    info = read_device_info(path)
    if config["serial_number"] != info["serial_number"]:
        raise OSError("The logger changed while its identity was being read.")
    config["fields"] = info["fields"]
    return config


class LocalHTTPServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR can allow two active servers on the same port.
    # Exclusive ownership also makes launching the app twice reopen its page.
    allow_reuse_address = sys.platform != "win32"

    def server_bind(self):
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        html = html.replace("__APP_TOKEN__", APP_TOKEN)
        html = html.replace("__IS_WINDOWS__", json.dumps(sys.platform == "win32"))
        body = html.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        content_length = self.headers.get("Content-Length", "0")

        try:
            length = int(content_length)
        except ValueError:
            raise ValueError("Invalid Content-Length.")

        if length < 0 or length > 64 * 1024:
            raise ValueError("Invalid request size.")

        raw = self.rfile.read(length)

        if not raw:
            return {}

        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Invalid JSON request.")

    def require_write_token(self):
        token = self.headers.get("X-Elitech-Token", "")

        if token != APP_TOKEN:
            self.send_json(
                {"error": "Invalid or missing application token."},
                status=403,
            )
            return False

        return True

    def resolve_device_or_404(self, device_path):
        device = find_device(device_path)

        if device is None:
            self.send_json(
                {
                    "error": (
                        "The selected logger is no longer connected."
                    )
                },
                status=404,
            )
            return None

        return device

    def send_device_exception(self, error):
        LOGGER.exception(
            "REQUEST ERROR | %s: %s",
            type(error).__name__,
            error,
        )

        if isinstance(error, PermissionError):
            self.send_json(
                {
                    "code": "permission_denied",
                    "error": "Cannot open the logger. Close other logger apps and check the USB connection.",
                },
                status=403,
            )
            return

        if isinstance(error, TimeoutError):
            self.send_json(
                {"error": str(error)},
                status=504,
            )
            return

        if isinstance(error, ValueError):
            self.send_json(
                {"error": str(error)},
                status=400,
            )
            return

        self.send_json(
            {"error": str(error)},
            status=500,
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_html(HTML)
            return

        if path == "/api/health":
            self.send_json({"app": "elitech-hid-webui", "version": APP_VERSION})
            return

        if path == "/api/sensors":
            self.send_json({"sensors": SYNC_MANAGER.snapshot() if SYNC_MANAGER else get_history().sensors(),
                            "database_path": str(get_history().path)})
            return

        if path == "/api/sensor-records":
            query = parse_qs(parsed.query)
            try:
                self.send_json(get_history().sensor_recording(query.get("serial", [""])[0],
                    query.get("session_id", ["all"])[0], int(query.get("limit", ["0"])[0]),
                    start=query.get("start", [None])[0], end=query.get("end", [None])[0]))
            except ValueError as error:
                self.send_device_exception(error)
            return

        if path == "/api/devices":
            try:
                self.send_json(scan_devices())
            except (OSError, RuntimeError) as error:
                self.send_device_exception(error)
            return

        if path == "/api/device-info":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                info = read_device_info(device_path)
                info["device"] = device
                self.send_json(info)
            except (
                PermissionError,
                TimeoutError,
                OSError,
                ValueError,
                RuntimeError,
            ) as error:
                self.send_device_exception(error)

            return

        if path == "/api/device-records":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            try:
                limit = int(
                    query.get("limit", ["500"])[0]
                )
            except ValueError:
                self.send_json(
                    {"error": "Invalid record limit."},
                    status=400,
                )
                return

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                data = read_device_records(
                    device_path,
                    limit=limit,
                )
                data["device"] = device
                self.send_json(data)
            except Exception as error:
                self.send_device_exception(error)

            return

        if path == "/api/history":
            self.send_json(get_history().sessions())
            return

        if path == "/api/history-records":
            query = parse_qs(parsed.query)
            try:
                self.send_json(get_history().recording(query.get("session_id", [""])[0],
                                                int(query.get("limit", ["0"])[0])))
            except (ValueError, OSError) as error:
                self.send_device_exception(error)
            return

        if path == "/api/device-config":
            query = parse_qs(parsed.query)
            device_path = query.get("path", [""])[0]

            device = self.resolve_device_or_404(device_path)
            if device is None:
                return

            try:
                config = read_device_config(device_path)
                config["device"] = device
                self.send_json(config)
            except Exception as error:
                self.send_device_exception(error)

            return

        self.send_json(
            {"error": "Not found"},
            status=404,
        )

    def do_POST(self):
        parsed = urlparse(self.path)

        if not self.require_write_token():
            return

        if parsed.path in ("/api/sensor-name", "/api/sync"):
            try:
                payload = self.read_json_body()
                serial = payload.get("serial", "")
                if parsed.path == "/api/sensor-name":
                    get_history().rename_sensor(serial, payload.get("name"))
                elif SYNC_MANAGER:
                    SYNC_MANAGER.request_sync(serial)
                self.send_json({"ok": True})
            except (ValueError, OSError) as error:
                self.send_device_exception(error)
            return

        if parsed.path == "/api/install-udev":
            try:
                result = install_udev_rule()
                self.send_json(result)
            except (
                RuntimeError,
                subprocess.SubprocessError,
                OSError,
            ) as error:
                self.send_json(
                    {"error": str(error)},
                    status=500,
                )
            return

        if parsed.path == "/api/device-config":
            try:
                payload = self.read_json_body()

                device_path = str(
                    payload.get("path", "")
                )

                device = self.resolve_device_or_404(device_path)
                if device is None:
                    return

                result = apply_device_config(
                    device_path,
                    interval_minutes=payload.get("interval_minutes"),
                    interval_seconds=payload.get("interval_seconds"),
                    temperature_unit=payload.get("temperature_unit"),
                    probe=payload.get("probe"),
                    alarm_high=payload.get("alarm_high"),
                    alarm_low=payload.get("alarm_low"),
                    sync_clock=bool(payload.get("sync_clock", True)),
                    button_stop=bool(payload.get("button_stop", False)),
                    software_stop=bool(
                        payload.get("software_stop", False)
                    ),
                    allow_data_loss=bool(
                        payload.get("allow_data_loss", False)
                    ),
                    expected_record_count=payload.get(
                        "expected_record_count"
                    ),
                    expected_session_id=payload.get("expected_session_id"),
                )

                self.send_json(result)

            except Exception as error:
                self.send_device_exception(error)

            return

        self.send_json(
            {"error": "Not found"},
            status=404,
        )


# ============================================================
# Böngészőindítás
# ============================================================

def open_browser():
    time.sleep(0.8)

    url = f"http://{HOST}:{PORT}/"
    firefox = shutil.which("firefox")

    if firefox:
        try:
            subprocess.Popen(
                [firefox, "--new-tab", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except OSError:
            pass

    try:
        webbrowser.open(url)
    except Exception:
        pass


# ============================================================
# Main
# ============================================================

def main():
    global HISTORY, SYNC_MANAGER, HOST, PORT, DEBUG_LOG_PATH
    parser = argparse.ArgumentParser(description="Elitech USB logger WebUI (Windows/Linux)")
    parser.add_argument("--no-browser", action="store_true", help="Print the URL without opening a browser")
    parser.add_argument("--open-browser", action="store_true", help="Open the local UI (desktop use)")
    parser.add_argument("--config", help="Path to config.json (default: working directory)")
    parser.add_argument("--database", help="Override database_path from config")
    args = parser.parse_args()
    settings = load_settings(args.config)
    if args.database:
        settings["database_path"] = args.database
    HOST, PORT = settings["host"], int(settings["port"])
    browser_enabled = not args.no_browser and (args.open_browser or settings["open_browser"])

    if sys.platform == "win32":
        load_hidapi()

    url = f"http://{HOST}:{PORT}/"
    try:
        server = LocalHTTPServer((HOST, PORT), Handler)
    except OSError as bind_error:
        try:
            with urlopen(url + "api/health", timeout=1) as response:
                already_running = json.load(response).get("app") == "elitech-hid-webui"
        except (OSError, ValueError):
            already_running = False
        if not already_running:
            raise bind_error
        print(f"Elitech WebUI is already running: {url}")
        if browser_enabled:
            open_browser()
        return

    HISTORY = open_history(settings)
    DEBUG_LOG_PATH = configured_path(settings["log_path"]) if settings["log_path"] else HISTORY.path.parent / "elitech-debug.log"
    DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(DEBUG_LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    LOGGER.addHandler(file_handler)
    SYNC_MANAGER = SensorSync(HISTORY, scan_devices, inspect_sensor, read_device_records,
                             settings["sync_interval_seconds"], settings["scan_interval_seconds"], identify=identify_sensor)
    SYNC_MANAGER.start()
    print()
    print(f"Elitech USB Logger Manager | {APP_VERSION}")
    print("---------------------------------------------")
    print(f"Web UI: {url}")
    print(f"Debug log: {DEBUG_LOG_PATH}")
    print("Stop server: Ctrl+C")

    LOGGER.info(
        "APPLICATION START | version=%s | script=%s | url=%s | debug_log=%s",
        APP_VERSION,
        Path(__file__).name,
        url,
        DEBUG_LOG_PATH,
    )
    print()

    if browser_enabled:
        threading.Thread(
            target=open_browser,
            daemon=True,
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        SYNC_MANAGER.stop()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

