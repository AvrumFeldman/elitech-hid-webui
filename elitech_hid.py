"""Small HID transport layer: Linux hidraw, Windows HIDAPI.

Protocol code exchanges 64-byte Elitech reports on both platforms. HIDAPI
requires a leading zero report ID on writes; that byte is not protocol data.
Linux continues to use only the Python standard library.
"""

import math
import os
import select
import sys


def load_hidapi():
    try:
        import hid
    except ImportError as error:
        raise RuntimeError(
            "Windows USB support requires hidapi. Run: "
            "python -m pip install -r requirements.txt"
        ) from error
    if not hasattr(hid, "device") or not hasattr(hid, "enumerate"):
        raise RuntimeError("Install the 'hidapi' package, which provides 'hid'.")
    return hid


def windows_devices(vendor_id, product_id):
    devices = []
    for info in load_hidapi().enumerate(int(vendor_id, 16), int(product_id, 16)):
        path = info["path"].decode("utf-8")
        name = info.get("product_string") or "Elitech USB logger"
        if name == "MSC+HID":
            name = "Elitech USB logger"
        devices.append({
            "path": path,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "name": name,
            "serial": info.get("serial_number") or "",
            "physical_path": path,
            "display_name": name,
            # Enumeration does not open the device. Any access error is
            # reported when the user requests data, not by a polling probe.
            "can_readwrite": None,
        })
    return sorted(devices, key=lambda device: device["path"])


class LinuxHID:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)

    def wait_readable(self, timeout):
        return bool(select.select([self.fd], [], [], timeout)[0])

    def read(self, size):
        return os.read(self.fd, size)

    def write(self, report):
        return os.write(self.fd, report)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class WindowsHID:
    def __init__(self, path):
        self.device = load_hidapi().device()
        self.pending = None
        try:
            self.device.open_path(path.encode("utf-8"))
            # read(..., 0) calls hid_read, so nonblocking mode is essential
            # for draining reports. Positive timeouts use hid_read_timeout.
            self.device.set_nonblocking(1)
        except Exception:
            self.device.close()
            raise

    def wait_readable(self, timeout):
        if self.pending is None:
            milliseconds = max(0, math.ceil(timeout * 1000))
            report = bytes(self.device.read(64, milliseconds))
            if report:
                self.pending = report
        return self.pending is not None

    def read(self, size):
        if size != 64:
            raise ValueError("Elitech HID reports must be read as 64 bytes.")
        if self.pending is not None:
            report, self.pending = self.pending, None
            return report
        report = bytes(self.device.read(size, 0))
        if not report:
            raise BlockingIOError("No HID report available.")
        return report

    def write(self, report):
        if len(report) != 64:
            raise ValueError("Elitech HID reports must be written as 64 bytes.")
        written = self.device.write(b"\x00" + report)
        if written < 0:
            raise OSError("Could not write to the logger; check the USB connection.")
        # Keep the protocol's short-write checks in terms of payload bytes.
        return max(0, written - 1)

    def close(self):
        self.pending = None
        self.device.close()


def open_device(path):
    if sys.platform == "win32":
        return WindowsHID(path)
    if sys.platform.startswith("linux"):
        return LinuxHID(path)
    raise RuntimeError("Supported platforms are Windows and Linux.")
