"""USB discovery and automatic downloads, independent of browser clients."""

from datetime import datetime, timezone
import logging
import threading
import time

LOGGER = logging.getLogger("elitech_rc5")


class SensorSync:
    def __init__(self, store, discover, inspect, download, sync_interval=10, scan_interval=1, identify=None):
        self.store, self.discover, self.inspect, self.download = store, discover, inspect, download
        self.sync_interval, self.scan_interval = sync_interval, scan_interval
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.stopped = threading.Event()
        self.paths, self.states, self.force = {}, {}, set()
        self.next_attempt = {}
        self.identify = identify
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.run, name="elitech-usb-sync", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        self.wake.set()
        if self.thread:
            self.thread.join(timeout=5)

    def run(self):
        while not self.stopped.is_set():
            try:
                self.poll_once()
            except Exception:
                LOGGER.exception("USB synchronization failed")
            self.wake.wait(self.scan_interval)
            self.wake.clear()

    def request_sync(self, serial):
        with self.lock:
            self.force.add(serial)
        self.wake.set()

    def snapshot(self):
        sensors = self.store.sensors()
        with self.lock:
            for sensor in sensors:
                sensor.update(self.states.get(sensor["serial_number"], {"connected": False, "path": None, "syncing": False}))
        return sensors

    def poll_once(self):
        present = {item["path"] for item in self.discover()}
        with self.lock:
            for path in set(self.paths) - present:
                serial = self.paths.pop(path)
                self.next_attempt.pop(path, None)
                self.states[serial].update(connected=False, path=None, syncing=False)
            forced = set(self.force)
            self.force.clear()
        for path in present:
            new_connection = path not in self.paths
            serial = self.paths.get(path)
            # Some identical USB loggers expose the same generic USB serial,
            # and Windows can reuse their path when swapped in the same port.
            if serial and self.identify:
                try:
                    if self.identify(path) != serial:
                        with self.lock:
                            self.states[serial].update(connected=False, path=None, syncing=False)
                            self.paths.pop(path, None)
                        self.next_attempt.pop(path, None)
                        new_connection = True
                except OSError:
                    continue
            now = time.monotonic()
            if serial not in forced and now < self.next_attempt.get(path, 0):
                continue
            self.next_attempt[path] = now + self.sync_interval
            try:
                info = self.inspect(path)
                serial = info["serial_number"]
                self.store.remember_sensor(serial, info)
                with self.lock:
                    previous_serial = self.paths.get(path)
                    if previous_serial and previous_serial != serial:
                        self.states[previous_serial].update(connected=False, path=None, syncing=False)
                    self.paths[path] = serial
                    state = self.states.setdefault(serial, {})
                    previous_signature = state.get("signature")
                    state.update(connected=True, path=path, syncing=True, error="")
                signature = (info["session_id"], info["record_count"])
                if new_connection or signature != previous_signature or serial in forced:
                    if info["record_count"]:
                        data = self.download(path, 0)
                        if "saved_count" not in data:
                            data.update(session_id=info["session_id"], serial_number=serial,
                                        probe=info["probe"], interval_seconds=info["interval_seconds"],
                                        logger_temperature_unit=info["temperature_unit"])
                            self.store.save(data)
                        signature = (data["session_id"], data["stored_count"])
                    else:
                        self.store.save({"session_id": info["session_id"], "serial_number": serial,
                            "configuration_time": info["configuration_time"], "started_at": None,
                            "probe": info["probe"], "interval_seconds": info["interval_seconds"],
                            "logger_temperature_unit": info["temperature_unit"], "stored_count": 0, "records": []})
                with self.lock:
                    self.states[serial].update(signature=signature, syncing=False, error="",
                        last_sync=datetime.now(timezone.utc).isoformat())
            except Exception as error:
                LOGGER.warning("USB SYNC | path=%s | %s", path, error)
                self.next_attempt[path] = time.monotonic() + min(5, self.sync_interval)
                if serial:
                    with self.lock:
                        self.states.setdefault(serial, {}).update(syncing=False, error=str(error))
