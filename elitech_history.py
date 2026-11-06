"""Persistent local recordings. Temperatures are stored in Celsius."""

from datetime import datetime, timezone
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3


class HistoryStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, serial TEXT NOT NULL, started_at TEXT,
                    configuration_time TEXT, probe TEXT NOT NULL,
                    interval_seconds INTEGER, logger_unit TEXT,
                    device_count INTEGER NOT NULL, saved_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS samples (
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    record_index INTEGER NOT NULL, timestamp TEXT,
                    temperature_c REAL, humidity REAL, probe TEXT NOT NULL,
                    status TEXT NOT NULL, details TEXT NOT NULL,
                    PRIMARY KEY(session_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS sensors (
                    serial TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
                    metadata TEXT NOT NULL DEFAULT '{}', last_seen TEXT
                );
                INSERT OR IGNORE INTO sensors(serial) SELECT DISTINCT serial FROM sessions;
                CREATE INDEX IF NOT EXISTS sessions_serial ON sessions(serial);
                CREATE INDEX IF NOT EXISTS samples_session_time ON samples(session_id, timestamp);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, data):
        session_id = data["session_id"]
        probe = data.get("probe", "unknown")
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO sensors(serial) VALUES (?)", (data["serial_number"],))
            db.execute("""INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    device_count=MAX(sessions.device_count, excluded.device_count),
                    saved_at=excluded.saved_at""", (
                session_id, data["serial_number"], data.get("started_at"),
                data.get("configuration_time"), probe, data.get("interval_seconds"),
                data.get("logger_temperature_unit"), data["stored_count"], now,
            ))
            # Existing samples are immutable: a later download/settings change
            # cannot relabel their original probe or reinterpret their value.
            db.executemany("INSERT OR IGNORE INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
                (session_id, record["index"], record.get("timestamp"),
                 record.get("temperature"), record.get("humidity"),
                 record.get("probe", probe), record["status"],
                 json.dumps(record, ensure_ascii=False))
                for record in data["records"]
            ])
            count = db.execute("SELECT COUNT(*) FROM samples WHERE session_id=?", (session_id,)).fetchone()[0]
        return count

    def remember_sensor(self, serial, metadata):
        with self.connect() as db:
            db.execute("""INSERT INTO sensors(serial, metadata, last_seen) VALUES (?, ?, ?)
                ON CONFLICT(serial) DO UPDATE SET metadata=excluded.metadata, last_seen=excluded.last_seen""",
                (serial, json.dumps(metadata, ensure_ascii=False), datetime.now(timezone.utc).isoformat()))

    def rename_sensor(self, serial, name):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or any(ord(c) < 32 for c in name):
            raise ValueError("Choose a sensor name from 1 to 100 characters.")
        with self.connect() as db:
            result = db.execute("UPDATE sensors SET name=? WHERE serial=?", (name.strip(), serial))
            if result.rowcount != 1:
                raise ValueError("Sensor not found.")

    def sensors(self):
        with self.connect() as db:
            rows = db.execute("""SELECT d.*,
                (SELECT COUNT(*) FROM samples r JOIN sessions s ON s.id=r.session_id WHERE s.serial=d.serial) AS saved_count,
                (SELECT COUNT(*) FROM sessions s WHERE s.serial=d.serial) AS recording_count,
                (SELECT MAX(saved_at) FROM sessions s WHERE s.serial=d.serial) AS data_updated
                FROM sensors d ORDER BY LOWER(CASE WHEN d.name='' THEN d.serial ELSE d.name END)""").fetchall()
        sensors = []
        for row in rows:
            metadata = json.loads(row["metadata"])
            sensors.append({"serial_number": row["serial"],
                "name": row["name"] or (metadata.get("model", "Elitech logger") + " · " + row["serial"]),
                "metadata": metadata, "last_seen": row["last_seen"],
                "saved_count": row["saved_count"], "recording_count": row["recording_count"],
                "data_updated": row["data_updated"]})
        return sensors

    def sessions(self, serial=None):
        with self.connect() as db:
            rows = db.execute("""SELECT s.*, COUNT(r.record_index) AS saved_count
                FROM sessions s LEFT JOIN samples r ON r.session_id=s.id
                WHERE (? IS NULL OR s.serial=?)
                GROUP BY s.id ORDER BY COALESCE(s.started_at, s.configuration_time) DESC, s.saved_at DESC""", (serial, serial)).fetchall()
        return [dict(row) for row in rows]

    def sensor_recording(self, serial, session_id="all", limit=0, start=None, end=None):
        # Device timestamps are local wall times. Use the same format as the
        # stored samples, with an inclusive start and an exclusive end.
        for value in (start, end):
            if value is not None:
                try:
                    if datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S") != value:
                        raise ValueError()
                except (TypeError, ValueError):
                    raise ValueError("Time bounds must use YYYY-MM-DD HH:MM:SS.") from None
        if start and end and start >= end:
            raise ValueError("The end time must be after the start time.")
        if session_id != "all":
            if start or end:
                raise ValueError("Time ranges apply to the sensor's combined recordings.")
            result = self.recording(session_id, limit)
            if result["serial_number"] != serial:
                raise ValueError("That recording belongs to a different sensor.")
            return result
        if not isinstance(limit, int) or not 0 <= limit <= 1000000:
            raise ValueError("Invalid measurement limit.")
        with self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM samples r JOIN sessions s ON r.session_id=s.id WHERE s.serial=?", (serial,)).fetchone()[0]
            where, params = "s.serial=?", [serial]
            if start:
                where += " AND r.timestamp>=?"
                params.append(start)
            if end:
                where += " AND r.timestamp<?"
                params.append(end)
            matched = db.execute("SELECT COUNT(*) FROM samples r JOIN sessions s ON r.session_id=s.id WHERE " + where, params).fetchone()[0]
            rows = db.execute("SELECT r.* FROM samples r JOIN sessions s ON r.session_id=s.id WHERE " + where
                + " ORDER BY r.timestamp DESC, r.session_id DESC, r.record_index DESC LIMIT ?", (*params, limit or -1)).fetchall()
        records = []
        for row in reversed(rows):
            record = json.loads(row["details"])
            record.update(session_id=row["session_id"], probe=row["probe"], temperature=row["temperature_c"],
                          humidity=row["humidity"], timestamp=row["timestamp"])
            records.append(record)
        return {"session_id": "all", "serial_number": serial, "stored_count": count,
                "loaded_count": len(records), "matched_count": matched, "range_start": start, "range_end": end,
                "records": records, "source": "local-db"}

    def recording(self, session_id, limit=0):
        if not isinstance(limit, int) or not 0 <= limit <= 64000:
            raise ValueError("History limit must be between 0 and 64000.")
        with self.connect() as db:
            session = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if session is None:
                raise ValueError("Saved recording not found.")
            count = db.execute("SELECT COUNT(*) FROM samples WHERE session_id=?", (session_id,)).fetchone()[0]
            rows = db.execute("""SELECT * FROM samples WHERE session_id=?
                ORDER BY record_index DESC LIMIT ?""", (session_id, limit or 64000)).fetchall()
        records = []
        for row in reversed(rows):
            record = json.loads(row["details"])
            record.update({"probe": row["probe"], "temperature": row["temperature_c"],
                           "humidity": row["humidity"], "timestamp": row["timestamp"], "session_id": session_id})
            records.append(record)
        return {
            "session_id": session_id, "serial_number": session["serial"],
            "started_at": session["started_at"], "probe": session["probe"],
            "interval_seconds": session["interval_seconds"],
            "logger_temperature_unit": session["logger_unit"],
            "stored_count": count, "loaded_count": len(records),
            "records": records, "source": "local-history",
        }
