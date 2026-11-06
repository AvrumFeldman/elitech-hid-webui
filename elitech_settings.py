"""Service-friendly configuration and persistent storage selection."""

import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys

SCRIPT_DIR = Path(__file__).resolve().parent


def load_settings(path=None):
    path = Path(path) if path else Path.cwd() / "config.json"
    settings = {"database_path": None, "host": "127.0.0.1", "port": 8765,
                "open_browser": False, "sync_interval_seconds": 10,
                "scan_interval_seconds": 1, "log_path": None}
    if path.exists():
        values = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(values, dict):
            raise ValueError("Configuration must be a JSON object.")
        settings.update(values)
    for key in ("sync_interval_seconds", "scan_interval_seconds"):
        if not isinstance(settings[key], (int, float)) or settings[key] <= 0:
            raise ValueError(f"{key} must be greater than zero.")
    return settings


def configured_path(value, script_dir=None):
    script_dir = script_dir or Path.cwd()
    path = Path(os.path.expandvars(str(value))).expanduser()
    return path if path.is_absolute() else script_dir / path


def open_history(settings, script_dir=None, default_path=None):
    script_dir = script_dir or Path.cwd()
    from elitech_history import HistoryStore
    override = settings.get("database_path")
    default = default_path or (Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ElitechHID" / "elitech-history.sqlite3"
                               if sys.platform == "win32" else Path("/var/lib/elitech-hid/elitech-history.sqlite3"))
    candidates = [configured_path(override, script_dir)] if override else [default, script_dir / "elitech-history.sqlite3"]
    last_error = None
    for target in candidates:
        try:
            existing = target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            # SQLite backup includes committed WAL data from the earlier path.
            previous = SCRIPT_DIR / "data" / "elitech-history.sqlite3"
            if not existing and previous.exists() and previous.resolve() != target.resolve():
                with closing(sqlite3.connect(previous)) as source, closing(sqlite3.connect(target)) as destination:
                    source.backup(destination)
                    destination.commit()
            return HistoryStore(target)
        except (OSError, sqlite3.Error) as error:
            last_error = error
    raise RuntimeError(f"Cannot open the configured database: {last_error}")
