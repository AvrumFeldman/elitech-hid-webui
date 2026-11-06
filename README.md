# Elitech HID WebUI — Windows and Linux

A local browser interface for Elitech USB temperature loggers. This fork adds
Windows HID access, an English interface, and native RC-4 Pro compact records
to [andrasschad/elitech-hid-webui](https://github.com/andrasschad/elitech-hid-webui).

## Run on Windows

Double-click **Start-Elitech.cmd**. On first use it creates a private Python
virtual environment and installs the small `hidapi` package from PyPI. Python
3.10 or newer must be installed, with the `py` launcher available.

The page opens at **http://127.0.0.1:8765/**. Keep the server window open while
using the app; Ctrl+C stops it. It listens only on this computer.

For an existing environment:

```powershell
.\.venv\Scripts\python.exe elitech-webui.py
```

The Python script runs without opening a browser by default; add
`--open-browser` for desktop use. The desktop launcher opens it automatically.

You can also use your installed Python without a virtual environment:

```powershell
python -m pip install -r requirements.txt
python elitech-webui.py --no-browser
```

No vendor software, replacement USB driver, admin privileges, or USB drive
access is required. Close other logger applications if opening HID fails.

## Prepare and start recording

1. Connect USB and open **Prepare logging**.
2. Choose the logging interval: **10 seconds to 24 hours**, in ten-second steps.
3. Choose **Celsius or Fahrenheit**, and **Internal or External probe**.
   The RC-4 Pro records one selected temperature probe per session.
4. Review alarm limits. **Use default limits** selects 60/-30 C (140/-22 F).
   Changing the logger unit converts alarm limits and temperature calibration.
5. Leave clock synchronization enabled and click **Save and prepare logging**.
6. Unplug USB, wait three seconds, then hold the logger button for five seconds.
   Confirm the recording symbol on its screen.

Saving a configuration prepares a new session and **erases existing logger
measurements**. Download and export first. Existing records require two
confirmations. Consent covers all measurements in that recording session,
including samples collected while configuring. The app rejects a different or
reset session while allowing its record count to grow normally. Original parameter bytes are backed up locally in
`.device-backups/` before writing.

After preparation, the app reopens HID and checks the logger identity, empty
record count, ready state, selected settings and running clock. A missing reset
acknowledgment is treated as an uncertain reply and resolved by these read-only
checks. A busy device is given time to settle; the reset command is never
retried automatically. If verification fails, inspect device information before
trying another preparation.

The logger has no separate software-start opcode in the protocol used here.
Preparation arms manual recording; the device button begins it. This sequence
was successfully verified on the connected RC-4 Pro.

## Sensors and measurements

The sidebar retains every known logger by its actual device serial number.
Choose a name with **Save name**. A green dot means connected; a gray dot means
offline. Offline sensors still open their saved measurements.

**Measurements** is the single database-backed view for current and historical
recordings. Every query is scoped to the selected logger serial, including
when identical loggers are swapped in the same USB port. Internal temperature
is blue; external temperature is orange. Separate sessions are not joined by
chart lines. Probe choices during configuration are colored radio controls.

Measurements default to **Today** (local midnight to the next midnight).
Choose Yesterday, Last 7 days, Last 30 days, All history, or enter a custom
From/To range and click **Apply range**. The end time is exclusive. The chart,
table, statistics and CSV export all use the same selected range, without a
last-N record cap. **Zoom in (+)** halves the time span; **Zoom out (−)** doubles
it. Drag left or right across the chart to select a time range; double-click
to zoom out. Zooming loads the corresponding readings from SQLite, including
earlier sessions. Empty ranges retain the chart and navigation controls.

The backend detects USB connections and downloads all available readings
without any browser open. It checks connected loggers for additional samples
at the configured sync interval (10 seconds by default). **Sync now** requests
an immediate check. The UI reads saved data from SQLite and works offline.
The app also archives the available recording before an approved reset.

Every sample retains its original probe, timestamp, Celsius value, raw bytes
and event flags. Downloading again deduplicates records and fills gaps without
changing the provenance of existing samples. Device resets create separate
sessions instead of overwriting earlier record indices.

**Charts and CSV** changes presentation units without changing the logger.
The logger temperature-unit setting controls its screen and storage units.
Recording capacity shows estimated days, months and years at the chosen
interval, based on logger memory capacity.

## Service configuration and database path

Run the Python app through your Windows service wrapper with its **Start in**
folder set explicitly. The app runs without opening a browser by default:

```powershell
C:\path\to\.venv\Scripts\python.exe C:\path\to\elitech-webui.py
```

The service wrapper provides Windows Service Control Manager integration;
this change does not install or register a Windows service.

Copy `config.example.json` to `config.json` in the working / **Start in**
directory, or pass `--config C:\path\to\config.json`. Example:

```json
{
  "database_path": "D:\\LoggerData\\readings.sqlite3",
  "open_browser": false,
  "sync_interval_seconds": 10,
  "scan_interval_seconds": 1
}
```

Database selection:

1. An explicit `database_path` (or `--database PATH`) uses that path.
2. Without an override, Windows defaults to
   `%PROGRAMDATA%/ElitechHID/elitech-history.sqlite3`.
3. If the default cannot be opened for writing, the fallback is
   `elitech-history.sqlite3` in the process working / **Start in** directory.

Relative configuration paths resolve from the working directory. An explicit
unwritable database override reports an error rather than silently choosing a
different file. The sidebar shows the actual database location.

Existing data from the earlier `data/elitech-history.sqlite3` location migrates
with SQLite backup when the destination is new. The earlier file is retained.
Logs default to the selected database directory; `log_path` can override this.
The service account needs write access to its chosen storage directory.
Linux defaults to `/var/lib/elitech-hid/elitech-history.sqlite3` with the same
working-directory fallback. The server binds to localhost by default.

## Configuration changes and resets

The app's **Charts and CSV** unit selector can change at any time without
changing the logger. For device settings, the vendor's SetParameter flow always
finishes with FormatCommand; a supported persistent save without resetting has
not been established. Changing interval, probe or logger units also changes the
session-level metadata used to decode its compact records. The app therefore
continues to use a new recording session for those settings, archiving the
previous one first. It does not expose an unverified in-place hardware save.

## Hardware and implementation

- Windows: real RC-4 Pro, model `0x0044`, protocol `0x54`, USB `246c:9001`.
  Verified discovery, parameter reads, configuration/clock synchronization,
  successful button start, and native multi-packet measurement downloads.
- RC-4 Pro records are four bytes. Their timestamps derive from session start,
  interval, and pause records. Negative temperatures, sensor error markers,
  pause duration and stop flags have protocol regression coverage.
- The external-probe setting is implemented from the vendor protocol; its
  hardware selection/readback must be verified on a new session. An existing
  internal-probe session cannot be changed into external measurements.
- The upstream RC-5 eight-byte record path and Linux hidraw transport remain.
  Linux hardware was not available for verification of this fork.
- Downloads currently cover the ordinary recording store. Shadow histories and
  a wrapped circular store are not implemented. The app refuses inconsistent
  counts rather than inventing timestamps.

`elitech_history.py` stores named sensors, sessions and immutable sample provenance.
`elitech_sync.py` runs USB discovery and downloads independently of the browser.
`elitech_settings.py` resolves service configuration and database paths.
`elitech_hid.py` handles Windows/Linux transport. `elitech_rc4.py` defines the
RC-4 Pro session and record data structures and compact decoder. Packet
checksums, addresses, report IDs and timeouts are validated. Vendor binaries
are not distributed or loaded by the app.

## Development checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node tests/test_ui.cjs
```

The Node check exercises controls, chart units and CSV export in memory,
without starting a browser. Real HID readback is separate from simulated tests.

Local configuration, credentials, device diagnostics, logs, parameter backups,
databases and exported readings are excluded by `.gitignore`. Keep custom data
in the ignored `data/`, `exports/` or `backups/` directories and custom settings
in `config.json` or `config.*.json`. Only `config.example.json` is published.

The original Hungarian project documentation is preserved in
[README.upstream.hu.md](README.upstream.hu.md). The upstream GPL-3.0 license
continues to apply; this is an unofficial project.
