#!/usr/bin/env python3
"""
update_cmdoutput.py - Append realistic web server processes to Cowrie cmdoutput.json.

Updates:
- /home/cowrie/cowrie/src/cowrie/data/cmdoutput.json
- /home/cowrie/cowrie/cowrie/src/cowrie/data/cmdoutput.json (if it exists)

The script loads existing JSON and adds process entries to command.ps
without removing existing rows.
"""

from __future__ import annotations

import json
from pathlib import Path

PRIMARY_CMDOUTPUT = Path("/home/cowrie/cowrie/src/cowrie/data/cmdoutput.json")
SECONDARY_CMDOUTPUT = Path("/home/cowrie/cowrie/cowrie/src/cowrie/data/cmdoutput.json")

PROCESSES_TO_ADD = [
    {
        "USER": "root",
        "PID": 445,
        "COMMAND": "/usr/sbin/nginx -g daemon on; master_process on;",
        "CPU": 0.0,
        "MEM": 0.5,
        "VSZ": 55452672,
        "RSS": 5242880,
        "TTY": "?",
        "STAT": "Ss",
        "START": "Mar29",
        "TIME": 0.12,
    },
    {
        "USER": "www-data",
        "PID": 446,
        "COMMAND": "nginx: worker process",
        "CPU": 0.1,
        "MEM": 0.8,
        "VSZ": 55976960,
        "RSS": 8388608,
        "TTY": "?",
        "STAT": "S",
        "START": "Mar29",
        "TIME": 2.34,
    },
    {
        "USER": "www-data",
        "PID": 447,
        "COMMAND": "nginx: worker process",
        "CPU": 0.1,
        "MEM": 0.8,
        "VSZ": 55976960,
        "RSS": 8388608,
        "TTY": "?",
        "STAT": "S",
        "START": "Mar29",
        "TIME": 2.21,
    },
    {
        "USER": "mysql",
        "PID": 892,
        "COMMAND": "/usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid",
        "CPU": 0.2,
        "MEM": 9.5,
        "VSZ": 1789100032,
        "RSS": 99614720,
        "TTY": "?",
        "STAT": "Sl",
        "START": "Mar29",
        "TIME": 45.2,
    },
    {
        "USER": "root",
        "PID": 512,
        "COMMAND": "/usr/sbin/sshd -D",
        "CPU": 0.0,
        "MEM": 0.3,
        "VSZ": 72351744,
        "RSS": 3145728,
        "TTY": "?",
        "STAT": "Ss",
        "START": "Mar29",
        "TIME": 0.0,
    },
    {
        "USER": "www-data",
        "PID": 1205,
        "COMMAND": "php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)",
        "CPU": 0.0,
        "MEM": 0.6,
        "VSZ": 196608000,
        "RSS": 6291456,
        "TTY": "?",
        "STAT": "Ss",
        "START": "Mar29",
        "TIME": 0.08,
    },
    {
        "USER": "www-data",
        "PID": 1206,
        "COMMAND": "php-fpm: pool www",
        "CPU": 0.0,
        "MEM": 1.2,
        "VSZ": 204800000,
        "RSS": 12582912,
        "TTY": "?",
        "STAT": "S",
        "START": "Mar29",
        "TIME": 0.0,
    },
    {
        "USER": "www-data",
        "PID": 1207,
        "COMMAND": "php-fpm: pool www",
        "CPU": 0.0,
        "MEM": 1.2,
        "VSZ": 204800000,
        "RSS": 12582912,
        "TTY": "?",
        "STAT": "S",
        "START": "Mar29",
        "TIME": 0.0,
    },
    {
        "USER": "root",
        "PID": 387,
        "COMMAND": "/usr/bin/python3 /usr/bin/fail2ban-server -xf start",
        "CPU": 0.0,
        "MEM": 2.1,
        "VSZ": 318767104,
        "RSS": 21495808,
        "TTY": "?",
        "STAT": "Sl",
        "START": "Mar29",
        "TIME": 1.45,
    },
    {
        "USER": "root",
        "PID": 298,
        "COMMAND": "/usr/lib/systemd/systemd-journald",
        "CPU": 0.0,
        "MEM": 0.4,
        "VSZ": 34078720,
        "RSS": 4194304,
        "TTY": "?",
        "STAT": "Ss",
        "START": "Mar29",
        "TIME": 0.89,
    },
]


def ensure_ps_array(data: dict) -> list[dict]:
    """Ensure data['command']['ps'] exists and is a list."""
    command = data.get("command")
    if not isinstance(command, dict):
        data["command"] = {}
        command = data["command"]

    ps_array = command.get("ps")
    if not isinstance(ps_array, list):
        command["ps"] = []
        ps_array = command["ps"]

    return ps_array


def update_cmdoutput_file(file_path: Path) -> tuple[int, int]:
    """
    Add required process entries to command.ps.

    Returns:
        (added_count, skipped_count)
    """
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    ps_array = ensure_ps_array(data)
    existing = {
        (proc.get("PID"), proc.get("COMMAND"))
        for proc in ps_array
        if isinstance(proc, dict)
    }

    added = 0
    skipped = 0
    for proc in PROCESSES_TO_ADD:
        key = (proc["PID"], proc["COMMAND"])
        if key in existing:
            skipped += 1
            continue
        ps_array.append(proc)
        existing.add(key)
        added += 1

    with file_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    return added, skipped


def main() -> int:
    targets = [PRIMARY_CMDOUTPUT]
    if SECONDARY_CMDOUTPUT.exists() and SECONDARY_CMDOUTPUT != PRIMARY_CMDOUTPUT:
        targets.append(SECONDARY_CMDOUTPUT)

    if not PRIMARY_CMDOUTPUT.exists():
        print(f"Error: primary cmdoutput file not found: {PRIMARY_CMDOUTPUT}")
        return 1

    had_error = False
    for target in targets:
        try:
            added, skipped = update_cmdoutput_file(target)
            print(f"Updated {target}: added {added}, already present {skipped}")
        except Exception as exc:
            had_error = True
            print(f"Failed to update {target}: {exc}")

    if had_error:
        print("Completed with errors.")
        return 1

    print("Done. cmdoutput.json process list updated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
