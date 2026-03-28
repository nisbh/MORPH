#!/usr/bin/env python3
"""
MORPH - Cowrie Honeypot Log Parser

Parses Cowrie JSON log files and aggregates events by session.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_timestamp(ts: str) -> datetime | None:
    """Parse ISO format timestamp."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def parse_cowrie_log(log_path: str) -> dict[str, dict[str, Any]]:
    """
    Parse a Cowrie honeypot JSON log file.

    Args:
        log_path: Path to the cowrie.json log file

    Returns:
        Dict of sessions keyed by session_id, each containing:
        - session_id, src_ip, start_time, end_time, duration_seconds
        - login_attempts: list of {username, password, success}
        - commands: list of command strings
        - downloads: list of URLs
    """
    sessions: dict[str, dict[str, Any]] = {}

    path = Path(log_path)
    if not path.exists():
        print(f"Warning: Log file not found: {log_path}")
        return sessions

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: Malformed JSON on line {line_num}: {e}")
                continue

            session_id = event.get("session")
            if not session_id:
                continue

            # Initialize session if new
            if session_id not in sessions:
                sessions[session_id] = {
                    "session_id": session_id,
                    "src_ip": event.get("src_ip"),
                    "start_time": None,
                    "end_time": None,
                    "duration_seconds": 0,
                    "login_attempts": [],
                    "commands": [],
                    "downloads": [],
                }

            session = sessions[session_id]
            timestamp = parse_timestamp(event.get("timestamp", ""))

            # Update time bounds
            if timestamp:
                if session["start_time"] is None or timestamp < session["start_time"]:
                    session["start_time"] = timestamp
                if session["end_time"] is None or timestamp > session["end_time"]:
                    session["end_time"] = timestamp

            # Update src_ip if not set
            if not session["src_ip"] and event.get("src_ip"):
                session["src_ip"] = event.get("src_ip")

            eventid = event.get("eventid", "")

            # Handle login attempts
            if "login" in eventid.lower():
                username = event.get("username")
                password = event.get("password")
                success = "success" in eventid.lower()
                if username is not None or password is not None:
                    session["login_attempts"].append({
                        "username": username,
                        "password": password,
                        "success": success,
                    })

            # Handle commands
            if event.get("input"):
                session["commands"].append(event["input"])

            # Handle downloads
            if event.get("url"):
                session["downloads"].append(event["url"])

    # Calculate durations
    for session in sessions.values():
        if session["start_time"] and session["end_time"]:
            delta = session["end_time"] - session["start_time"]
            session["duration_seconds"] = delta.total_seconds()

    return sessions


def print_summary(sessions: dict[str, dict[str, Any]]) -> None:
    """Print a summary of parsed sessions."""
    print(f"\n{'='*60}")
    print(f"MORPH Cowrie Log Parser - Summary")
    print(f"{'='*60}")
    print(f"Total sessions: {len(sessions)}")

    if not sessions:
        print("No sessions found.")
        return

    total_logins = sum(len(s["login_attempts"]) for s in sessions.values())
    total_commands = sum(len(s["commands"]) for s in sessions.values())
    total_downloads = sum(len(s["downloads"]) for s in sessions.values())

    print(f"Total login attempts: {total_logins}")
    print(f"Total commands executed: {total_commands}")
    print(f"Total downloads: {total_downloads}")

    # Unique IPs
    unique_ips = set(s["src_ip"] for s in sessions.values() if s["src_ip"])
    print(f"Unique source IPs: {len(unique_ips)}")

    print(f"\n{'-'*60}")
    print("Session Details:")
    print(f"{'-'*60}")

    for session_id, session in sessions.items():
        print(f"\nSession: {session_id}")
        print(f"  Source IP: {session['src_ip'] or 'Unknown'}")
        print(f"  Duration: {session['duration_seconds']:.1f}s")
        print(f"  Login attempts: {len(session['login_attempts'])}")
        print(f"  Commands: {len(session['commands'])}")
        print(f"  Downloads: {len(session['downloads'])}")

        if session["login_attempts"]:
            print("  Credentials tried:")
            for attempt in session["login_attempts"][:5]:
                status = "✓" if attempt["success"] else "✗"
                print(f"    [{status}] {attempt['username']}:{attempt['password']}")
            if len(session["login_attempts"]) > 5:
                print(f"    ... and {len(session['login_attempts']) - 5} more")

        if session["commands"]:
            print("  Commands:")
            for cmd in session["commands"][:5]:
                print(f"    > {cmd}")
            if len(session["commands"]) > 5:
                print(f"    ... and {len(session['commands']) - 5} more")

        if session["downloads"]:
            print("  Downloads:")
            for url in session["downloads"][:3]:
                print(f"    - {url}")
            if len(session["downloads"]) > 3:
                print(f"    ... and {len(session['downloads']) - 3} more")


# Path to local synced log file (synced from WSL by sync.py)
COWRIE_LOG = r"C:\Users\nisar\OneDrive\Desktop\Github Projects\MORPH\cowrie.json"

if __name__ == "__main__":
    sessions = parse_cowrie_log(COWRIE_LOG)
    print_summary(sessions)
