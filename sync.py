#!/usr/bin/env python3
"""
MORPH - Log Sync Utility

Copies Cowrie logs from WSL to Windows project directory for processing.
"""

import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

# Paths
WSL_LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
WINDOWS_LOG_PATH = r"C:\Users\nisar\OneDrive\Desktop\Github Projects\MORPH\cowrie.json"
SYNC_LOG = "morph/sync.log"

# Background sync control
_sync_thread: threading.Thread | None = None
_stop_sync = threading.Event()


def _log(message: str) -> None:
    """Log a sync action."""
    log_path = Path(SYNC_LOG)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry)


def sync_log() -> bool:
    """
    Copy Cowrie log from WSL to Windows project directory.
    
    Returns:
        True if sync succeeded, False otherwise
    """
    # Convert Windows path to format WSL can write to
    windows_path_for_wsl = WINDOWS_LOG_PATH.replace("\\", "/")
    
    cmd = [
        "wsl", "cp",
        WSL_LOG_PATH,
        f"/mnt/c{windows_path_for_wsl[2:]}"  # Convert C:/ to /mnt/c/
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            _log(f"Synced: {WSL_LOG_PATH} -> {WINDOWS_LOG_PATH}")
            return True
        else:
            _log(f"Sync failed: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        _log("Sync timed out")
        return False
    except FileNotFoundError:
        _log("WSL not found - is WSL installed?")
        return False
    except Exception as e:
        _log(f"Sync error: {e}")
        return False


def sync_log_safe() -> bool:
    """
    Sync log with warning on failure (doesn't raise exceptions).
    
    Returns:
        True if sync succeeded, False otherwise
    """
    success = sync_log()
    if not success:
        print("[!] Warning: Log sync failed, using existing file if available")
    return success


def _sync_loop(interval: int = 30) -> None:
    """Background sync loop."""
    _log(f"Starting background sync (interval: {interval}s)")
    
    while not _stop_sync.is_set():
        sync_log()
        _stop_sync.wait(interval)
    
    _log("Background sync stopped")


def watch_and_sync(interval: int = 30) -> threading.Thread:
    """
    Start background thread that syncs logs periodically.
    
    Args:
        interval: Seconds between syncs (default 30)
        
    Returns:
        The background thread (can be stopped with stop_sync())
    """
    global _sync_thread, _stop_sync
    
    _stop_sync.clear()
    _sync_thread = threading.Thread(
        target=_sync_loop,
        args=(interval,),
        daemon=True,
        name="LogSyncThread"
    )
    _sync_thread.start()
    
    print(f"[*] Background log sync started (every {interval}s)")
    return _sync_thread


def stop_sync() -> None:
    """Stop the background sync thread."""
    global _sync_thread
    
    if _sync_thread and _sync_thread.is_alive():
        _stop_sync.set()
        _sync_thread.join(timeout=5)
        _log("Background sync stopped")
        print("[*] Background log sync stopped")


def get_local_log_path() -> str:
    """Return the path to the local (synced) log file."""
    return WINDOWS_LOG_PATH


if __name__ == "__main__":
    print("MORPH Log Sync Utility")
    print("=" * 60)
    print(f"Source: {WSL_LOG_PATH}")
    print(f"Destination: {WINDOWS_LOG_PATH}")
    print()
    
    print("Syncing...")
    if sync_log():
        print("✓ Sync successful")
        
        # Show file info
        log_path = Path(WINDOWS_LOG_PATH)
        if log_path.exists():
            size = log_path.stat().st_size
            print(f"  File size: {size:,} bytes")
    else:
        print("✗ Sync failed")
    
    print(f"\nLog file: {SYNC_LOG}")
