#!/usr/bin/env python3
"""
MORPH dossier cleanup utility.

Keeps dossier storage bounded by deleting oldest dossiers when thresholds are exceeded.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dossier import DOSSIERS_DIR

MAX_DOSSIERS = 5000
WARNING_THRESHOLD = 3000


def _parse_generated_at(value: Any) -> datetime:
    """Parse generated_at value to UTC datetime, defaulting to minimum."""
    if not isinstance(value, str) or not value.strip():
        return datetime.min.replace(tzinfo=timezone.utc)

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _list_dossier_files() -> list[Path]:
    """Return all dossier json files from morph/dossiers."""
    dossiers_dir = Path(DOSSIERS_DIR)
    if not dossiers_dir.exists():
        return []
    return list(dossiers_dir.glob("*.json"))


def count_dossiers() -> int:
    """Return current number of dossier files."""
    return len(_list_dossier_files())


def _dossier_sort_key(file_path: Path) -> datetime:
    """Sort dossiers by generated_at oldest first; unreadable files are oldest."""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return _parse_generated_at(payload.get("generated_at"))
    except (OSError, json.JSONDecodeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def run_cleanup() -> dict[str, int | str]:
    """
    Run dossier cleanup according to configured thresholds.

    Returns:
        A result dictionary with count/deleted/remaining/action fields.
    """
    files = _list_dossier_files()
    count = len(files)

    print(f"[cleanup] Dossier count: {count}")

    if count > MAX_DOSSIERS:
        to_delete = count - MAX_DOSSIERS
        sorted_files = sorted(files, key=_dossier_sort_key)

        deleted = 0
        for file_path in sorted_files[:to_delete]:
            try:
                file_path.unlink()
                deleted += 1
            except OSError as exc:
                print(f"[cleanup] Warning: failed to delete {file_path.name}: {exc}")

        remaining = count - deleted
        print(f"[cleanup] Deleted {deleted} old dossiers (threshold {MAX_DOSSIERS}).")
        print(f"[cleanup] Remaining dossiers: {remaining}")
        return {
            "count": count,
            "deleted": deleted,
            "remaining": remaining,
            "action": "deleted",
        }

    if count > WARNING_THRESHOLD:
        print(
            f"[cleanup] Warning: dossier count is above warning threshold "
            f"({count} > {WARNING_THRESHOLD})."
        )
        return {
            "count": count,
            "deleted": 0,
            "remaining": count,
            "action": "warning",
        }

    print(f"[cleanup] Within safe threshold (<= {WARNING_THRESHOLD}).")
    return {
        "count": count,
        "deleted": 0,
        "remaining": count,
        "action": "none",
    }


if __name__ == "__main__":
    run_cleanup()
