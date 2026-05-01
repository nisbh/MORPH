#!/usr/bin/env python3
"""
MORPH - Main Entry Point

Orchestrates the honeypot analysis pipeline:
1. Parse Cowrie logs
2. Classify each session
3. Generate dossiers
4. Adapt environment based on history
5. Start Flask web UI
"""

import json
from datetime import datetime
from pathlib import Path
import sys
from log_parser import parse_cowrie_log, print_summary, COWRIE_LOG
from classifier import classify_session
from dossier import generate, summarize_all, DOSSIERS_DIR
from deception import initialize as init_deception, adapt
from adaptor import adapt_environment, generate_adaptation_report
from osint import enrich_all_dossiers
from app import app
from cleanup import count_dossiers, run_cleanup

STATS_PATH = Path(__file__).parent / "morph" / "stats.json"


def update_total_attacks(session_count: int) -> None:
    """Persist the running total of attacks across pipeline runs."""
    safe_count = max(0, int(session_count or 0))
    stats_path = Path(STATS_PATH)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.utcnow().isoformat() + "Z"

    try:
        with open(stats_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        total_attacks = int(data.get("total_attacks", 0))
    except FileNotFoundError:
        data = {}
        total_attacks = 0
    except (json.JSONDecodeError, IOError, TypeError, ValueError):
        data = {}
        total_attacks = 0

    data["total_attacks"] = total_attacks + safe_count
    data["last_updated"] = now_iso

    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def process_sessions() -> int:
    """Parse, classify, and generate dossiers for all sessions."""
    print("=" * 60)
    print("MORPH Honeypot Analysis Pipeline")
    print("=" * 60)

    # Step 1: Parse logs
    print(f"\n[1/5] Parsing logs from: {COWRIE_LOG}")
    sessions = parse_cowrie_log(COWRIE_LOG)
    print(f"      Found {len(sessions)} sessions")

    if not sessions:
        print("      No sessions to process.")
        return 0

    # Step 2: Classify sessions
    print("\n[2/5] Classifying sessions...")
    classifications = {}
    for session_id, session in sessions.items():
        classifications[session_id] = classify_session(session)

    # Count by type/risk
    bots = sum(1 for c in classifications.values() if c["type"] == "bot")
    high_risk = sum(1 for c in classifications.values() if c["risk"] == "high")
    print(f"      Bots: {bots}, Humans: {len(sessions) - bots}")
    print(f"      High risk: {high_risk}")

    # Step 3: Generate dossiers
    print("\n[3/5] Generating dossiers...")
    for session_id, session in sessions.items():
        classification = classifications[session_id]
        generate(session, classification)
    print(f"      Generated {len(sessions)} dossiers")

    # Step 3.5: OSINT enrichment
    print("\n[3.5/5] Enriching dossiers with OSINT...")
    osint_result = enrich_all_dossiers(DOSSIERS_DIR)
    print(f"      Enriched: {osint_result['enriched']}, Skipped: {osint_result['skipped']}, Failed: {osint_result['failed']}")

    # Step 4: Initialize deception & adapt per-session
    print("\n[4/5] Running deception adaptations...")
    init_deception()
    adaptations = 0
    for session_id, session in sessions.items():
        classification = classifications[session_id]
        actions = adapt(session, classification)
        if actions and actions[0] != "No adaptation actions taken":
            adaptations += len(actions)
    print(f"      Applied {adaptations} per-session adaptations")

    # Step 5: Start Flask app
    print("\n[5/5] Adapt environment from attack history...")
    env_adaptations = adapt_environment()
    adaptation_report = generate_adaptation_report()
    print(f"      Applied {len(env_adaptations)} environment adaptations")
    for a in env_adaptations:
        print(f"        - [{a['rule']}] {a['reason'][:50]}...")

    # Summary
    summary = summarize_all()
    print("\n" + "-" * 60)
    print("Summary:")
    print(f"  Total sessions: {summary['total']}")
    print(f"  By type: {summary['by_type']}")
    print(f"  By risk: {summary['by_risk']}")
    print(f"  By intent: {summary['by_intent']}")
    print("-" * 60)

    # Step 6: Dossier cleanup safeguard (only above hard limit)
    dossier_count = count_dossiers()
    if dossier_count > 5000:
        print("\n[6/6] Running dossier cleanup...")
        run_cleanup()
    else:
        print(f"\n[6/6] Dossier cleanup not needed ({dossier_count} <= 5000)")

    update_total_attacks(len(sessions))

    return len(sessions)


def main():
    """Main entry point."""
    # Process existing logs and adapt environment
    process_sessions()

    # Start Flask app
    print("\n[*] Starting MORPH Web UI...")
    print("[*] Dashboard: http://localhost:5000")
    print("[*] Press Ctrl+C to stop\n")

    try:
        app.run(debug=False, host="0.0.0.0", port=5000)
    except KeyboardInterrupt:
        print("\n[*] Shutting down MORPH...")
        sys.exit(0)


if __name__ == "__main__":
    main()
