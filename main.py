#!/usr/bin/env python3
"""
MORPH - Main Entry Point

Orchestrates the honeypot analysis pipeline:
1. Parse Cowrie logs
2. Classify each session
3. Generate dossiers
4. Start Flask web UI
"""

import sys
from log_parser import parse_cowrie_log, print_summary
from classifier import classify_session
from dossier import generate, summarize_all
from deception import initialize as init_deception, adapt
from app import app

LOG_PATH = "var/log/cowrie/cowrie.json"


def process_sessions() -> int:
    """Parse, classify, and generate dossiers for all sessions."""
    print("=" * 60)
    print("MORPH Honeypot Analysis Pipeline")
    print("=" * 60)

    # Step 1: Parse logs
    print(f"\n[1/4] Parsing logs from: {LOG_PATH}")
    sessions = parse_cowrie_log(LOG_PATH)
    print(f"      Found {len(sessions)} sessions")

    if not sessions:
        print("      No sessions to process.")
        return 0

    # Step 2: Classify sessions
    print("\n[2/4] Classifying sessions...")
    classifications = {}
    for session_id, session in sessions.items():
        classifications[session_id] = classify_session(session)

    # Count by type/risk
    bots = sum(1 for c in classifications.values() if c["type"] == "bot")
    high_risk = sum(1 for c in classifications.values() if c["risk"] == "high")
    print(f"      Bots: {bots}, Humans: {len(sessions) - bots}")
    print(f"      High risk: {high_risk}")

    # Step 3: Generate dossiers
    print("\n[3/4] Generating dossiers...")
    for session_id, session in sessions.items():
        classification = classifications[session_id]
        generate(session, classification)
    print(f"      Generated {len(sessions)} dossiers")

    # Step 4: Initialize deception & adapt
    print("\n[4/4] Running deception adaptations...")
    init_deception()
    adaptations = 0
    for session_id, session in sessions.items():
        classification = classifications[session_id]
        actions = adapt(session, classification)
        if actions and actions[0] != "No adaptation actions taken":
            adaptations += len(actions)
    print(f"      Applied {adaptations} adaptations")

    # Summary
    summary = summarize_all()
    print("\n" + "-" * 60)
    print("Summary:")
    print(f"  Total sessions: {summary['total']}")
    print(f"  By type: {summary['by_type']}")
    print(f"  By risk: {summary['by_risk']}")
    print(f"  By intent: {summary['by_intent']}")
    print("-" * 60)

    return len(sessions)


def main():
    """Main entry point."""
    # Process existing logs
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
