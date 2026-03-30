#!/usr/bin/env python3
"""
MORPH - Flask Web UI

Dashboard for viewing honeypot sessions, classifications, and live logs.
"""

import os
from flask import Flask, render_template, abort
from pathlib import Path
from collections import deque

from log_parser import parse_cowrie_log, COWRIE_LOG
from classifier import classify_session
from dossier import generate, load, load_all, summarize_all

app = Flask(__name__)

DECEPTION_LOG = os.getenv("DECEPTION_LOG", "morph/deception.log")


def get_sessions_with_classification() -> list[dict]:
    """Parse logs and classify all sessions."""
    sessions = parse_cowrie_log(COWRIE_LOG)
    results = []
    
    for session_id, session in sessions.items():
        classification = classify_session(session)
        # Generate/update dossier
        generate(session, classification)
        results.append({
            "session": session,
            "classification": classification,
        })
    
    # Sort by start_time descending (most recent first)
    results.sort(
        key=lambda x: x["session"].get("start_time") or "",
        reverse=True
    )
    return results


def read_log_tail(log_path: str, lines: int = 20) -> list[str]:
    """Read the last N lines from a log file."""
    path = Path(log_path)
    if not path.exists():
        return ["Log file not found"]
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            return list(deque(f, maxlen=lines))
    except IOError:
        return ["Error reading log file"]


@app.route("/")
def index():
    """Dashboard with summary statistics."""
    summary = summarize_all()
    dossiers = load_all()
    
    # Get recent dossiers (last 5)
    recent = sorted(
        dossiers,
        key=lambda d: d.get("generated_at", ""),
        reverse=True
    )[:5]
    
    return render_template("index.html", summary=summary, recent=recent)


@app.route("/sessions")
def sessions():
    """List all sessions with classifications."""
    data = get_sessions_with_classification()
    return render_template("sessions.html", sessions=data)


@app.route("/dossier/<session_id>")
def dossier_detail(session_id: str):
    """View full dossier for a session."""
    dossier = load(session_id)
    if not dossier:
        abort(404)
    return render_template("dossier.html", dossier=dossier)


@app.route("/live-logs")
def live_logs():
    """Live logs page with auto-refresh."""
    return render_template("live_logs.html")


@app.route("/api/logs")
def api_logs():
    """Return latest log lines as HTML fragment for HTMX."""
    lines = read_log_tail(DECEPTION_LOG, 20)
    return render_template("_log_fragment.html", lines=lines)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
