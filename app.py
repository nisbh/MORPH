#!/usr/bin/env python3
"""
MORPH - Flask Web UI

Dashboard for viewing honeypot sessions, classifications, and live logs.
"""

from flask import Flask, render_template, abort
from pathlib import Path
from collections import Counter, deque
from datetime import datetime, timezone

from log_parser import parse_cowrie_log, COWRIE_LOG
from classifier import classify_session
from dossier import generate, load, load_all, summarize_all

app = Flask(__name__)

DECEPTION_LOG = "morph/deception.log"


def parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse ISO datetime strings from dossiers, handling trailing Z."""
    if not value or not isinstance(value, str):
        return None

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_time_ago(timestamp: datetime | None) -> str:
    """Return a compact relative time string for dashboard activity rows."""
    if timestamp is None:
        return "unknown"

    now = datetime.now(timezone.utc)
    delta_seconds = max(0, int((now - timestamp).total_seconds()))

    if delta_seconds < 60:
        return "just now"
    if delta_seconds < 3600:
        minutes = delta_seconds // 60
        return f"{minutes}m ago"
    if delta_seconds < 86400:
        hours = delta_seconds // 3600
        return f"{hours}h ago"
    if delta_seconds < 604800:
        days = delta_seconds // 86400
        return f"{days}d ago"
    return timestamp.strftime("%Y-%m-%d")


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


def classify_log_event(message: str) -> str:
    """Classify a log message into a UI event category."""
    lower = message.lower()

    if any(token in lower for token in ["session closed", "disconnect", "stopping", "reactor stopped", "polling loop stopped"]):
        return "disconnect"

    if any(token in lower for token in ["login", "password", "invalid user", "auth", "accepted publickey", "accepted password"]):
        return "login"

    if any(token in lower for token in ["triggered", "command", "wget", "curl", "cat /", "ls /", "process listing"]):
        return "command"

    if any(token in lower for token in ["starting", "started", "connected", "watching"]):
        return "connect"

    return "connect"


def parse_log_line(line: str) -> dict[str, str]:
    """Split a raw log line into timestamp, message, and event class."""
    raw = line.strip()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    message = raw

    if raw.startswith("[") and "]" in raw:
        end_idx = raw.find("]")
        timestamp = raw[1:end_idx]
        message = raw[end_idx + 1:].strip() or "-"
    elif len(raw) >= 19 and raw[4] == "-" and raw[7] == "-" and raw[13] == ":":
        timestamp = raw[:19]
        message = raw[19:].strip() or "-"

    return {
        "timestamp": timestamp,
        "message": message,
        "event_type": classify_log_event(message),
    }


@app.route("/")
def index():
    """Dashboard with summary statistics."""
    summary = summarize_all()
    dossiers = load_all()

    ip_counts = Counter()
    for dossier in dossiers:
        ip = dossier.get("src_ip") or "Unknown"
        ip_counts[ip] += 1
    top_attacker_ips = [
        {"ip": ip, "count": count}
        for ip, count in ip_counts.most_common(5)
    ]
    
    # Get recent dossiers (last 5)
    recent = sorted(
        dossiers,
        key=lambda d: d.get("generated_at", ""),
        reverse=True
    )[:5]

    recent_activity = []
    for dossier in recent:
        classification = dossier.get("classification") or {}
        generated_dt = parse_iso_datetime(dossier.get("generated_at"))
        recent_activity.append({
            "session_id": dossier.get("session_id", "unknown"),
            "src_ip": dossier.get("src_ip") or "Unknown",
            "type": classification.get("type") or "unknown",
            "time_ago": format_time_ago(generated_dt),
        })
    
    return render_template(
        "index.html",
        summary=summary,
        recent=recent,
        top_attacker_ips=top_attacker_ips,
        recent_activity=recent_activity,
    )


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


@app.route("/about")
def about():
    """Technical summary page for MORPH."""
    summary = summarize_all()
    return render_template("about.html", summary=summary)


@app.route("/api/logs")
def api_logs():
    """Return latest log lines as HTML fragment for HTMX."""
    lines = read_log_tail(DECEPTION_LOG, 20)
    entries = [parse_log_line(line) for line in lines if line.strip()]
    return render_template("_log_fragment.html", entries=entries)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
