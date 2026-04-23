#!/usr/bin/env python3
"""
MORPH - Flask Web UI

Dashboard for viewing honeypot sessions, classifications, and live logs.
"""

from __future__ import annotations

from flask import Flask, render_template, abort, request
from pathlib import Path
from collections import Counter, deque
from datetime import datetime, timezone
from math import ceil
import time
from typing import Any

from dossier import load, load_all

app = Flask(__name__)

DECEPTION_LOG = "morph/deception.log"
CACHE_TTL_SECONDS = 60
SESSIONS_PER_PAGE = 50

_summary_cache: dict[str, Any] | None = None
_cache_time = 0

_dashboard_cache: dict[str, Any] | None = None
_dashboard_cache_time = 0

_sessions_cache: list[dict[str, Any]] | None = None
_sessions_cache_time = 0

_total_sessions_count_cache = 0


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


def _cache_expired(cache_time: int | float) -> bool:
    """Return True when cache entry is older than TTL."""
    return (time.time() - float(cache_time)) > CACHE_TTL_SECONDS


def _normalize_session_row(dossier: dict[str, Any]) -> dict[str, Any]:
    """Convert a dossier object into a compact row used by dashboard/sessions."""
    classification = dossier.get("classification") or {}
    commands = dossier.get("commands") or []
    downloads = dossier.get("downloads") or []

    generated_dt = parse_iso_datetime(dossier.get("generated_at"))
    if not generated_dt:
        generated_dt = parse_iso_datetime(dossier.get("start_time"))

    return {
        "session": {
            "session_id": dossier.get("session_id", "unknown"),
            "src_ip": dossier.get("src_ip") or "Unknown",
            "duration_seconds": dossier.get("duration_seconds") or 0,
            "commands": commands,
            "downloads": downloads,
        },
        "classification": {
            "type": classification.get("type") or "unknown",
            "intent": classification.get("intent") or "unknown",
            "risk": classification.get("risk") or "unknown",
        },
        "generated_at": dossier.get("generated_at", ""),
        "sort_ts": generated_dt.timestamp() if generated_dt else 0,
        "generated_dt": generated_dt,
    }


def _refresh_sessions_cache() -> None:
    """Refresh the in-memory dossier/session cache from disk."""
    global _sessions_cache, _sessions_cache_time, _total_sessions_count_cache
    global _summary_cache, _cache_time, _dashboard_cache, _dashboard_cache_time

    dossiers = load_all()
    rows = [_normalize_session_row(d) for d in dossiers]
    rows.sort(key=lambda row: row.get("sort_ts", 0), reverse=True)

    _sessions_cache = rows
    _total_sessions_count_cache = len(rows)
    _sessions_cache_time = time.time()

    # Invalidate dependent caches so they stay aligned with refreshed session rows.
    _summary_cache = None
    _cache_time = 0
    _dashboard_cache = None
    _dashboard_cache_time = 0


def get_cached_sessions_rows() -> list[dict[str, Any]]:
    """Return cached session rows, refreshing at most once per TTL."""
    if _sessions_cache is None or _cache_expired(_sessions_cache_time):
        _refresh_sessions_cache()
    return _sessions_cache or []


def get_cached_total_sessions_count() -> int:
    """Return the cached total number of sessions/dossiers."""
    if _sessions_cache is None or _cache_expired(_sessions_cache_time):
        _refresh_sessions_cache()
    return _total_sessions_count_cache


def _build_summary_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build summary stats from cached rows without touching disk."""
    summary: dict[str, Any] = {
        "total": len(rows),
        "by_risk": {"low": 0, "medium": 0, "high": 0},
        "by_type": {"bot": 0, "human": 0},
        "by_intent": {"recon": 0, "exploit": 0, "persistence": 0},
        "unique_ips": set(),
        "total_commands": 0,
        "total_downloads": 0,
    }

    for row in rows:
        session = row.get("session") or {}
        classification = row.get("classification") or {}

        risk = str(classification.get("risk", "")).lower()
        if risk in summary["by_risk"]:
            summary["by_risk"][risk] += 1

        session_type = str(classification.get("type", "")).lower()
        if session_type in summary["by_type"]:
            summary["by_type"][session_type] += 1

        intent = str(classification.get("intent", "")).lower()
        if intent in summary["by_intent"]:
            summary["by_intent"][intent] += 1

        src_ip = session.get("src_ip")
        if src_ip:
            summary["unique_ips"].add(src_ip)

        summary["total_commands"] += len(session.get("commands") or [])
        summary["total_downloads"] += len(session.get("downloads") or [])

    summary["unique_ips"] = len(summary["unique_ips"])
    return summary


def get_cached_summary() -> dict[str, Any]:
    """Return cached summarize_all equivalent for 60s TTL."""
    global _summary_cache, _cache_time

    if _summary_cache is None or _cache_expired(_cache_time):
        rows = get_cached_sessions_rows()
        _summary_cache = _build_summary_from_rows(rows)
        _cache_time = time.time()

    return _summary_cache or {
        "total": 0,
        "by_risk": {"low": 0, "medium": 0, "high": 0},
        "by_type": {"bot": 0, "human": 0},
        "by_intent": {"recon": 0, "exploit": 0, "persistence": 0},
        "unique_ips": 0,
        "total_commands": 0,
        "total_downloads": 0,
    }


def get_cached_dashboard_data() -> dict[str, Any]:
    """Return cached top IPs and recent activity for the dashboard."""
    global _dashboard_cache, _dashboard_cache_time

    if _dashboard_cache is None or _cache_expired(_dashboard_cache_time):
        rows = get_cached_sessions_rows()

        ip_counts = Counter()
        for row in rows:
            ip = row.get("session", {}).get("src_ip") or "Unknown"
            ip_counts[ip] += 1

        top_attacker_ips = [
            {"ip": ip, "count": count}
            for ip, count in ip_counts.most_common(5)
        ]

        recent_rows = rows[:5]
        recent = [
            {
                "session_id": row.get("session", {}).get("session_id", "unknown"),
                "src_ip": row.get("session", {}).get("src_ip") or "Unknown",
                "duration_seconds": row.get("session", {}).get("duration_seconds") or 0,
                "classification": row.get("classification") or {},
                "generated_at": row.get("generated_at", ""),
            }
            for row in recent_rows
        ]

        recent_activity = [
            {
                "session_id": row.get("session", {}).get("session_id", "unknown"),
                "src_ip": row.get("session", {}).get("src_ip") or "Unknown",
                "type": row.get("classification", {}).get("type") or "unknown",
                "time_ago": format_time_ago(row.get("generated_dt")),
            }
            for row in recent_rows
        ]

        _dashboard_cache = {
            "top_attacker_ips": top_attacker_ips,
            "recent": recent,
            "recent_activity": recent_activity,
        }
        _dashboard_cache_time = time.time()

    return _dashboard_cache or {
        "top_attacker_ips": [],
        "recent": [],
        "recent_activity": [],
    }


def _sanitize_filter(value: str | None, allowed: set[str]) -> str:
    """Normalize and validate query filters."""
    normalized = (value or "").strip().lower()
    return normalized if normalized in allowed else ""


def _filter_rows(
    rows: list[dict[str, Any]],
    type_filter: str,
    risk_filter: str,
    intent_filter: str,
) -> list[dict[str, Any]]:
    """Apply server-side filters to cached rows."""
    filtered = rows

    if type_filter:
        filtered = [r for r in filtered if (r.get("classification", {}).get("type") or "").lower() == type_filter]
    if risk_filter:
        filtered = [r for r in filtered if (r.get("classification", {}).get("risk") or "").lower() == risk_filter]
    if intent_filter:
        filtered = [r for r in filtered if (r.get("classification", {}).get("intent") or "").lower() == intent_filter]

    return filtered


def _paginate_rows(
    rows: list[dict[str, Any]],
    page: int,
    per_page: int,
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Return page items and pagination metadata."""
    total_count = len(rows)
    total_pages = max(1, ceil(total_count / per_page))
    current_page = max(1, min(page, total_pages))

    start = (current_page - 1) * per_page
    end = start + per_page
    return rows[start:end], total_count, total_pages, current_page


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
    summary = get_cached_summary()
    dashboard_data = get_cached_dashboard_data()

    return render_template(
        "index.html",
        summary=summary,
        recent=dashboard_data["recent"],
        top_attacker_ips=dashboard_data["top_attacker_ips"],
        recent_activity=dashboard_data["recent_activity"],
    )


@app.route("/sessions")
def sessions():
    """List cached dossier sessions with server-side filtering and pagination."""
    page = request.args.get("page", default=1, type=int) or 1
    type_filter = _sanitize_filter(request.args.get("type"), {"bot", "human"})
    risk_filter = _sanitize_filter(request.args.get("risk"), {"low", "medium", "high"})
    intent_filter = _sanitize_filter(request.args.get("intent"), {"recon", "exploit", "persistence"})

    all_rows = get_cached_sessions_rows()
    filtered_rows = _filter_rows(all_rows, type_filter, risk_filter, intent_filter)

    page_rows, filtered_count, total_pages, current_page = _paginate_rows(
        filtered_rows,
        page,
        SESSIONS_PER_PAGE,
    )

    return render_template(
        "sessions.html",
        sessions=page_rows,
        page=current_page,
        total_pages=total_pages,
        has_prev=current_page > 1,
        has_next=current_page < total_pages,
        prev_page=current_page - 1,
        next_page=current_page + 1,
        filtered_count=filtered_count,
        total_count=get_cached_total_sessions_count(),
        filters={
            "type": type_filter,
            "risk": risk_filter,
            "intent": intent_filter,
        },
    )


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
    summary = get_cached_summary()
    return render_template("about.html", summary=summary)


@app.route("/api/logs")
def api_logs():
    """Return latest log lines as HTML fragment for HTMX."""
    lines = read_log_tail(DECEPTION_LOG, 20)
    entries = [parse_log_line(line) for line in lines if line.strip()]
    return render_template("_log_fragment.html", entries=entries)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
