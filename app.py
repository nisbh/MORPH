#!/usr/bin/env python3
"""
MORPH - Flask Web UI

Dashboard for viewing honeypot sessions, classifications, and live logs.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from math import ceil
from pathlib import Path
import threading
import time
from typing import Any

from flask import Flask, abort, jsonify, render_template, request

from dossier import load, load_all
from ip_profiles import PROFILES_PATH, build_ip_profiles, enrich_ip_profiles, load_ip_profiles, save_ip_profiles

app = Flask(__name__)

DECEPTION_LOG = "morph/deception.log"
CACHE_TTL_SECONDS = 60
SESSIONS_PER_PAGE = 50
IP_DETAIL_SESSIONS_PER_PAGE = 20
INTELLIGENCE_IPS_PER_PAGE = 50
IP_PROFILES_FILE_FRESH_SECONDS = 300
TYPE_FILTER_VALUES = ("bot", "human")
RISK_FILTER_VALUES = ("low", "medium", "high")
INTENT_FILTER_VALUES = ("recon", "exploit", "persistence")
FILTER_LABELS = {
    "type": {"bot": "Bot", "human": "Human"},
    "risk": {"low": "Low", "medium": "Medium", "high": "High"},
    "intent": {"recon": "Recon", "exploit": "Exploit", "persistence": "Persistence"},
}

_summary_cache: dict[str, Any] | None = None
_cache_time = 0

_dashboard_cache: dict[str, Any] | None = None
_dashboard_cache_time = 0

_sessions_cache: list[dict[str, Any]] | None = None
_sessions_cache_time = 0
_dossiers_cache: list[dict[str, Any]] | None = None

_total_sessions_count_cache = 0

_ip_profiles_cache: dict[str, dict[str, Any]] | None = None
_ip_profiles_cache_time = 0

_enrichment_lock = threading.Lock()
_enrichment_in_progress = False


def _format_minutes_ago(epoch_seconds: float | int | None) -> str:
    """Return a readable relative age string in minutes."""
    if not epoch_seconds:
        return "unknown"

    elapsed_seconds = max(0, int(time.time() - float(epoch_seconds)))
    if elapsed_seconds < 60:
        return "just now"

    minutes = elapsed_seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"

    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"

    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''} ago"


def _ip_profiles_file_age_seconds() -> float | None:
    """Return current age of ip_profiles.json in seconds, if it exists."""
    if not PROFILES_PATH.exists():
        return None
    return max(0.0, time.time() - PROFILES_PATH.stat().st_mtime)


def get_ip_profiles_last_updated_text() -> str:
    """Return human-readable last-updated text for intelligence summary UI."""
    if PROFILES_PATH.exists():
        return _format_minutes_ago(PROFILES_PATH.stat().st_mtime)

    if _ip_profiles_cache_time:
        return _format_minutes_ago(_ip_profiles_cache_time)

    return "unknown"


def format_human_datetime(value: str | datetime | None) -> str:
    """Format an ISO timestamp as 'Apr 22, 2026 00:00'."""
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    else:
        dt = parse_iso_datetime(value)

    if dt is None:
        return "-"

    return dt.strftime("%b %d, %Y %H:%M")


def format_int_comma(value: Any) -> str:
    """Format integer values with comma separators for display."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


@app.template_filter("human_ts")
def _human_ts_filter(value: str | datetime | None) -> str:
    """Jinja filter for human-readable timestamps."""
    return format_human_datetime(value)


@app.template_filter("intcomma")
def _int_comma_filter(value: Any) -> str:
    """Jinja filter for comma-separated integer rendering."""
    return format_int_comma(value)


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
    global _sessions_cache, _sessions_cache_time, _total_sessions_count_cache, _dossiers_cache
    global _summary_cache, _cache_time, _dashboard_cache, _dashboard_cache_time
    global _ip_profiles_cache, _ip_profiles_cache_time

    dossiers = load_all()
    rows = [_normalize_session_row(d) for d in dossiers]
    rows.sort(key=lambda row: row.get("sort_ts", 0), reverse=True)

    _dossiers_cache = dossiers
    _sessions_cache = rows
    _total_sessions_count_cache = len(rows)
    _sessions_cache_time = time.time()

    # Invalidate dependent caches so they stay aligned with refreshed session rows.
    _summary_cache = None
    _cache_time = 0
    _dashboard_cache = None
    _dashboard_cache_time = 0
    _ip_profiles_cache = None
    _ip_profiles_cache_time = 0


def get_cached_dossiers() -> list[dict[str, Any]]:
    """Return cached dossiers, refreshing from disk at most once per TTL."""
    if _dossiers_cache is None or _cache_expired(_sessions_cache_time):
        _refresh_sessions_cache()
    return _dossiers_cache or []


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


def _merge_osint_into_profiles(
    profiles: dict[str, dict[str, Any]],
    saved_profiles: dict[str, dict[str, Any]],
) -> None:
    """Merge persisted OSINT data into freshly built profiles by IP."""
    for ip, saved_profile in saved_profiles.items():
        if ip not in profiles:
            continue
        saved_osint = saved_profile.get("osint") or {}
        if saved_osint and not (profiles[ip].get("osint") or {}):
            profiles[ip]["osint"] = saved_osint


def get_cached_ip_profiles(force_refresh: bool = False) -> dict[str, dict[str, Any]]:
    """Return cached IP intelligence profiles built from cached dossiers."""
    global _ip_profiles_cache, _ip_profiles_cache_time

    if force_refresh or _ip_profiles_cache is None or _cache_expired(_ip_profiles_cache_time):
        file_age = _ip_profiles_file_age_seconds()
        file_is_fresh = file_age is not None and file_age <= IP_PROFILES_FILE_FRESH_SECONDS

        if not force_refresh and file_is_fresh:
            profiles = load_ip_profiles()
        else:
            dossiers = get_cached_dossiers()
            profiles = build_ip_profiles(dossiers)
            saved_profiles = load_ip_profiles()
            _merge_osint_into_profiles(profiles, saved_profiles)
            save_ip_profiles(profiles)

        _ip_profiles_cache = profiles
        _ip_profiles_cache_time = time.time()

    return _ip_profiles_cache or {}


def _risk_sort_tuple(profile: dict[str, Any]) -> tuple[int, int, int, int]:
    """Sort helper for highest-risk ordering in intelligence list."""
    risk = profile.get("risk_breakdown") or {}
    return (
        int(risk.get("high", 0)),
        int(risk.get("medium", 0)),
        int(risk.get("low", 0)),
        int(profile.get("total_sessions", 0)),
    )


def _sort_intelligence_profiles(
    profiles: list[dict[str, Any]],
    sort_key: str,
) -> list[dict[str, Any]]:
    """Apply requested sort mode for /intelligence list."""
    if sort_key == "last_seen":
        return sorted(
            profiles,
            key=lambda p: (
                parse_iso_datetime(p.get("last_seen")) or datetime.fromtimestamp(0, tz=timezone.utc),
                int(p.get("total_sessions", 0)),
            ),
            reverse=True,
        )

    if sort_key == "highest_risk":
        return sorted(profiles, key=_risk_sort_tuple, reverse=True)

    return sorted(
        profiles,
        key=lambda p: (
            int(p.get("total_sessions", 0)),
            parse_iso_datetime(p.get("last_seen")) or datetime.fromtimestamp(0, tz=timezone.utc),
        ),
        reverse=True,
    )


def _profile_danger_tuple(profile: dict[str, Any]) -> tuple[int, int, int, int]:
    """Sort helper for selecting the most dangerous profile."""
    risk = profile.get("risk_breakdown") or {}
    return (
        int(risk.get("high", 0)),
        int(risk.get("medium", 0)),
        int(risk.get("low", 0)),
        int(profile.get("total_sessions", 0)),
    )


def _build_ip_timeline(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a per-day session timeline for one IP profile."""
    timeline_counts = Counter()
    for row in rows:
        generated_dt = row.get("generated_dt")
        if generated_dt:
            timeline_counts[generated_dt.strftime("%Y-%m-%d")] += 1

    return [
        {"date": day, "sessions": timeline_counts[day]}
        for day in sorted(timeline_counts.keys())
    ]


def _run_ip_enrichment_background() -> None:
    """Background worker for enriching cached profiles."""
    global _ip_profiles_cache, _ip_profiles_cache_time, _enrichment_in_progress

    try:
        profiles = get_cached_ip_profiles(force_refresh=True)
        enriched = enrich_ip_profiles(profiles)
        _ip_profiles_cache = enriched
        _ip_profiles_cache_time = time.time()
    finally:
        with _enrichment_lock:
            _enrichment_in_progress = False


def _parse_multi_filter(
    key: str,
    allowed_values: tuple[str, ...],
) -> list[str]:
    """Parse repeated and/or comma-separated query values for a filter key."""
    allowed_set = set(allowed_values)
    selected: list[str] = []
    seen: set[str] = set()

    for raw_value in request.args.getlist(key):
        for token in str(raw_value).split(","):
            normalized = token.strip().lower()
            if normalized in allowed_set and normalized not in seen:
                selected.append(normalized)
                seen.add(normalized)

    return selected


def _join_filter_values(values: list[str]) -> str:
    """Serialize selected filter values into comma-separated query format."""
    return ",".join(values)


def _build_filter_counts(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Build count metadata for each sidebar filter option."""
    counts = {
        "type": {key: 0 for key in TYPE_FILTER_VALUES},
        "risk": {key: 0 for key in RISK_FILTER_VALUES},
        "intent": {key: 0 for key in INTENT_FILTER_VALUES},
    }

    for row in rows:
        classification = row.get("classification") or {}

        row_type = (classification.get("type") or "").lower()
        if row_type in counts["type"]:
            counts["type"][row_type] += 1

        row_risk = (classification.get("risk") or "").lower()
        if row_risk in counts["risk"]:
            counts["risk"][row_risk] += 1

        row_intent = (classification.get("intent") or "").lower()
        if row_intent in counts["intent"]:
            counts["intent"][row_intent] += 1

    return counts


def _build_active_filter_tags(
    type_filters: list[str],
    risk_filters: list[str],
    intent_filters: list[str],
) -> list[str]:
    """Build display tags for active session filters."""
    tags: list[str] = []

    for value in type_filters:
        tags.append(f"Type: {FILTER_LABELS['type'].get(value, value.title())}")
    for value in risk_filters:
        tags.append(f"Risk: {FILTER_LABELS['risk'].get(value, value.title())}")
    for value in intent_filters:
        tags.append(f"Intent: {FILTER_LABELS['intent'].get(value, value.title())}")

    return tags


def _filter_rows(
    rows: list[dict[str, Any]],
    type_filters: list[str],
    risk_filters: list[str],
    intent_filters: list[str],
) -> list[dict[str, Any]]:
    """Apply server-side filters to cached rows."""
    filtered = rows

    if type_filters:
        type_selected = set(type_filters)
        filtered = [
            r for r in filtered
            if (r.get("classification", {}).get("type") or "").lower() in type_selected
        ]

    if risk_filters:
        risk_selected = set(risk_filters)
        filtered = [
            r for r in filtered
            if (r.get("classification", {}).get("risk") or "").lower() in risk_selected
        ]

    if intent_filters:
        intent_selected = set(intent_filters)
        filtered = [
            r for r in filtered
            if (r.get("classification", {}).get("intent") or "").lower() in intent_selected
        ]

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
    type_filters = _parse_multi_filter("type", TYPE_FILTER_VALUES)
    risk_filters = _parse_multi_filter("risk", RISK_FILTER_VALUES)
    intent_filters = _parse_multi_filter("intent", INTENT_FILTER_VALUES)

    all_rows = get_cached_sessions_rows()
    filtered_rows = _filter_rows(all_rows, type_filters, risk_filters, intent_filters)
    filter_counts = _build_filter_counts(all_rows)
    active_filter_tags = _build_active_filter_tags(type_filters, risk_filters, intent_filters)

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
            "type": type_filters,
            "risk": risk_filters,
            "intent": intent_filters,
        },
        filter_counts=filter_counts,
        active_filter_tags=active_filter_tags,
        filter_query={
            "type": _join_filter_values(type_filters) or None,
            "risk": _join_filter_values(risk_filters) or None,
            "intent": _join_filter_values(intent_filters) or None,
        },
    )


@app.route("/intelligence")
def intelligence():
    """Aggregated attacker IP intelligence profiles."""
    page = request.args.get("page", default=1, type=int) or 1
    sort = request.args.get("sort", default="sessions", type=str) or "sessions"
    if sort not in {"sessions", "last_seen", "highest_risk"}:
        sort = "sessions"

    profiles_map = get_cached_ip_profiles()
    all_profiles = list(profiles_map.values())
    profiles = _sort_intelligence_profiles(all_profiles, sort)

    page_profiles, total_ips, total_pages, current_page = _paginate_rows(
        profiles,
        page,
        INTELLIGENCE_IPS_PER_PAGE,
    )

    showing_start = 0 if total_ips == 0 else ((current_page - 1) * INTELLIGENCE_IPS_PER_PAGE) + 1
    showing_end = min(current_page * INTELLIGENCE_IPS_PER_PAGE, total_ips)

    ips_with_osint = sum(1 for profile in all_profiles if profile.get("osint"))
    most_active = max(all_profiles, key=lambda p: int(p.get("total_sessions", 0))) if all_profiles else None
    most_dangerous = max(all_profiles, key=_profile_danger_tuple) if all_profiles else None

    with _enrichment_lock:
        enriching = _enrichment_in_progress

    return render_template(
        "intelligence.html",
        profiles=page_profiles,
        intelligence_summary={
            "total_unique_ips": total_ips,
            "ips_with_osint": ips_with_osint,
            "most_active_ip": most_active.get("ip") if most_active else "-",
            "most_active_sessions": int(most_active.get("total_sessions", 0)) if most_active else 0,
            "most_dangerous_ip": most_dangerous.get("ip") if most_dangerous else "-",
            "most_dangerous_high": int((most_dangerous.get("risk_breakdown") or {}).get("high", 0)) if most_dangerous else 0,
            "last_updated": get_ip_profiles_last_updated_text(),
        },
        enrichment_in_progress=enriching,
        sort=sort,
        page=current_page,
        total_pages=total_pages,
        has_prev=current_page > 1,
        has_next=current_page < total_pages,
        prev_page=current_page - 1,
        next_page=current_page + 1,
        showing_start=showing_start,
        showing_end=showing_end,
        total_ips=total_ips,
    )


@app.route("/intelligence/<ip>")
def intelligence_detail(ip: str):
    """Detailed view for one attacker IP profile."""
    profiles_map = get_cached_ip_profiles()
    profile = profiles_map.get(ip)
    if not profile:
        abort(404)

    page = request.args.get("page", default=1, type=int) or 1
    ip_rows = [
        row for row in get_cached_sessions_rows()
        if (row.get("session", {}).get("src_ip") or "Unknown") == ip
    ]

    page_rows, total_count, total_pages, current_page = _paginate_rows(
        ip_rows,
        page,
        IP_DETAIL_SESSIONS_PER_PAGE,
    )

    command_frequency = sorted(
        (profile.get("command_frequency") or {}).items(),
        key=lambda item: (-int(item[1]), item[0]),
    )
    top_commands = command_frequency[:30]
    remaining_command_count = max(0, len(command_frequency) - len(top_commands))
    timeline = _build_ip_timeline(ip_rows)
    timeline_max = max((point["sessions"] for point in timeline), default=1)

    osint = profile.get("osint") or {}
    osint_fields = ("country", "city", "region", "org", "timezone", "hostname")
    has_osint_data = any(str(osint.get(field) or "").strip() for field in osint_fields)

    first_seen_dt = parse_iso_datetime(profile.get("first_seen"))
    last_seen_dt = parse_iso_datetime(profile.get("last_seen"))

    if first_seen_dt and not last_seen_dt:
        last_seen_dt = first_seen_dt
    if last_seen_dt and not first_seen_dt:
        first_seen_dt = last_seen_dt

    timeline_activity_text = "Active for less than 1 day"
    timeline_range_text = "-"
    if first_seen_dt and last_seen_dt:
        if first_seen_dt.date() == last_seen_dt.date():
            timeline_activity_text = "Active for less than 1 day"
        else:
            active_days = (last_seen_dt.date() - first_seen_dt.date()).days + 1
            timeline_activity_text = f"Active for {active_days} days"

        timeline_range_text = f"{format_human_datetime(first_seen_dt)} to {format_human_datetime(last_seen_dt)}"

    return render_template(
        "ip_detail.html",
        profile=profile,
        has_osint_data=has_osint_data,
        command_frequency=top_commands,
        total_unique_commands=len(command_frequency),
        remaining_command_count=remaining_command_count,
        timeline=timeline,
        timeline_max=timeline_max,
        timeline_activity_text=timeline_activity_text,
        timeline_range_text=timeline_range_text,
        sessions=page_rows,
        total_count=total_count,
        page=current_page,
        total_pages=total_pages,
        has_prev=current_page > 1,
        has_next=current_page < total_pages,
        prev_page=current_page - 1,
        next_page=current_page + 1,
    )


@app.route("/intelligence/enrich", methods=["POST"])
def intelligence_enrich():
    """Trigger background OSINT enrichment for all tracked IP profiles."""
    global _enrichment_in_progress

    profiles = get_cached_ip_profiles()
    pending_count = sum(1 for profile in profiles.values() if not (profile.get("osint") or {}))

    with _enrichment_lock:
        if not _enrichment_in_progress:
            _enrichment_in_progress = True
            worker = threading.Thread(target=_run_ip_enrichment_background, daemon=True)
            worker.start()

    return jsonify({"status": "enriching", "count": pending_count})


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
