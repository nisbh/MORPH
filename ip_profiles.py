#!/usr/bin/env python3
"""
ip_profiles.py - IP intelligence profile utilities for MORPH.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROFILES_PATH = Path(__file__).parent / "morph" / "ip_profiles.json"
IPINFO_TIMEOUT_SECONDS = 6


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO-like timestamps and return timezone-aware UTC datetimes."""
    if not value:
        return None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_utc_iso(value: datetime | None) -> str:
    """Convert datetime to canonical UTC ISO string."""
    if not value:
        return ""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _primary_key(breakdown: dict[str, int], preferred_order: list[str]) -> str:
    """Pick a primary category from a count breakdown dict."""
    if not breakdown:
        return "unknown"

    max_count = max(int(v) for v in breakdown.values())
    candidates = {k for k, v in breakdown.items() if int(v) == max_count}

    for key in preferred_order:
        if key in candidates:
            return key

    return sorted(candidates)[0] if candidates else "unknown"


def _highest_risk(risk_breakdown: dict[str, int]) -> str:
    """Select highest observed risk severity."""
    if int(risk_breakdown.get("high", 0)) > 0:
        return "high"
    if int(risk_breakdown.get("medium", 0)) > 0:
        return "medium"
    if int(risk_breakdown.get("low", 0)) > 0:
        return "low"

    return _primary_key(risk_breakdown, ["high", "medium", "low"])


def _country_code_to_flag(country_code: str | None) -> str:
    """Return Unicode flag emoji from a two-letter country code."""
    if not country_code:
        return ""
    code = country_code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""

    base = ord("A")
    return "".join(chr(0x1F1E6 + ord(ch) - base) for ch in code)


def _is_private_or_local_ip(ip: str) -> bool:
    """Return True for private/loopback/reserved IP ranges or invalid values."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True

    return bool(addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)


def build_ip_profiles(dossiers: list) -> dict[str, dict[str, Any]]:
    """Build aggregated attacker profiles keyed by source IP."""
    profiles: dict[str, dict[str, Any]] = {}
    command_counters: dict[str, Counter[str]] = {}

    for raw in dossiers:
        if not isinstance(raw, dict):
            continue

        ip = str(raw.get("src_ip") or "Unknown")
        profile = profiles.setdefault(
            ip,
            {
                "ip": ip,
                "total_sessions": 0,
                "first_seen": "",
                "last_seen": "",
                "type_breakdown": {"bot": 0, "human": 0},
                "intent_breakdown": {"recon": 0, "exploit": 0, "persistence": 0},
                "risk_breakdown": {"low": 0, "medium": 0, "high": 0},
                "primary_type": "unknown",
                "primary_intent": "unknown",
                "highest_risk": "unknown",
                "total_commands": 0,
                "unique_commands": [],
                "sessions": [],
                "osint": {},
                "command_frequency": {},
            },
        )

        counter = command_counters.setdefault(ip, Counter())

        profile["total_sessions"] = int(profile["total_sessions"]) + 1

        classification = raw.get("classification") or {}
        session_type = str(classification.get("type") or "unknown").lower()
        intent = str(classification.get("intent") or "unknown").lower()
        risk = str(classification.get("risk") or "unknown").lower()

        if session_type not in profile["type_breakdown"]:
            profile["type_breakdown"][session_type] = 0
        profile["type_breakdown"][session_type] += 1

        if intent not in profile["intent_breakdown"]:
            profile["intent_breakdown"][intent] = 0
        profile["intent_breakdown"][intent] += 1

        if risk not in profile["risk_breakdown"]:
            profile["risk_breakdown"][risk] = 0
        profile["risk_breakdown"][risk] += 1

        session_id = str(raw.get("session_id") or "").strip()
        if session_id and session_id not in profile["sessions"]:
            profile["sessions"].append(session_id)

        commands = raw.get("commands") or []
        profile["total_commands"] = int(profile["total_commands"]) + len(commands)
        for command in commands:
            cmd = str(command).strip()
            if cmd:
                counter[cmd] += 1

        start_dt = _parse_timestamp(raw.get("start_time")) or _parse_timestamp(raw.get("generated_at"))
        end_dt = _parse_timestamp(raw.get("end_time")) or _parse_timestamp(raw.get("generated_at")) or start_dt

        first_seen_dt = _parse_timestamp(profile.get("first_seen"))
        last_seen_dt = _parse_timestamp(profile.get("last_seen"))

        if start_dt and (first_seen_dt is None or start_dt < first_seen_dt):
            profile["first_seen"] = _to_utc_iso(start_dt)

        if end_dt and (last_seen_dt is None or end_dt > last_seen_dt):
            profile["last_seen"] = _to_utc_iso(end_dt)

    for ip, profile in profiles.items():
        command_counter = command_counters.get(ip, Counter())
        ordered_commands = [cmd for cmd, _count in command_counter.most_common()]
        profile["unique_commands"] = ordered_commands
        profile["command_frequency"] = dict(command_counter.most_common())

        profile["primary_type"] = _primary_key(
            profile.get("type_breakdown", {}),
            ["bot", "human"],
        )
        profile["primary_intent"] = _primary_key(
            profile.get("intent_breakdown", {}),
            ["recon", "exploit", "persistence"],
        )
        profile["highest_risk"] = _highest_risk(profile.get("risk_breakdown", {}))

    return profiles


def _fetch_ipinfo(ip: str) -> dict[str, Any]:
    """Fetch IP intelligence from ipinfo.io."""
    request = Request(
        f"https://ipinfo.io/{ip}/json",
        headers={"User-Agent": "MORPH-IP-Intel/1.0"},
    )

    with urlopen(request, timeout=IPINFO_TIMEOUT_SECONDS) as response:
        payload = response.read().decode("utf-8", errors="replace")

    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        return {}
    return parsed


def save_ip_profiles(profiles: dict[str, dict[str, Any]]) -> None:
    """Persist profile cache to morph/ip_profiles.json."""
    PROFILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PROFILES_PATH, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2, sort_keys=True)
        f.write("\n")


def load_ip_profiles() -> dict[str, dict[str, Any]]:
    """Load saved profiles from morph/ip_profiles.json."""
    if not PROFILES_PATH.exists():
        return {}

    try:
        with open(PROFILES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    if isinstance(data, dict):
        return data
    return {}


def enrich_ip_profiles(profiles: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Enrich cached profiles with ipinfo.io OSINT and persist results."""
    saved_profiles = load_ip_profiles()

    for ip, profile in profiles.items():
        existing_osint = profile.get("osint") or {}
        saved_osint = (saved_profiles.get(ip) or {}).get("osint") or {}

        if saved_osint and not existing_osint:
            profile["osint"] = saved_osint
            existing_osint = saved_osint

        if existing_osint:
            continue

        if _is_private_or_local_ip(ip):
            profile["osint"] = {
                "is_private": True,
                "city": "",
                "region": "",
                "country": "",
                "country_flag": "",
                "org": "",
                "timezone": "",
                "hostname": "",
            }
            continue

        try:
            payload = _fetch_ipinfo(ip)
            country_code = str(payload.get("country") or "").upper()
            profile["osint"] = {
                "city": str(payload.get("city") or ""),
                "region": str(payload.get("region") or ""),
                "country": country_code,
                "country_flag": _country_code_to_flag(country_code),
                "org": str(payload.get("org") or ""),
                "timezone": str(payload.get("timezone") or ""),
                "hostname": str(payload.get("hostname") or ""),
            }
        except (URLError, HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            profile["osint"] = {
                "error": str(exc),
                "city": "",
                "region": "",
                "country": "",
                "country_flag": "",
                "org": "",
                "timezone": "",
                "hostname": "",
            }

    save_ip_profiles(profiles)
    return profiles
