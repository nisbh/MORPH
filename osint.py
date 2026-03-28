#!/usr/bin/env python3
"""
MORPH - OSINT Enrichment Module

Queries ipinfo.io for IP intelligence and enriches dossiers.
"""

import json
import re
from pathlib import Path
from typing import Any

import requests

# In-memory cache to avoid duplicate requests
_ip_cache: dict[str, dict[str, Any]] = {}

# Timeout for HTTP requests
REQUEST_TIMEOUT = 5

# Regex for private/loopback IPs
PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),                          # Loopback
    re.compile(r"^10\."),                           # Class A private
    re.compile(r"^192\.168\."),                     # Class C private
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),  # Class B private
    re.compile(r"^0\."),                            # Invalid
    re.compile(r"^169\.254\."),                     # Link-local
]

# Country code to flag emoji mapping
COUNTRY_FLAGS = {
    "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "DE": "🇩🇪", "FR": "🇫🇷",
    "GB": "🇬🇧", "JP": "🇯🇵", "KR": "🇰🇷", "BR": "🇧🇷", "IN": "🇮🇳",
    "NL": "🇳🇱", "CA": "🇨🇦", "AU": "🇦🇺", "IT": "🇮🇹", "ES": "🇪🇸",
    "PL": "🇵🇱", "UA": "🇺🇦", "RO": "🇷🇴", "VN": "🇻🇳", "ID": "🇮🇩",
    "TW": "🇹🇼", "HK": "🇭🇰", "SG": "🇸🇬", "TH": "🇹🇭", "MY": "🇲🇾",
    "PH": "🇵🇭", "TR": "🇹🇷", "IR": "🇮🇷", "SA": "🇸🇦", "AE": "🇦🇪",
    "IL": "🇮🇱", "ZA": "🇿🇦", "EG": "🇪🇬", "NG": "🇳🇬", "KE": "🇰🇪",
    "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "MX": "🇲🇽", "PE": "🇵🇪",
    "SE": "🇸🇪", "NO": "🇳🇴", "FI": "🇫🇮", "DK": "🇩🇰", "CH": "🇨🇭",
    "AT": "🇦🇹", "BE": "🇧🇪", "CZ": "🇨🇿", "HU": "🇭🇺", "GR": "🇬🇷",
}


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private or loopback."""
    if not ip:
        return True
    for pattern in PRIVATE_IP_PATTERNS:
        if pattern.match(ip):
            return True
    return False


def get_country_flag(country_code: str) -> str:
    """Get flag emoji for a country code."""
    if not country_code:
        return "🌐"
    return COUNTRY_FLAGS.get(country_code.upper(), "🏳️")


def enrich_ip(ip: str) -> dict[str, Any]:
    """
    Query ipinfo.io for IP intelligence.

    Args:
        ip: IP address to enrich

    Returns:
        Dict with: ip, hostname, city, region, country, org, timezone, is_tor, is_vpn
        On error: {"ip": ip, "error": "enrichment failed"}
    """
    if not ip:
        return {"ip": ip, "error": "no IP provided"}

    # Check cache first
    if ip in _ip_cache:
        return _ip_cache[ip]

    # Skip private IPs
    if is_private_ip(ip):
        result = {
            "ip": ip,
            "hostname": None,
            "city": "Private Network",
            "region": None,
            "country": None,
            "country_flag": "🏠",
            "org": "Private/Internal",
            "timezone": None,
            "is_tor": False,
            "is_vpn": False,
            "is_private": True,
        }
        _ip_cache[ip] = result
        return result

    # Query ipinfo.io
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        # Parse response
        country_code = data.get("country", "")
        result = {
            "ip": ip,
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": country_code,
            "country_flag": get_country_flag(country_code),
            "org": data.get("org"),
            "timezone": data.get("timezone"),
            "is_tor": False,
            "is_vpn": False,
            "is_private": False,
        }

        # Check for Tor/VPN indicators in org field
        org_lower = (data.get("org") or "").lower()
        if "tor" in org_lower or "exit" in org_lower:
            result["is_tor"] = True
        if "vpn" in org_lower or "proxy" in org_lower or "hosting" in org_lower:
            result["is_vpn"] = True

        # ipinfo.io privacy detection (if available in response)
        if data.get("privacy"):
            privacy = data["privacy"]
            result["is_tor"] = privacy.get("tor", False)
            result["is_vpn"] = privacy.get("vpn", False) or privacy.get("proxy", False)

        _ip_cache[ip] = result
        return result

    except requests.exceptions.Timeout:
        result = {"ip": ip, "error": "timeout"}
        _ip_cache[ip] = result
        return result
    except requests.exceptions.RequestException as e:
        result = {"ip": ip, "error": f"request failed: {str(e)[:50]}"}
        _ip_cache[ip] = result
        return result
    except Exception as e:
        result = {"ip": ip, "error": f"enrichment failed: {str(e)[:50]}"}
        _ip_cache[ip] = result
        return result


def enrich_session(session: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a session dict with OSINT data.

    Args:
        session: Session dict with src_ip field

    Returns:
        Session dict with "osint" key added
    """
    ip = session.get("src_ip")
    session["osint"] = enrich_ip(ip) if ip else {"error": "no IP"}
    return session


def enrich_all_dossiers(dossier_path: str) -> dict[str, int]:
    """
    Enrich all dossiers in a directory with OSINT data.

    Args:
        dossier_path: Path to dossiers directory

    Returns:
        Summary dict: {total, enriched, skipped, failed}
    """
    path = Path(dossier_path)
    if not path.exists():
        return {"total": 0, "enriched": 0, "skipped": 0, "failed": 0}

    summary = {"total": 0, "enriched": 0, "skipped": 0, "failed": 0}

    for file_path in path.glob("*.json"):
        summary["total"] += 1

        try:
            # Load dossier
            with open(file_path, "r", encoding="utf-8") as f:
                dossier = json.load(f)

            # Skip if already enriched (has valid osint data)
            existing_osint = dossier.get("osint", {})
            if existing_osint and "error" not in existing_osint and existing_osint.get("country"):
                summary["skipped"] += 1
                continue

            # Enrich IP
            ip = dossier.get("src_ip")
            if not ip:
                dossier["osint"] = {"error": "no IP"}
                summary["failed"] += 1
            else:
                osint_data = enrich_ip(ip)
                dossier["osint"] = osint_data

                if "error" in osint_data:
                    summary["failed"] += 1
                else:
                    summary["enriched"] += 1

            # Save updated dossier
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(dossier, f, indent=2)

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            summary["failed"] += 1

    return summary


def clear_cache():
    """Clear the in-memory IP cache."""
    global _ip_cache
    _ip_cache = {}


if __name__ == "__main__":
    print("MORPH OSINT Enrichment Module")
    print("=" * 60)

    # Test with some IPs
    test_ips = [
        "8.8.8.8",         # Google DNS
        "1.1.1.1",         # Cloudflare
        "192.168.1.1",     # Private
        "127.0.0.1",       # Loopback
    ]

    print("\nTesting IP enrichment:")
    for ip in test_ips:
        result = enrich_ip(ip)
        print(f"\n{ip}:")
        if "error" in result:
            print(f"  Error: {result['error']}")
        else:
            flag = result.get("country_flag", "")
            country = result.get("country", "Unknown")
            city = result.get("city", "Unknown")
            org = result.get("org", "Unknown")
            print(f"  Location: {flag} {country} - {city}")
            print(f"  Org: {org}")
            if result.get("is_tor"):
                print("  ⚠️  TOR EXIT NODE")
            if result.get("is_vpn"):
                print("  ⚠️  VPN/PROXY")

    # Test dossier enrichment
    print("\n" + "=" * 60)
    print("Testing dossier enrichment:")
    dossier_path = "morph/dossiers"
    result = enrich_all_dossiers(dossier_path)
    print(f"  Total: {result['total']}")
    print(f"  Enriched: {result['enriched']}")
    print(f"  Skipped: {result['skipped']}")
    print(f"  Failed: {result['failed']}")
