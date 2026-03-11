"""
IP Geolocation via ip-api.com (free, no API key required).

Results are cached in SQLite to minimise repeated network lookups.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import requests

from utils.logger import get_logger

logger = get_logger(__name__)

_PRIVATE_RESULT: dict[str, Any] = {
    "status": "success",
    "country": "Private/Local",
    "countryCode": "LO",
    "city": "Local Network",
    "isp": "N/A",
    "org": "N/A",
    "lat": 0.0,
    "lon": 0.0,
    "query": "",
}

_TIMEOUT = 3  # seconds


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a private/reserved address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup(ip: str, use_cache: bool = True) -> dict[str, Any]:
    """
    Return geolocation data for *ip*.

    Checks the in-memory + SQLite cache first. Falls back to ip-api.com.
    Returns a dict with at least: country, countryCode, city, isp, lat, lon, org, query.
    """
    if _is_private(ip):
        result = dict(_PRIVATE_RESULT)
        result["query"] = ip
        return result

    # try DB cache
    if use_cache:
        cached = _cache_get(ip)
        if cached:
            return cached

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=_TIMEOUT)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        if data.get("status") == "success":
            if use_cache:
                _cache_set(ip, data)
            return data
        logger.warning("ip-api.com returned non-success for %s: %s", ip, data.get("message"))
        return _error_result(ip, data.get("message", "Unknown error"))
    except requests.exceptions.Timeout:
        logger.warning("Geolocation timeout for %s", ip)
        return _error_result(ip, "Timeout")
    except Exception as exc:
        logger.warning("Geolocation lookup failed for %s: %s", ip, exc)
        return _error_result(ip, str(exc))


def _error_result(ip: str, message: str) -> dict[str, Any]:
    return {
        "status": "fail",
        "query": ip,
        "message": message,
        "country": "Unknown",
        "countryCode": "??",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
    }


# ---------------------------------------------------------------------------
# Cache helpers (backed by core.blocklist DB)
# ---------------------------------------------------------------------------

def _cache_get(ip: str) -> dict[str, Any] | None:
    try:
        import json
        from core.blocklist import get_db
        con = get_db()
        cur = con.execute(
            "SELECT data_json FROM geo_cache WHERE ip = ?", (ip,)
        )
        row = cur.fetchone()
        if row:
            return json.loads(row[0])
    except Exception as exc:
        logger.debug("geo cache get failed: %s", exc)
    return None


def _cache_set(ip: str, data: dict[str, Any]) -> None:
    try:
        import json
        import time
        from core.blocklist import get_db
        con = get_db()
        con.execute(
            "INSERT OR REPLACE INTO geo_cache (ip, data_json, cached_at) VALUES (?, ?, ?)",
            (ip, json.dumps(data), time.time()),
        )
        con.commit()
    except Exception as exc:
        logger.debug("geo cache set failed: %s", exc)
