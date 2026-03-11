"""
Whitelist management — trusted IPs that are never blocked.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_WHITELIST = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

_WHITELIST_FILE = "whitelist.txt"
_whitelist: set[str] = set(_DEFAULT_WHITELIST)


def load(path: str = _WHITELIST_FILE) -> None:
    """Load whitelist from a text file (one entry per line)."""
    global _whitelist
    _whitelist = set(_DEFAULT_WHITELIST)
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            _whitelist.add(entry)
    logger.info("Whitelist loaded: %d entries from %s", len(_whitelist), path)


def save(path: str = _WHITELIST_FILE) -> None:
    """Save the current whitelist to a text file."""
    p = Path(path)
    p.write_text("\n".join(sorted(_whitelist)) + "\n")
    logger.info("Whitelist saved to %s", path)


def add(ip: str) -> bool:
    """Add *ip* to the whitelist. Returns True if newly added."""
    if ip in _whitelist:
        return False
    _whitelist.add(ip)
    save()
    return True


def remove(ip: str) -> bool:
    """Remove *ip* from the whitelist. Returns True if it was present."""
    if ip not in _whitelist:
        return False
    _whitelist.discard(ip)
    save()
    return True


def is_whitelisted(ip: str) -> bool:
    """Return True if *ip* or its network is whitelisted."""
    if ip in _whitelist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for entry in _whitelist:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


def get_all() -> list[str]:
    """Return all whitelisted entries."""
    return sorted(_whitelist)
