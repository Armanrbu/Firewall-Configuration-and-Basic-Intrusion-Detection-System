"""
IP address and port validation helpers.
"""

from __future__ import annotations

import ipaddress
import re

_PORT_RE = re.compile(r"^\d{1,5}$")


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Return True if *cidr* is a valid IP network in CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_port(port: int | str) -> bool:
    """Return True if *port* is a valid TCP/UDP port number (1–65535)."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if *ip* is a private/reserved address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def normalise_ip(ip: str) -> str:
    """Return the canonical string representation of an IP address."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip
