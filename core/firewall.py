"""
Cross-platform firewall facade.

Public API: block_ip, unblock_ip, block_port, unblock_port, list_rules,
get_status, enable_firewall, disable_firewall, enable_logging.

Delegates to the active ``FirewallBackend`` implementation which is
auto-detected based on the OS. Tests and plugins can inject a custom
backend via ``set_firewall_backend()``.

All public functions return a dict: {"success": bool, "message": str, ...}
"""

from __future__ import annotations

import platform
from typing import Any

from utils.logger import get_logger
from utils.validators import is_valid_ip, is_valid_cidr, is_valid_port

from core.firewall_abc import FirewallBackend, FirewallResult

logger = get_logger(__name__)

_OS = platform.system()          # "Windows" | "Linux" | "Darwin"
_RULES_PREFIX = "NetGuard_"
_VALID_PROTOCOLS = frozenset(("TCP", "UDP"))


# ---------------------------------------------------------------------------
# Backend management (Strategy + Factory)
# ---------------------------------------------------------------------------

_backend: FirewallBackend | None = None


def get_firewall_backend() -> FirewallBackend:
    """Return the active firewall backend, auto-detecting the platform.

    Raises ``RuntimeError`` on unsupported platforms.
    """
    global _backend
    if _backend is None:
        if _OS == "Windows":
            from core.firewall_windows import WindowsNetshBackend
            _backend = WindowsNetshBackend()
        elif _OS == "Linux":
            from core.firewall_linux import LinuxIptablesBackend
            _backend = LinuxIptablesBackend()
        else:
            raise RuntimeError(f"Unsupported OS: {_OS}")
    return _backend


def set_firewall_backend(backend: FirewallBackend | None) -> None:
    """Inject a custom backend (for testing or plugin use).

    Pass ``None`` to reset to auto-detection.
    """
    global _backend
    _backend = backend


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------

def _rule_name(ip: str) -> str:
    return f"{_RULES_PREFIX}Block_{ip.replace('/', '_')}"


def _port_rule_name(port: int, protocol: str) -> str:
    return f"{_RULES_PREFIX}Port_{protocol}_{port}"


# ---------------------------------------------------------------------------
# Public API (unchanged signatures)
# ---------------------------------------------------------------------------

def get_status() -> dict[str, Any]:
    """Return firewall status for all profiles (or current profile on Linux)."""
    try:
        return get_firewall_backend().get_status()
    except RuntimeError as exc:
        return {"success": False, "message": str(exc), "profiles": {}}


def enable_firewall() -> dict[str, Any]:
    """Enable the system firewall."""
    try:
        return get_firewall_backend().enable()
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def disable_firewall() -> dict[str, Any]:
    """Disable the system firewall."""
    try:
        return get_firewall_backend().disable()
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def block_ip(ip: str, rule_name: str | None = None) -> dict[str, Any]:
    """Block all inbound traffic from *ip*."""
    if not (is_valid_ip(ip) or is_valid_cidr(ip)):
        logger.warning("block_ip rejected invalid IP: %r", ip)
        return {"success": False, "message": f"Invalid IP address: {ip}"}

    name = rule_name or _rule_name(ip)
    try:
        return get_firewall_backend().block_ip(ip, name)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def unblock_ip(ip: str) -> dict[str, Any]:
    """Remove the block rule for *ip*."""
    if not (is_valid_ip(ip) or is_valid_cidr(ip)):
        logger.warning("unblock_ip rejected invalid IP: %r", ip)
        return {"success": False, "message": f"Invalid IP address: {ip}"}

    name = _rule_name(ip)
    try:
        return get_firewall_backend().unblock_ip(ip, name)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def block_port(port: int, protocol: str = "TCP") -> dict[str, Any]:
    """Block a specific port for the given protocol."""
    if not is_valid_port(port):
        return {"success": False, "message": f"Invalid port: {port}"}
    proto = protocol.upper()
    if proto not in _VALID_PROTOCOLS:
        return {"success": False, "message": f"Invalid protocol: {protocol}"}

    name = _port_rule_name(port, proto)
    try:
        return get_firewall_backend().block_port(port, proto, name)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def unblock_port(port: int, protocol: str = "TCP") -> dict[str, Any]:
    """Remove the block rule for a specific port."""
    if not is_valid_port(port):
        return {"success": False, "message": f"Invalid port: {port}"}
    proto = protocol.upper()
    if proto not in _VALID_PROTOCOLS:
        return {"success": False, "message": f"Invalid protocol: {protocol}"}

    name = _port_rule_name(port, proto)
    try:
        return get_firewall_backend().unblock_port(port, proto, name)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}


def list_rules() -> dict[str, Any]:
    """Return active firewall rules added by this app."""
    try:
        return get_firewall_backend().list_rules(_RULES_PREFIX)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc), "rules": []}


def enable_logging(log_path: str = r"C:\Temp\pfirewall.log") -> dict[str, Any]:
    """Enable firewall connection logging."""
    try:
        return get_firewall_backend().enable_logging(log_path)
    except RuntimeError as exc:
        return {"success": False, "message": str(exc)}
