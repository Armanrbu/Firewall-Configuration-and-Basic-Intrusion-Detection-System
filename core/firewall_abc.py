"""
Abstract firewall backend interface.

Platform-specific implementations (Windows netsh, Linux iptables) inherit
from ``FirewallBackend`` and are auto-selected by ``get_firewall_backend()``
in ``core.firewall``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


# Return type alias used by all backend methods
FirewallResult = dict[str, Any]
"""Standard result dict: {"success": bool, "message": str, ...}"""


class FirewallBackend(ABC):
    """Abstract interface for platform-specific firewall operations.

    All methods return a ``FirewallResult`` dict.
    Input validation (IP, port) is handled by the facade (``core.firewall``),
    so backend methods can assume inputs are already validated.
    """

    @abstractmethod
    def block_ip(self, ip: str, rule_name: str) -> FirewallResult:
        """Block all inbound traffic from *ip*."""

    @abstractmethod
    def unblock_ip(self, ip: str, rule_name: str) -> FirewallResult:
        """Remove the block rule for *ip*."""

    @abstractmethod
    def block_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        """Block a specific port for the given protocol."""

    @abstractmethod
    def unblock_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        """Remove the block rule for a specific port."""

    @abstractmethod
    def list_rules(self, prefix: str) -> FirewallResult:
        """Return active firewall rules matching *prefix*."""

    @abstractmethod
    def get_status(self) -> FirewallResult:
        """Return firewall status for all profiles."""

    @abstractmethod
    def enable(self) -> FirewallResult:
        """Enable the system firewall."""

    @abstractmethod
    def disable(self) -> FirewallResult:
        """Disable the system firewall."""

    @abstractmethod
    def enable_logging(self, log_path: str) -> FirewallResult:
        """Enable firewall connection logging."""
