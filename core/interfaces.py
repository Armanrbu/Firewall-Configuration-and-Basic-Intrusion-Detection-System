"""
Abstract interfaces and event types for engine-to-frontend communication.

This module defines:
  - EngineEventHandler: Protocol for frontends to receive engine events
  - Event dataclasses: Typed, immutable events published by the engine
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Event handler protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class EngineEventHandler(Protocol):
    """Protocol for receiving engine events.

    Frontends (GUI, CLI, API) implement this to receive
    real-time updates from the engine without tight coupling.
    All methods have default no-op implementations via the protocol,
    so implementors only need to override the events they care about.
    """

    def on_connection(self, ip: str, port: int, protocol: str, direction: str) -> None:
        """Called for each new connection detected."""
        ...

    def on_ip_flagged(self, ip: str, count: int) -> None:
        """Called when an IP exceeds the connection threshold."""
        ...

    def on_ip_blocked(self, ip: str) -> None:
        """Called when an IP is auto-blocked by the engine."""
        ...

    def on_port_scan(self, ip: str, ports: list[int]) -> None:
        """Called when a port scan is detected from an IP."""
        ...

    def on_anomaly(self, ip: str, score: float) -> None:
        """Called when the ML model flags anomalous traffic."""
        ...

    def on_engine_status(self, status: str, details: dict[str, Any]) -> None:
        """Called when the engine status changes (started, stopped, error)."""
        ...


# ---------------------------------------------------------------------------
# Typed event dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EngineEvent:
    """Base class for all engine events."""
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ConnectionDetectedEvent(EngineEvent):
    """A new network connection was observed."""
    ip: str = ""
    port: int = 0
    protocol: str = "TCP"
    direction: str = "in"


@dataclass(frozen=True)
class IPFlaggedEvent(EngineEvent):
    """An IP exceeded the connection-count threshold."""
    ip: str = ""
    count: int = 0


@dataclass(frozen=True)
class IPBlockedEvent(EngineEvent):
    """An IP was auto-blocked by the engine."""
    ip: str = ""
    rule_name: str = ""


@dataclass(frozen=True)
class PortScanEvent(EngineEvent):
    """A port scan was detected from a single IP."""
    ip: str = ""
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class AnomalyEvent(EngineEvent):
    """The ML model flagged anomalous traffic."""
    ip: str = ""
    score: float = 0.0


@dataclass(frozen=True)
class EngineStatusEvent(EngineEvent):
    """Engine lifecycle status change."""
    status: str = ""  # "started", "stopped", "error"
    details: str = ""
