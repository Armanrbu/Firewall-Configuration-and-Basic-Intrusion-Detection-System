"""
EventBus → PySide6 Qt signal bridge.

Subscribes to all EventBus events and re-emits them as Qt signals so that
GUI widgets can connect to them.  Qt signal delivery is automatically
thread-safe (cross-thread QueuedConnection), so background engine threads
can safely publish to the EventBus without worrying about Qt threading rules.

Usage:
    bridge = EventBusBridge()
    bridge.ip_flagged.connect(my_slot)          # Qt slot
    bridge.start(get_event_bus())               # subscribe to EventBus
    ...
    bridge.stop()                               # unsubscribe cleanly
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from core.interfaces import (
    IPFlaggedEvent,
    IPBlockedEvent,
    PortScanEvent,
    AnomalyEvent,
    ConnectionDetectedEvent,
    EngineStatusEvent,
)
from utils.logger import get_logger

logger = get_logger(__name__)


class EventBusBridge(QObject):
    """
    Thin adapter: EventBus subscriber → PySide6 Signal emitter.

    Every engine event type gets its own typed Qt signal.
    Widgets connect to these signals exactly as they would to any other Qt signal.
    """

    # All signals must be class-level
    ip_flagged       = Signal(str, int)   # ip, count
    ip_blocked       = Signal(str)        # ip
    port_scan        = Signal(str, list)  # ip, [ports]
    anomaly_detected = Signal(str, float) # ip, score
    connection_seen  = Signal(str, int, str, str)  # ip, port, proto, direction
    engine_status    = Signal(str, str)   # status, details
    alert_event      = Signal(object)     # raw event (for catch-all consumers)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._bus = None
        self._subscribed = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, bus=None) -> None:
        """Subscribe to the EventBus.  Call once after Qt app is created."""
        if self._subscribed:
            return
        from core.event_bus import get_event_bus
        self._bus = bus or get_event_bus()
        self._bus.subscribe_all(self._on_event)
        self._subscribed = True
        logger.debug("EventBusBridge subscribed to EventBus.")

    def stop(self) -> None:
        """Unsubscribe cleanly."""
        if self._bus and self._subscribed:
            self._bus.unsubscribe_all(self._on_event)
            self._subscribed = False
            logger.debug("EventBusBridge unsubscribed from EventBus.")

    # ------------------------------------------------------------------
    # Internal event dispatcher
    # ------------------------------------------------------------------

    def _on_event(self, event: object) -> None:
        """Route raw EventBus events to typed Qt signals."""
        try:
            if isinstance(event, IPFlaggedEvent):
                self.ip_flagged.emit(event.ip, event.count)
            elif isinstance(event, IPBlockedEvent):
                self.ip_blocked.emit(event.ip)
            elif isinstance(event, PortScanEvent):
                self.port_scan.emit(event.ip, list(event.ports))
            elif isinstance(event, AnomalyEvent):
                self.anomaly_detected.emit(event.ip, event.score)
            elif isinstance(event, ConnectionDetectedEvent):
                self.connection_seen.emit(event.ip, event.port, event.protocol, event.direction)
            elif isinstance(event, EngineStatusEvent):
                self.engine_status.emit(event.status, event.details)

            # Always emit the catch-all for any custom subscribers
            self.alert_event.emit(event)
        except Exception as exc:
            logger.warning("EventBusBridge: error dispatching %s: %s", type(event).__name__, exc)
