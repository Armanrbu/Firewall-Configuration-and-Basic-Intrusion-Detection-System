"""
Standalone NetGuard IDS engine.

Runs the IDS detection pipeline without any GUI dependency.
Can be used headless on servers or consumed by GUI/API/CLI frontends.

Usage:
    engine = NetGuardEngine(config)
    engine.register_handler(my_handler)
    engine.start()
    ...
    engine.stop()
"""

from __future__ import annotations

import threading
import time
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

# Lazy imports to avoid circular dependencies and keep Qt out
# of the engine's import chain.


class NetGuardEngine:
    """
    Core engine that owns the IDS pipeline, scheduler, and monitoring threads.

    This class has **zero** Qt/GUI dependencies. Frontends register as
    event handlers to receive real-time updates, either via:
      - ``register_handler()`` — legacy protocol-based callbacks
      - ``get_event_bus().subscribe(EventType, callback)`` — typed EventBus
    """

    def __init__(self, config: dict[str, Any] | None = None, event_bus=None) -> None:
        self._config = config or {}
        self._running = False
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

        # Handlers registered for engine events (legacy protocol API)
        self._handlers: list[Any] = []

        # EventBus for typed event dispatch
        from core.event_bus import get_event_bus
        self._bus = event_bus or get_event_bus()

        # IDS engine (pure logic, no Qt)
        from core.ids import IDSEngine
        ids_cfg = self._config.get("ids", {})
        whitelist: set[str] | None = None
        try:
            from core.whitelist import get_all
            whitelist = set(get_all())
        except Exception:
            pass

        self._ids = IDSEngine(
            threshold=ids_cfg.get("alert_threshold", 10),
            window_seconds=ids_cfg.get("time_window_seconds", 60),
            port_scan_threshold=ids_cfg.get("port_scan_threshold", 5),
            port_scan_window=ids_cfg.get("port_scan_window_seconds", 30),
            auto_block=ids_cfg.get("auto_block", True),
            whitelist=whitelist,
        )

        # Wire IDS callbacks to our dispatchers
        self._ids.on_connection = self._dispatch_connection
        self._ids.on_ip_flagged = self._dispatch_ip_flagged
        self._ids.on_ip_blocked = self._dispatch_ip_blocked
        self._ids.on_port_scan = self._dispatch_port_scan

        # Anomaly detector (optional)
        self._anomaly = None
        try:
            from core.anomaly import AnomalyDetector
            self._anomaly = AnomalyDetector()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Handler management
    # ------------------------------------------------------------------

    def register_handler(self, handler: Any) -> None:
        """Register an event handler to receive engine events.

        The handler should implement some or all of the methods defined
        by the ``EngineEventHandler`` protocol in ``core.interfaces``.
        """
        if handler not in self._handlers:
            self._handlers.append(handler)

    def unregister_handler(self, handler: Any) -> None:
        """Remove a previously registered handler."""
        try:
            self._handlers.remove(handler)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the engine: psutil monitoring + scheduler."""
        if self._running:
            logger.warning("Engine already running.")
            return

        self._running = True
        self._stop_event.clear()

        # Start psutil monitoring thread
        t = threading.Thread(target=self._psutil_loop, daemon=True, name="Engine-PsutilMonitor")
        self._threads.append(t)
        t.start()

        # Optionally start firewall log monitoring
        fw_cfg = self._config.get("firewall", {})
        log_path = fw_cfg.get("log_path", "")
        if log_path:
            t_log = threading.Thread(
                target=self._log_loop, args=(log_path,),
                daemon=True, name="Engine-LogMonitor",
            )
            self._threads.append(t_log)
            t_log.start()

        self._dispatch_status("started", "Engine is monitoring")
        logger.info("NetGuard engine started (headless mode).")

    def stop(self, timeout: float = 5.0) -> None:
        """Gracefully stop all engine threads."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()

        self._dispatch_status("stopped", "Engine shut down cleanly")
        logger.info("NetGuard engine stopped.")

    @property
    def running(self) -> bool:
        """Return True if the engine is currently running."""
        return self._running

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        """Return engine state for API/CLI consumption."""
        ids_stats = self._ids.get_stats()
        return {
            "running": self._running,
            "threads": len([t for t in self._threads if t.is_alive()]),
            "tracked_ips": ids_stats.get("tracked_ips", 0),
            "flagged_ips": ids_stats.get("flagged_ips", []),
            "anomaly_detector": self._anomaly is not None,
        }

    @property
    def ids_engine(self) -> Any:
        """Return the underlying IDSEngine for direct access."""
        return self._ids

    # ------------------------------------------------------------------
    # Monitoring loops (extracted from IDSWorker)
    # ------------------------------------------------------------------

    def _psutil_loop(self) -> None:
        """Monitor live connections via psutil."""
        try:
            import psutil
        except ImportError:
            logger.warning("psutil not installed; live connection monitoring disabled.")
            return

        from core.ids import ConnectionEvent

        seen: set[tuple] = set()
        while not self._stop_event.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
                current: set[tuple] = set()
                for conn in conns:
                    if conn.raddr and conn.raddr.ip:
                        key = (conn.raddr.ip, conn.raddr.port, conn.type)
                        current.add(key)
                        if key not in seen:
                            proto = "TCP" if conn.type == 1 else "UDP"
                            event = ConnectionEvent(
                                ip=conn.raddr.ip,
                                port=conn.raddr.port,
                                protocol=proto,
                                direction="in",
                            )
                            self._ids.feed(event)

                            # Anomaly check
                            if self._anomaly:
                                count = len(self._ids._conn_times.get(conn.raddr.ip, []))
                                try:
                                    if self._anomaly.is_anomaly(conn.raddr.ip, count, [conn.raddr.port]):
                                        self._dispatch_anomaly(conn.raddr.ip, 1.0)
                                except Exception:
                                    pass

                    seen = current
            except Exception as exc:
                logger.debug("psutil loop error: %s", exc)
            self._stop_event.wait(2)

    def _log_loop(self, log_path: str) -> None:
        """Monitor firewall log file for connection events."""
        import os
        import re
        from core.ids import ConnectionEvent

        _IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

        if not os.path.exists(log_path):
            logger.warning("Log file not found: %s", log_path)
            return

        try:
            with open(log_path, "r", errors="ignore") as fh:
                fh.seek(0, 2)  # seek to end
                while not self._stop_event.is_set():
                    line = fh.readline()
                    if not line:
                        self._stop_event.wait(0.5)
                        continue
                    text = line.strip()
                    m = _IP_RE.search(text)
                    if m:
                        ip = m.group(1)
                        parts = text.split()
                        port = 0
                        if len(parts) >= 7:
                            try:
                                port = int(parts[6])
                            except ValueError:
                                pass
                        event = ConnectionEvent(ip=ip, port=port, direction="in")
                        self._ids.feed(event)
        except Exception as exc:
            logger.error("Log loop error: %s", exc)

    # ------------------------------------------------------------------
    # Event dispatchers
    # ------------------------------------------------------------------

    def _dispatch_connection(self, event: Any) -> None:
        """Dispatch a connection event to all handlers and the event bus."""
        from core.interfaces import ConnectionDetectedEvent
        self._bus.publish(ConnectionDetectedEvent(
            ip=event.ip, port=event.port,
            protocol=event.protocol, direction=event.direction,
        ))
        for h in self._handlers:
            try:
                if hasattr(h, "on_connection"):
                    h.on_connection(event.ip, event.port, event.protocol, event.direction)
            except Exception as exc:
                logger.debug("Handler error in on_connection: %s", exc)

    def _dispatch_ip_flagged(self, ip: str, count: int) -> None:
        """Dispatch an IP-flagged event to all handlers and the event bus."""
        from core.interfaces import IPFlaggedEvent
        self._bus.publish(IPFlaggedEvent(ip=ip, count=count))
        for h in self._handlers:
            try:
                if hasattr(h, "on_ip_flagged"):
                    h.on_ip_flagged(ip, count)
            except Exception as exc:
                logger.debug("Handler error in on_ip_flagged: %s", exc)

    def _dispatch_ip_blocked(self, ip: str) -> None:
        """Dispatch an IP-blocked event to all handlers and the event bus."""
        from core.interfaces import IPBlockedEvent
        self._bus.publish(IPBlockedEvent(ip=ip))
        for h in self._handlers:
            try:
                if hasattr(h, "on_ip_blocked"):
                    h.on_ip_blocked(ip)
            except Exception as exc:
                logger.debug("Handler error in on_ip_blocked: %s", exc)

    def _dispatch_port_scan(self, ip: str, ports: list[int]) -> None:
        """Dispatch a port-scan event to all handlers and the event bus."""
        from core.interfaces import PortScanEvent
        self._bus.publish(PortScanEvent(ip=ip, ports=tuple(ports)))
        for h in self._handlers:
            try:
                if hasattr(h, "on_port_scan"):
                    h.on_port_scan(ip, ports)
            except Exception as exc:
                logger.debug("Handler error in on_port_scan: %s", exc)

    def _dispatch_anomaly(self, ip: str, score: float) -> None:
        """Dispatch an anomaly event to all handlers and the event bus."""
        from core.interfaces import AnomalyEvent
        self._bus.publish(AnomalyEvent(ip=ip, score=score))
        for h in self._handlers:
            try:
                if hasattr(h, "on_anomaly"):
                    h.on_anomaly(ip, score)
            except Exception as exc:
                logger.debug("Handler error in on_anomaly: %s", exc)

    def _dispatch_status(self, status: str, details: str) -> None:
        """Dispatch an engine status event to all handlers and the event bus."""
        from core.interfaces import EngineStatusEvent
        self._bus.publish(EngineStatusEvent(status=status, details=details))
        for h in self._handlers:
            try:
                if hasattr(h, "on_engine_status"):
                    h.on_engine_status(status, {"message": details})
            except Exception as exc:
                logger.debug("Handler error in on_engine_status: %s", exc)
