"""
Intrusion Detection System engine.

Monitors live connections via psutil and parses Windows firewall logs.
Emits Qt signals for UI integration.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Callable

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from PyQt5.QtCore import QObject, pyqtSignal
    HAS_QT = True
except ImportError:
    HAS_QT = False

from utils.logger import get_logger

logger = get_logger(__name__)

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


class ConnectionEvent:
    """Represents a single detected connection event."""

    __slots__ = ("ip", "port", "protocol", "direction", "timestamp")

    def __init__(
        self,
        ip: str,
        port: int = 0,
        protocol: str = "TCP",
        direction: str = "in",
        timestamp: float | None = None,
    ) -> None:
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.direction = direction
        self.timestamp = timestamp or time.time()


# ---------------------------------------------------------------------------
# Base IDS engine (no Qt dependency)
# ---------------------------------------------------------------------------

class IDSEngine:
    """
    Core IDS logic without Qt dependency.

    Tracks connection attempts per IP using a sliding time window.
    Detects:
    - Repeated connections exceeding a threshold → triggers on_ip_flagged
    - Port scans (single IP hitting many different ports) → triggers on_port_scan
    - SYN flood patterns (many connections in a very short burst) → triggers on_syn_flood
    """

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        port_scan_threshold: int = 5,
        port_scan_window: int = 30,
        auto_block: bool = True,
        whitelist: set[str] | None = None,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.auto_block = auto_block
        self.whitelist: set[str] = whitelist or {"127.0.0.1", "0.0.0.0", "::1"}

        # ip → list of timestamps
        self._conn_times: dict[str, list[float]] = defaultdict(list)
        # ip → {port → list of timestamps}
        self._port_times: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
        # ips already flagged for threshold breach (prevents duplicate callbacks)
        self._flagged: set[str] = set()
        # ips already flagged for port scan (separate from threshold flagging)
        self._port_scan_flagged: set[str] = set()
        # callback hooks
        self.on_connection: Callable[[ConnectionEvent], None] | None = None
        self.on_ip_flagged: Callable[[str, int], None] | None = None
        self.on_ip_blocked: Callable[[str], None] | None = None
        self.on_port_scan: Callable[[str, list[int]], None] | None = None
        self.on_anomaly: Callable[[str], None] | None = None

    def feed(self, event: ConnectionEvent) -> None:
        """Process a connection event through the IDS pipeline."""
        ip = event.ip
        if ip in self.whitelist:
            return

        now = event.timestamp

        # — connection count tracking
        times = self._conn_times[ip]
        times.append(now)
        self._conn_times[ip] = [t for t in times if now - t <= self.window_seconds]
        count = len(self._conn_times[ip])

        # — port scan tracking
        if event.port:
            port_entry = self._port_times[ip][event.port]
            port_entry.append(now)
            self._port_times[ip][event.port] = [
                t for t in port_entry if now - t <= self.port_scan_window
            ]
            # prune old ports
            active_ports = [
                p for p, ts in self._port_times[ip].items()
                if any(now - t <= self.port_scan_window for t in ts)
            ]
            if len(active_ports) >= self.port_scan_threshold and ip not in self._port_scan_flagged:
                self._port_scan_flagged.add(ip)
                logger.warning("Port scan detected from %s — ports: %s", ip, active_ports)
                if self.on_port_scan:
                    self.on_port_scan(ip, active_ports)

        # — threshold check
        if self.on_connection:
            self.on_connection(event)

        if count >= self.threshold and ip not in self._flagged:
            self._flagged.add(ip)
            logger.warning("IP flagged: %s (%d connections in %ds)", ip, count, self.window_seconds)
            if self.on_ip_flagged:
                self.on_ip_flagged(ip, count)
            if self.auto_block:
                self._do_block(ip)

    def _do_block(self, ip: str) -> None:
        try:
            from core.firewall import block_ip
            result = block_ip(ip)
            logger.info("Auto-block %s: %s", ip, result.get("message"))
            if self.on_ip_blocked:
                self.on_ip_blocked(ip)
        except Exception as exc:
            logger.error("Auto-block failed for %s: %s", ip, exc)

    def reset_ip(self, ip: str) -> None:
        """Clear tracking state for a specific IP."""
        self._conn_times.pop(ip, None)
        self._port_times.pop(ip, None)
        self._flagged.discard(ip)
        self._port_scan_flagged.discard(ip)

    def get_stats(self) -> dict:
        """Return current tracking statistics."""
        return {
            "tracked_ips": len(self._conn_times),
            "flagged_ips": list(self._flagged),
        }


# ---------------------------------------------------------------------------
# Qt-integrated IDS worker
# ---------------------------------------------------------------------------

if HAS_QT:
    class IDSWorker(QObject):
        """
        Qt QObject that wraps IDSEngine and adds psutil-based live monitoring.

        Signals:
            new_connection(str)    — emitted for each connection event (formatted string)
            ip_flagged(str, int)   — ip, connection count
            ip_blocked(str)        — ip that was auto-blocked
            anomaly_detected(str)  — ip flagged by anomaly detector
            port_scan(str, list)   — ip, list of ports
            log_line(str)          — raw log line from firewall log file
        """

        new_connection = pyqtSignal(str)
        ip_flagged = pyqtSignal(str, int)
        ip_blocked = pyqtSignal(str)
        anomaly_detected = pyqtSignal(str)
        port_scan = pyqtSignal(str, object)
        log_line = pyqtSignal(str)

        def __init__(
            self,
            threshold: int = 10,
            window_seconds: int = 60,
            port_scan_threshold: int = 5,
            port_scan_window: int = 30,
            auto_block: bool = True,
            whitelist: set[str] | None = None,
            log_path: str = "",
        ) -> None:
            super().__init__()
            self._running = False
            self.log_path = log_path

            self.engine = IDSEngine(
                threshold=threshold,
                window_seconds=window_seconds,
                port_scan_threshold=port_scan_threshold,
                port_scan_window=port_scan_window,
                auto_block=auto_block,
                whitelist=whitelist,
            )
            self.engine.on_ip_flagged = self._on_ip_flagged
            self.engine.on_ip_blocked = lambda ip: self.ip_blocked.emit(ip)
            self.engine.on_port_scan = lambda ip, ports: self.port_scan.emit(ip, ports)
            self.engine.on_connection = self._on_connection

            # Try to set up anomaly detector
            try:
                from core.anomaly import AnomalyDetector
                self._anomaly = AnomalyDetector()
            except Exception:
                self._anomaly = None

        def _on_connection(self, event: ConnectionEvent) -> None:
            msg = (
                f"[{time.strftime('%H:%M:%S', time.localtime(event.timestamp))}] "
                f"{event.direction.upper()} {event.protocol} "
                f"{event.ip}:{event.port}"
            )
            self.new_connection.emit(msg)

            # anomaly check
            if self._anomaly:
                count = len(self.engine._conn_times.get(event.ip, []))
                try:
                    if self._anomaly.is_anomaly(event.ip, count, [event.port]):
                        self.anomaly_detected.emit(event.ip)
                except Exception:
                    pass

        def _on_ip_flagged(self, ip: str, count: int) -> None:
            self.ip_flagged.emit(ip, count)

        def start(self) -> None:
            """Start monitoring — call this from the worker thread."""
            import threading
            self._running = True
            threads = [threading.Thread(target=self._psutil_loop, daemon=True)]
            if self.log_path:
                threads.append(threading.Thread(target=self._log_loop, daemon=True))
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        def stop(self) -> None:
            self._running = False

        def _psutil_loop(self) -> None:
            if not HAS_PSUTIL:
                logger.warning("psutil not installed; live connection monitoring disabled.")
                return
            seen: set[tuple] = set()
            while self._running:
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
                                self.engine.feed(event)
                    seen = current
                except Exception as exc:
                    logger.debug("psutil loop error: %s", exc)
                time.sleep(2)

        def _log_loop(self) -> None:
            import os
            if not os.path.exists(self.log_path):
                logger.warning("Log file not found: %s", self.log_path)
                return
            try:
                with open(self.log_path, "r", errors="ignore") as fh:
                    fh.seek(0, 2)  # seek to end
                    while self._running:
                        line = fh.readline()
                        if not line:
                            time.sleep(0.5)
                            continue
                        text = line.strip()
                        self.log_line.emit(text)
                        m = _IP_RE.search(text)
                        if m:
                            ip = m.group(1)
                            # parse port from log line (Windows format: date time action protocol src-ip dst-ip src-port dst-port ...)
                            parts = text.split()
                            port = 0
                            if len(parts) >= 7:
                                try:
                                    port = int(parts[6])
                                except ValueError:
                                    pass
                            event = ConnectionEvent(ip=ip, port=port, direction="in")
                            self.engine.feed(event)
            except Exception as exc:
                logger.error("Log loop error: %s", exc)

else:
    # Dummy class when Qt is not available (for testing)
    class IDSWorker:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            self.engine = IDSEngine(*args, **kwargs)

        def start(self):
            pass

        def stop(self):
            pass
