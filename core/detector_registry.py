"""
Detector registry with entry_points plugin discovery.

Built-in detectors (threshold, port-scan) are registered automatically.
Third-party detectors can register via:

    # pyproject.toml / setup.cfg:
    [project.entry-points."netguard.detectors"]
    my_plugin = "my_package.my_module:MyDetector"

Usage:
    from core.detector_registry import DetectorRegistry, get_registry

    registry = get_registry()
    registry.discover_plugins()           # load entry_points plugins

    results = registry.run_all("10.0.0.1", events, context={"count": 15})
"""

from __future__ import annotations

import threading
from typing import Any

from utils.logger import get_logger
from core.detector_abc import AbstractDetector, DetectorResult

logger = get_logger(__name__)

_ENTRY_POINT_GROUP = "netguard.detectors"


class DetectorRegistry:
    """Thread-safe registry managing all active detector instances."""

    def __init__(self) -> None:
        self._detectors: dict[str, AbstractDetector] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, detector: AbstractDetector) -> None:
        """Register a detector instance.

        If a detector with the same name is already registered it is
        replaced and a warning is emitted.
        """
        if not isinstance(detector, AbstractDetector):
            raise TypeError(f"Expected AbstractDetector, got {type(detector)}")
        with self._lock:
            if detector.name in self._detectors:
                logger.warning(
                    "Replacing detector %r (old=%s, new=%s)",
                    detector.name,
                    type(self._detectors[detector.name]).__name__,
                    type(detector).__name__,
                )
            self._detectors[detector.name] = detector
            logger.debug("Registered detector: %r", detector)

    def unregister(self, name: str) -> bool:
        """Remove a detector by name. Returns True if it was found."""
        with self._lock:
            if name in self._detectors:
                del self._detectors[name]
                logger.debug("Unregistered detector: %r", name)
                return True
            return False

    def get(self, name: str) -> AbstractDetector | None:
        """Return the detector with *name*, or None."""
        with self._lock:
            return self._detectors.get(name)

    @property
    def names(self) -> list[str]:
        """Names of all registered detectors."""
        with self._lock:
            return list(self._detectors.keys())

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._detectors)

    # ------------------------------------------------------------------
    # Plugin discovery
    # ------------------------------------------------------------------

    def discover_plugins(self) -> int:
        """Load detector plugins registered via entry_points.

        Returns the number of NEW plugins loaded this call.
        """
        try:
            from importlib.metadata import entry_points
            eps = entry_points(group=_ENTRY_POINT_GROUP)
        except Exception as exc:
            logger.warning("entry_points discovery failed: %s", exc)
            return 0

        loaded = 0
        for ep in eps:
            try:
                cls = ep.load()
                if not (isinstance(cls, type) and issubclass(cls, AbstractDetector)):
                    logger.warning(
                        "Plugin %r is not an AbstractDetector subclass — skipped.", ep.name
                    )
                    continue
                self.register(cls())
                loaded += 1
                logger.info("Loaded plugin detector: %r from %r", ep.name, ep.value)
            except Exception as exc:
                logger.error("Failed to load plugin %r: %s", ep.name, exc)

        return loaded

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_all(self) -> None:
        """Call ``on_start()`` on every registered detector."""
        with self._lock:
            detectors = list(self._detectors.values())
        for d in detectors:
            try:
                d.on_start()
            except Exception as exc:
                logger.warning("Detector %r on_start error: %s", d.name, exc)

    def stop_all(self) -> None:
        """Call ``on_stop()`` on every registered detector."""
        with self._lock:
            detectors = list(self._detectors.values())
        for d in detectors:
            try:
                d.on_stop()
            except Exception as exc:
                logger.warning("Detector %r on_stop error: %s", d.name, exc)

    def train_all(self, data: list[Any]) -> None:
        """Pass training data to all detectors that implement ``on_train``."""
        with self._lock:
            detectors = list(self._detectors.values())
        for d in detectors:
            try:
                d.on_train(data)
            except Exception as exc:
                logger.warning("Detector %r on_train error: %s", d.name, exc)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def run_all(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> list[DetectorResult]:
        """Run all detectors against *events* for *ip*.

        Results from detectors that raise are replaced with a
        non-triggered result so one broken plugin can't silence others.
        """
        with self._lock:
            detectors = list(self._detectors.values())

        results: list[DetectorResult] = []
        for d in detectors:
            try:
                result = d.analyze(ip, events, context=context)
                results.append(result)
            except Exception as exc:
                logger.error("Detector %r raised during analyze: %s", d.name, exc)
                results.append(DetectorResult(triggered=False, reason=f"Error: {exc}"))
        return results

    def run_one(
        self,
        name: str,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult | None:
        """Run a single detector by name. Returns None if not found."""
        with self._lock:
            detector = self._detectors.get(name)
        if detector is None:
            return None
        try:
            return detector.analyze(ip, events, context=context)
        except Exception as exc:
            logger.error("Detector %r raised during analyze: %s", name, exc)
            return DetectorResult(triggered=False, reason=f"Error: {exc}")


# ---------------------------------------------------------------------------
# Built-in detectors
# ---------------------------------------------------------------------------

class ThresholdDetector(AbstractDetector):
    """Detect IPs exceeding connection count threshold (port-scan aware)."""

    name = "threshold"
    version = "1.0.0"

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        port_scan_threshold: int = 5,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold

    def analyze(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult:
        import time
        ctx = context or {}
        now = ctx.get("now", time.time())
        recent = [e for e in events if now - getattr(e, "timestamp", now) <= self.window_seconds]
        count = len(recent)

        ports_hit = list({getattr(e, "port", 0) for e in recent if getattr(e, "port", 0)})
        port_scan = len(ports_hit) >= self.port_scan_threshold

        if count >= self.threshold or port_scan:
            reason = []
            if count >= self.threshold:
                reason.append(f"{count} connections in {self.window_seconds}s")
            if port_scan:
                reason.append(f"port scan: {len(ports_hit)} ports hit")
            score = min(1.0, count / (self.threshold * 2))
            return DetectorResult(
                triggered=True,
                score=score,
                reason="; ".join(reason),
                features={"count": count, "ports_hit": len(ports_hit)},
                rule_id="threshold_builtin",
                action="block" if count >= self.threshold * 2 else "alert",
            )
        return DetectorResult(triggered=False, features={"count": count}, score=0.0)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_registry: DetectorRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> DetectorRegistry:
    """Return the global DetectorRegistry, creating it with built-ins if needed."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = DetectorRegistry()
                _registry.register(ThresholdDetector())
    return _registry


def reset_registry() -> None:
    """Replace the singleton with None so next get_registry() recreates with built-ins (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
