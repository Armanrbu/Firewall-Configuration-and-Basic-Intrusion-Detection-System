"""
Abstract detector interface for the NetGuard IDS plugin architecture.

All detection strategies (threshold, YAML rules, ML, signature) implement
``AbstractDetector`` and are registered via ``entry_points`` or the
``register_detector()`` API.

Usage:
    from core.detector_abc import AbstractDetector, DetectorResult

    class MyDetector(AbstractDetector):
        name = "my_detector"
        version = "1.0.0"

        def analyze(self, ip, events):
            if len(events) > 100:
                return DetectorResult(triggered=True, score=1.0, reason="High volume")
            return DetectorResult(triggered=False)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectorResult:
    """Standardised result returned by every detector.

    Attributes:
        triggered:  Whether the detector considers this behaviour malicious.
        score:      Confidence 0.0–1.0 (1.0 = certain threat).
        reason:     Human-readable explanation for why it triggered.
        features:   Dict of feature name → value for explainability.
        rule_id:    ID of the rule that triggered (if applicable).
        action:     Recommended action: "alert", "block", "ignore".
    """

    triggered: bool
    score: float = 0.0
    reason: str = ""
    features: dict[str, Any] = field(default_factory=dict)
    rule_id: str = ""
    action: str = "alert"

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"DetectorResult.score must be 0.0–1.0, got {self.score}")
        if self.action not in ("alert", "block", "ignore"):
            raise ValueError(f"DetectorResult.action must be alert/block/ignore, got {self.action!r}")


class AbstractDetector(ABC):
    """Base class for all IDS detection strategies.

    Subclasses must set:
        name:    Unique identifier used in config and logs.
        version: Semantic version string.

    Subclasses must implement:
        analyze(ip, events) → DetectorResult

    Optionally override:
        on_start()  — called when the engine starts
        on_stop()   — called when the engine stops
        on_train(data) — called when training data is available
    """

    name: str = "abstract"
    version: str = "0.0.0"

    @abstractmethod
    def analyze(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult:
        """Analyze the given connection events for IP *ip*.

        Args:
            ip:      The source IP address being analyzed.
            events:  List of ``ConnectionEvent`` objects for this IP.
            context: Optional extra context (ports hit, timestamps, etc.).

        Returns:
            ``DetectorResult`` describing whether a threat was detected.
        """

    def on_start(self) -> None:
        """Called when the engine starts. Override for initialization."""

    def on_stop(self) -> None:
        """Called when the engine stops. Override for cleanup."""

    def on_train(self, data: list[Any]) -> None:
        """Called with training data. Override for ML detectors."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} version={self.version!r}>"
