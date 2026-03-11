"""
Alert intelligence layer for NetGuard IDS.

Provides:
  - Deduplication: suppress repeated alerts for the same IP/rule within a window
  - Enrichment:    attach feature explanation to each DetectorResult
  - Correlation:   group related alerts into incidents
  - Severity ranking: merge results from multiple detectors into one verdict

Usage:
    from core.alert_manager import AlertManager

    mgr = AlertManager()
    verdict = mgr.process(ip="10.0.0.1", results=[...])
    if verdict.should_alert:
        print(verdict.summary)
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from utils.logger import get_logger
from core.detector_abc import DetectorResult

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Alert verdict
# ---------------------------------------------------------------------------

@dataclass
class AlertVerdict:
    """Final verdict after deduplication, correlation and ranking.

    Attributes:
        ip:           Source IP.
        should_alert: True when this alert should be written to the log / UI.
        action:       Recommended action: "block" | "alert" | "ignore".
        score:        Aggregate confidence 0.0–1.0.
        severity:     "critical" | "high" | "medium" | "low" | "none".
        summary:      One-line human-readable description.
        triggered_by: List of (detector_name, result) pairs that fired.
        features:     Merged feature dict for explainability.
        deduplicated: True if this alert was suppressed (duplicate).
        incident_id:  Correlation group ID (IP-based for now).
        timestamp:    When this verdict was produced.
    """

    ip: str
    should_alert: bool
    action: str = "alert"
    score: float = 0.0
    severity: str = "none"
    summary: str = ""
    triggered_by: list[tuple[str, DetectorResult]] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    deduplicated: bool = False
    incident_id: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"


# ---------------------------------------------------------------------------
# Feature explainability
# ---------------------------------------------------------------------------

_FEATURE_EXPLANATIONS: dict[str, str] = {
    "count": "total connections in window",
    "unique_ports": "distinct destination ports",
    "unique_protocols": "distinct protocols used",
    "inbound_ratio": "fraction of inbound connections",
    "rate_per_second": "connections per second",
    "max_port_norm": "highest port accessed (normalised)",
    "well_known_port_hits": "service port hits (≤1024)",
    "ports_hit": "distinct destination ports",
}

_SEVERITY_FROM_SCORE = [
    (0.85, "critical"),
    (0.70, "high"),
    (0.45, "medium"),
    (0.20, "low"),
    (0.0,  "none"),
]


def explain_features(features: dict[str, Any]) -> list[str]:
    """Produce a list of human-readable feature explanations for an alert."""
    lines = []
    for key, val in features.items():
        desc = _FEATURE_EXPLANATIONS.get(key, key.replace("_", " "))
        if isinstance(val, float):
            lines.append(f"  • {desc}: {val:.2f}")
        else:
            lines.append(f"  • {desc}: {val}")
    return lines


def score_to_severity(score: float) -> str:
    """Map a 0–1 score to a severity label."""
    for threshold, label in _SEVERITY_FROM_SCORE:
        if score >= threshold:
            return label
    return "none"


# ---------------------------------------------------------------------------
# Deduplication tracker
# ---------------------------------------------------------------------------

class DeduplicationState:
    """Tracks recent alerts per (ip, rule_id) to suppress duplicates."""

    def __init__(self, window_seconds: int = 300, max_suppress: int = 10) -> None:
        """
        Args:
            window_seconds: How long after first alert to suppress duplicates.
            max_suppress:   After this many suppressions, let the next one through.
        """
        self.window = window_seconds
        self.max_suppress = max_suppress
        # (ip, rule_id) → (first_seen, suppress_count)
        self._seen: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.RLock()

    def is_duplicate(self, ip: str, rule_id: str) -> bool:
        """Return True if this alert should be suppressed."""
        key = (ip, rule_id)
        now = time.time()
        with self._lock:
            if key not in self._seen:
                self._seen[key] = (now, 0)
                return False

            first_seen, count = self._seen[key]

            # Window expired — reset
            if now - first_seen > self.window:
                self._seen[key] = (now, 0)
                return False

            # Max suppressions reached — let it through and reset count
            if count >= self.max_suppress:
                self._seen[key] = (now, 0)
                return False

            # Within window and under limit — suppress
            self._seen[key] = (first_seen, count + 1)
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()

    def prune_expired(self) -> int:
        """Remove entries older than the dedup window. Returns count pruned."""
        now = time.time()
        with self._lock:
            expired = [k for k, (ts, _) in self._seen.items() if now - ts > self.window]
            for k in expired:
                del self._seen[k]
            return len(expired)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._seen)


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------

class AlertManager:
    """Processes DetectorResults into deduplicated, enriched AlertVerdicts.

    Workflow:
        1. Collect all triggered results for an IP.
        2. Deduplicate per (ip, rule_id) against the dedup window.
        3. Merge features from all results for explainability.
        4. Compute aggregate score and severity.
        5. Determine recommended action (most severe wins).
        6. Return AlertVerdict.
    """

    _ACTION_RANK = {"ignore": 0, "alert": 1, "block": 2}
    _SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(
        self,
        dedup_window_seconds: int = 300,
        max_suppress: int = 10,
        persist_to_db: bool = True,
    ) -> None:
        self._dedup = DeduplicationState(dedup_window_seconds, max_suppress)
        self._persist = persist_to_db
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Main processing
    # ------------------------------------------------------------------

    def process(
        self,
        ip: str,
        results: list[DetectorResult],
        *,
        detector_names: list[str] | None = None,
        extra_features: dict[str, Any] | None = None,
    ) -> AlertVerdict:
        """Turn a list of DetectorResults into a single AlertVerdict.

        Args:
            ip:              Source IP being evaluated.
            results:         Output from DetectorRegistry.run_all().
            detector_names:  Parallel list of detector names for attribution.
            extra_features:  Additional context to merge into the verdict features.

        Returns:
            An AlertVerdict. Check `should_alert` before acting on it.
        """
        names = detector_names or [f"detector_{i}" for i in range(len(results))]

        triggered = [
            (name, r) for name, r in zip(names, results) if r.triggered
        ]

        if not triggered:
            return AlertVerdict(
                ip=ip,
                should_alert=False,
                action="ignore",
                severity="none",
                summary=f"No threats detected for {ip}",
            )

        # Deduplication
        non_dupes = []
        for name, r in triggered:
            if self._dedup.is_duplicate(ip, r.rule_id or name):
                logger.debug("Deduplicated alert: ip=%s rule=%s", ip, r.rule_id)
            else:
                non_dupes.append((name, r))

        if not non_dupes:
            return AlertVerdict(
                ip=ip,
                should_alert=False,
                action="ignore",
                deduplicated=True,
                summary=f"Alert suppressed (duplicate) for {ip}",
            )

        # Merge features for explainability
        merged_features: dict[str, Any] = {}
        for _, r in non_dupes:
            merged_features.update(r.features)
        if extra_features:
            merged_features.update(extra_features)

        # Aggregate score (max of triggered scores)
        agg_score = max(r.score for _, r in non_dupes)

        # Highest-priority action wins
        best_action = max(
            (r.action for _, r in non_dupes),
            key=lambda a: self._ACTION_RANK.get(a, 0),
        )

        severity = score_to_severity(agg_score)
        incident_id = f"INC-{ip.replace('.', '-')}"

        # Build summary
        rule_ids = [r.rule_id for _, r in non_dupes if r.rule_id]
        reasons = [r.reason for _, r in non_dupes if r.reason]
        top_reason = reasons[0] if reasons else "Anomalous behaviour detected"

        summary = (
            f"[{severity.upper()}] {ip} — {top_reason}"
            + (f" (rules: {', '.join(rule_ids[:3])})" if rule_ids else "")
        )

        verdict = AlertVerdict(
            ip=ip,
            should_alert=True,
            action=best_action,
            score=agg_score,
            severity=severity,
            summary=summary,
            triggered_by=non_dupes,
            features=merged_features,
            incident_id=incident_id,
            timestamp=time.time(),
        )

        if self._persist:
            self._write_to_db(verdict)

        return verdict

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def explain(self, verdict: AlertVerdict) -> str:
        """Produce a human-readable explanation of an AlertVerdict."""
        if not verdict.should_alert:
            return f"No alert: {verdict.summary}"

        lines = [
            f"=== Alert: {verdict.ip} ===",
            f"Severity  : {verdict.severity.upper()}",
            f"Action    : {verdict.action.upper()}",
            f"Score     : {verdict.score:.2f}",
            f"Incident  : {verdict.incident_id}",
            "",
            "Triggered by:",
        ]
        for name, r in verdict.triggered_by:
            lines.append(f"  [{name}] {r.reason or '(no reason)'} (score={r.score:.2f})")

        if verdict.features:
            lines.append("")
            lines.append("Evidence features:")
            lines.extend(explain_features(verdict.features))

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Database persistence
    # ------------------------------------------------------------------

    def _write_to_db(self, verdict: AlertVerdict) -> None:
        """Persist the alert verdict to the database via blocklist.add_alert."""
        try:
            from core.blocklist import add_alert
            details = f"score={verdict.score:.2f}; incident={verdict.incident_id}; rules={[r.rule_id for _, r in verdict.triggered_by]}"
            add_alert(
                ip=verdict.ip,
                alert_type=verdict.severity,
                details=details[:500],  # truncate for safety
            )
        except Exception as exc:
            logger.warning("Could not persist alert to DB: %s", exc)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def prune_dedup_state(self) -> int:
        """Remove expired deduplication entries. Returns count pruned."""
        return self._dedup.prune_expired()

    @property
    def dedup_state_size(self) -> int:
        return self._dedup.size


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_manager: AlertManager | None = None
_manager_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    """Return the global AlertManager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = AlertManager()
    return _manager


def reset_alert_manager() -> None:
    """Reset the singleton (for testing)."""
    global _manager
    with _manager_lock:
        _manager = None
