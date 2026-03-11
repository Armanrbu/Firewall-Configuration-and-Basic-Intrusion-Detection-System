"""
Config hot-reload, ML A/B testing, and active learning for NetGuard IDS.

Hot-reload:
    Watches config.yaml and any rules/*.yaml files for changes using a
    background watchdog thread (no dependency on the `watchdog` library —
    uses mtime polling). Config changes apply without engine restart.

ML A/B Testing:
    Runs two ML detector instances in parallel, collecting per-IP comparison
    metrics (agreement rate, score delta, which one fired more alerts). A
    "champion" is crowned when it has processed enough samples.

Active Learning:
    Builds a small uncertainty-sampling loop: when two detectors disagree on
    a sample, it is added to a labelling queue. Labelled samples feed the
    next re-train cycle.
"""

from __future__ import annotations

import copy
import statistics
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from utils.logger import get_logger
from core.detector_abc import AbstractDetector, DetectorResult

logger = get_logger(__name__)


# ===========================================================================
# Config Hot-Reload
# ===========================================================================

class ConfigWatcher:
    """
    Background thread that polls config files for mtime changes.

    Usage::

        watcher = ConfigWatcher(
            paths=["config.yaml", "rules/"],
            on_change=lambda changed: engine.reload_config(changed),
            poll_interval=2.0,
        )
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        paths: list[str | Path],
        on_change: Callable[[list[Path]], None],
        poll_interval: float = 2.0,
    ) -> None:
        self._paths         = [Path(p) for p in paths]
        self._on_change     = on_change
        self._poll_interval = poll_interval
        self._stop          = threading.Event()
        self._thread: threading.Thread | None = None
        self._mtimes: dict[Path, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._mtimes = self._snapshot()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="ConfigWatcher", daemon=True
        )
        self._thread.start()
        logger.info("ConfigWatcher started (poll=%.1fs, paths=%s)",
                    self._poll_interval,
                    [str(p) for p in self._paths])

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.debug("ConfigWatcher stopped.")

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            changed = self._detect_changes()
            if changed:
                logger.info("ConfigWatcher: detected changes in %s", changed)
                try:
                    self._on_change(changed)
                except Exception as exc:
                    logger.error("ConfigWatcher on_change callback raised: %s", exc)
                # Snapshot again so we don't re-fire for the same change
                self._mtimes = self._snapshot()

    def _snapshot(self) -> dict[Path, float]:
        """Walk paths, return {file → mtime}."""
        result: dict[Path, float] = {}
        for p in self._paths:
            if p.is_dir():
                for child in p.rglob("*"):
                    if child.is_file():
                        try:
                            result[child] = child.stat().st_mtime
                        except OSError:
                            pass
            elif p.is_file():
                try:
                    result[p] = p.stat().st_mtime
                except OSError:
                    pass
        return result

    def _detect_changes(self) -> list[Path]:
        current = self._snapshot()
        changed: list[Path] = []
        for path, mtime in current.items():
            if self._mtimes.get(path, -1) != mtime:
                changed.append(path)
        # Also detect deletions
        for path in self._mtimes:
            if path not in current:
                changed.append(path)
        return changed

    def force_check(self) -> list[Path]:
        """Trigger an immediate check synchronously (useful for tests)."""
        changed = self._detect_changes()
        if changed:
            self._on_change(changed)
            self._mtimes = self._snapshot()
        return changed


# ===========================================================================
# ML A/B Testing
# ===========================================================================

@dataclass
class ABMetrics:
    """Per-sample comparison record between champion and challenger."""
    ip:               str
    champion_score:   float
    challenger_score: float
    champion_fired:   bool
    challenger_fired: bool
    agreement:        bool = field(init=False)

    def __post_init__(self) -> None:
        self.agreement = self.champion_fired == self.challenger_fired


@dataclass
class ABSummary:
    """Aggregate statistics for the A/B test run so far."""
    samples:          int   = 0
    agreements:       int   = 0
    champion_wins:    int   = 0    # fired while challenger did not
    challenger_wins:  int   = 0    # fired while champion did not
    avg_score_delta:  float = 0.0  # mean(|champion_score - challenger_score|)
    champion_name:    str   = ""
    challenger_name:  str   = ""

    @property
    def agreement_rate(self) -> float:
        return self.agreements / self.samples if self.samples else 0.0

    @property
    def champion_precision_edge(self) -> float:
        """Positive → champion fires more selectively."""
        denom = max(1, self.champion_wins + self.challenger_wins)
        return (self.champion_wins - self.challenger_wins) / denom


class MLABTester:
    """
    Run two ``AbstractDetector`` instances in parallel and track comparison
    metrics. After *min_samples*, ``choose_champion()`` returns the winner.

    Usage::

        champion   = MLDetector(model="isolation_forest")
        challenger = MLDetector(model="ecod")
        tester = MLABTester(champion, challenger, min_samples=500)

        for ip, events in stream:
            result = tester.run(ip, events)  # champion's result wins
            ...

        summary = tester.summary()
        winner  = tester.choose_champion()
    """

    def __init__(
        self,
        champion:    AbstractDetector,
        challenger:  AbstractDetector,
        min_samples: int = 200,
    ) -> None:
        self._champion   = champion
        self._challenger = challenger
        self._min_samples = min_samples
        self._records: list[ABMetrics] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def run(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult:
        """
        Run both detectors; return champion's result.
        Records a comparison metric for every call.
        """
        c_res  = self._safe_analyze(self._champion,   ip, events, context)
        ch_res = self._safe_analyze(self._challenger, ip, events, context)

        with self._lock:
            self._records.append(ABMetrics(
                ip=ip,
                champion_score=c_res.score,
                challenger_score=ch_res.score,
                champion_fired=c_res.triggered,
                challenger_fired=ch_res.triggered,
            ))
        return c_res   # champion's decision is the authoritative result

    def summary(self) -> ABSummary:
        """Return aggregate statistics over all recorded samples."""
        with self._lock:
            records = list(self._records)

        s = ABSummary(
            champion_name=self._champion.name,
            challenger_name=self._challenger.name,
        )
        s.samples = len(records)
        if not records:
            return s

        s.agreements     = sum(1 for r in records if r.agreement)
        s.champion_wins  = sum(1 for r in records if r.champion_fired and not r.challenger_fired)
        s.challenger_wins= sum(1 for r in records if r.challenger_fired and not r.champion_fired)
        deltas = [abs(r.champion_score - r.challenger_score) for r in records]
        s.avg_score_delta = statistics.mean(deltas) if deltas else 0.0
        return s

    def choose_champion(self) -> AbstractDetector:
        """
        Compare detectors and return the better one.

        Promotion heuristic:
          If challenger has ≥ min_samples AND
          challenger_wins > champion_wins by a 20 % margin,
          the challenger is crowned new champion.

        Otherwise returns the current champion.
        """
        s = self.summary()
        if s.samples < self._min_samples:
            logger.info(
                "A/B test: only %d/%d samples — keeping champion '%s'",
                s.samples, self._min_samples, self._champion.name,
            )
            return self._champion

        threshold = s.champion_wins * 1.20
        if s.challenger_wins > threshold:
            logger.info(
                "A/B test: challenger '%s' wins (%d vs %d champion wins) — promoting!",
                self._challenger.name, s.challenger_wins, s.champion_wins,
            )
            return self._challenger

        logger.info(
            "A/B test: champion '%s' retains crown (wins=%d vs %d challenger wins, "
            "agreement=%.1f%%)",
            self._champion.name, s.champion_wins, s.challenger_wins,
            s.agreement_rate * 100,
        )
        return self._champion

    def uncertain_samples(self, limit: int = 100) -> list[ABMetrics]:
        """
        Return the *limit* most uncertain samples for active learning labelling.

        Uncertainty = |champion_score - challenger_score| (high means disagreement)
        """
        with self._lock:
            records = list(self._records)
        uncertain = sorted(records, key=lambda r: abs(r.champion_score - r.challenger_score), reverse=True)
        return uncertain[:limit]

    def reset(self) -> None:
        with self._lock:
            self._records.clear()

    def _safe_analyze(
        self,
        detector: AbstractDetector,
        ip: str,
        events: list[Any],
        context: dict[str, Any] | None,
    ) -> DetectorResult:
        try:
            return detector.analyze(ip, events, context=context)
        except Exception as exc:
            logger.error("A/B detector '%s' raised: %s", detector.name, exc)
            return DetectorResult(triggered=False, reason=f"Error: {exc}")


# ===========================================================================
# Active Learning Queue
# ===========================================================================

@dataclass
class LabellingItem:
    """A sample waiting for a human (or oracle) label."""
    ip:               str
    events:           list[Any]
    context:          dict[str, Any]
    champion_score:   float
    challenger_score: float
    label:            str | None = None   # "benign" | "malicious" | None
    labelled_at:      float | None = None


class ActiveLearningQueue:
    """
    Collects uncertain samples from the A/B tester for human review.

    Usage::

        alq = ActiveLearningQueue(max_size=1000)
        # Feed uncertain items from tester
        for item in tester.uncertain_samples():
            alq.push(item.ip, [], {}, item.champion_score, item.challenger_score)

        # UI / analyst labels items
        alq.label("10.0.0.1", "malicious")

        # When enough labelled items exist, pass to re-train
        labelled = alq.labelled_items(min_items=50)
        detector.on_train(labelled)
    """

    def __init__(self, max_size: int = 1000) -> None:
        self._items: list[LabellingItem] = []
        self._lock = threading.Lock()
        self._max_size = max_size

    def push(
        self,
        ip: str,
        events: list[Any],
        context: dict[str, Any],
        champion_score: float,
        challenger_score: float,
    ) -> None:
        """Add a sample to the queue if there's room."""
        with self._lock:
            if len(self._items) >= self._max_size:
                # Remove oldest labelled item to make room
                labelled = [i for i in self._items if i.label is not None]
                if labelled:
                    self._items.remove(labelled[0])
                else:
                    return  # queue full of unlabelled items — discard
            self._items.append(LabellingItem(
                ip=ip,
                events=copy.copy(events),
                context=copy.copy(context),
                champion_score=champion_score,
                challenger_score=challenger_score,
            ))

    def label(self, ip: str, label: str) -> int:
        """
        Apply *label* to all unlabelled items for *ip*.
        Returns the number of items labelled.
        """
        assert label in ("benign", "malicious"), f"Invalid label: {label!r}"
        count = 0
        with self._lock:
            for item in self._items:
                if item.ip == ip and item.label is None:
                    item.label = label
                    item.labelled_at = time.time()
                    count += 1
        return count

    def pending_items(self) -> list[LabellingItem]:
        """Return items that have not been labelled yet."""
        with self._lock:
            return [i for i in self._items if i.label is None]

    def labelled_items(self, min_items: int = 0) -> list[LabellingItem]:
        """Return labelled items. Empty list if count < min_items."""
        with self._lock:
            result = [i for i in self._items if i.label is not None]
        return result if len(result) >= min_items else []

    def clear_labelled(self) -> int:
        """Remove all labelled items (e.g., after re-training). Returns count removed."""
        with self._lock:
            before = len(self._items)
            self._items = [i for i in self._items if i.label is None]
            return before - len(self._items)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._items)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items if i.label is None)

    @property
    def labelled_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._items if i.label is not None)
