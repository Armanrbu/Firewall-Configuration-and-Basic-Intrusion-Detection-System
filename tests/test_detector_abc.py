"""Tests for core.detector_abc and core.detector_registry."""

from __future__ import annotations

import sys
import os
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detector_abc import AbstractDetector, DetectorResult


# ---------------------------------------------------------------------------
# DetectorResult
# ---------------------------------------------------------------------------

class TestDetectorResult:

    def test_basic_not_triggered(self) -> None:
        r = DetectorResult(triggered=False)
        assert r.triggered is False
        assert r.score == 0.0
        assert r.action == "alert"

    def test_triggered_with_score(self) -> None:
        r = DetectorResult(triggered=True, score=0.9, reason="High volume")
        assert r.triggered is True
        assert r.score == 0.9
        assert r.reason == "High volume"

    def test_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="score"):
            DetectorResult(triggered=True, score=1.5)

    def test_score_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            DetectorResult(triggered=True, score=-0.1)

    def test_invalid_action_raises(self) -> None:
        with pytest.raises(ValueError, match="action"):
            DetectorResult(triggered=True, score=0.5, action="destroy")

    def test_valid_actions(self) -> None:
        for action in ("alert", "block", "ignore"):
            r = DetectorResult(triggered=True, score=0.5, action=action)
            assert r.action == action

    def test_features_dict(self) -> None:
        r = DetectorResult(triggered=True, score=0.5, features={"count": 15, "ports": 3})
        assert r.features["count"] == 15

    def test_rule_id(self) -> None:
        r = DetectorResult(triggered=True, score=0.8, rule_id="high-volume")
        assert r.rule_id == "high-volume"

    def test_frozen_immutable(self) -> None:
        r = DetectorResult(triggered=False)
        with pytest.raises(Exception):
            r.triggered = True  # type: ignore


# ---------------------------------------------------------------------------
# AbstractDetector ABC
# ---------------------------------------------------------------------------

class TestAbstractDetectorABC:

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            AbstractDetector()  # type: ignore

    def test_incomplete_subclass_raises(self) -> None:
        class IncompleteDetector(AbstractDetector):
            name = "incomplete"
            pass  # missing analyze()

        with pytest.raises(TypeError):
            IncompleteDetector()

    def test_complete_subclass_works(self) -> None:
        class SimpleDetector(AbstractDetector):
            name = "simple"
            version = "1.0.0"

            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=len(events) > 5, score=0.5)

        d = SimpleDetector()
        result = d.analyze("1.2.3.4", [1, 2, 3, 4, 5, 6])
        assert result.triggered is True

    def test_default_lifecycle_hooks_are_noop(self) -> None:
        class MinimalDetector(AbstractDetector):
            name = "minimal"

            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=False)

        d = MinimalDetector()
        d.on_start()   # should not raise
        d.on_stop()    # should not raise
        d.on_train([]) # should not raise

    def test_repr(self) -> None:
        class ReprDetector(AbstractDetector):
            name = "repr_test"
            version = "2.0.0"

            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=False)

        d = ReprDetector()
        assert "repr_test" in repr(d)
        assert "2.0.0" in repr(d)


# ---------------------------------------------------------------------------
# DetectorRegistry
# ---------------------------------------------------------------------------

class TestDetectorRegistry:

    @pytest.fixture
    def registry(self):
        from core.detector_registry import DetectorRegistry
        return DetectorRegistry()

    def _make_detector(self, name="test_det"):
        det_name = name

        class D(AbstractDetector):
            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=False)

        D.name = det_name
        D.version = "1.0.0"
        return D()

    def test_register_and_get(self, registry) -> None:
        d = self._make_detector("alpha")
        registry.register(d)
        assert registry.get("alpha") is d

    def test_register_non_detector_raises(self, registry) -> None:
        with pytest.raises(TypeError):
            registry.register("not a detector")  # type: ignore

    def test_unregister(self, registry) -> None:
        d = self._make_detector("beta")
        registry.register(d)
        assert registry.unregister("beta") is True
        assert registry.get("beta") is None

    def test_unregister_missing_returns_false(self, registry) -> None:
        assert registry.unregister("nonexistent") is False

    def test_names(self, registry) -> None:
        registry.register(self._make_detector("a"))
        registry.register(self._make_detector("b"))
        assert set(registry.names) == {"a", "b"}

    def test_count(self, registry) -> None:
        registry.register(self._make_detector("x"))
        registry.register(self._make_detector("y"))
        assert registry.count == 2

    def test_run_all_returns_results(self, registry) -> None:
        class TriggeringDetector(AbstractDetector):
            name = "triggering"
            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=True, score=0.8)

        registry.register(TriggeringDetector())
        results = registry.run_all("1.2.3.4", [])
        assert len(results) == 1
        assert results[0].triggered is True

    def test_run_all_isolates_exceptions(self, registry) -> None:
        class BrokenDetector(AbstractDetector):
            name = "broken"
            def analyze(self, ip, events, *, context=None):
                raise RuntimeError("I am broken")

        class GoodDetector(AbstractDetector):
            name = "good"
            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=True, score=0.5)

        registry.register(BrokenDetector())
        registry.register(GoodDetector())

        results = registry.run_all("1.2.3.4", [])
        # broken gives fallback non-triggered, good gives triggered
        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 1

    def test_run_one_returns_result(self, registry) -> None:
        registry.register(self._make_detector("solo"))
        result = registry.run_one("solo", "1.2.3.4", [])
        assert result is not None
        assert result.triggered is False

    def test_run_one_missing_returns_none(self, registry) -> None:
        result = registry.run_one("missing", "1.2.3.4", [])
        assert result is None

    def test_lifecycle_start_stop(self, registry) -> None:
        started = []
        stopped = []

        class LifecycleDetector(AbstractDetector):
            name = "lifecycle"
            def analyze(self, ip, events, *, context=None):
                return DetectorResult(triggered=False)
            def on_start(self):
                started.append(1)
            def on_stop(self):
                stopped.append(1)

        registry.register(LifecycleDetector())
        registry.start_all()
        registry.stop_all()
        assert len(started) == 1
        assert len(stopped) == 1


# ---------------------------------------------------------------------------
# ThresholdDetector
# ---------------------------------------------------------------------------

class TestThresholdDetector:

    def setup_method(self) -> None:
        from core.detector_registry import ThresholdDetector
        from core.ids import ConnectionEvent
        self.detector = ThresholdDetector(threshold=10, window_seconds=60, port_scan_threshold=5)
        self.ConnectionEvent = ConnectionEvent

    def test_under_threshold_not_triggered(self) -> None:
        events = [self.ConnectionEvent(ip="1.2.3.4", port=80) for _ in range(5)]
        result = self.detector.analyze("1.2.3.4", events)
        assert result.triggered is False

    def test_over_threshold_triggers(self) -> None:
        import time
        events = [self.ConnectionEvent(ip="1.2.3.4", port=80, timestamp=time.time())
                  for _ in range(15)]
        result = self.detector.analyze("1.2.3.4", events, context={"now": time.time()})
        assert result.triggered is True

    def test_port_scan_triggers(self) -> None:
        import time
        now = time.time()
        events = [self.ConnectionEvent(ip="1.2.3.4", port=p, timestamp=now)
                  for p in [22, 80, 443, 8080, 3306, 5432]]  # 6 distinct ports
        result = self.detector.analyze("1.2.3.4", events, context={"now": now})
        assert result.triggered is True
        assert "port scan" in result.reason.lower()

    def test_result_has_features(self) -> None:
        import time
        events = [self.ConnectionEvent(ip="1.2.3.4", port=80, timestamp=time.time())
                  for _ in range(15)]
        result = self.detector.analyze("1.2.3.4", events, context={"now": time.time()})
        assert "count" in result.features


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

class TestGlobalSingleton:

    def setup_method(self) -> None:
        from core.detector_registry import reset_registry
        reset_registry()

    def teardown_method(self) -> None:
        from core.detector_registry import reset_registry
        reset_registry()

    def test_get_registry_has_builtin(self) -> None:
        from core.detector_registry import get_registry
        r = get_registry()
        assert "threshold" in r.names

    def test_singleton_is_same_object(self) -> None:
        from core.detector_registry import get_registry
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2
