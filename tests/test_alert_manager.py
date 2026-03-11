"""Tests for core.alert_manager — deduplication, explainability, verdict processing."""

from __future__ import annotations

import sys
import os
import time
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alert_manager import (
    AlertManager, AlertVerdict, DeduplicationState,
    explain_features, score_to_severity, get_alert_manager, reset_alert_manager,
)
from core.detector_abc import DetectorResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result(
    triggered=True, score=0.8, reason="test", rule_id="test-rule", action="alert"
):
    return DetectorResult(
        triggered=triggered, score=score,
        reason=reason, rule_id=rule_id, action=action,
        features={"count": 15.0, "unique_ports": 3.0},
    )


@pytest.fixture
def mgr():
    """Fresh AlertManager with DB persistence disabled."""
    return AlertManager(dedup_window_seconds=60, max_suppress=5, persist_to_db=False)


# ---------------------------------------------------------------------------
# AlertVerdict
# ---------------------------------------------------------------------------

class TestAlertVerdict:

    def test_should_alert_true(self) -> None:
        v = AlertVerdict(ip="1.2.3.4", should_alert=True, action="block", score=0.9)
        assert v.should_alert is True

    def test_is_blocked_property(self) -> None:
        v = AlertVerdict(ip="x", should_alert=True, action="block")
        assert v.is_blocked is True

    def test_is_blocked_alert_action(self) -> None:
        v = AlertVerdict(ip="x", should_alert=True, action="alert")
        assert v.is_blocked is False

    def test_timestamp_auto_set(self) -> None:
        before = time.time()
        v = AlertVerdict(ip="x", should_alert=False)
        assert v.timestamp >= before


# ---------------------------------------------------------------------------
# score_to_severity
# ---------------------------------------------------------------------------

class TestScoreToSeverity:

    def test_critical(self) -> None:
        assert score_to_severity(0.90) == "critical"
        assert score_to_severity(0.85) == "critical"

    def test_high(self) -> None:
        assert score_to_severity(0.75) == "high"
        assert score_to_severity(0.70) == "high"

    def test_medium(self) -> None:
        assert score_to_severity(0.50) == "medium"
        assert score_to_severity(0.45) == "medium"

    def test_low(self) -> None:
        assert score_to_severity(0.25) == "low"
        assert score_to_severity(0.20) == "low"

    def test_none(self) -> None:
        assert score_to_severity(0.0) == "none"
        assert score_to_severity(0.10) == "none"


# ---------------------------------------------------------------------------
# explain_features
# ---------------------------------------------------------------------------

class TestExplainFeatures:

    def test_returns_list_of_strings(self) -> None:
        lines = explain_features({"count": 15.0, "unique_ports": 3})
        assert isinstance(lines, list)
        assert len(lines) == 2
        for line in lines:
            assert isinstance(line, str)

    def test_known_feature_uses_friendly_name(self) -> None:
        lines = explain_features({"count": 20.0})
        assert any("connections" in line.lower() or "count" in line.lower() for line in lines)

    def test_unknown_feature_uses_key(self) -> None:
        lines = explain_features({"my_custom_feat": 42})
        assert any("my_custom_feat" in line or "my custom feat" in line for line in lines)

    def test_float_formatted(self) -> None:
        lines = explain_features({"count": 15.999})
        assert any("15.99" in line or "16.00" in line for line in lines)


# ---------------------------------------------------------------------------
# DeduplicationState
# ---------------------------------------------------------------------------

class TestDeduplicationState:

    def test_first_occurrence_not_duplicate(self) -> None:
        dedup = DeduplicationState(window_seconds=60, max_suppress=5)
        assert dedup.is_duplicate("1.2.3.4", "rule-1") is False

    def test_second_occurrence_is_duplicate(self) -> None:
        dedup = DeduplicationState(window_seconds=60, max_suppress=5)
        dedup.is_duplicate("1.2.3.4", "rule-1")  # first → False
        assert dedup.is_duplicate("1.2.3.4", "rule-1") is True

    def test_different_rule_not_duplicate(self) -> None:
        dedup = DeduplicationState(window_seconds=60, max_suppress=5)
        dedup.is_duplicate("1.2.3.4", "rule-1")
        assert dedup.is_duplicate("1.2.3.4", "rule-2") is False

    def test_different_ip_not_duplicate(self) -> None:
        dedup = DeduplicationState(window_seconds=60, max_suppress=5)
        dedup.is_duplicate("1.2.3.4", "rule-1")
        assert dedup.is_duplicate("5.6.7.8", "rule-1") is False

    def test_expired_window_resets(self) -> None:
        dedup = DeduplicationState(window_seconds=1, max_suppress=5)
        dedup.is_duplicate("1.2.3.4", "rule-1")  # first
        dedup.is_duplicate("1.2.3.4", "rule-1")  # duplicate
        time.sleep(1.1)
        # After window expires, should NOT be a duplicate
        assert dedup.is_duplicate("1.2.3.4", "rule-1") is False

    def test_max_suppress_resets(self) -> None:
        dedup = DeduplicationState(window_seconds=60, max_suppress=3)
        dedup.is_duplicate("x", "r")  # 1st: False
        dedup.is_duplicate("x", "r")  # 2nd: True (suppress 1)
        dedup.is_duplicate("x", "r")  # 3rd: True (suppress 2)
        dedup.is_duplicate("x", "r")  # 4th: True (suppress 3 = max)
        result = dedup.is_duplicate("x", "r")  # 5th: should let through (reset)
        assert result is False

    def test_clear_removes_all(self) -> None:
        dedup = DeduplicationState()
        dedup.is_duplicate("x", "r")
        dedup.clear()
        assert dedup.size == 0

    def test_prune_expired(self) -> None:
        dedup = DeduplicationState(window_seconds=1)
        dedup.is_duplicate("a", "r1")
        dedup.is_duplicate("b", "r2")
        time.sleep(1.1)
        pruned = dedup.prune_expired()
        assert pruned == 2
        assert dedup.size == 0


# ---------------------------------------------------------------------------
# AlertManager.process
# ---------------------------------------------------------------------------

class TestAlertManagerProcess:

    def test_no_triggered_results_no_alert(self, mgr) -> None:
        results = [make_result(triggered=False, score=0.0)]
        verdict = mgr.process("1.2.3.4", results, detector_names=["threshold"])
        assert verdict.should_alert is False
        assert verdict.action == "ignore"

    def test_triggered_result_produces_alert(self, mgr) -> None:
        results = [make_result(triggered=True, score=0.8)]
        verdict = mgr.process("1.2.3.4", results, detector_names=["threshold"])
        assert verdict.should_alert is True
        assert verdict.ip == "1.2.3.4"

    def test_severity_computed_from_score(self, mgr) -> None:
        results = [make_result(score=0.90)]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d"])
        assert verdict.severity == "critical"

    def test_block_action_propagated(self, mgr) -> None:
        results = [make_result(action="block", score=0.95)]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d"])
        assert verdict.action == "block"

    def test_block_wins_over_alert(self, mgr) -> None:
        results = [
            make_result(action="alert", score=0.5, rule_id="r1"),
            make_result(action="block", score=0.9, rule_id="r2"),
        ]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d1", "d2"])
        assert verdict.action == "block"

    def test_incident_id_assigned(self, mgr) -> None:
        results = [make_result()]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d"])
        assert verdict.incident_id.startswith("INC-")

    def test_features_merged(self, mgr) -> None:
        r1 = DetectorResult(triggered=True, score=0.7, rule_id="r1",
                            features={"count": 10.0}, action="alert")
        r2 = DetectorResult(triggered=True, score=0.8, rule_id="r2",
                            features={"unique_ports": 5.0}, action="alert")
        verdict = mgr.process("1.2.3.4", [r1, r2], detector_names=["d1", "d2"])
        assert "count" in verdict.features
        assert "unique_ports" in verdict.features

    def test_extra_features_merged(self, mgr) -> None:
        results = [make_result(rule_id="r1")]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d"],
                              extra_features={"geo_country": "XX"})
        assert "geo_country" in verdict.features

    def test_empty_results_no_alert(self, mgr) -> None:
        verdict = mgr.process("1.2.3.4", [], detector_names=[])
        assert verdict.should_alert is False

    def test_timestamp_is_recent(self, mgr) -> None:
        before = time.time()
        results = [make_result()]
        verdict = mgr.process("x", results, detector_names=["d"])
        assert verdict.timestamp >= before

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def test_duplicate_alert_suppressed(self, mgr) -> None:
        results = [make_result(rule_id="dup-rule")]
        # First call
        v1 = mgr.process("1.2.3.4", results, detector_names=["d"])
        assert v1.should_alert is True
        # Immediate second call with same rule — should be deduplicated
        v2 = mgr.process("1.2.3.4", results, detector_names=["d"])
        assert v2.should_alert is False
        assert v2.deduplicated is True

    def test_different_ips_not_deduplicated(self, mgr) -> None:
        results = [make_result(rule_id="same-rule")]
        v1 = mgr.process("1.2.3.4", results, detector_names=["d"])
        v2 = mgr.process("5.6.7.8", results, detector_names=["d"])
        assert v1.should_alert is True
        assert v2.should_alert is True

    def test_dedup_housekeeping(self, mgr) -> None:
        results = [make_result()]
        mgr.process("1.2.3.4", results, detector_names=["d"])
        assert mgr.dedup_state_size >= 1

    def test_prune_dedup_state(self) -> None:
        mgr2 = AlertManager(dedup_window_seconds=1, persist_to_db=False)
        results = [make_result(rule_id="prune-test")]
        mgr2.process("1.2.3.4", results, detector_names=["d"])
        time.sleep(1.1)
        pruned = mgr2.prune_dedup_state()
        assert pruned >= 1


# ---------------------------------------------------------------------------
# AlertManager.explain
# ---------------------------------------------------------------------------

class TestAlertManagerExplain:

    def test_explain_triggered_verdict(self, mgr) -> None:
        results = [make_result(score=0.9, reason="Port scan")]
        verdict = mgr.process("1.2.3.4", results, detector_names=["ml_anomaly"])
        explanation = mgr.explain(verdict)
        assert "1.2.3.4" in explanation
        assert "Port scan" in explanation
        assert "CRITICAL" in explanation or "HIGH" in explanation

    def test_explain_no_alert_verdict(self, mgr) -> None:
        verdict = AlertVerdict(ip="5.5.5.5", should_alert=False, summary="Clean")
        explanation = mgr.explain(verdict)
        assert "No alert" in explanation

    def test_explain_shows_features(self, mgr) -> None:
        results = [make_result(score=0.75)]
        verdict = mgr.process("1.2.3.4", results, detector_names=["d"])
        explanation = mgr.explain(verdict)
        assert "count" in explanation.lower() or "connections" in explanation.lower()


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

class TestGlobalSingleton:

    def setup_method(self) -> None:
        reset_alert_manager()

    def teardown_method(self) -> None:
        reset_alert_manager()

    def test_singleton_same_object(self) -> None:
        m1 = get_alert_manager()
        m2 = get_alert_manager()
        assert m1 is m2

    def test_reset_creates_new(self) -> None:
        m1 = get_alert_manager()
        reset_alert_manager()
        m2 = get_alert_manager()
        assert m1 is not m2
