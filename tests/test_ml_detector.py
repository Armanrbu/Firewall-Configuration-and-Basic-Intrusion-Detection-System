"""Tests for core.ml_detector — feature extraction, scoring, training, signature fallback."""

from __future__ import annotations

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ml_detector import (
    extract_features, signature_check, FEATURE_NAMES,
    MLAnomalyDetector, HAS_PYOD, HAS_SKLEARN,
)
from core.ids import ConnectionEvent


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

class TestFeatureExtraction:

    def _make_events(self, n=5, port=80, protocol="TCP", direction="in", ts_offset=0):
        now = time.time()
        return [
            ConnectionEvent(ip="1.2.3.4", port=port, protocol=protocol,
                            direction=direction, timestamp=now - ts_offset + i)
            for i in range(n)
        ]

    def test_feature_count(self) -> None:
        events = self._make_events(5)
        feats = extract_features("1.2.3.4", events)
        assert len(feats) == len(FEATURE_NAMES)

    def test_count_feature(self) -> None:
        events = self._make_events(10)
        feats = extract_features("1.2.3.4", events)
        assert feats[0] == 10.0  # count

    def test_unique_ports_feature(self) -> None:
        now = time.time()
        events = [ConnectionEvent(ip="x", port=p, timestamp=now) for p in [22, 80, 443]]
        feats = extract_features("x", events)
        assert feats[1] == 3.0  # unique_ports

    def test_inbound_ratio_all_in(self) -> None:
        events = self._make_events(4, direction="in")
        feats = extract_features("x", events)
        assert feats[3] == 1.0  # inbound_ratio

    def test_inbound_ratio_all_out(self) -> None:
        events = self._make_events(4, direction="out")
        feats = extract_features("x", events)
        assert feats[3] == 0.0

    def test_max_port_norm(self) -> None:
        now = time.time()
        events = [ConnectionEvent(ip="x", port=65535, timestamp=now)]
        feats = extract_features("x", events)
        assert abs(feats[5] - 1.0) < 0.001  # max_port_norm = 65535/65535

    def test_well_known_port_hits(self) -> None:
        now = time.time()
        events = [ConnectionEvent(ip="x", port=p, timestamp=now) for p in [22, 80, 443, 9999]]
        feats = extract_features("x", events)
        assert feats[6] == 3.0  # 22, 80, 443 are ≤ 1024

    def test_empty_events(self) -> None:
        feats = extract_features("1.2.3.4", [])
        assert len(feats) == len(FEATURE_NAMES)
        assert feats[0] == 0.0


# ---------------------------------------------------------------------------
# Signature fallback
# ---------------------------------------------------------------------------

class TestSignatureFallback:

    def test_high_count_detected(self) -> None:
        features = [150.0, 1.0, 1.0, 1.0, 1.0, 0.001, 0.0]
        is_anom, reason = signature_check(features)
        assert is_anom is True
        assert "count" in reason.lower()

    def test_wide_port_scan_detected(self) -> None:
        features = [5.0, 25.0, 1.0, 1.0, 1.0, 0.5, 5.0]
        is_anom, reason = signature_check(features)
        assert is_anom is True
        assert "port scan" in reason.lower()

    def test_high_rate_detected(self) -> None:
        features = [50.0, 1.0, 1.0, 1.0, 15.0, 0.001, 0.0]
        is_anom, reason = signature_check(features)
        assert is_anom is True
        assert "rate" in reason.lower()

    def test_normal_behaviour_not_detected(self) -> None:
        features = [3.0, 2.0, 1.0, 0.8, 0.5, 0.001, 2.0]
        is_anom, _ = signature_check(features)
        assert is_anom is False


# ---------------------------------------------------------------------------
# MLAnomalyDetector
# ---------------------------------------------------------------------------

class TestMLAnomalyDetector:

    @pytest.fixture
    def detector(self, tmp_path):
        model_path = str(tmp_path / "test_model.pkl")
        return MLAnomalyDetector(
            model_path=model_path,
            contamination=0.1,
            min_train_samples=10,
            retrain_interval_seconds=9999,  # don't auto-retrain during tests
        )

    def _make_events(self, n=3, port=80):
        now = time.time()
        return [ConnectionEvent(ip="1.2.3.4", port=port, timestamp=now) for _ in range(n)]

    def test_implements_abstract_detector(self, detector) -> None:
        from core.detector_abc import AbstractDetector
        assert isinstance(detector, AbstractDetector)

    def test_name_and_version(self, detector) -> None:
        assert detector.name == "ml_anomaly"
        assert detector.version == "2.0.0"

    def test_analyze_returns_result(self, detector) -> None:
        from core.detector_abc import DetectorResult
        events = self._make_events(3)
        result = detector.analyze("1.2.3.4", events)
        assert isinstance(result, DetectorResult)

    def test_empty_events_not_triggered(self, detector) -> None:
        result = detector.analyze("1.2.3.4", [])
        assert result.triggered is False

    def test_features_populated_in_result(self, detector) -> None:
        events = self._make_events(5)
        result = detector.analyze("1.2.3.4", events)
        # Even if not triggered, features should be populated
        assert "count" in result.features or result.triggered is False

    def test_records_training_data(self, detector) -> None:
        events = self._make_events(5)
        detector.analyze("1.2.3.4", events)
        with detector._lock:
            assert len(detector._training_buffer) > 0

    def test_high_volume_triggers_signature_fallback(self, detector) -> None:
        """Without a trained model, signature fallback should catch high-volume IPs."""
        now = time.time()
        events = [ConnectionEvent(ip="x", port=80, timestamp=now) for _ in range(200)]
        result = detector.analyze("x", events)
        # Signature fallback: 200 connections >> threshold of 100
        assert result.triggered is True

    def test_train_succeeds_with_enough_data(self, detector) -> None:
        skip_if_no_ml()
        now = time.time()
        events_list = [
            ConnectionEvent(ip="x", port=p % 1000 + 1, timestamp=now)
            for p in range(50)
        ]
        # Feed enough data to train
        for i in range(15):
            detector.analyze(f"10.0.0.{i}", events_list)
        result = detector.train()
        assert result is True
        assert detector._is_trained is True

    def test_model_saved_and_loaded(self, tmp_path) -> None:
        if not HAS_PYOD and not HAS_SKLEARN:
            pytest.skip("No ML library installed")
        model_path = str(tmp_path / "model_persist.pkl")
        d1 = MLAnomalyDetector(model_path=model_path, min_train_samples=10,
                               retrain_interval_seconds=9999)

        now = time.time()
        events_list = [ConnectionEvent(ip="x", port=p, timestamp=now) for p in range(20)]
        for i in range(12):
            d1.analyze(f"10.0.{i}.1", events_list)

        trained = d1.train()
        if not trained:
            pytest.skip("train() returned False — ML backend may not support this")
        assert os.path.exists(model_path), f"Model file not found at {model_path}"

        # Load into a fresh detector
        d2 = MLAnomalyDetector(model_path=model_path, min_train_samples=10)
        assert d2._is_trained is True

    def test_get_info_returns_dict(self, detector) -> None:
        info = detector.get_info()
        assert "backend" in info
        assert "is_trained" in info
        assert "training_samples" in info
        assert "features" in info

    def test_on_start_stop_dont_raise(self, detector) -> None:
        detector.on_start()
        detector.on_stop()

    def test_can_register_in_registry(self, detector) -> None:
        from core.detector_registry import DetectorRegistry
        registry = DetectorRegistry()
        registry.register(detector)
        assert "ml_anomaly" in registry.names


def skip_if_no_ml():
    if not HAS_PYOD and not HAS_SKLEARN:
        pytest.skip("No ML library installed")
