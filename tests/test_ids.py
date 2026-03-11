"""
Tests for the IDS engine.

Tests threshold detection, port scan detection, and whitelist behaviour.
No Qt dependency — uses the base IDSEngine class only.
"""

import time
import pytest

from core.ids import IDSEngine, ConnectionEvent


@pytest.fixture
def engine():
    return IDSEngine(
        threshold=3,
        window_seconds=60,
        port_scan_threshold=4,
        port_scan_window=30,
        auto_block=False,
        whitelist={"127.0.0.1"},
    )


class TestThresholdDetection:
    def test_flag_on_threshold(self, engine):
        flagged = []
        engine.on_ip_flagged = lambda ip, count: flagged.append(ip)

        ip = "1.2.3.4"
        for _ in range(3):
            engine.feed(ConnectionEvent(ip=ip, port=80))

        assert ip in flagged

    def test_no_flag_below_threshold(self, engine):
        flagged = []
        engine.on_ip_flagged = lambda ip, count: flagged.append(ip)

        for _ in range(2):
            engine.feed(ConnectionEvent(ip="1.2.3.5", port=80))

        assert not flagged

    def test_window_expiry(self, engine):
        """Connections older than the window should not count."""
        flagged = []
        engine.on_ip_flagged = lambda ip, count: flagged.append(ip)
        engine.window_seconds = 1  # very short window

        ip = "2.2.2.2"
        # Feed 2 events, then wait for window to expire, then feed again
        for _ in range(2):
            engine.feed(ConnectionEvent(ip=ip, port=80))

        time.sleep(1.1)
        # This event is after window; previous ones should be pruned
        engine.feed(ConnectionEvent(ip=ip, port=80))

        # 1 fresh event is below threshold of 3 → should NOT flag
        assert ip not in flagged

    def test_whitelist_skipped(self, engine):
        flagged = []
        engine.on_ip_flagged = lambda ip, count: flagged.append(ip)

        for _ in range(10):
            engine.feed(ConnectionEvent(ip="127.0.0.1", port=80))

        assert "127.0.0.1" not in flagged

    def test_reset_ip(self, engine):
        flagged = []
        engine.on_ip_flagged = lambda ip, count: flagged.append(ip)

        ip = "3.3.3.3"
        for _ in range(3):
            engine.feed(ConnectionEvent(ip=ip, port=80))
        assert ip in flagged

        engine.reset_ip(ip)
        assert ip not in engine._flagged


class TestPortScanDetection:
    def test_port_scan_detected(self, engine):
        scans = []
        engine.on_port_scan = lambda ip, ports: scans.append((ip, ports))

        ip = "4.4.4.4"
        for port in (22, 80, 443, 8080):
            engine.feed(ConnectionEvent(ip=ip, port=port))

        assert any(s[0] == ip for s in scans)
        assert len(scans[0][1]) >= 4

    def test_no_scan_below_threshold(self, engine):
        scans = []
        engine.on_port_scan = lambda ip, ports: scans.append((ip, ports))

        ip = "5.5.5.5"
        for port in (22, 80, 443):
            engine.feed(ConnectionEvent(ip=ip, port=port))

        assert not scans  # threshold is 4


class TestStats:
    def test_get_stats(self, engine):
        engine.feed(ConnectionEvent(ip="6.6.6.6", port=80))
        stats = engine.get_stats()
        assert "tracked_ips" in stats
        assert "flagged_ips" in stats
        assert stats["tracked_ips"] >= 1
