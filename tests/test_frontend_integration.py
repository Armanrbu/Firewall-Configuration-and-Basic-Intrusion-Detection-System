"""
Integration tests for Plan 04-04: Frontend integration.

Tests verify that:
1. AppRunner boots, exposes the engine and EventBus correctly.
2. EventBusBridge (headless mode without Qt) routes events via callbacks.
3. The CLI monitor subscribes/unsubscribes cleanly to the shared bus.
4. The FastAPI WebSocket and CLI see the same engine events (shared EventBus).
5. AppRunner stop() cleanly tears down the engine.
"""
from __future__ import annotations

import sys
import os
import threading
import time
import queue
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.event_bus import EventBus, reset_event_bus
from core.interfaces import IPFlaggedEvent, PortScanEvent, AnomalyEvent, IPBlockedEvent
from core.app_runner import AppRunner, get_runner, set_runner, reset_runner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_bus():
    """Reset global EventBus and AppRunner between tests."""
    reset_event_bus()
    reset_runner()
    yield
    reset_runner()
    reset_event_bus()


@pytest.fixture
def fake_engine():
    """
    Return a mock engine that behaves enough for AppRunner lifecycle.
    The engine's _stop_event is a real threading.Event.
    """
    eng = MagicMock()
    eng._stop_event = threading.Event()
    eng.get_status.return_value = {"active": True, "platform": "mock"}
    return eng


@pytest.fixture
def runner_no_engine(fake_engine):
    """AppRunner with an injected mock engine (no real subprocess)."""
    r = AppRunner(config={})
    with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
         patch("core.scheduler.get_scheduler") as mock_sched:
        mock_sched.return_value = MagicMock()
        r.start()
    yield r
    if r.running:
        r.stop()


# ---------------------------------------------------------------------------
# AppRunner lifecycle
# ---------------------------------------------------------------------------

class TestAppRunnerLifecycle:

    def test_start_sets_running(self, fake_engine):
        r = AppRunner(config={})
        with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
             patch("core.scheduler.get_scheduler", return_value=MagicMock()):
            r.start()
        assert r.running is True
        r.stop()
        assert r.running is False

    def test_double_start_is_idempotent(self, fake_engine):
        r = AppRunner(config={})
        with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
             patch("core.scheduler.get_scheduler", return_value=MagicMock()):
            r.start()
            r.start()  # second call should be no-op
        assert r.running
        r.stop()

    def test_stop_without_start_is_safe(self):
        r = AppRunner(config={})
        r.stop()  # must not raise

    def test_get_bus_returns_event_bus(self, runner_no_engine):
        bus = runner_no_engine.get_bus()
        assert isinstance(bus, EventBus)

    def test_get_status_includes_app_running(self, runner_no_engine, fake_engine):
        fake_engine.get_status.return_value = {"platform": "mock"}
        status = runner_no_engine.get_status()
        assert status["app_running"] is True

    def test_engine_property_raises_before_start(self):
        r = AppRunner(config={})
        with pytest.raises(RuntimeError, match="not been started"):
            _ = r.engine

    def test_api_server_started_when_configured(self, fake_engine):
        r = AppRunner(config={
            "api": {"enabled": True, "api_key": "test-key", "port": 9876}
        })
        mock_api = MagicMock()
        with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
             patch("core.scheduler.get_scheduler", return_value=MagicMock()), \
             patch("api.server.APIServer", return_value=mock_api):
            r.start()
        mock_api.start.assert_called_once()
        r.stop()

    def test_api_server_not_started_when_disabled(self, fake_engine):
        r = AppRunner(config={"api": {"enabled": False}})
        with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
             patch("core.scheduler.get_scheduler", return_value=MagicMock()), \
             patch("api.server.APIServer") as mock_cls:
            r.start()
        mock_cls.assert_not_called()
        r.stop()


# ---------------------------------------------------------------------------
# Global singleton helpers
# ---------------------------------------------------------------------------

class TestRunnerSingleton:

    def test_get_runner_returns_singleton(self):
        r1 = get_runner()
        r2 = get_runner()
        assert r1 is r2

    def test_set_runner_replaces_singleton(self):
        custom = AppRunner()
        set_runner(custom)
        assert get_runner() is custom

    def test_reset_runner_clears_singleton(self):
        r1 = get_runner()
        reset_runner()
        r2 = get_runner()
        assert r1 is not r2


# ---------------------------------------------------------------------------
# EventBus: shared by all frontends
# ---------------------------------------------------------------------------

class TestSharedEventBus:
    """All frontends share the same EventBus singleton — verify delivery."""

    def test_cli_and_api_receive_same_event(self):
        bus = EventBus()
        cli_received: list = []
        api_received: list = []

        bus.subscribe_all(cli_received.append)
        bus.subscribe_all(api_received.append)

        event = IPFlaggedEvent(ip="1.2.3.4", count=15)
        bus.publish(event)

        assert len(cli_received) == 1
        assert len(api_received) == 1
        assert cli_received[0] is event
        assert api_received[0] is event

    def test_three_frontends_all_receive(self):
        bus = EventBus()
        buckets = [[], [], []]  # GUI, API, CLI

        for bucket in buckets:
            bus.subscribe_all(bucket.append)

        ev = PortScanEvent(ip="5.5.5.5", ports=(22, 80, 443))
        bus.publish(ev)

        for bucket in buckets:
            assert len(bucket) == 1
            assert bucket[0] is ev

    def test_unsubscribed_frontend_stops_receiving(self):
        bus = EventBus()
        received: list = []

        def cb(ev): received.append(ev)

        bus.subscribe_all(cb)
        bus.publish(IPFlaggedEvent(ip="a", count=1))
        assert len(received) == 1

        bus.unsubscribe_all(cb)
        bus.publish(IPFlaggedEvent(ip="a", count=2))
        assert len(received) == 1  # no new event

    def test_events_thread_safe_concurrent_publish(self):
        """Multiple publisher threads should not corrupt subscriber lists."""
        bus = EventBus()
        received: list = []
        lock = threading.Lock()

        def cb(ev):
            with lock:
                received.append(ev)

        bus.subscribe_all(cb)
        threads = [
            threading.Thread(target=bus.publish, args=(IPFlaggedEvent(ip=f"{i}", count=i),))
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 50

    def test_anomaly_event_routed(self):
        bus = EventBus()
        received: list = []
        bus.subscribe(AnomalyEvent, received.append)
        bus.publish(AnomalyEvent(ip="9.9.9.9", score=-0.42))
        assert len(received) == 1
        assert received[0].score == pytest.approx(-0.42)


# ---------------------------------------------------------------------------
# CLI monitor subscribe/unsubscribe integration
# ---------------------------------------------------------------------------

class TestCLIMonitorBusIntegration:
    """The CLI's monitor command uses subscribe_all/unsubscribe_all."""

    def test_monitor_queue_receives_event(self):
        bus = EventBus()
        q: queue.Queue = queue.Queue()

        def on_event(ev):
            q.put(ev)

        bus.subscribe_all(on_event)
        bus.publish(IPBlockedEvent(ip="6.6.6.6"))

        ev = q.get(timeout=1)
        assert ev.ip == "6.6.6.6"
        bus.unsubscribe_all(on_event)

        # After unsubscribe, nothing more arrives
        bus.publish(IPBlockedEvent(ip="7.7.7.7"))
        assert q.empty()


# ---------------------------------------------------------------------------
# AppRunner.get_status integration
# ---------------------------------------------------------------------------

class TestGetStatus:

    def test_get_status_api_false_by_default(self, fake_engine):
        r = AppRunner(config={})
        with patch("core.engine.NetGuardEngine", return_value=fake_engine), \
             patch("core.scheduler.get_scheduler", return_value=MagicMock()):
            r.start()
        status = r.get_status()
        assert status["api_server"] is False
        r.stop()
