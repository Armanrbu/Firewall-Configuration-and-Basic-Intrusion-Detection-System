"""Tests for core.event_bus — publish/subscribe and thread safety."""

from __future__ import annotations

import sys
import os
import threading
import time
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def fresh_bus():
    """Reset the global event bus before each test."""
    from core.event_bus import reset_event_bus
    reset_event_bus()
    yield
    reset_event_bus()


# ---------------------------------------------------------------------------
# Basic subscribe/publish/unsubscribe
# ---------------------------------------------------------------------------

class TestEventBusBasics:

    def test_subscribe_and_publish(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        received = []
        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, lambda e: received.append(e))
        bus.publish(IPFlaggedEvent(ip="1.2.3.4", count=5))
        assert len(received) == 1
        assert received[0].ip == "1.2.3.4"

    def test_publish_wrong_type_not_delivered(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent, IPBlockedEvent

        received = []
        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, lambda e: received.append(e))
        bus.publish(IPBlockedEvent(ip="1.2.3.4"))  # different type
        assert len(received) == 0

    def test_unsubscribe_stops_delivery(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        received = []
        cb = lambda e: received.append(e)
        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, cb)
        bus.unsubscribe(IPFlaggedEvent, cb)
        bus.publish(IPFlaggedEvent(ip="1.2.3.4", count=5))
        assert len(received) == 0

    def test_multiple_subscribers_same_type(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPBlockedEvent

        calls = []
        bus = get_event_bus()
        bus.subscribe(IPBlockedEvent, lambda e: calls.append("h1"))
        bus.subscribe(IPBlockedEvent, lambda e: calls.append("h2"))
        bus.publish(IPBlockedEvent(ip="5.5.5.5"))
        assert "h1" in calls
        assert "h2" in calls
        assert len(calls) == 2

    def test_subscribe_multiple_types(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent, IPBlockedEvent

        received = []
        bus = get_event_bus()
        cb = lambda e: received.append(type(e).__name__)
        bus.subscribe(IPFlaggedEvent, cb)
        bus.subscribe(IPBlockedEvent, cb)
        bus.publish(IPFlaggedEvent(ip="a", count=1))
        bus.publish(IPBlockedEvent(ip="b"))
        assert "IPFlaggedEvent" in received
        assert "IPBlockedEvent" in received

    def test_no_duplicate_subscriptions(self) -> None:
        from core.event_bus import get_event_bus, EventBus
        from core.interfaces import IPFlaggedEvent

        bus = get_event_bus()
        calls = []
        cb = lambda e: calls.append(1)
        bus.subscribe(IPFlaggedEvent, cb)
        bus.subscribe(IPFlaggedEvent, cb)  # duplicate
        bus.publish(IPFlaggedEvent(ip="x", count=1))
        assert len(calls) == 1  # called only once


# ---------------------------------------------------------------------------
# subscribe_all
# ---------------------------------------------------------------------------

class TestSubscribeAll:

    def test_subscribe_all_receives_every_type(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent, IPBlockedEvent, PortScanEvent

        received = []
        bus = get_event_bus()
        bus.subscribe_all(lambda e: received.append(type(e).__name__))
        bus.publish(IPFlaggedEvent(ip="a", count=1))
        bus.publish(IPBlockedEvent(ip="b"))
        bus.publish(PortScanEvent(ip="c", ports=(22, 80)))
        assert "IPFlaggedEvent" in received
        assert "IPBlockedEvent" in received
        assert "PortScanEvent" in received

    def test_unsubscribe_all_stops_delivery(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        received = []
        bus = get_event_bus()
        cb = lambda e: received.append(e)
        bus.subscribe_all(cb)
        bus.unsubscribe_all(cb)
        bus.publish(IPFlaggedEvent(ip="x", count=1))
        assert len(received) == 0


# ---------------------------------------------------------------------------
# Exception isolation
# ---------------------------------------------------------------------------

class TestExceptionIsolation:

    def test_bad_subscriber_doesnt_crash_others(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        good_calls = []

        def bad_cb(e):
            raise RuntimeError("I am broken")

        def good_cb(e):
            good_calls.append(e)

        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, bad_cb)
        bus.subscribe(IPFlaggedEvent, good_cb)

        # Should not raise
        bus.publish(IPFlaggedEvent(ip="1.2.3.4", count=5))
        assert len(good_calls) == 1

    def test_all_subscriber_exception_isolated(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import AnomalyEvent

        safe_calls = []
        bus = get_event_bus()
        bus.subscribe_all(lambda e: (_ for _ in ()).throw(ValueError("boom")))
        bus.subscribe_all(lambda e: safe_calls.append(e))
        bus.publish(AnomalyEvent(ip="x", score=0.9))
        assert len(safe_calls) == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:

    def test_concurrent_publish_doesnt_crash(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import ConnectionDetectedEvent

        bus = get_event_bus()
        received = []
        lock = threading.Lock()

        def cb(e):
            with lock:
                received.append(e)

        bus.subscribe(ConnectionDetectedEvent, cb)

        def publisher():
            for i in range(20):
                bus.publish(ConnectionDetectedEvent(ip=f"10.0.0.{i}", port=80))

        threads = [threading.Thread(target=publisher) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(received) == 100  # 5 threads × 20 events

    def test_subscribe_during_publish_safe(self) -> None:
        """Subscribing from inside a callback doesn't deadlock (RLock)."""
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        bus = get_event_bus()
        new_cb_calls = []

        def cb(e):
            # Subscribe another callback during publish
            bus.subscribe(IPFlaggedEvent, lambda e2: new_cb_calls.append(e2))

        bus.subscribe(IPFlaggedEvent, cb)
        bus.publish(IPFlaggedEvent(ip="x", count=1))
        # Should not deadlock


# ---------------------------------------------------------------------------
# subscriber_count and clear
# ---------------------------------------------------------------------------

class TestHousekeeping:

    def test_subscriber_count(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent, IPBlockedEvent

        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, lambda e: None)
        bus.subscribe(IPBlockedEvent, lambda e: None)
        bus.subscribe_all(lambda e: None)
        assert bus.subscriber_count == 3

    def test_clear_removes_all_subscribers(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent

        bus = get_event_bus()
        bus.subscribe(IPFlaggedEvent, lambda e: None)
        bus.subscribe_all(lambda e: None)
        bus.clear()
        assert bus.subscriber_count == 0

    def test_unsubscribe_from_all_cleanup(self) -> None:
        from core.event_bus import get_event_bus
        from core.interfaces import IPFlaggedEvent, IPBlockedEvent

        bus = get_event_bus()
        cb = lambda e: None
        bus.subscribe(IPFlaggedEvent, cb)
        bus.subscribe(IPBlockedEvent, cb)
        bus.subscribe_all(cb)
        bus.unsubscribe_from_all(cb)
        assert bus.subscriber_count == 0


# ---------------------------------------------------------------------------
# Engine integration: engine publishes to bus
# ---------------------------------------------------------------------------

class TestEngineEventBusIntegration:

    def test_engine_dispatches_to_bus(self) -> None:
        from core.event_bus import EventBus
        from core.interfaces import IPFlaggedEvent
        from core.engine import NetGuardEngine

        # Use an isolated bus, not the global singleton
        bus = EventBus()
        received = []
        bus.subscribe(IPFlaggedEvent, lambda e: received.append(e))

        engine = NetGuardEngine(event_bus=bus)
        engine._dispatch_ip_flagged("10.0.0.1", 15)

        assert len(received) == 1
        assert received[0].ip == "10.0.0.1"
        assert received[0].count == 15

    def test_engine_publishes_all_event_types(self) -> None:
        from core.event_bus import EventBus
        from core.interfaces import (
            IPFlaggedEvent, IPBlockedEvent, PortScanEvent,
            AnomalyEvent, EngineStatusEvent, ConnectionDetectedEvent,
        )
        from core.engine import NetGuardEngine
        from core.ids import ConnectionEvent as IDSConn

        bus = EventBus()
        seen_types = set()
        bus.subscribe_all(lambda e: seen_types.add(type(e)))

        engine = NetGuardEngine(event_bus=bus)
        engine._dispatch_ip_flagged("1.1.1.1", 5)
        engine._dispatch_ip_blocked("2.2.2.2")
        engine._dispatch_port_scan("3.3.3.3", [22, 80])
        engine._dispatch_anomaly("4.4.4.4", 0.95)
        engine._dispatch_status("started", "engine up")

        assert IPFlaggedEvent in seen_types
        assert IPBlockedEvent in seen_types
        assert PortScanEvent in seen_types
        assert AnomalyEvent in seen_types
        assert EngineStatusEvent in seen_types
