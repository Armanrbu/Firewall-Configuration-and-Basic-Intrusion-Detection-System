"""
In-process publish/subscribe event bus for NetGuard IDS.

Decouples the engine from its consumers (GUI, API, CLI) — any number
of subscribers can receive any event type without the engine knowing
who they are.

Usage:
    from core.event_bus import get_event_bus
    from core.interfaces import IPFlaggedEvent

    bus = get_event_bus()
    bus.subscribe(IPFlaggedEvent, lambda evt: print(evt.ip))

    # ... later, from the engine:
    bus.publish(IPFlaggedEvent(ip="1.2.3.4", count=15))

Future:
    The ``publish()`` interface is intentionally kept minimal so this
    can be replaced with a Redis Streams adapter without changing callers.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Callable, Type

from utils.logger import get_logger

logger = get_logger(__name__)


class EventBus:
    """Thread-safe in-process publish/subscribe event bus.

    - Subscribers register per event type OR for all events.
    - publish() is synchronous: it blocks until all subscribers have been called.
    - Subscriber exceptions are caught and logged — they never crash the publisher.
    - Thread-safe: subscribe/unsubscribe/publish can be called from any thread.
    """

    def __init__(self) -> None:
        # type → list of callbacks
        self._subscribers: dict[type, list[Callable]] = defaultdict(list)
        # catch-all subscribers (receive every event type)
        self._all_subscribers: list[Callable] = []
        self._lock = threading.RLock()

    def subscribe(self, event_type: type, callback: Callable) -> None:
        """Register *callback* to receive events of *event_type*.

        The same callback can be subscribed to multiple event types.
        Duplicate registrations for the same type are silently ignored.
        """
        with self._lock:
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable) -> None:
        """Register *callback* to receive ALL event types.

        Useful for loggers, debuggers, and audit trails.
        """
        with self._lock:
            if callback not in self._all_subscribers:
                self._all_subscribers.append(callback)

    def unsubscribe(self, event_type: type, callback: Callable) -> None:
        """Remove *callback* from the subscriber list for *event_type*."""
        with self._lock:
            try:
                self._subscribers[event_type].remove(callback)
            except ValueError:
                pass

    def unsubscribe_all(self, callback: Callable) -> None:
        """Remove *callback* from the catch-all subscriber list."""
        with self._lock:
            try:
                self._all_subscribers.remove(callback)
            except ValueError:
                pass

    def unsubscribe_from_all(self, callback: Callable) -> None:
        """Remove *callback* from every list it appears in."""
        with self._lock:
            for subscribers in self._subscribers.values():
                try:
                    subscribers.remove(callback)
                except ValueError:
                    pass
            try:
                self._all_subscribers.remove(callback)
            except ValueError:
                pass

    def publish(self, event: object) -> None:
        """Dispatch *event* to all matching subscribers.

        The event type is used for routing. Exceptions in subscribers
        are caught, logged, and do not affect other subscribers.
        """
        with self._lock:
            # Snapshot to avoid mutation during iteration
            type_cbs = list(self._subscribers.get(type(event), []))
            all_cbs = list(self._all_subscribers)

        for cb in type_cbs + all_cbs:
            try:
                cb(event)
            except Exception as exc:
                logger.warning(
                    "EventBus: subscriber %r raised %s: %s",
                    cb, type(exc).__name__, exc,
                )

    def clear(self) -> None:
        """Remove all subscribers (for test cleanup)."""
        with self._lock:
            self._subscribers.clear()
            self._all_subscribers.clear()

    @property
    def subscriber_count(self) -> int:
        """Total number of registered callbacks (for diagnostics)."""
        with self._lock:
            return sum(len(v) for v in self._subscribers.values()) + len(self._all_subscribers)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_bus: EventBus | None = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Return the global EventBus singleton."""
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Replace the singleton with a fresh EventBus (for testing)."""
    global _bus
    with _bus_lock:
        _bus = EventBus()
