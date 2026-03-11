---
phase: 02-architecture
plan: 04
status: complete
completed_at: 2026-03-11
---

# Plan 02-04 Summary: Event-Driven Messaging (EventBus)

## What was done

### Task 1: core/event_bus.py — In-process EventBus
- `EventBus` class with thread-safe pub/sub using `threading.RLock`
- `subscribe(event_type, cb)` – per-type registration, no duplicates
- `subscribe_all(cb)` – catch-all for loggers, auditors
- `unsubscribe(event_type, cb)` / `unsubscribe_all(cb)` / `unsubscribe_from_all(cb)`
- `publish(event)` – snapshots subscriber list before iterating (safe for mutation)
- Subscriber exceptions: caught, logged, isolated — never crash the publisher
- `clear()` for test cleanup; `subscriber_count` property for diagnostics
- Global singleton via `get_event_bus()` with double-checked locking
- `reset_event_bus()` for per-test isolation

### Task 2: core/engine.py — EventBus integration
- `NetGuardEngine.__init__` accepts optional `event_bus` parameter (defaults to global singleton)
- All 6 dispatcher methods now **both** publish a typed event to the bus **and** call legacy handlers
- Typed events published: `ConnectionDetectedEvent`, `IPFlaggedEvent`, `IPBlockedEvent`, `PortScanEvent`, `AnomalyEvent`, `EngineStatusEvent`
- Zero breaking changes — existing `register_handler()` API still works exactly as before

### Task 3: Tests — tests/test_event_bus.py
**17 tests** covering:
- Basic subscribe/publish/unsubscribe routing
- Type filtering (wrong type → not delivered)
- No duplicate subscriptions
- subscribe_all receives every type
- Exception isolation (bad subscriber doesn't crash good ones)
- Thread safety: 5 threads × 20 publishes = 100 events received correctly
- RLock re-entrancy: subscribe inside a callback doesn't deadlock
- Housekeeping: subscriber_count, clear, unsubscribe_from_all
- Engine integration: engine dispatches all 5 event types to a custom bus

## Verification
- `pytest tests/test_event_bus.py` → **17 tests pass**
- Engine publishes to bus: `bus.subscribe(IPFlaggedEvent, cb); engine._dispatch_ip_flagged(...)` → cb called
- Full suite: **191 passing** (no regressions)

## Files created/modified
- `core/event_bus.py` — NEW: Thread-safe EventBus + global singleton
- `core/engine.py` — MODIFIED: EventBus integration in all dispatchers + optional event_bus param
- `tests/test_event_bus.py` — NEW: 17 tests
