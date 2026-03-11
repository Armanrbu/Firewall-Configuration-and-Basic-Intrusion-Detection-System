---
phase: 01-security-stability
plan: 02
status: complete
completed_at: 2026-03-11
---

# Plan 01-02 Summary: Thread Safety & Graceful Shutdown

## What was done

### Task 1: Thread-safe database access in core/blocklist.py
- Replaced global `_con` singleton with `threading.local()` storage
- Each thread now gets its own `sqlite3.Connection`, lazily initialized
- Added `close_db()` to close the current thread's connection
- Added `close_all_connections()` with a tracked connection list and generation counter
- All connections registered in `_all_connections` list (thread-safe via `_connections_lock`)
- `set_db_path()` properly resets all connections via `close_all_connections()`
- Multi-threaded tests confirm concurrent writes succeed without `sqlite3.ProgrammingError`

### Task 2: Graceful shutdown for scheduler, IDS worker, API, and main app
- **core/scheduler.py** — `threading.Event` replaces boolean flag; `_loop()` uses `_stop_event.wait(30)` for instant wake on stop; `stop()` joins thread with 5s timeout
- **core/ids.py** — `IDSWorker` has `request_stop()` method; `_running` flag checked in monitoring loops
- **ui/main_window.py** — `closeEvent()` overridden to call `_shutdown()`; orderly teardown of IDS worker, scheduler, and DB connections
- **main.py** — `atexit.register(_cleanup)` for shutdown; `signal.SIGINT` handler; `sys.excepthook` for unhandled exceptions

## Verification
- `pytest tests/test_blocklist.py tests/test_shutdown.py -x -v` → All pass
- Scheduler thread joins within 5 seconds of `stop()`
- No `sqlite3.ProgrammingError` in threaded test runs

## Files modified
- `core/blocklist.py` — Per-thread connections, close_db, close_all_connections
- `core/scheduler.py` — threading.Event, graceful stop with join
- `core/ids.py` — request_stop() method
- `ui/main_window.py` — closeEvent + _shutdown
- `main.py` — atexit, signal, excepthook handlers
- `tests/test_blocklist.py` — Multi-threaded DB tests
- `tests/test_shutdown.py` — Shutdown verification tests
