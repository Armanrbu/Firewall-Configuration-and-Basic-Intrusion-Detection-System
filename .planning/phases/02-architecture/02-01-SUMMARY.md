---
phase: 02-architecture
plan: 01
status: complete
completed_at: 2026-03-11
---

# Plan 02-01 Summary: Engine/Frontend Split

## What was done

### Task 1: core/interfaces.py — EngineEventHandler protocol + event dataclasses
- Created `EngineEventHandler` as a `@runtime_checkable` Protocol with 6 methods:
  `on_connection`, `on_ip_flagged`, `on_ip_blocked`, `on_port_scan`, `on_anomaly`, `on_engine_status`
- Created typed frozen dataclasses for all engine events:
  `EngineEvent` (base), `ConnectionDetectedEvent`, `IPFlaggedEvent`, `IPBlockedEvent`,
  `PortScanEvent`, `AnomalyEvent`, `EngineStatusEvent`
- All events have auto-populated `timestamp` field and are immutable (`frozen=True`)

### Task 2: core/engine.py — Standalone NetGuardEngine
- `NetGuardEngine` class owns the IDS pipeline, psutil monitoring thread, and log monitoring thread
- **Zero Qt/GUI dependencies** — confirmed clean via import audit
- `register_handler()` / `unregister_handler()` for frontend consumers
- `start()` / `stop(timeout)` for lifecycle management
- `get_status()` returns dict for API/CLI consumption
- `ids_engine` property exposes the underlying `IDSEngine`
- Handler exceptions are isolated: one bad handler doesn't crash others
- Multiple handlers all receive every dispatched event

### Task 3: main.py — --headless flag
- Added `argparse` with `--headless` flag
- `_run_headless()` starts `NetGuardEngine` and blocks on `_stop_event` (no Qt import)
- `_run_gui()` contains all existing Qt startup logic (unchanged behavior)
- In headless mode: **zero PyQt5 imports** — confirmed clean

## Verification
- `pytest tests/test_engine.py -v` → **26 tests pass**
- `python -c "from core.engine import NetGuardEngine"` → zero Qt imports in sys.modules
- `python main.py --help` → `--headless` present in output
- Full suite: **130 passing** (no regressions)

## Files created/modified
- `core/interfaces.py` — NEW: EngineEventHandler protocol + event dataclasses
- `core/engine.py` — NEW: Standalone NetGuardEngine
- `main.py` — MODIFIED: argparse + --headless + _run_headless/_run_gui split
- `tests/test_engine.py` — NEW: 26 tests
