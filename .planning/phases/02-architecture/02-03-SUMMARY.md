---
phase: 02-architecture
plan: 03
status: complete
completed_at: 2026-03-11
---

# Plan 02-03 Summary: SQLAlchemy ORM + Repository Pattern

## What was done

### Task 1: core/models.py — SQLAlchemy ORM models
- All 6 tables defined as typed SQLAlchemy ORM models:
  `BlockedIP`, `Alert`, `ConnectionLog`, `GeoCache`, `SchemaVersion`, `ScheduledRule`
- All migration v1 columns included (`expires_at`, `status`, `ml_score`, `rule_id`, `action`, `details_json`)
- `create_db_engine(db_url)` factory supports SQLite + PostgreSQL via URL string
- `init_schema(engine)` creates all tables idempotently
- Fail-safe stubs when SQLAlchemy not installed (import doesn't crash)
- `to_dict()` methods on key models return `dict[str, Any]` matching existing contract

### Task 2: core/repository.py — Repository pattern
- Four repository classes with CRUD matching existing `blocklist.py` signatures:
  - `BlocklistRepository`: `add_block`, `remove_block`, `get_all_blocked`, `is_blocked`, `purge_block`
  - `AlertRepository`: `add_alert`, `get_alerts`, `resolve_alert`, `prune_old_alerts`
  - `ConnectionLogRepository`: `log_connection`, `get_connection_log`, `get_stats_today`, `prune`
  - `GeoCacheRepository`: `get`, `set`
- `Repositories` NamedTuple bundles all repos
- `init_db(url)` / `reset_db()` manage the singleton engine (reset_db for tests)
- `get_repositories()` returns wired instances
- Session factory pattern: each call to a method uses a scoped session

### Task 3: Tests
- `tests/test_models.py`: 13 tests — table schema, column sets, instantiation, to_dict(), PK, idempotent schema
- `tests/test_repository.py`: 31 tests — full CRUD for all 4 repos, upsert, prune, stats, bundle

## Verification
- `pytest tests/test_models.py tests/test_repository.py` → **44 tests pass**
- `from core.repository import init_db, get_repositories; init_db("sqlite:///:memory:")` — works
- All existing callers in `core/blocklist.py` unchanged (facade still works)
- Full suite: **191 passing** (no regressions)

## Files created
- `core/models.py` — NEW: SQLAlchemy ORM models for all 6 tables
- `core/repository.py` — NEW: Repository CRUD classes + singleton management
- `tests/test_models.py` — NEW: 13 model tests
- `tests/test_repository.py` — NEW: 31 repository CRUD tests
