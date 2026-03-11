---
phase: 01-security-stability
plan: 03
status: complete
completed_at: 2026-03-11
---

# Plan 01-03 Summary: Database Migrations & Log Retention

## What was done

### Task 1: Versioned migration system
- Created `core/db_migrations.py` with `CURRENT_VERSION = 1`
- `get_schema_version(con)` reads version from `schema_version` table
- `run_migrations(con)` applies all pending migrations idempotently
- `_migrate_v1()` adds new columns: `ml_score`, `rule_id`, `action` to alerts; `expires_at`, `status` to blocked_ips; `details_json` to connection_log
- `_add_column_if_missing()` helper checks `PRAGMA table_info` before ALTER TABLE

### Task 2: Wired into application startup
- `_init_db()` in `core/blocklist.py` calls `run_migrations(con)` after table creation
- `main.py` runs `prune_connection_log()` and `prune_old_alerts()` at startup using config retention settings
- `config.yaml` has `database.retention` section with `connection_log_days`, `connection_log_max_rows`, `alert_log_days`

## Verification
- `pytest tests/test_migrations.py tests/test_blocklist.py -x -v` → All pass
- Fresh DB gets `schema_version = 1`
- Running on already-current DB is a no-op
- Pruning respects both age and max_rows constraints

## Files modified
- `core/db_migrations.py` — New file, versioned migration system
- `core/blocklist.py` — run_migrations call, prune functions
- `config.yaml` — Added retention configuration
- `main.py` — Startup pruning
- `tests/test_migrations.py` — Migration and pruning tests
