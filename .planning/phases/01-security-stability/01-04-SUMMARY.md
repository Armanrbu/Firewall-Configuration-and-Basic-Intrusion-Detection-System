---
phase: 01-security-stability
plan: 04
status: complete
completed_at: 2026-03-11
---

# Plan 01-04 Summary: Structured JSON Logging + .env Credential Migration

## What was done

### Task 1: Migrate credentials to .env with python-dotenv
- **`.env.example`** updated with `NETGUARD_` prefixed variables: `NETGUARD_API_KEY`, `NETGUARD_SMTP_USER`, `NETGUARD_SMTP_PASSWORD`, `NETGUARD_TWILIO_SID`/`TOKEN`/`FROM`/`TO`
- **`config.yaml`** — Removed `api_key`, `username`, `password` fields; replaced with comments pointing to .env
- **`api/server.py`** — `APIServer` reads API key from `os.environ.get("NETGUARD_API_KEY")` with fallback to empty string
- **`core/notifier.py`** — SMTP user/pass read from `NETGUARD_SMTP_USER`/`NETGUARD_SMTP_PASSWORD` env vars; Twilio credentials use `NETGUARD_TWILIO_*` variables
- **`main.py`** — Already calls `load_dotenv()` early (wrapped in try/except for fail-safe)
- **`.gitignore`** — Already has `.env` entry

### Task 2: Add structured JSON logging
- **`utils/logger.py`** — Added `JsonFormatter` class that outputs valid JSON with keys: `timestamp`, `level`, `logger`, `message`, optional `exception` and `ip`
- **`setup_logging()`** — Now accepts `log_format` parameter ("human" or "json"); defaults to "human"
- **`config.yaml`** — Added `format: "human"` under logging section with comment explaining options
- **`main.py`** — Passes `log_format` config option through to `setup_logging()`
- **`tests/test_logger.py`** — 9 tests covering JSON validity, required keys, exception info, extra fields, special characters, different log levels, and get_logger behavior

## Verification
- `pytest tests/test_logger.py -x -v` → 9 tests pass
- `grep "api_key" config.yaml` → Only comment reference, no value
- `grep "password" config.yaml` → Only comment reference, no value
- `.env.example` exists with all NETGUARD_* variable placeholders
- Application starts without .env file (fail-safe via try/except)

## Files modified
- `utils/logger.py` — JsonFormatter + log_format parameter
- `api/server.py` — Reads API key from env var
- `core/notifier.py` — Reads SMTP/Twilio creds from env vars
- `config.yaml` — Removed secrets, added format option
- `.env.example` — Updated with NETGUARD_ prefixed variables
- `main.py` — Passes log_format to setup_logging
- `tests/test_logger.py` — New file, 9 tests
