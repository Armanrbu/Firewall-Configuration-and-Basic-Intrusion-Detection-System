# NetGuard IDS — Project Instructions for Claude

## Project Overview
NetGuard IDS is an industry-ready, cross-platform Firewall Control & Intrusion Detection System built with Python and PyQt5. It detects, blocks, and logs unauthorized network access on Windows and Linux.

## Tech Stack
- **Language:** Python 3.10+
- **GUI:** PyQt5 5.15+ (dark theme, tabbed interface)
- **Backend:** psutil, scikit-learn, Flask, SQLite (via sqlite3)
- **Notifications:** plyer, smtplib
- **Config:** PyYAML, python-dotenv
- **Exports:** reportlab, csv
- **Scheduling:** schedule
- **Testing:** pytest

## Architecture
```
main.py          # Entry point — launches GUI + background services
core/            # Business logic (firewall, IDS, ML, geo, DB, notifications)
ui/              # PyQt5 tabs and windows
utils/           # Helpers (logger, config, exporter, validators)
api/             # Optional Flask REST API
tests/           # pytest test suite
```

## Coding Conventions
- All functions must have **type hints** and **docstrings**
- Use `logging` module (never `print()`) — logger configured in `utils/logger.py`
- All subprocess calls (netsh, iptables) must be wrapped in try/except
- Optional dependencies (scikit-learn, flask, reportlab, twilio) must fail-safe — never crash the app if missing
- SQLite DB auto-created on first run at `firewall_ids.db`
- Config loaded from `config.yaml` via `utils/config_loader.py`
- Cross-platform: detect OS with `platform.system()`, branch for Windows/Linux

## Critical Rules
1. NEVER use `print()` — always use the logger
2. NEVER let optional import failures crash the app — use try/except with fallback
3. ALWAYS wrap subprocess/shell commands in try/except
4. ALWAYS validate IP addresses before passing to firewall commands
5. The PyQt5 GUI must never block the main thread — use QThread for all background work
6. All DB operations go through `core/blocklist.py` — never raw SQL elsewhere

## File Placement Guide
- New GUI tabs → `ui/{name}_tab.py`
- New core logic → `core/{name}.py`
- New utilities → `utils/{name}.py`
- New tests → `tests/test_{name}.py`

## Testing
Run tests: `pytest tests/ -v`
Test files use in-memory SQLite (`:memory:`) — never touch production DB

## Security
- Firewall commands require admin/root privileges — document this clearly
- Never log or store credentials in plaintext
- IP validation before any shell command execution
- `.env` file for credentials — never commit secrets
