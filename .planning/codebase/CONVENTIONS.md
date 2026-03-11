# Coding Conventions

## Type Hints
All functions have type hints (parameters and return types). Uses `from __future__ import annotations` for deferred evaluation.

```python
def block_ip(ip: str, rule_name: str | None = None) -> dict[str, Any]:
```

## Docstrings
Every module and every public function has a docstring. Module-level docstrings describe purpose and key concepts.

## Logging
- **NEVER use `print()`** — always `utils.logger.get_logger(__name__)`
- Logger format: `%(asctime)s [%(levelname)-8s] %(name)s — %(message)s`
- Rotating file handler (10MB, 5 backups) + console handler
- Pattern: `logger = get_logger(__name__)` at module top level

## Error Handling
- Optional imports wrapped in `try/except ImportError` with `HAS_X = True/False` flags
- Subprocess commands wrapped in `try/except` with error logging
- All notification methods are fail-safe (exceptions logged, never propagated)
- Pattern used throughout:
```python
try:
    from optional_lib import something
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
```

## API Return Convention
Core firewall functions return `dict[str, Any]`:
```python
{"success": bool, "message": str, ...}
```

## Naming
- Modules: `snake_case.py`
- Classes: `PascalCase` (e.g., `IDSEngine`, `MainWindow`, `StatCard`)
- Functions/methods: `snake_case` (e.g., `block_ip`, `get_all_blocked`)
- Private: leading underscore (`_run`, `_flagged`, `_setup_ui`)
- Constants: `UPPER_SNAKE_CASE` (`_RULES_PREFIX`, `REFRESH_MS`)
- Rule naming: `NetGuard_Block_{ip}`, `NetGuard_Port_{protocol}_{port}`

## Database Access
- All DB operations go through `core/blocklist.py` — never raw SQL elsewhere
- Singleton connection via `get_db()`
- `set_db_path()` for test overrides
- Uses `sqlite3.Row` row factory for dict-like access

## Cross-Platform
- OS detection: `platform.system()` → `"Windows"` / `"Linux"`
- Branch logic in firewall functions for netsh vs iptables
- Unsupported OS returns `{"success": False, "message": "Unsupported OS: ..."}`

## Qt Patterns
- Background work always in `QThread` (never block main thread)
- Inter-thread communication via `pyqtSignal`
- Tabs are `QWidget` subclasses with `_setup_ui()` pattern
- 2-second refresh timer on dashboard
