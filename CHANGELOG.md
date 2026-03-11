# Changelog

All notable changes to NetGuard IDS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.0.0] — 2026-03-11

### Added — Phase 4: New Frontends

- **FastAPI REST server** (`api/server.py`) — replaces Flask; async endpoints, Pydantic validation, OpenAPI docs at `/docs`, WebSocket event streaming at `/ws/events`
- **Pydantic schemas** (`api/schemas.py`) — `BlockRequest`, `UnblockRequest`, `StatusResponse`, `GenericResponse`
- **PySide6 migration** — all seven UI tabs ported from PyQt5 to PySide6
- **YAML Rule Editor tab** (`ui/rule_editor_tab.py`) — in-GUI rule editing with syntax highlighting and hot-reload trigger
- **Typer CLI** (`cli/main.py`) — 10 commands: `status`, `block`, `unblock`, `alerts`, `blocklist`, `connections`, `config show`, `rules list/reload/validate`, `monitor`
- **AppRunner** (`core/app_runner.py`) — unified engine boot shim; single singleton shared by all frontends
- **EventBusBridge** (`ui/event_bus_bridge.py`) — thread-safe PySide6 adapter from EventBus → Qt signals

### Added — Phase 5: Packaging & CI/CD

- **`pyproject.toml`** — optional dependency groups (`gui`, `api`, `cli`, `ml`, `dev`), two entry-points, ruff/mypy/pytest/coverage config
- **`Dockerfile`** — multi-stage build; non-root user; health-check
- **`docker-compose.yml`** — named volumes for data/logs; live config + rules mount
- **GitHub Actions CI** (`.github/workflows/ci.yml`) — lint (ruff+mypy), 3×2 test matrix, Docker build, docs build, PyPI publish on tags
- **MkDocs site** (`mkdocs.yml` + `docs/`) — Material theme, API reference via mkdocstrings
- **`SECURITY.md`** — responsible disclosure process and security design principles
- **`CHANGELOG.md`** — this file

### Changed

- `requirements.txt` — Flask replaced with FastAPI/Uvicorn/Pydantic/websockets
- `setup.py` — superseded by `pyproject.toml` (kept for legacy compatibility)

### Added — Phase 3: Detection Engine

- `AbstractDetector` ABC + `DetectorRegistry` with entry-points plugin discovery
- `RuleEngine` — YAML rule loading, hot-reload, Python escape hatch, `rules/builtin.yaml`
- `MLAnomalyDetector` — PyOD ECOD / scikit-learn IsolationForest, batch scoring, model persistence, auto-retrain
- `AlertManager` — deduplication, severity ranking, action recommendation, DB persistence

---

## [1.0.0] — initial release

- PyQt5 GUI with dashboard, rules, alerts, blocklist, scheduler, threat map, settings tabs
- psutil-based connection monitor (`core/ids.py`)
- Platform firewall integration (Windows Firewall / iptables)
- SQLite persistence, whitelist, scheduler, system tray, PDF report export
