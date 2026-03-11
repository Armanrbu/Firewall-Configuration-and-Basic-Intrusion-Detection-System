# Requirements — NetGuard IDS v2

## Legend
- **v1** — Must ship in v2.0 release (core product)
- **v2** — Post-launch iteration (v2.x releases)
- **oos** — Out of scope (not planned)

---

## FOUNDATION — Security & Stability

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| FND-001 | Replace all `os.system()` / f-string subprocess calls with `subprocess.run([list])` to prevent command injection | v1 | PITFALLS S2, CONCERNS.md |
| FND-002 | Validate all IP addresses with `ipaddress` module before any firewall or network operation | v1 | PITFALLS S2, CONCERNS.md |
| FND-003 | Implement graceful shutdown for all background threads (IDS, scheduler, API) | v1 | CONCERNS.md |
| FND-004 | Add thread-safe database access (connection pooling or per-thread connections) | v1 | CONCERNS.md |
| FND-005 | Implement database migration system (Alembic or manual versioned migrations) | v1 | CONCERNS.md |
| FND-006 | Add connection log retention/pruning (configurable max age/count) | v1 | CONCERNS.md |
| FND-007 | Move API key storage from plaintext config to `.env` file with python-dotenv | v1 | CONCERNS.md |
| FND-008 | Add structured JSON logging alongside human-readable logs | v1 | FEATURES |
| FND-009 | Implement proper error boundaries — no unhandled exceptions crash the app | v1 | CONCERNS.md |
| FND-010 | IPv6 support in firewall commands and IP validation | v1 | PITFALLS A1 |

## ARCHITECTURE — Microkernel & Decoupling

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| ARC-001 | Separate detection engine into standalone service (runs without GUI) | v1 | PROJECT.md, ARCHITECTURE |
| ARC-002 | Define IPC protocol between engine and frontends (Redis Streams or multiprocessing.Queue) | v1 | ARCHITECTURE |
| ARC-003 | Implement event-driven architecture with message queues between layers | v1 | ARCHITECTURE |
| ARC-004 | Create abstract `FirewallCommand` interface with platform-specific implementations | v1 | ARCHITECTURE |
| ARC-005 | Implement database repository pattern with SQLAlchemy ORM | v1 | ARCHITECTURE |
| ARC-006 | Support configurable database backend (SQLite default, optional PostgreSQL) | v1 | STACK |
| ARC-007 | Headless mode — engine runs as system service without any GUI dependency | v1 | PROJECT.md |
| ARC-008 | Configuration hot-reload without service restart | v2 | FEATURES |

## DETECTION — Rule Engine & ML

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| DET-001 | YAML-based rule engine with match conditions (ip, port, protocol, rate, payload pattern) | v1 | PROJECT.md |
| DET-002 | Python escape hatch in rules for complex detection logic | v1 | PROJECT.md |
| DET-003 | Rule hot-reload — new/modified rules active without restart | v1 | FEATURES |
| DET-004 | Upgrade ML pipeline to PyOD with ECOD as default algorithm | v1 | STACK |
| DET-005 | Batch ML scoring (10-100 flows per batch) to reduce per-flow overhead | v1 | PITFALLS P2 |
| DET-006 | Automated ML model retraining on configurable schedule (default: 7 days) | v1 | PITFALLS ML1 |
| DET-007 | Alert deduplication — suppress repeated identical alerts within configurable window | v1 | FEATURES |
| DET-008 | Alert explainability — include triggering features and rule ID in every alert | v1 | FEATURES |
| DET-009 | Signature-based detection module alongside behavioral ML | v1 | PROJECT.md |
| DET-010 | Deep packet inspection via Scapy as optional plugin | v2 | PROJECT.md |
| DET-011 | ML model A/B testing framework | v2 | PITFALLS ML1 |
| DET-012 | Active learning — flag uncertain predictions for manual review | v2 | PITFALLS ML1 |

## PLUGIN — Extension System

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| PLG-001 | Define `AbstractDetector` ABC with `fit()` and `predict()` interface | v1 | ARCHITECTURE |
| PLG-002 | Plugin discovery via `importlib.metadata.entry_points()` | v1 | ARCHITECTURE |
| PLG-003 | Built-in plugins: IsolationForest, ECOD, YAMLRuleMatcher | v1 | STACK |
| PLG-004 | Plugin resource limits (timeout, memory cap) for safety | v2 | PITFALLS S1 |
| PLG-005 | Plugin marketplace/registry documentation | v2 | FEATURES |

## GUI — PySide6 Modern Interface

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| GUI-001 | Migrate from PyQt5 to PySide6 (Qt6) | v1 | PROJECT.md, STACK |
| GUI-002 | Real-time traffic visualization dashboard with charts | v1 | PROJECT.md |
| GUI-003 | Rule editor with YAML syntax highlighting | v1 | DET-001 |
| GUI-004 | Alert viewer with filtering, search, and export | v1 | Existing |
| GUI-005 | Plugin manager UI (list, enable/disable installed plugins) | v2 | PLG-002 |
| GUI-006 | Network flow visualization (topology/graph view) | v2 | PROJECT.md |

## API — FastAPI Async REST

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| API-001 | Migrate from Flask to FastAPI with async endpoints | v1 | PROJECT.md, STACK |
| API-002 | Auto-generated OpenAPI/Swagger documentation | v1 | STACK |
| API-003 | WebSocket endpoint for real-time alert streaming | v1 | ARCHITECTURE |
| API-004 | API key + optional JWT authentication | v1 | Existing + upgrade |
| API-005 | Rate limiting and request validation (Pydantic models) | v1 | FEATURES |

## CLI — Terminal Interface

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| CLI-001 | Typer-based CLI with auto-completion | v1 | STACK |
| CLI-002 | Commands: status, block/unblock, alerts, rules, config | v1 | PROJECT.md |
| CLI-003 | Rich terminal output (tables, colors, progress bars) | v1 | STACK |
| CLI-004 | CLI connects to engine via same API as GUI | v1 | ARC-001 |

## PACKAGING — Build, Deploy, Test

| ID | Requirement | Scope | Source |
|----|-------------|-------|--------|
| PKG-001 | pyproject.toml with proper metadata and optional dependency groups | v1 | STACK |
| PKG-002 | Docker + Docker Compose for one-command deployment | v1 | PROJECT.md |
| PKG-003 | GitHub Actions CI/CD (pytest, linting, type checking, builds) | v1 | PROJECT.md |
| PKG-004 | Test coverage ≥80% (unit + integration) | v1 | PROJECT.md |
| PKG-005 | GUI test suite (PySide6 QTest or pytest-qt) | v1 | CONCERNS.md |
| PKG-006 | API integration tests | v1 | CONCERNS.md |
| PKG-007 | Documentation site (MkDocs or Sphinx) | v1 | FEATURES |
| PKG-008 | Contribution guide + security policy (SECURITY.md) | v1 | FEATURES |
| PKG-009 | Platform installers (Windows MSI, Linux .deb/.rpm) | v2 | PROJECT.md |
| PKG-010 | PyPI package publication | v2 | PROJECT.md |

---

## Traceability

| Category | v1 Count | v2 Count | Total |
|----------|----------|----------|-------|
| FOUNDATION | 10 | 0 | 10 |
| ARCHITECTURE | 7 | 1 | 8 |
| DETECTION | 9 | 3 | 12 |
| PLUGIN | 3 | 2 | 5 |
| GUI | 4 | 2 | 6 |
| API | 5 | 0 | 5 |
| CLI | 4 | 0 | 4 |
| PACKAGING | 8 | 2 | 10 |
| **Total** | **50** | **10** | **60** |

Every v1 requirement maps to exactly one roadmap phase. See ROADMAP.md.

---
*Last updated: 2026-03-11*

## Out of Scope

| Feature | Reason |
|---------|--------|
| Cloud sync / remote dashboard | Keeps app self-contained; adds attack surface |
| macOS support | Windows and Linux are primary targets for v1 |
| Mobile application | Desktop-only for v1 |
| Real-time collaboration | Out of domain for a security tool |
| Deep packet inspection | Requires kernel-level access beyond project scope |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| FOUND-01 to FOUND-06 | Phase 1: Foundation | Complete |
| FW-01 to FW-08 | Phase 2: Firewall Core | Complete |
| IDS-01 to IDS-06 | Phase 3: IDS Engine | Complete |
| GUI-01 to GUI-07, GUI-09, GUI-10 | Phase 4: GUI | Complete |
| GUI-08 | Phase 4: GUI | In Progress |
| NOTF-01 to NOTF-04 | Phase 5: Notifications & Scheduler | Mostly Complete |
| SCHED-01 to SCHED-03 | Phase 5: Notifications & Scheduler | Complete |
| API-01 to API-04 | Phase 6: API & Exports | Complete |
| EXP-01 to EXP-02 | Phase 6: API & Exports | Complete |
| TEST-01 to TEST-05 | Phase 7: Testing & Polish | Complete |

**Coverage:**
- v1 requirements: 39 total
- Mapped to phases: 39
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-11*
*Last updated: 2026-03-11 after GSD initialisation*
