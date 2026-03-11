# Project State — NetGuard IDS v2

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-11)

**Core value:** One-click network security with ML-powered detection that anyone can install, configure via GUI, and extend via plugins — cross-platform, no Ph.D. required.
**Version:** v2 (production-grade rewrite)
**Current focus:** Phase 3 — Detection Engine COMPLETE

## Current Position

Phase: 6 of 7 (Advanced Features)
Plan: Completed 06-03 (Plugin Manager UI + Flow Visualization)
Status: Phase 6 COMPLETE ✅
Last activity: DPI plugin, ConfigWatcher, MLABTester, ActiveLearningQueue, PluginManagerTab, FlowVisualizationTab — 447 tests (446 passing)

Progress: [█████████▒] 92% (24/26 plans)

## Architecture Summary

**Current (v1, hardened):** Monolith — PyQt5 GUI + embedded IDS engine + Flask API, all in one process. Now with thread-safe DB, graceful shutdown, hardened subprocess calls, and structured logging.
**Target (v2):** Microkernel — engine daemon ↔ PySide6 GUI / FastAPI API / Typer CLI as separate frontends

## Key Stack Changes
| Component | v1 | v2 |
|-----------|----|----|
| GUI | PyQt5 | PySide6 (Qt6) |
| API | Flask | FastAPI (async) |
| ML | Isolation Forest (sklearn) | PyOD (ECOD + ensemble) |
| DB Access | Raw sqlite3 | SQLAlchemy ORM |
| Messaging | Direct function calls | Redis Streams / multiprocessing.Queue |
| CLI | None | Typer + Rich |
| Packaging | setup.py + requirements.txt | pyproject.toml + Docker |
| CI/CD | None | GitHub Actions |

## Performance Metrics

**Velocity:**
- Total plans: 26 across 7 phases
- Completed: 24 (Phases 1–6)
- v1 codebase: ~2500 lines, 20 modules (starting point)
- Tests: 447 total (446 passing, 1 pre-existing Windows tmp-path flake)

**Phase Plan Counts:**

| Phase | Plans | Status |
|-------|-------|--------|
| 1. Security & Stability | 4/4 | ✅ Complete |
| 2. Architecture | 4/4 | ✅ Complete |
| 3. Detection Engine | 4/4 | ✅ Complete |
| 4. New Frontends | 4/4 | ✅ Complete |
| 5. Packaging & CI/CD | 5/5 | ✅ Complete |
| 6. Advanced Features | 3/3 | ✅ Complete |
| 7. Release Polish | 0/2 | Not started |

## Accumulated Context

### Key Decisions (v2)
- Microkernel architecture: engine runs headless, frontends are optional consumers
- PySide6 over PyQt5: LGPL license, Qt6, OSS-friendly
- FastAPI over Flask: async, OpenAPI, Pydantic, modern standard
- PyOD over raw sklearn: 45 algorithms, ECOD default, plugin-extensible
- Redis for messaging: caching + streams + pub/sub in one service
- SQLAlchemy for DB: backend-agnostic, supports SQLite → PostgreSQL migration
- entry_points for plugins: standard Python packaging, pip-installable
- YAML rules + Python escape hatch: simple for users, powerful for devs
- Flow-based default + optional DPI plugin: lightweight by default

### Phase 1 Completions
1. ✅ 01-01: Command injection eliminated — all subprocess calls use list-form args, IP validation enforced
2. ✅ 01-02: Thread safety added — per-thread DB connections, graceful shutdown, error boundaries
3. ✅ 01-03: Database migrations — versioned schema, auto-upgrade, configurable log pruning
4. ✅ 01-04: JSON logging + .env credentials — no secrets in config.yaml, structured log output

### Phase 2 Completions
1. ✅ 02-01: Engine / GUI split — `NetGuardEngine` decoupled, headless mode
2. ✅ 02-02: Firewall Backend Abstraction — Windows/Linux strategies + Facade
3. ✅ 02-03: SQLAlchemy ORM + Repository Pattern
4. ✅ 02-04: Event-Driven Messaging — In-process publish/subscribe EventBus

### Phase 3 Completions
1. ✅ 03-01: AbstractDetector ABC + DetectorRegistry (entry_points plugins)
2. ✅ 03-02: YAML Rule Engine (hot-reload, Python escape hatch)
3. ✅ 03-03: ML Anomaly Detector (PyOD ECOD / IsolationForest, batch scoring, persistence)
4. ✅ 03-04: AlertManager (deduplication, explainable features, severity ranking, correlation)

### Phase 4 Completions
1. ✅ 04-01: FastAPI Server & IPC (async endpoints, Pydantic, OpenAPI docs, WebSockets)
2. ✅ 04-02: PySide6 GUI Migration (all tabs ported, RuleEditorTab created)
3. ✅ 04-03: Typer CLI (10 commands, Rich output, EventBus monitor, validate/reload rules)
4. ✅ 04-04: Frontend Integration (AppRunner singleton, EventBusBridge Qt adapter, 18 integration tests)

### Critical Risks
1. ~~Command injection in firewall commands~~ — ✅ Fixed in Plan 01-01
2. Model drift in ML detection — Phase 3 adds auto-retraining
3. GIL limitations for packet capture — Phase 2 uses multiprocessing
4. Cross-platform parity — CI tests both Windows + Linux

### Research Artifacts
- `.planning/research/STACK.md` — technology versions and trade-offs
- `.planning/research/FEATURES.md` — production IDS feature requirements
- `.planning/research/ARCHITECTURE.md` — microkernel design patterns
- `.planning/research/PITFALLS.md` — failure modes and mitigations
- `.planning/research/SUMMARY.md` — consolidated findings

## Session Continuity

Last session: 2026-03-12
Stopped at: Phase 6 COMPLETE — all 3 plans done (447 tests, 446 passing)
Resume with: Phase 7 — Release Polish (plans 07-01 through 07-02)
