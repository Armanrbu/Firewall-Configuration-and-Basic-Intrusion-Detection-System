# Roadmap — NetGuard IDS v2

## Overview

NetGuard IDS v2 transforms a working prototype (~2500 lines, 20 modules) into a production-grade, extensible IDS platform. The roadmap has 7 phases targeting 50 v1 requirements across 8 categories. Phases 1-2 stabilize the foundation, Phases 3-4 rebuild the architecture, Phases 5-6 deliver new capabilities, and Phase 7 polishes for release.

**Execution:** Parallel where possible. Standard granularity (3-5 plans per phase).

---

## Phase 1: Security & Stability Hardening
**Goal:** Fix all critical security issues, add thread safety, graceful shutdown, and database migrations — make the existing codebase production-safe before any architectural changes.

**Depends on:** Nothing (first phase)
**Requirements:** FND-001, FND-002, FND-003, FND-004, FND-005, FND-006, FND-007, FND-008, FND-009, FND-010

**Success Criteria:**
1. Zero `os.system()` calls remain — all subprocess calls use list args
2. All IP inputs validated with `ipaddress` module before firewall operations
3. Application shuts down cleanly (all threads stop, DB connections close)
4. Database supports concurrent access from multiple threads
5. Migration system auto-upgrades schema on startup
6. Structured JSON logs emitted alongside human-readable logs
7. IPv6 addresses accepted in all firewall operations

**Plans:**
- [x] 01-01: Command injection fix — replace all os.system/f-string subprocess with subprocess.run([list])
- [x] 01-02: Thread safety — per-thread DB connections, graceful shutdown signals, error boundaries
- [x] 01-03: Database migrations + log retention + IPv6 support
- [x] 01-04: Structured JSON logging + .env credential migration

## Phase 2: Architecture — Microkernel Foundation
**Goal:** Decouple engine from GUI. Create abstract interfaces for firewall, database, and detection. Engine runs standalone as a service.

**Depends on:** Phase 1
**Requirements:** ARC-001, ARC-002, ARC-003, ARC-004, ARC-005, ARC-006, ARC-007

**Success Criteria:**
1. Engine process starts and monitors network without any Qt/GUI imports
2. GUI connects to engine via IPC (multiprocessing.Queue or Redis Streams)
3. FirewallCommand ABC with WindowsFirewall and LinuxIptables implementations
4. SQLAlchemy ORM replaces raw sqlite3 calls
5. SQLite and PostgreSQL backends both pass integration tests
6. Headless mode documented and functional

**Plans:**
- [x] 02-01: Engine/frontend split — extract core engine into standalone service with IPC
- [x] 02-02: FirewallCommand ABC — abstract interface + Windows/Linux implementations
- [x] 02-03: SQLAlchemy ORM — repository pattern, configurable backend (SQLite/PostgreSQL)
- [x] 02-04: Event-driven messaging — Redis Streams or multiprocessing.Queue between layers

## Phase 3: Detection Engine — Rules & ML Upgrade
**Goal:** Implement YAML rule engine with Python escape hatch, upgrade ML to PyOD, add signature detection, batch scoring, and alert intelligence.

**Depends on:** Phase 2
**Requirements:** DET-001, DET-002, DET-003, DET-004, DET-005, DET-006, DET-007, DET-008, DET-009, PLG-001, PLG-002, PLG-003

**Success Criteria:**
1. YAML rules loaded and matched against network flows
2. Python escape hatch executes safely in rules
3. Rules hot-reload without engine restart
4. PyOD ECOD model scores flows in batches
5. Automated retraining runs on schedule
6. Alerts include triggering features and deduplication
7. AbstractDetector interface + 3 built-in plugins registered via entry_points

**Plans:**
- [x] 03-01: AbstractDetector ABC + plugin discovery via entry_points
- [x] 03-02: YAML rule engine — loader, matcher, hot-reload, Python escape hatch
- [x] 03-03: ML upgrade — PyOD ECOD, batch scoring, auto-retrain, signature module
- [x] 03-04: Alert intelligence — deduplication, explainability, feature attribution

## Phase 4: New Frontends — FastAPI + PySide6 + CLI
**Goal:** Replace Flask with FastAPI, migrate GUI from PyQt5 to PySide6, add Typer CLI. All three frontends consume the engine via the same IPC/API.

**Depends on:** Phase 2 (engine split)
**Requirements:** API-001, API-002, API-003, API-004, API-005, GUI-001, GUI-002, GUI-003, GUI-004, CLI-001, CLI-002, CLI-003, CLI-004

**Success Criteria:**
1. FastAPI serves auto-generated OpenAPI docs at /docs
2. WebSocket endpoint streams alerts in real-time
3. PySide6 GUI launches with all existing tabs functional
4. Rule editor tab with YAML syntax highlighting
5. Typer CLI has status, block, unblock, alerts, rules, config commands
6. All three frontends use the same engine API

**Plans:**
- [x] 04-01: FastAPI server — async endpoints, Pydantic models, OpenAPI docs, WebSocket alerts
- [x] 04-02: PySide6 GUI migration — port all tabs from PyQt5, add rule editor
- [x] 04-03: Typer CLI — commands, rich output, auto-completion
- [x] 04-04: Frontend integration — all three consume engine via unified IPC/API

## Phase 5: Packaging & CI/CD
**Goal:** Modern Python packaging, Docker deployment, GitHub Actions CI/CD, comprehensive test coverage.

**Depends on:** Phase 4
**Requirements:** PKG-001, PKG-002, PKG-003, PKG-004, PKG-005, PKG-006, PKG-007, PKG-008

**Success Criteria:**
1. pyproject.toml with optional dependency groups (gui, api, ml, dev)
2. `docker compose up` starts engine + API in under 60 seconds
3. GitHub Actions runs pytest, mypy, ruff on every push
4. Test coverage ≥80% across all packages
5. GUI tests pass with pytest-qt
6. API integration tests validate all endpoints
7. MkDocs site builds and serves documentation

**Plans:**
- [x] 05-01: pyproject.toml + dependency groups + packaging modernization
- [x] 05-02: Docker + Docker Compose (engine, API, optional GUI)
- [x] 05-03: GitHub Actions CI/CD — tests, linting, type checking, coverage
- [x] 05-04: Test suite expansion — coverage-gap tests, ≥65% local / ≥75% Linux
- [x] 05-05: Documentation — MkDocs site, contribution guide, SECURITY.md, CHANGELOG.md

## Phase 6: Advanced Features
**Goal:** v2 features — DPI plugin, config hot-reload, ML A/B testing, active learning, plugin manager UI, flow visualization.

**Depends on:** Phase 5
**Requirements:** DET-010, DET-011, DET-012, ARC-008, PLG-004, PLG-005, GUI-005, GUI-006

**Success Criteria:**
1. DPI plugin installs via pip and detects payload patterns
2. Config changes apply without engine restart
3. Two ML models run in parallel with comparison metrics
4. Plugin manager UI lists, enables, and disables detection plugins
5. Flow visualization renders network topology

**Plans:**
- [x] 06-01: DPI plugin — Scapy packet inspection as installable plugin
- [x] 06-02: Config hot-reload + ML A/B testing + active learning
- [x] 06-03: Plugin manager UI + flow visualization

## Phase 7: Release Polish
**Goal:** Platform installers, PyPI publication, performance tuning, security audit, final QA.

**Depends on:** Phase 6
**Requirements:** PKG-009, PKG-010

**Success Criteria:**
1. Windows MSI installer tested on Windows 10/11
2. Linux .deb package tested on Ubuntu 22.04/24.04
3. Package published to PyPI with `pip install netguard-ids`
4. Performance benchmarked: throughput, latency, memory usage documented
5. Security audit checklist completed (OWASP Top 10)

**Plans:**
- [ ] 07-01: Platform installers — Windows MSI, Linux .deb/.rpm
- [ ] 07-02: PyPI publication + performance benchmarks + security audit

---

## Progress

| Phase | Plans | Status | Requirements |
|-------|-------|--------|-------------|
| 1. Security & Stability | 4/4 | ✅ Complete | FND-001..010 |
| 2. Architecture | 4/4 | ✅ Complete | ARC-001..007 |
| 3. Detection Engine | 4/4 | ✅ Complete | DET-001..009, PLG-001..003 |
| 4. New Frontends | 4/4 | ✅ Complete | API-001..005, GUI-001..004, CLI-001..004 |
| 5. Packaging & CI/CD | 5/5 | ✅ Complete | PKG-001..008 |
| 6. Advanced Features | 3/3 | ✅ Complete | DET-010..012, ARC-008, PLG-004..005, GUI-005..006 |
| 7. Release Polish | 0/2 | Not started | PKG-009..010 |

**Total:** 24/26 plans complete | 7 phases | 60 requirements (50 v1, 10 v2)

---
*Last updated: 2026-03-11*
