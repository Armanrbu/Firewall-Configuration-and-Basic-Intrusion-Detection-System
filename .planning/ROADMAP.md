# Roadmap: NetGuard IDS

## Overview

NetGuard IDS is built in seven phases — from project foundation through a full-featured PyQt5 GUI, ML-powered intrusion detection, notifications, REST API, and a complete pytest test suite. Phases 1–7 deliver the v1 release. Phases 1–6 are complete; Phase 7 (Testing & Polish) is in progress — the pytest suite is done, but the threat map tab (GUI-08) and Twilio SMS (NOTF-03) remain pending.

## Phases

- [x] **Phase 1: Foundation** — Project scaffold, config, logging, SQLite, validators
- [x] **Phase 2: Firewall Core** — Cross-platform firewall backend, blocklist, whitelist
- [x] **Phase 3: IDS Engine** — Real-time monitoring, ML anomaly detection, geolocation
- [x] **Phase 4: GUI** — Dark-theme PyQt5 tabbed interface with all core tabs
- [x] **Phase 5: Notifications & Scheduler** — Desktop/email alerts, time-based rules
- [x] **Phase 6: API & Exports** — Flask REST API, CSV/PDF export
- [ ] **Phase 7: Testing & Polish** — pytest suite complete; threat map & Twilio pending

## Phase Details

### Phase 1: Foundation
**Goal**: Establish project scaffold — config loading, structured logging, SQLite DB, IP/port validators, and .env support.
**Depends on**: Nothing (first phase)
**Requirements**: FOUND-01, FOUND-02, FOUND-03, FOUND-04, FOUND-05, FOUND-06
**Success Criteria** (what must be TRUE):
  1. `pip install -r requirements.txt` completes without error
  2. `config.yaml` is loaded and accessible throughout the application
  3. Logs are written to a rotating file handler
  4. SQLite database is auto-created on first run
  5. IP and port validation rejects malformed input
**Plans**: 3 plans

Plans:
- [x] 01-01: Project scaffold — directory structure, requirements.txt, setup.py
- [x] 01-02: Config loader, logger, and .env support
- [x] 01-03: SQLite initialisation and validators

### Phase 2: Firewall Core
**Goal**: Implement a cross-platform firewall backend that can block/unblock IPs and ports on Windows (netsh) and Linux (iptables), with a persistent SQLite blocklist and whitelist.
**Depends on**: Phase 1
**Requirements**: FW-01, FW-02, FW-03, FW-04, FW-05, FW-06, FW-07, FW-08
**Success Criteria** (what must be TRUE):
  1. Blocking an IP creates a firewall rule and adds it to the SQLite blocklist
  2. Unblocking an IP removes the rule and updates the DB
  3. All firewall calls return `{success: bool, message: str}`
  4. Whitelisted IPs are never blocked, even if requested
  5. Works on both Windows and Linux without code changes at call sites
**Plans**: 3 plans

Plans:
- [x] 02-01: firewall.py — Windows netsh and Linux iptables backend
- [x] 02-02: blocklist.py — SQLite schema, CRUD operations
- [x] 02-03: whitelist.py — trusted IP management

### Phase 3: IDS Engine
**Goal**: Real-time intrusion detection via psutil connection monitoring, ML anomaly detection (Isolation Forest with threshold fallback), and IP geolocation cached in SQLite.
**Depends on**: Phase 2
**Requirements**: IDS-01, IDS-02, IDS-03, IDS-04, IDS-05, IDS-06
**Success Criteria** (what must be TRUE):
  1. IDS engine runs in a QThread and emits Qt signals for each alert
  2. Suspicious connections are detected and auto-blocked
  3. ML anomaly detection degrades gracefully when scikit-learn is absent
  4. IP geolocation lookups are cached — no repeated network calls for the same IP
  5. Windows firewall log is parsed for dropped packet events
**Plans**: 3 plans

Plans:
- [x] 03-01: ids.py — QThread-based monitoring engine with Qt signals
- [x] 03-02: anomaly.py — Isolation Forest + threshold fallback
- [x] 03-03: geo.py — ip-api.com geolocation with SQLite cache

### Phase 4: GUI
**Goal**: Full dark-theme PyQt5 tabbed interface — dashboard, blocklist, rules, alerts, scheduler, settings, threat map, system tray, and splash screen.
**Depends on**: Phase 3
**Requirements**: GUI-01, GUI-02, GUI-03, GUI-04, GUI-05, GUI-06, GUI-07, GUI-08, GUI-09, GUI-10
**Success Criteria** (what must be TRUE):
  1. Application launches and displays the main window with all tabs
  2. Dashboard shows live connection list updated in real time
  3. Blocklist tab shows all blocked IPs and supports add/unblock
  4. Alerts tab shows IDS alerts with geolocation data
  5. Settings tab saves changes to config.yaml
  6. System tray icon appears and supports minimize-to-tray
  7. Threat map loads (or degrades gracefully if PyQtWebEngine unavailable)
**Plans**: 4 plans

Plans:
- [x] 04-01: main_window.py, theme.py — application shell and dark stylesheet
- [x] 04-02: dashboard_tab.py, blocklist_tab.py, rules_tab.py
- [x] 04-03: alerts_tab.py, scheduler_tab.py, settings_tab.py
- [ ] 04-04: threat_map_tab.py — Leaflet.js world map (PyQtWebEngine, partial)

### Phase 5: Notifications & Scheduler
**Goal**: Desktop and email notifications on alert events, plus a time-based firewall rule scheduler (background thread).
**Depends on**: Phase 4
**Requirements**: NOTF-01, NOTF-02, NOTF-03, NOTF-04, SCHED-01, SCHED-02, SCHED-03
**Success Criteria** (what must be TRUE):
  1. Desktop notification fires when a new alert is generated
  2. Email alert is sent when configured (smtplib)
  3. Time-based rules activate and deactivate at the scheduled times
  4. Scheduler runs in a background thread — does not block the GUI
  5. All notification failures are logged and never crash the app
**Plans**: 2 plans

Plans:
- [x] 05-01: notifier.py — desktop (plyer) and email (smtplib) notifications
- [x] 05-02: scheduler.py — `schedule`-based background rule engine

### Phase 6: API & Exports
**Goal**: Optional Flask REST API for remote control/monitoring, CSV blocklist export, and PDF report generation.
**Depends on**: Phase 5
**Requirements**: API-01, API-02, API-03, API-04, EXP-01, EXP-02
**Success Criteria** (what must be TRUE):
  1. Flask API starts as a daemon thread when enabled in settings
  2. API endpoints return current blocked IPs and alert history
  3. API fails silently when Flask is not installed
  4. Blocklist exports to a valid CSV file
  5. PDF report is generated via reportlab (degrades gracefully if absent)
**Plans**: 2 plans

Plans:
- [x] 06-01: api/server.py — Flask REST API endpoints
- [x] 06-02: utils/exporter.py — CSV and PDF export

### Phase 7: Testing & Polish
**Goal**: Complete pytest test suite, packaging via setup.py, and final documentation polish.
**Depends on**: Phase 6
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04, TEST-05
**Success Criteria** (what must be TRUE):
  1. `pytest tests/ -v` passes with no failures
  2. Tests use in-memory SQLite — never touch the production database
  3. setup.py installs the package correctly
  4. README reflects actual capabilities
**Plans**: 2 plans

Plans:
- [x] 07-01: pytest suite — conftest.py, test_blocklist, test_firewall, test_ids, test_validators
- [ ] 07-02: Packaging (setup.py), README polish, and remaining features (threat map, Twilio)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 3/3 | Complete | 2026-03-11 |
| 2. Firewall Core | 3/3 | Complete | 2026-03-11 |
| 3. IDS Engine | 3/3 | Complete | 2026-03-11 |
| 4. GUI | 3/4 | In progress | - |
| 5. Notifications & Scheduler | 2/2 | Complete | 2026-03-11 |
| 6. API & Exports | 2/2 | Complete | 2026-03-11 |
| 7. Testing & Polish | 1/2 | In progress | - |
