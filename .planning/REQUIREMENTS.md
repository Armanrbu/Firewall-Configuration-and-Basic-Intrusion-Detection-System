# Requirements: NetGuard IDS

**Defined:** 2026-03-11
**Core Value:** Administrators can detect and block malicious network activity in real time from a single, self-contained desktop application — no cloud dependency, no complex setup.

## v1 Requirements

### Foundation

- [x] **FOUND-01**: Project installs cleanly via `pip install -r requirements.txt`
- [x] **FOUND-02**: Configuration loaded from `config.yaml` via `utils/config_loader.py`
- [x] **FOUND-03**: Structured logging with rotating file handler (`utils/logger.py`)
- [x] **FOUND-04**: SQLite database auto-created on first run (`firewall_ids.db`)
- [x] **FOUND-05**: `.env` support for credentials (python-dotenv, optional)
- [x] **FOUND-06**: IP and port validation before any shell command (`utils/validators.py`)

### Firewall

- [x] **FW-01**: Block an IP address on Windows using `netsh advfirewall`
- [x] **FW-02**: Block an IP address on Linux using `iptables`
- [x] **FW-03**: Block a port (TCP/UDP) on Windows and Linux
- [x] **FW-04**: Unblock an IP address (remove firewall rule)
- [x] **FW-05**: List all NetGuard-managed firewall rules
- [x] **FW-06**: All firewall operations wrapped in try/except; return `{success, message}`
- [x] **FW-07**: Persistent blocklist stored in SQLite (`core/blocklist.py`)
- [x] **FW-08**: Whitelist for trusted IPs that are never blocked (`core/whitelist.py`)

### Intrusion Detection

- [x] **IDS-01**: Real-time connection monitoring via psutil
- [x] **IDS-02**: Parse Windows firewall log for dropped packets
- [x] **IDS-03**: ML anomaly detection using Isolation Forest (`core/anomaly.py`)
- [x] **IDS-04**: Fallback threshold-based detection when scikit-learn is absent
- [x] **IDS-05**: IDS engine emits Qt signals for UI integration (`core/ids.py`)
- [x] **IDS-06**: IP geolocation with SQLite caching (`core/geo.py`)

### GUI

- [x] **GUI-01**: Dark-theme PyQt5 application with tabbed interface
- [x] **GUI-02**: Dashboard tab — live network connections and statistics
- [x] **GUI-03**: Blocklist tab — view, add, unblock IPs; import/export
- [x] **GUI-04**: Rules tab — view and manage firewall rules
- [x] **GUI-05**: Alerts tab — alert history with geolocation, filter, block action
- [x] **GUI-06**: Scheduler tab — time-based firewall rules (e.g., block port 22 at night)
- [x] **GUI-07**: Settings tab — configure all parameters, saved to `config.yaml`
- [ ] **GUI-08**: Threat map tab — Leaflet.js world map of blocked/flagged IPs (requires PyQtWebEngine)
- [x] **GUI-09**: System tray icon with balloon notifications
- [x] **GUI-10**: Splash screen on startup

### Notifications

- [x] **NOTF-01**: Desktop notifications via plyer
- [x] **NOTF-02**: Email alerts via smtplib
- [ ] **NOTF-03**: SMS alerts via Twilio (optional, fail-safe)
- [x] **NOTF-04**: All notification methods are fail-safe (never crash the app)

### Scheduling

- [x] **SCHED-01**: Time-based rule scheduler using `schedule` library
- [x] **SCHED-02**: Scheduler runs in a background thread
- [x] **SCHED-03**: Rules persist across restarts via SQLite

### API

- [x] **API-01**: Optional Flask REST API (`api/server.py`)
- [x] **API-02**: API runs as a background daemon thread when enabled
- [x] **API-03**: Endpoints for remote monitoring and control
- [x] **API-04**: API fails safely when Flask is not installed

### Export

- [x] **EXP-01**: Export blocklist to CSV (`utils/exporter.py`)
- [x] **EXP-02**: Export PDF reports via reportlab (optional, fail-safe)

### Testing

- [x] **TEST-01**: pytest test suite with in-memory SQLite (never touches production DB)
- [x] **TEST-02**: Tests for blocklist CRUD (`tests/test_blocklist.py`)
- [x] **TEST-03**: Tests for firewall backend (`tests/test_firewall.py`)
- [x] **TEST-04**: Tests for IDS engine (`tests/test_ids.py`)
- [x] **TEST-05**: Tests for validators (`tests/test_validators.py`)

## v2 Requirements

### Advanced Detection

- **ADV-01**: Signature-based detection (known attack patterns)
- **ADV-02**: Rate-limiting / connection throttling
- **ADV-03**: Port scan detection

### Reporting

- **REP-01**: Scheduled PDF reports (daily/weekly summary)
- **REP-02**: Email digest of blocked IPs

### Packaging

- **PKG-01**: Windows .exe installer via PyInstaller
- **PKG-02**: Linux .deb / .rpm package

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
