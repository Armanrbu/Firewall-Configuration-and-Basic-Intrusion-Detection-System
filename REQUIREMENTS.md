# NetGuard IDS — Requirements

## v1 Requirements (Current Milestone)

### Core Infrastructure
- REQ-001: Cross-platform firewall backend (Windows netsh + Linux iptables)
- REQ-002: SQLite persistent storage (blocked_ips, alerts, connection_log, geo_cache tables)
- REQ-003: Configuration system via config.yaml with runtime reload
- REQ-004: Rotating file logger (utils/logger.py)
- REQ-005: IP address validation utility

### IDS Engine
- REQ-006: Sliding window connection tracking per IP (configurable window + threshold)
- REQ-007: Auto-block on threshold exceeded
- REQ-008: Port scan detection (>5 unique ports from same IP in <30s)
- REQ-009: Qt signals for: new_connection, ip_flagged, ip_blocked, anomaly_detected
- REQ-010: Real-time connection monitoring via psutil

### ML & Geolocation
- REQ-011: Isolation Forest anomaly detection (scikit-learn, fail-safe if not installed)
- REQ-012: IP geolocation via ip-api.com with SQLite caching
- REQ-013: Private IP detection (return "Local Network")

### Notifications
- REQ-014: Desktop toast notifications via plyer
- REQ-015: Email alerts via smtplib (HTML format, rate-limited 1/hour/IP)
- REQ-016: Optional Twilio SMS (fail-safe if not configured)

### GUI (PyQt5)
- REQ-017: Dark theme (background #1e1e2e, accent #7c3aed)
- REQ-018: Tabbed interface with 7 tabs: Dashboard, Rules, Alerts, Blocklist, Scheduler, Threat Map, Settings
- REQ-019: Real-time traffic dashboard (QTableWidget, 2s refresh, color-coded rows)
- REQ-020: Live connection count graph (matplotlib or pyqtgraph embedded)
- REQ-021: Rules management tab (add/remove/view/import/export firewall rules)
- REQ-022: Alerts tab with filter, geo info, resolve/block actions, export
- REQ-023: Blocklist tab with manual add/remove, import/export, geo info
- REQ-024: Scheduler tab for time-based firewall rules
- REQ-025: Threat map tab (Leaflet.js via QWebEngineView, fallback to table)
- REQ-026: Settings tab (all config.yaml settings editable, save button)
- REQ-027: System tray integration (minimize, notifications, tray menu)
- REQ-028: Splash screen on startup
- REQ-029: Status bar (firewall status, alert count, connection count, API status)

### REST API
- REQ-030: Optional Flask API on localhost:5000 (toggled in settings)
- REQ-031: Endpoints: GET /status, GET /blocked, POST /block, POST /unblock, GET /alerts, GET /connections
- REQ-032: API key authentication

### Data Export
- REQ-033: CSV export for all table views
- REQ-034: PDF report export (reportlab) with summary + detailed tables

### Scheduling
- REQ-035: Time-based firewall rules (block port X from HH:MM to HH:MM)
- REQ-036: Rules persisted in SQLite, managed via background thread

### Testing
- REQ-037: pytest tests for IP validation
- REQ-038: pytest tests for blocklist CRUD (in-memory SQLite)
- REQ-039: pytest tests for IDS threshold logic
- REQ-040: pytest tests for firewall command generation (mocked subprocess)

## v2 Requirements (Future)
- Packet capture with scapy
- PCAP file analysis
- Threat intelligence feed integration
- Multi-host monitoring dashboard
- Docker container support
