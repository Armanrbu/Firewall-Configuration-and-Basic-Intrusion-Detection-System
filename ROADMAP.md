# NetGuard IDS — Roadmap

## Milestone: v1.0-netguard-ids
**Goal:** Production-ready, cross-platform Firewall & IDS with full GUI, API, ML, and tests.

---

## Phase 1: Core Infrastructure & Data Layer ✅ Planned
**Goal:** Set up the foundational modules — project structure, config, logging, SQLite storage, IP validation, and cross-platform firewall backend.

Delivers: `core/firewall.py`, `core/blocklist.py`, `utils/logger.py`, `utils/config_loader.py`, `utils/validators.py`, `config.yaml`, `requirements.txt`, `firewall_ids.db` auto-creation.

---

## Phase 2: IDS Engine & Geolocation ✅ Planned
**Goal:** Build the intrusion detection system with sliding window tracking, port scan detection, auto-blocking, Qt signals, and IP geolocation with caching.

Delivers: `core/ids.py`, `core/geo.py`, psutil-based live connection monitoring.

---

## Phase 3: ML Anomaly Detection & Notifications ✅ Planned
**Goal:** Add Isolation Forest ML model for anomaly detection and multi-channel notification system (desktop, email, SMS).

Delivers: `core/anomaly.py`, `core/notifier.py`, anomaly_model.pkl persistence.

---

## Phase 4: PyQt5 GUI — Foundation & Core Tabs ✅ Planned
**Goal:** Build the main window, dark theme, splash screen, system tray, status bar, and the first 4 tabs: Dashboard, Rules, Alerts, Blocklist.

Delivers: `ui/main_window.py`, `ui/dashboard_tab.py`, `ui/rules_tab.py`, `ui/alerts_tab.py`, `ui/blocklist_tab.py`, `ui/tray.py`, `main.py`.

---

## Phase 5: Advanced GUI Tabs ✅ Planned
**Goal:** Build the remaining 3 tabs: Scheduler (time-based rules), Threat Map (Leaflet.js world map), and Settings (full config editor).

Delivers: `ui/scheduler_tab.py`, `ui/threat_map_tab.py`, `ui/settings_tab.py`, `core/scheduler.py`.

---

## Phase 6: REST API & Data Export ✅ Planned
**Goal:** Add the optional Flask REST API with API key auth and CSV/PDF export functionality.

Delivers: `api/server.py`, `utils/exporter.py`.

---

## Phase 7: Testing & Polish ✅ Planned
**Goal:** Write comprehensive pytest suite, add docstrings throughout, final README rewrite, and ensure all optional dependencies fail gracefully.

Delivers: `tests/test_firewall.py`, `tests/test_ids.py`, `tests/test_blocklist.py`, `tests/test_validators.py`, polished `README.md`.

---

## Phase Status

| Phase | Status | Branch |
|---|---|---|
| 1 — Core Infrastructure | 🔵 Ready to Plan | — |
| 2 — IDS Engine | 🔵 Ready to Plan | — |
| 3 — ML & Notifications | 🔵 Ready to Plan | — |
| 4 — GUI Foundation | 🔵 Ready to Plan | — |
| 5 — Advanced GUI | 🔵 Ready to Plan | — |
| 6 — API & Export | 🔵 Ready to Plan | — |
| 7 — Testing & Polish | 🔵 Ready to Plan | — |
