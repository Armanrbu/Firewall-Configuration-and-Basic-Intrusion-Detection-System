# NetGuard IDS

## What This Is

NetGuard IDS is an industry-ready, cross-platform Firewall Control & Intrusion Detection System built with Python and PyQt5. It detects, blocks, and logs unauthorised network access on Windows and Linux, presenting everything through a polished dark-theme tabbed GUI.

## Core Value

Administrators can detect and block malicious network activity in real time from a single, self-contained desktop application — no cloud dependency, no complex setup.

## Requirements

### Validated

- [x] Cross-platform firewall backend (Windows netsh / Linux iptables)
- [x] SQLite-based persistent blocklist and alert history
- [x] Real-time connection monitoring via psutil
- [x] Dark-theme PyQt5 GUI with tabbed interface
- [x] ML anomaly detection (Isolation Forest, fail-safe fallback)
- [x] IP geolocation with SQLite cache
- [x] Desktop + email notifications
- [x] Time-based firewall rule scheduler
- [x] Optional Flask REST API
- [x] CSV and PDF export
- [x] IP/port validation before any shell command
- [x] Whitelist for trusted IPs
- [x] pytest test suite

### Active

- [ ] Threat map tab (Leaflet.js, requires PyQtWebEngine)
- [ ] SMS notifications via Twilio (optional, fail-safe)
- [ ] Packaging / installer (setup.py exists, needs testing)

### Out of Scope

- Cloud sync / remote dashboard — keep it self-contained
- Real-time chat or collaboration features — out of domain
- Mobile application — desktop-only for v1

## Context

- Python 3.10+, PyQt5 5.15+, SQLite, psutil, scikit-learn (optional), Flask (optional)
- Targets Windows (netsh advfirewall) and Linux (iptables)
- Logger configured in utils/logger.py — never use print()
- DB access exclusively through core/blocklist.py
- All subprocess calls wrapped in try/except

## Constraints

- **Platform**: Windows & Linux only — macOS not targeted in v1
- **Privileges**: Firewall commands require admin/root — must be documented clearly
- **Dependencies**: All heavy dependencies (scikit-learn, flask, reportlab, twilio) are optional and must fail-safe
- **Threading**: GUI must never block the main thread — use QThread for all background work

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| SQLite for persistence | Zero-config, embedded, sufficient for desktop app | ✓ Good |
| psutil for connection monitoring | Cross-platform, no raw sockets needed | ✓ Good |
| Isolation Forest for anomaly detection | Good unsupervised baseline; fails safely to threshold mode | ✓ Good |
| ip-api.com for geolocation | Free, no API key, cached in SQLite | ✓ Good |
| PyQt5 over Tkinter | Richer widget set, custom dark theme, QThread support | ✓ Good |
| Flask API optional | Avoids mandatory dependency; works headlessly for power users | ✓ Good |

---
*Last updated: 2026-03-11 after GSD initialisation*
