# 🛡️ NetGuard IDS — Project Vision

## What We're Building
A professional, industry-ready, cross-platform **Firewall Control & Intrusion Detection System** with a PyQt5 GUI, REST API, ML anomaly detection, and real-time network monitoring.

## Who It's For
- Security-conscious developers and sysadmins on Windows/Linux
- Students learning network security
- Portfolio demonstration of systems security programming

## Core Value Proposition
Transform from a simple Windows-only PyQt5 demo into a production-grade IDS that:
- Works cross-platform (Windows + Linux)
- Detects intrusions with both rule-based and ML approaches
- Provides a beautiful dark-themed GUI with real-time dashboards
- Exposes a REST API for integration
- Persists all data in SQLite
- Sends alerts via desktop, email, and SMS

## Tech Stack
- Python 3.10+, PyQt5, psutil, scikit-learn, Flask, SQLite
- Config: PyYAML + python-dotenv
- Notifications: plyer + smtplib + optional Twilio
- Exports: reportlab + csv

## Success Criteria (v1.0)
- [ ] App launches with `python main.py`
- [ ] All 7 GUI tabs functional
- [ ] Cross-platform firewall commands
- [ ] IDS auto-blocks on threshold breach
- [ ] SQLite DB auto-created
- [ ] Geolocation works for public IPs
- [ ] Settings persist to config.yaml
- [ ] System tray integration
- [ ] CSV export works
- [ ] REST API toggleable
- [ ] pytest suite passes
- [ ] Zero crashes from missing optional dependencies

## Out of Scope (v2+)
- Packet capture (requires raw sockets/scapy)
- Web-based UI (separate project)
- Mobile alerts beyond SMS
- Distributed/multi-host monitoring
- Paid threat intelligence feeds
