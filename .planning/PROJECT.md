# NetGuard IDS

## What This Is

NetGuard IDS is a production-grade, open-source Intrusion Detection System and Firewall Control platform for Windows and Linux. It provides real-time network monitoring, ML-powered anomaly detection, optional deep packet inspection, and a modern desktop GUI — designed as the accessible alternative to Snort/Suricata for sysadmins, security teams, home power users, and developers who want an extensible IDS framework without CLI/config-file complexity.

## Core Value

**One-click network security with ML-powered detection that anyone can install, configure via GUI, and extend via plugins — cross-platform, no Ph.D. required.**

## Requirements

### Validated

<!-- Shipped and confirmed valuable — existing capabilities. -->

- ✓ Cross-platform firewall control (Windows netsh, Linux iptables) — existing
- ✓ Real-time connection monitoring via psutil with live dashboard — existing
- ✓ IDS engine with threshold-based detection (repeated connections, port scans) — existing
- ✓ ML anomaly detection via Isolation Forest with auto-retrain — existing
- ✓ SQLite persistent storage (blocked IPs, alerts, connection log, geo cache) — existing
- ✓ IP geolocation via ip-api.com with caching — existing
- ✓ Dark-themed PyQt5 GUI with 7 tabbed interface — existing
- ✓ Desktop/email/SMS notification system — existing
- ✓ Time-based firewall rule scheduling — existing
- ✓ CSV/TXT/PDF export capabilities — existing
- ✓ REST API with API key authentication — existing
- ✓ IP whitelist management — existing
- ✓ System tray integration with balloon alerts — existing
- ✓ YAML-based configuration — existing
- ✓ pytest test suite with mocked subprocess — existing

### Active

<!-- v2 milestone: production-grade, scalable, extensible. -->

- [ ] Microkernel architecture (engine as service, GUI/API/CLI as separate frontends)
- [ ] Plugin system with pip-installable detection modules
- [ ] Deep packet inspection via Scapy/pyshark (optional plugin)
- [ ] YAML-based rule engine with Python escape hatch
- [ ] PySide6 (Qt6) modern GUI upgrade
- [ ] FastAPI async REST API with auto-generated OpenAPI docs
- [ ] Optional PostgreSQL/TimescaleDB backend for scale
- [ ] Redis/ZMQ inter-component messaging
- [ ] Headless mode (engine runs as system service without GUI)
- [ ] Docker + Docker Compose deployment
- [ ] CI/CD pipeline (GitHub Actions: pytest, linting, builds)
- [ ] Comprehensive test coverage (GUI, API, integration tests)
- [ ] Thread safety and graceful shutdown
- [ ] Database migration system
- [ ] Connection log retention/pruning
- [ ] Rich CLI frontend (click + rich)
- [ ] Proper packaging (pip, installers, Docker images)
- [ ] Documentation site, contribution guide, security policy
- [ ] Signature-based detection alongside ML behavioral detection
- [ ] Network flow visualization and analytics dashboard

### Out of Scope

- Commercial/paid features — this is fully open source (MIT)
- Cloud-hosted SaaS version — this is a self-hosted tool
- Full network TAP/SPAN integration — focus on host-based monitoring
- Custom hardware appliance support — software-only
- Windows kernel-level packet capture (WinDivert/Npcap kernel) — userspace only
- Mobile app — desktop and headless server only

## Context

**Competitive landscape:** Snort, Suricata, OSSEC, Wazuh dominate. All are CLI-first, complex to configure, Linux-focused. NetGuard's edge is GUI-first simplicity, cross-platform, ML-native detection, and a plugin ecosystem.

**Existing codebase:** ~2500 lines of Python across 20 modules. Working prototype with functional GUI, IDS engine, firewall control, and basic ML. Needs architectural refactoring for production use — see `.planning/codebase/CONCERNS.md` for 20 identified issues.

**Tech evolution:**
- PyQt5 → PySide6 (Qt6, better OSS license, actively maintained)
- Flask → FastAPI (async, OpenAPI, modern standard)
- Monolith → microkernel (engine ↔ frontends via messaging)
- SQLite-only → SQLite + optional PostgreSQL/TimescaleDB
- Manual deploy → Docker + CI/CD

**Target users:**
1. Sysadmins managing small business networks
2. Home power users wanting traffic visibility
3. Security teams in SMBs (affordable IDS alternative)
4. Developers extending the framework via plugins

## Constraints

- **Language**: Python 3.10+ — maintain ecosystem compatibility, largest security library support
- **License**: MIT — maximum adoption potential
- **Cross-platform**: Must work on Windows 10+ and major Linux distros
- **Backwards compatibility**: Existing config.yaml and firewall_ids.db must migrate cleanly
- **Optional dependencies**: Heavy packages (Scapy, PostgreSQL drivers, ML) must be optional — core runs minimal
- **Admin privileges**: Firewall/packet capture requires root/admin — document clearly, fail gracefully without

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| SQLite for persistence | Zero-config, embedded, sufficient for single-node | ✓ Good |
| psutil for connection monitoring | Cross-platform, no raw sockets needed | ✓ Good |
| Isolation Forest for anomaly detection | Good unsupervised baseline; fails safely to threshold mode | ✓ Good |
| ip-api.com for geolocation | Free, no API key, cached in SQLite | ✓ Good |
| Microkernel over monolith | Engine must run headless on servers; GUI is optional frontend | — Pending |
| PySide6 over PyQt5 | True LGPL license, Qt6, actively maintained, better for OSS | — Pending |
| FastAPI over Flask | Async, auto OpenAPI docs, modern Python API standard | — Pending |
| YAML rules over custom DSL | Lowest barrier for contributors; Python escape hatch for power users | — Pending |
| Flow-based + optional DPI | Flow-based default (lighter, privacy-friendly); DPI plugin for deep inspection | — Pending |
| Redis/ZMQ for messaging | Decouples engine from frontends; enables distributed deployment | — Pending |
| SQLite default + optional Postgres | Zero-config default; scale path for enterprise | — Pending |
| Plugin system via entry points | pip-installable modules; standard Python packaging pattern | — Pending |

---
*Last updated: 2026-03-11 after v2 initialization*
