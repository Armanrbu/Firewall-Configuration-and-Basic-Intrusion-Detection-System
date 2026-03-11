# Research Summary

## Key Findings

### Stack Decisions (Confirmed)
| Component | Choice | Confidence |
|-----------|--------|------------|
| GUI | PySide6 6.10+ | High — LGPL, Qt6, actively maintained |
| API | FastAPI 0.135+ | High — async, OpenAPI, industry standard |
| ML | PyOD 2.0.7+ (ECOD default) | High — 45 algorithms, extensible |
| Messaging | Redis v8 Streams | High — caching + events in one |
| DB Default | SQLite + WAL | High — zero-config, embedded |
| DB Scale | PostgreSQL + TimescaleDB | Medium — only for 10K+ events/sec |
| Packets | Scapy 2.7.0+ | High — cross-platform, protocol-rich |
| Plugins | entry_points (stdlib) | High — standard, zero-overhead |
| CLI | Typer 0.24+ | High — modern, auto-complete |
| ORM | SQLAlchemy 2.0+ | High — backend-agnostic |

### Architecture Decisions (Confirmed)
- Microkernel: engine as daemon, frontends as consumers
- Event-driven: queues between layers, no polling
- Plugin system: ABC interface + entry_points registration
- Cross-platform: strategy pattern for firewall abstraction
- Database: repository pattern + configurable backend

### Critical Risks Identified
1. **Command injection** — firewall commands must use subprocess list args (MUST FIX in existing code)
2. **Model drift** — need automated retraining pipeline
3. **GIL limitations** — multiprocessing required for packet capture scaling
4. **Cross-platform parity** — need CI testing on both Windows + Linux

### Scope Validation
- **In scope:** Host-based IDS, single-machine, ML-first, GUI+API+CLI, plugins
- **Out of scope:** Clustering, DPI-by-default, encrypted traffic ML, cloud SaaS
- **Performance target:** 10-50k pps (Python), document clearly vs. C-based tools

### Competitive Position
- NetGuard fills gap between "complex enterprise IDS" (Snort/Suricata/Wazuh) and "no IDS at all"
- ML-native + GUI-first + plugin ecosystem = unique combination
- Python limits throughput but enables rapid development + extensibility

## Impact on Roadmap
1. **Phase 1:** Foundation cleanup — fix security issues, threading, DB migrations
2. **Phase 2:** Architecture refactor — microkernel, engine/frontend split
3. **Phase 3:** New stack — PySide6, FastAPI, Redis
4. **Phase 4:** Features — rule engine, plugin system, YAML rules
5. **Phase 5:** ML upgrade — PyOD, retraining, ensemble
6. **Phase 6:** Packaging — Docker, CI/CD, docs, installers
7. **Phase 7:** Polish — performance tuning, UX, testing, security audit

---
*Research date: 2026-03-11*
