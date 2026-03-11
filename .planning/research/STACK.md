# Research: Technology Stack

## Packet Capture & Analysis
- **Scapy v2.7.0+** — 28+ protocol layers, TUN/TAP, Python-native, cross-platform
- **dpkt** — lighter weight for basic TCP/IP parsing
- **pyshark** — TShark wrapper, requires Wireshark 4.6.4+
- **Recommendation:** Scapy for DPI plugin; psutil stays for flow-based default

## Async Framework & API
- **FastAPI 0.135.0+** — microsecond latencies, Starlette+Pydantic, auto OpenAPI docs
- **Quart 0.20.1+** — Flask-compatible async alternative (drop-in if needed)
- **Recommendation:** FastAPI, used by Microsoft/Uber/Netflix/Cisco

## ML Anomaly Detection
- **PyOD v2.0.7+** — 45+ algorithms, LLM-powered model selection
  - ECOD — parameter-free, robust, ~10µs per prediction
  - LOF — density-based, good for network traffic
  - Deep Isolation Forest — better than classic IForest, ~500µs
  - LODA — O(1) prediction, ideal for real-time
- **Isolation Forest** — benchmark baseline, ~100µs per prediction
- **Recommendation:** Keep IForest as default; add ECOD + ensemble via plugin system

## Message Broker
| Broker | Use Case | Notes |
|--------|----------|-------|
| ZeroMQ | Low-latency embedded | Sub-microsecond, multi-transport |
| Redis v8 | Caching + streams | 18 data structures, cluster support |
| RabbitMQ 4.2.4 | Enterprise reliability | AMQP 1.0, MQTT 5.0 |
- **Recommendation:** Redis v8 — caching + streams + pub/sub in one

## Time-Series / Database
| DB | When | Notes |
|----|------|-------|
| SQLite + WAL | Dev/small deploy | Zero-config, embedded |
| TimescaleDB | 10K+ events/sec | Requires PostgreSQL |
| InfluxDB v3 | Pure metrics | External service |
- **Recommendation:** SQLite+WAL default → optional TimescaleDB/Postgres for scale

## Plugin System
- **entry_points (Python 3.10+)** — `importlib.metadata.entry_points()`
- Standard pattern used by pytest, flake8, Django
- Minimal overhead, pip-installable modules
- **Recommendation:** entry_points via pyproject.toml

## GUI Framework
- **PySide6 (Qt 6.10+)** — LGPL v3, Qt Company maintained, Qt6 backend
- **PyQt6** — identical API, different licensing (GPL/commercial)
- **Recommendation:** PySide6 for OSS licensing

## CLI Framework
- **Typer v0.24.1+** — type hints → CLI args, auto-completion, built on Click
- **Recommendation:** Typer for management commands

## Version Summary
| Component | Package | Version |
|-----------|---------|---------|
| Packet Capture | Scapy | 2.7.0+ |
| ML Anomaly | PyOD (ECOD) | 2.0.7+ |
| Events | Redis | 8.0+ |
| API | FastAPI | 0.135+ |
| Plugins | entry_points | stdlib |
| GUI | PySide6 | 6.10+ |
| CLI | Typer | 0.24+ |
| ORM | SQLAlchemy | 2.0+ |

---
*Research date: 2026-03-11*
