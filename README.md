<div align="center">

<img src="https://img.shields.io/badge/version-2.0.0-4fc3f7?style=flat-square" alt="version">

# 🛡️ NetGuard IDS

### Advanced Firewall & Intrusion Detection System

**Production-ready network security platform with ML-powered threat detection, real-time flow visualization, and a full REST API — for Windows and Linux.**

<br>

[![Python](https://img.shields.io/badge/Python-3.10%20|%203.11%20|%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6.5+-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PySide6/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-446%20passing-success?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge&logo=linux)](https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![Security](https://img.shields.io/badge/OWASP%20Audit-56%2F58-brightgreen?style=for-the-badge&logo=owasp)](docs/security-audit.md)

<br>

> **NetGuard IDS** is a fully-featured, production-grade network security tool that combines stateful firewall control with a multi-layer intrusion detection engine — including rule-based detection, ML anomaly scoring, and Deep Packet Inspection — all wrapped in a modern dark-themed GUI, a FastAPI REST backend, and a Typer CLI.

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#%EF%B8%8F-architecture)
- [Quick Start](#-quick-start)
- [Installation Options](#-installation-options)
- [Configuration](#%EF%B8%8F-configuration)
- [REST API](#-rest-api)
- [CLI Reference](#-cli-reference)
- [Detection Engine](#-detection-engine)
- [Performance](#-performance)
- [Docker](#-docker)
- [Testing](#-testing)
- [Security](#-security)
- [Contributing](#-contributing)

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

**🔥 Firewall Control**
- Enable / Disable system firewall
- Block & unblock IPs and port ranges
- Time-based scheduling (cron-like)
- Cross-platform: `netsh` on Windows, `iptables` on Linux
- YAML-defined rule files with hot-reload

**🕵️ Intrusion Detection (3 layers)**
- **Layer 1 — Threshold:** Sliding-window connection counting, port-scan detection, SYN flood heuristics
- **Layer 2 — Rules:** YAML-based declarative rules evaluated per connection event
- **Layer 3 — ML:** IsolationForest / ECOD anomaly scoring with auto-retrain

**🔬 Deep Packet Inspection**
- 7 signature categories: SQLi, directory traversal, CMDi, Log4Shell, shellcode, XSS, HTTP Basic Auth
- C2 beacon detection via inter-arrival time variance
- Suspicious-port scoring (Metasploit, Tor, IRC, etc.)
- Optional Scapy integration; falls back to metadata heuristics

</td>
<td width="50%" valign="top">

**🌐 Network Flow Graph**
- Real-time force-directed topology graph (pure QPainter — no external libs)
- Colour-coded threat levels (green → amber → red)
- Drag-to-reposition nodes, pause/resume simulation
- Auto-refresh from live engine data

**🤖 ML Advanced Features**
- A/B testing: run champion vs. challenger detector, promote winner automatically
- Active Learning Queue: label uncertain samples, feed back into re-training
- Config hot-reload: edit `config.yaml` or rule files — changes apply in ≤ 3s without restart

**🖥️ Three Frontends**
- **PySide6 GUI** — 10-tab dark-themed window + system tray
- **FastAPI REST** — OpenAPI docs, WebSocket streaming, API-key auth
- **Typer CLI** — Full engine control, rule management, live `watch` mode

</td>
</tr>
<tr>
<td valign="top">

**🔌 Plugin Architecture**
- `AbstractDetector` base class + `DetectorRegistry`
- Third-party detectors installable via `pip` (entry-points)
- Built-in Plugin Manager UI tab: enable/disable, discover, install from pip

**📊 Monitoring & Alerts**
- Real-time connections table + psutil-powered graph
- IP geolocation (country, city, ISP) with SQLite caching
- Desktop toast, HTML email, optional SMS (Twilio)
- Threat map tab with world-map visualization

</td>
<td valign="top">

**📦 Deployment**
- Docker: multi-stage build, non-root user, health checks
- Docker Compose: engine + API + config/rules hot-mount
- systemd service unit (Linux)
- Windows MSI installer (WiX v3 + PyInstaller)
- Linux `.deb` (Ubuntu/Debian) and `.rpm` (Fedora/RHEL)
- PyPI: `pip install netguard-ids`

**🔒 Security**
- OWASP Top 10 audit: 56/58 controls passed
- Parameterised SQLite queries only
- `yaml.safe_load` exclusively; no shell=True subprocess calls
- API keys via `secrets.compare_digest` (constant-time)
- PrivateTmp + ProtectSystem in systemd

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
netguard-ids/
├── main.py                      # GUI entry point
├── config.yaml                  # All settings (hot-reloaded)
├── rules/                       # YAML rule files (hot-reloaded)
│
├── core/                        # Business logic — zero Qt dependency
│   ├── engine.py                # NetGuardEngine — orchestrates all layers
│   ├── app_runner.py            # Thread manager (engine + API + watcher)
│   ├── event_bus.py             # Typed pub/sub event bus
│   ├── firewall.py              # Cross-platform firewall abstraction
│   ├── firewall_windows.py      # netsh backend
│   ├── firewall_linux.py        # iptables backend
│   ├── ids.py                   # IDS worker (threshold + port scan)
│   ├── rule_engine.py           # YAML rule evaluation
│   ├── detector_abc.py          # AbstractDetector + DetectorResult
│   ├── detector_registry.py     # Plugin registry + entry-point discovery
│   ├── dpi_plugin.py            # Deep Packet Inspection detector
│   ├── advanced_features.py     # ConfigWatcher, MLABTester, ActiveLearningQueue
│   ├── anomaly.py               # ML anomaly detector (IsolationForest/ECOD)
│   ├── alert_manager.py         # Alert persistence + querying
│   ├── blocklist.py             # SQLite block/alert store
│   ├── whitelist.py             # IP whitelist (checked before all detection)
│   ├── geo.py                   # IP geolocation + caching
│   ├── scheduler.py             # Time-based firewall rule scheduler
│   └── notifier.py              # Desktop / email / SMS alerts
│
├── ui/                          # PySide6 GUI (10 tabs)
│   ├── main_window.py           # Tabbed main window + engine wiring
│   ├── dashboard_tab.py         # Live connections + graph
│   ├── rules_tab.py             # Firewall rule management
│   ├── rule_editor_tab.py       # YAML rule editor
│   ├── alerts_tab.py            # Alert history + export
│   ├── blocklist_tab.py         # Block / unblock IPs
│   ├── scheduler_tab.py         # Time-based rules
│   ├── threat_map_tab.py        # World map of blocked IPs
│   ├── flow_visualization_tab.py# Force-directed network graph  ← NEW
│   ├── plugin_manager_tab.py    # Plugin enable/disable/install  ← NEW
│   ├── settings_tab.py          # Config editor
│   └── event_bus_bridge.py      # Thread-safe Qt signal bridge
│
├── api/                         # FastAPI REST + WebSocket
│   └── server.py                # OpenAPI, streaming, API-key auth
│
├── cli/                         # Typer CLI
│   └── main.py                  # Commands: engine, rules, blocklist, watch
│
├── utils/
│   ├── logger.py                # Rotating JSON logger
│   ├── config_loader.py         # YAML loader with schema validation
│   ├── exporter.py              # CSV / PDF export
│   └── validators.py            # IP / CIDR validation
│
├── tests/                       # 447 pytest tests (446 passing)
├── benchmarks/                  # Performance benchmark suite
├── packaging/
│   ├── windows/                 # WiX MSI + build_installer.ps1
│   └── linux/                   # .deb build script + .rpm spec
└── docs/                        # MkDocs Material documentation site
```

### Detection Pipeline

```
Network Connection Event
        │
        ▼
┌─────────────────┐     whitelist?   ┌─────────────┐
│  IP Whitelist   │ ──── YES ──────► │  Allow (log)│
└─────────────────┘                  └─────────────┘
        │ NO
        ▼
┌─────────────────┐
│  ThresholdIDS   │  (sliding window, port-scan, SYN flood)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Rule Engine   │  (YAML declarative rules, hot-reloaded)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ML Anomaly     │  (IsolationForest / ECOD — optional)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  DPI Plugin     │  (7 payload signatures, C2 beacon, port heuristics)
└────────┬────────┘
         │
         ▼
┌─────────────────┐   triggered?   ┌───────────────────────┐
│  DetectorResult │ ── YES ──────► │ Alert / Block / Notify │
└─────────────────┘                └───────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Windows | Linux |
|-------------|---------|-------|
| Python | 3.10+ (in PATH) | 3.10+ |
| Privilege | Run as **Administrator** | Run with **sudo** / `CAP_NET_ADMIN` |
| Firewall | Windows Firewall enabled | iptables installed |

### Install from PyPI *(recommended)*

```bash
# Core engine only (headless, no GUI)
pip install netguard-ids

# With GUI
pip install "netguard-ids[gui]"

# Everything
pip install "netguard-ids[gui,api,cli,ml]"
```

### Install from Source

```bash
git clone https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System.git
cd Firewall-Configuration-and-Basic-Intrusion-Detection-System

pip install -e ".[gui,api,cli,ml,dev]"

# Launch GUI
python main.py

# Or use CLI
netguard-cli engine start
```

---

## 📦 Installation Options

| Method | Command | Best for |
|--------|---------|----------|
| **PyPI** | `pip install "netguard-ids[gui]"` | Quick install, any OS |
| **Source** | `git clone` + `pip install -e .` | Development |
| **Docker** | `docker compose up` | Headless / server deploy |
| **Windows MSI** | `packaging/windows/build_installer.ps1` | End-user Windows install |
| **Linux .deb** | `packaging/linux/build_deb.sh` | Ubuntu / Debian |
| **Linux .rpm** | `packaging/linux/netguard-ids.spec` | Fedora / RHEL |

---

## ⚙️ Configuration

Copy `.env.example` → `.env` and set any secrets:

```bash
cp .env.example .env
```

Edit `config.yaml` — changes are **hot-reloaded** within 3 seconds (no restart needed):

```yaml
ids:
  alert_threshold: 10          # Connections/window before flagging
  time_window_seconds: 60      # Sliding window duration
  auto_block: false            # Auto-block flagged IPs (off by default)
  port_scan_threshold: 15      # Distinct ports to trigger scan alert

ml:
  enabled: true
  model: isolation_forest      # or: ecod
  contamination: 0.01          # Expected anomaly fraction

dpi:
  enabled: true                # Deep Packet Inspection
  c2_variance_threshold: 200   # ms — lower = stricter beacon detection

api:
  enabled: false               # Enable REST API
  port: 8000
  api_key: ""                  # Auto-generated on first start if empty

notifications:
  desktop: true
  email:
    enabled: false
    smtp_host: smtp.gmail.com
    smtp_port: 587
```

---

## 🔌 REST API

Start the API via Settings tab or CLI:

```bash
netguard-cli api start --port 8000
```

Interactive docs at `http://localhost:8000/docs` (Swagger UI).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/status` | Engine status + active connections |
| `GET` | `/blocked` | All blocked IPs |
| `POST` | `/block` | Block an IP `{"ip": "1.2.3.4", "reason": "..."}` |
| `POST` | `/unblock` | Unblock an IP |
| `GET` | `/alerts` | Recent alerts (filterable) |
| `GET` | `/connections` | Live connection snapshot |
| `GET` | `/detectors` | Registered plugins + status |
| `WS` | `/ws/stream` | WebSocket — real-time event stream |

All endpoints require: `X-API-Key: <your_key>`

```bash
# Example
curl -H "X-API-Key: your-key" http://localhost:8000/status | jq
```

---

## 💻 CLI Reference

```bash
netguard-cli --help

# Engine
netguard-cli engine start          # Start the detection engine (headless)
netguard-cli engine stop
netguard-cli engine status

# Rules
netguard-cli rules list
netguard-cli rules add --ip 1.2.3.4 --action block --name "bad actor"
netguard-cli rules remove --id 42

# Blocklist
netguard-cli blocklist show
netguard-cli blocklist block 1.2.3.4
netguard-cli blocklist unblock 1.2.3.4

# Live monitoring
netguard-cli watch                 # Tail live alerts (rich table)
netguard-cli watch --filter alert  # Filter by severity
```

---

## 🧠 Detection Engine

### Plugin System

Write a custom detector in 10 lines:

```python
from core.detector_abc import AbstractDetector, DetectorResult

class MyDetector(AbstractDetector):
    name = "my_detector"
    version = "1.0.0"

    def analyze(self, ip, events, *, context=None):
        score = len(events) / 100.0
        return DetectorResult(
            triggered=score > 0.5,
            score=score,
            reason="too many connections",
            action="alert",
        )
```

Register via `pyproject.toml` entry-point:

```toml
[project.entry-points."netguard.detectors"]
my_detector = "my_package.detector:MyDetector"
```

Then install your package — NetGuard auto-discovers it at startup.

### ML A/B Testing

```python
from core.advanced_features import MLABTester

tester = MLABTester(champion_detector, challenger_detector, min_samples=500)
result = tester.run(ip, events)      # Routes to both, returns champion result
summary = tester.summary()           # agreement_rate, win counts
winner  = tester.choose_champion()   # Promote winner after enough samples
```

### Config Hot-Reload

```python
from core.advanced_features import ConfigWatcher

watcher = ConfigWatcher(
    paths=["config.yaml", "rules/"],
    on_change=lambda changed: engine.reload_rules(),
    poll_interval=3.0,
)
watcher.start()
```

---

## ⚡ Performance

Benchmarked on Windows 10, Python 3.10, AMD64 (7/7 passing):

| Component | Mean Latency | p99 Latency | Throughput |
|-----------|-------------|-------------|-----------|
| Threshold Detector | 0.03 ms | < 1 ms | > 10,000 /s |
| Rule Engine | 0.002 ms | < 5 ms | > 50,000 /s |
| DPI Detector | 0.07 ms | < 3 ms | > 5,000 /s |
| Event Bus | 0.004 ms | < 2 ms | > 50,000 /s |
| Config Loader | 1.3 ms | < 50 ms | > 700 /s |
| ML A/B Tester | 0.04 ms | < 10 ms | > 20,000 /s |

Run benchmarks yourself:

```bash
python benchmarks/benchmark_suite.py
# Results saved to benchmarks/results/benchmark_<timestamp>.json
```

---

## 🐳 Docker

```bash
# Start everything (engine + API)
docker compose up -d

# Engine only (headless)
docker run --rm --cap-add NET_ADMIN \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  ghcr.io/armanrbu/netguard-ids:latest \
  netguard-cli engine start --headless
```

`docker-compose.yml` mounts `config.yaml` and `rules/` live — edit them and changes apply in ≤ 3s via hot-reload.

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=. --cov-report=html

# Run benchmarks
python benchmarks/benchmark_suite.py

# Specific module
pytest tests/test_advanced_features.py -v
```

**Test stats:** 447 tests · 446 passing · 1 known Windows temp-path flake in `test_ml_detector.py`

---

## 🔒 Security

NetGuard IDS has been audited against the **OWASP Top 10 (2021)**:

| Category | Status |
|----------|--------|
| A01 Broken Access Control | ✅ Passed (API key auth, non-root Docker) |
| A02 Cryptographic Failures | ✅ Passed (no hardcoded secrets, TLS-ready) |
| A03 Injection | ✅ Passed (parameterised SQL, `safe_load`, no `shell=True`) |
| A04 Insecure Design | ✅ Passed (whitelist-first, auto-block off by default) |
| A05 Security Misconfiguration | ✅ Passed (secure defaults, minimal Docker EXPOSE) |
| A06 Vulnerable Components | ✅ Passed (Dependabot + pip-audit in CI) |
| A07 Auth Failures | ✅ Passed (`secrets.compare_digest`, auto-generated key) |
| A08 Software Integrity | ✅ Passed (OIDC PyPI publish, entry-point validation) |
| A09 Logging Failures | ✅ Passed (structured JSON logs, alert persistence) |
| A10 SSRF | ✅ Passed (no outbound requests to user-supplied URLs) |

**Result: 56/58 controls passed.** Full audit: [`docs/security-audit.md`](docs/security-audit.md)

To report a vulnerability: see [`SECURITY.md`](SECURITY.md).

---

## 🤝 Contributing

Contributions welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first.

```bash
# Setup dev environment
pip install -e ".[dev]"

# Run linter
ruff check .

# Run type-checker
mypy core/ ui/ api/ cli/

# Run tests
pytest tests/ -q
```

See [`CHANGELOG.md`](CHANGELOG.md) for version history.

---

## 👤 Author

**Arman** — Computer Engineer · Security Research · Systems Programming

[![GitHub](https://img.shields.io/badge/GitHub-Armanrbu-181717?style=flat-square&logo=github)](https://github.com/Armanrbu)

---

## 📄 License

[MIT License](LICENSE) — free for personal and commercial use.

---

<div align="center">

**If NetGuard IDS helped you, please ⭐ star the repo!**

*Built with ❤️ and Python*

</div>
