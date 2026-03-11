<div align="center">

# 🛡️ NetGuard IDS

**Industry-ready, cross-platform Firewall Control & Intrusion Detection System**

Built with Python + PyQt5 | Windows & Linux | ML-powered anomaly detection

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15+-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PyQt5/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)](https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System)

</div>

---

## ✨ Features

| Category | Features |
|---|---|
| 🔥 **Firewall** | Enable/Disable, block/unblock IPs, block ports, list rules (Windows + Linux) |
| 🕵️ **IDS** | Sliding window tracking, auto-block, port scan detection, SYN flood detection |
| 🤖 **ML** | Isolation Forest anomaly detection, model persistence, auto-retrain |
| 🌍 **Geolocation** | IP country/city/ISP lookup with SQLite caching |
| 🔔 **Alerts** | Desktop toast, HTML email, optional SMS (Twilio) |
| ⏰ **Scheduler** | Time-based firewall rules (cron-like) |
| 🗄️ **Storage** | Full SQLite persistence (blocks, alerts, connections, geo cache) |
| 🌐 **REST API** | Flask API on localhost:5000 with API key auth |
| 📊 **Dashboard** | Real-time connections table + live graph (psutil-powered) |
| 🗺️ **Threat Map** | Leaflet.js world map of blocked IP origins |
| 📤 **Export** | CSV and PDF reports |
| 🎨 **GUI** | Dark-themed PyQt5, 7 tabs, system tray, splash screen |

---

## 🏗️ Architecture

```
NetGuard IDS
├── main.py                 # Entry point
├── config.yaml             # All settings
├── .env.example            # Credentials template
├── core/                   # Business logic (no Qt)
│   ├── firewall.py         # Cross-platform firewall commands
│   ├── ids.py              # Intrusion detection engine
│   ├── anomaly.py          # ML anomaly detection
│   ├── geo.py              # IP geolocation
│   ├── blocklist.py        # SQLite persistence
│   ├── scheduler.py        # Time-based rules
│   └── notifier.py         # Alert notifications
├── ui/                     # PyQt5 GUI
│   ├── main_window.py      # Tabbed main window
│   ├── dashboard_tab.py    # Real-time traffic
│   ├── rules_tab.py        # Firewall rules
│   ├── alerts_tab.py       # Alert history
│   ├── blocklist_tab.py    # Block/unblock IPs
│   ├── scheduler_tab.py    # Time-based rules
│   ├── threat_map_tab.py   # World map
│   ├── settings_tab.py     # Configuration
│   └── tray.py             # System tray
├── api/
│   └── server.py           # Flask REST API
├── utils/
│   ├── logger.py           # Rotating file logger
│   ├── config_loader.py    # YAML config manager
│   ├── exporter.py         # CSV/PDF export
│   └── validators.py       # IP validation
└── tests/                  # pytest suite
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- **Windows:** Run as Administrator (for firewall commands)
- **Linux:** Run with sudo (for iptables commands)

### Installation

```bash
git clone https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System.git
cd Firewall-Configuration-and-Basic-Intrusion-Detection-System
pip install -r requirements.txt
python main.py
```

### Configuration

Copy `.env.example` to `.env` and fill in your email/SMS credentials:
```bash
cp .env.example .env
```

Edit `config.yaml` to tune IDS thresholds, enable notifications, etc.

```yaml
ids:
  alert_threshold: 10          # Connections before flagging an IP
  time_window_seconds: 60      # Sliding time window
  auto_block: true             # Auto-block flagged IPs

notifications:
  desktop: true
  email: false                 # Set to true + configure email section

api:
  enabled: false               # Set to true to enable REST API
  port: 5000
  api_key: "change-me"
```

---

## 🔌 REST API

When enabled in Settings, the API runs on `http://localhost:5000`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/status` | Firewall status + stats |
| GET | `/blocked` | List all blocked IPs |
| POST | `/block` | Block an IP `{"ip": "x.x.x.x", "reason": "..."}` |
| POST | `/unblock` | Unblock an IP `{"ip": "x.x.x.x"}` |
| GET | `/alerts` | Recent alerts |
| GET | `/connections` | Live connections snapshot |

All requests require header: `X-API-Key: <your_key>`

```bash
curl -H "X-API-Key: your-api-key" http://localhost:5000/status
```

---

## 📦 Optional Dependencies

| Package | Feature | Install |
|---|---|---|
| `plyer` | Desktop notifications | `pip install plyer` |
| `scikit-learn` | ML anomaly detection | `pip install scikit-learn` |
| `PyQtWebEngine` | Interactive threat map | `pip install PyQtWebEngine` |
| `flask` | REST API | `pip install flask` |
| `reportlab` | PDF export | `pip install reportlab` |
| `twilio` | SMS alerts | `pip install twilio` |
| `schedule` | Time-based rules | `pip install schedule` |

The app works without any of these — features degrade gracefully.

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## ⚙️ Development — GSD Workflow

This project uses the [GSD spec-driven development system](https://github.com/gsd-build/get-shit-done).

```bash
# Install GSD (requires Claude Code)
npx get-shit-done-cc@latest

# Then in Claude Code:
/gsd:progress          # See current state
/gsd:discuss-phase 1   # Start Phase 1
/gsd:plan-phase 1      # Research + create plans
/gsd:execute-phase 1   # Build Phase 1
/gsd:verify-work 1     # Verify it works
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push and open a Pull Request

---

## 🧑‍💻 Author

**Arman** — Computer Engineer • Reverse Engineering • Systems Research

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
