# 🛡️ NetGuard IDS

**Professional, cross-platform Firewall Control & Intrusion Detection System**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green.svg)](https://pypi.org/project/PyQt5/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()

```
███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

---

## ✨ Features

| Category | Feature |
|---|---|
| 🔥 **Firewall** | Cross-platform (Windows `netsh` + Linux `iptables`), enable/disable, block IP/port |
| 🕵️ **IDS Engine** | Sliding-window connection tracking, port-scan detection, SYN-flood heuristics |
| 🤖 **ML Detection** | Isolation Forest anomaly detection (scikit-learn), auto-retrain, model persistence |
| 🌍 **Geolocation** | ip-api.com lookup with SQLite caching, country flags, lat/lon for map |
| 💾 **Storage** | SQLite DB — blocked IPs, alerts, connection log, geo cache |
| 📬 **Notifications** | Desktop (plyer), Email SMTP, optional Twilio SMS — all fail-safe |
| ⏰ **Scheduler** | Time-based rules ("Block port 22 from 22:00–06:00 daily") via `schedule` |
| 🗺️ **Threat Map** | Leaflet.js world map embedded via QWebEngineView |
| 🔌 **REST API** | Flask API on localhost:5000 — block/unblock/status/alerts endpoints |
| 📤 **Export** | CSV + formatted PDF reports (reportlab) for alerts and blocklist |
| 🔔 **System Tray** | Minimize-to-tray, balloon alerts, tray menu for quick actions |

---

## 🏗️ Architecture

```
├── main.py                  # Entry point
├── requirements.txt
├── config.yaml              # User-configurable settings
├── .env.example             # Email/Twilio credentials template
├── core/
│   ├── firewall.py          # Cross-platform firewall backend
│   ├── ids.py               # IDS engine + Qt worker
│   ├── anomaly.py           # ML anomaly detection (Isolation Forest)
│   ├── geo.py               # IP geolocation (ip-api.com)
│   ├── blocklist.py         # SQLite storage layer
│   ├── whitelist.py         # Whitelist management
│   ├── scheduler.py         # Time-based rule scheduler
│   └── notifier.py          # Email + desktop notifications
├── ui/
│   ├── main_window.py       # Main window (tabs, status bar, tray)
│   ├── dashboard_tab.py     # Real-time traffic dashboard (psutil)
│   ├── rules_tab.py         # Firewall rules management
│   ├── alerts_tab.py        # Alert history + geo info
│   ├── blocklist_tab.py     # Block/Unblock IPs
│   ├── settings_tab.py      # Config editor
│   ├── scheduler_tab.py     # Scheduler UI
│   ├── threat_map_tab.py    # Leaflet.js threat map
│   ├── tray.py              # System tray icon
│   └── theme.py             # Dark/Light QSS stylesheets
├── utils/
│   ├── logger.py            # Rotating file logger
│   ├── config_loader.py     # YAML config management
│   ├── exporter.py          # CSV + PDF export
│   └── validators.py        # IP/port validation helpers
├── api/
│   └── server.py            # Flask REST API (optional)
├── tests/
│   ├── test_firewall.py
│   ├── test_ids.py
│   ├── test_blocklist.py
│   └── test_validators.py
└── assets/
    └── icon.png
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- Windows (with Administrator rights) **or** Linux (with root/sudo for iptables)

### Quick Start

```bash
# Clone the repo
git clone https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System.git
cd Firewall-Configuration-and-Basic-Intrusion-Detection-System

# Install dependencies
pip install -r requirements.txt

# (Optional) Copy and edit the environment template
cp .env.example .env

# Run the application
python main.py
```

> **Windows Users:** Run your terminal as Administrator for firewall control.
> **Linux Users:** Run with `sudo python main.py` for iptables access.

---

## ⚙️ Configuration

Edit `config.yaml` or use the **Settings tab** in the GUI:

```yaml
ids:
  alert_threshold: 10          # Connections before flagging an IP
  time_window_seconds: 60      # Sliding time window
  auto_block: true             # Auto-block flagged IPs

firewall:
  log_path: "C:\\Temp\\pfirewall.log"   # Windows firewall log

notifications:
  desktop: true
  email: false                 # Set to true + configure email section

api:
  enabled: false               # Set to true to enable REST API
  port: 5000
  api_key: "change-me"
```

### Email Alerts

```yaml
notifications:
  email: true
email:
  smtp_host: "smtp.gmail.com"
  smtp_port: 465
  username: "you@gmail.com"
  password: "your-app-password"
  recipient: "alert@example.com"
```

---

## 🌐 REST API

Enable in `config.yaml` (`api.enabled: true`) then use:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/status` | Firewall status + stats |
| GET | `/blocked` | List blocked IPs |
| POST | `/block` | Block an IP `{"ip":"x.x.x.x","reason":"..."}` |
| POST | `/unblock` | Unblock an IP `{"ip":"x.x.x.x"}` |
| GET | `/alerts` | Recent alerts |
| GET | `/connections` | Live connections snapshot |

Authentication: `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:5000/status
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
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

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push and open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
