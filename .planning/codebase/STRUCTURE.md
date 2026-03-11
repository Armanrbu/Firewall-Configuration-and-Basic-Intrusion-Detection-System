# Directory Structure

```
.
├── main.py                    # Entry point — bootstrap, load config, launch GUI
├── config.yaml                # Application configuration (YAML)
├── requirements.txt           # Full pip dependencies
├── setup.py                   # setuptools packaging
├── CLAUDE.md                  # Project coding conventions for AI agents
├── README.md                  # Project documentation
├── LICENSE                    # MIT license
│
├── core/                      # Business logic layer
│   ├── __init__.py
│   ├── anomaly.py             # ML anomaly detection (Isolation Forest)
│   ├── blocklist.py           # SQLite storage layer (blocked IPs, alerts, connections, geo cache)
│   ├── firewall.py            # Cross-platform firewall commands (netsh/iptables)
│   ├── geo.py                 # IP geolocation via ip-api.com with DB cache
│   ├── ids.py                 # Intrusion detection engine + Qt worker
│   ├── notifier.py            # Desktop/email/SMS notification dispatcher
│   ├── scheduler.py           # Time-based firewall rule scheduler
│   └── whitelist.py           # Trusted IP whitelist management
│
├── ui/                        # PyQt5 GUI layer
│   ├── __init__.py
│   ├── main_window.py         # Main QMainWindow — tabs, status bar, IDS, API, tray
│   ├── dashboard_tab.py       # Real-time connection monitoring + stat cards
│   ├── rules_tab.py           # Firewall rule management (IP/port block/unblock)
│   ├── alerts_tab.py          # Alert log with geo-IP, resolve, export
│   ├── blocklist_tab.py       # Blocked IPs management, import/export
│   ├── scheduler_tab.py       # Time-based rule scheduling UI
│   ├── settings_tab.py        # Configuration editor (IDS, notifications, API, etc.)
│   ├── threat_map_tab.py      # Geographic threat visualization (WebEngine map)
│   ├── theme.py               # Dark theme QSS stylesheet
│   └── tray.py                # System tray icon + context menu
│
├── utils/                     # Shared utilities
│   ├── __init__.py
│   ├── config_loader.py       # YAML config with defaults + merge
│   ├── exporter.py            # CSV, TXT, PDF export
│   ├── logger.py              # Rotating file + console logging setup
│   └── validators.py          # IP, port, CIDR validation
│
├── api/                       # Optional REST API
│   ├── __init__.py
│   └── server.py              # Flask app with API key auth
│
├── tests/                     # pytest test suite
│   ├── conftest.py            # Path setup fixture
│   ├── test_blocklist.py      # SQLite layer tests (temp DB)
│   ├── test_firewall.py       # Firewall tests (mocked subprocess)
│   ├── test_ids.py            # IDS engine tests (threshold, port scan)
│   └── test_validators.py     # Validation helper tests
│
└── assets/                    # Icons and static assets
```

## Key Locations
- **Config:** `config.yaml` (runtime), `CLAUDE.md` (coding conventions)
- **Database:** `firewall_ids.db` (auto-created at project root)
- **Logs:** `netguard.log` (rotating, 10MB max, 5 backups)
- **ML Model:** `anomaly_model.pkl` (auto-created when trained)
- **Whitelist:** `whitelist.txt` (one IP per line)
