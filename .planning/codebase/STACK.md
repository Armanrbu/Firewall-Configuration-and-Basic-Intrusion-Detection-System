# Technology Stack

## Language & Runtime
- **Python 3.10+** — primary language, type hints used throughout
- Entry point: `main.py` → `main()` function

## GUI Framework
- **PyQt5 >= 5.15** — desktop GUI with dark-themed tabbed interface
- **PyQtWebEngine >= 5.15** — used for the Threat Map tab (renders HTML/JS map in QWebEngineView)

## Core Dependencies (required)
| Package | Version | Purpose |
|---------|---------|---------|
| PyQt5 | >= 5.15 | Desktop GUI |
| psutil | >= 5.9 | Live network connection monitoring |
| requests | >= 2.28 | HTTP calls (geo-IP lookups) |
| PyYAML | >= 6.0 | Configuration file parsing |
| python-dotenv | >= 1.0 | `.env` file support for secrets |

## Optional Dependencies (fail-safe imports)
| Package | Version | Purpose | Fallback |
|---------|---------|---------|----------|
| scikit-learn | >= 1.3 | Isolation Forest anomaly detection | Threshold-based detection |
| joblib | >= 1.3 | ML model persistence | No model save/load |
| schedule | >= 1.2 | Time-based firewall rule scheduling | Scheduling disabled |
| plyer | >= 2.1 | Desktop notifications | Notifications skipped |
| flask | >= 3.0 | REST API server | API disabled |
| reportlab | >= 4.0 | PDF report generation | PDF export disabled |
| matplotlib | >= 3.7 | Chart/graph rendering | Charts unavailable |
| numpy | >= 1.24 | Numerical operations for ML | ML disabled |
| twilio | (optional) | SMS notifications | SMS disabled |

## Data Storage
- **SQLite** via `sqlite3` (stdlib) — auto-created at `firewall_ids.db`
- WAL journal mode enabled
- Tables: `blocked_ips`, `alerts`, `connection_log`, `geo_cache`

## Configuration
- `config.yaml` — application settings (YAML format)
- `.env` — credentials and secrets (optional, loaded via python-dotenv)
- `whitelist.txt` — trusted IPs file (one per line)

## Packaging
- `setup.py` — setuptools-based, supports `pip install -e .`
- `requirements.txt` — full dependency list
- `extras_require["full"]` — optional heavy dependencies separated from core

## System Commands (cross-platform)
- **Windows:** `netsh advfirewall`, PowerShell `New-NetFirewallRule`/`Remove-NetFirewallRule`
- **Linux:** `iptables` commands
- OS detection via `platform.system()`
