# NetGuard IDS — Recommended Tech Stack

## Core Runtime
- **Python 3.10+** — required minimum for type union syntax and modern stdlib features
- **PyQt5 5.15+** — GUI framework; use `PyQt5.QtWidgets`, `PyQt5.QtCore`, `PyQt5.QtGui`

## System & Network
- **psutil 5.9+** — cross-platform process/network connection enumeration (`psutil.net_connections()`)
- **subprocess** (built-in) — shell commands for netsh / iptables; always use `capture_output=True, text=True`
- **platform** (built-in) — OS detection via `platform.system()` → `"Windows"` or `"Linux"`
- **socket** (built-in) — IP address parsing and validation helpers

## Machine Learning
- **scikit-learn 1.3+** — `IsolationForest` for unsupervised anomaly detection
- **joblib 1.3+** — model serialization (`joblib.dump` / `joblib.load`) for persisting trained model
- **numpy 1.24+** — feature array construction for ML input

## GUI Extras
- **matplotlib 3.7+** OR **pyqtgraph 0.13+** — embedded live connection count graph in Dashboard tab
  - Prefer pyqtgraph for real-time performance; matplotlib for publication-quality static charts
- **PyQtWebEngine 5.15+** — `QWebEngineView` for embedding Leaflet.js threat map; install separately with `pip install PyQtWebEngine`

## HTTP & Geolocation
- **requests 2.28+** — HTTP client for ip-api.com geolocation API calls

## Storage
- **sqlite3** (built-in) — no ORM; use direct SQL with parameterized queries
  - Tables: `blocked_ips`, `alerts`, `connection_log`, `geo_cache`

## Configuration
- **pyyaml 6.0+** — parse and write `config.yaml`
- **python-dotenv 1.0+** — load `.env` file for credentials at startup

## REST API (optional)
- **flask 3.0+** — lightweight REST API server on localhost:5000; run in daemon thread

## Notifications
- **plyer 2.1+** — cross-platform desktop toast notifications
- **smtplib** (built-in) — email alerts via SMTP; wrap in `ssl.create_default_context()`
- **twilio** (optional) — SMS alerts; guard import with `try/except ImportError`

## Export
- **reportlab 4.0+** — PDF report generation (`SimpleDocTemplate`, `Table`, `Paragraph`)
- **csv** (built-in) — CSV export for all table data

## Scheduling
- **schedule 1.2+** — simple time-based job scheduler; run in dedicated background thread

## Testing
- **pytest 7.4+** — test runner
- **pytest-mock** — for mocking subprocess calls in firewall tests
- Use in-memory SQLite (`:memory:`) for all DB-touching tests

## Full pip install command
```bash
pip install PyQt5>=5.15 psutil>=5.9 scikit-learn>=1.3 joblib>=1.3 numpy>=1.24 \
            matplotlib>=3.7 requests>=2.28 pyyaml>=6.0 python-dotenv>=1.0 \
            flask>=3.0 plyer>=2.1 reportlab>=4.0 schedule>=1.2 \
            pytest>=7.4 pytest-mock
# Optional extras:
pip install PyQtWebEngine pyqtgraph twilio
```
