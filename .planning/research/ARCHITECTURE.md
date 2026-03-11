# NetGuard IDS — Layered Architecture

## Entry Point
`main.py` orchestrates startup:
1. Add project root to `sys.path`
2. Load `.env` (python-dotenv, fail-safe)
3. Load `config.yaml` via `utils/config_loader.py`
4. Set up rotating log via `utils/logger.py`
5. Initialize SQLite DB via `core/blocklist.get_db()`
6. Start scheduler background thread via `core/scheduler.get_scheduler().start()`
7. Create `QApplication`, show splash screen
8. Instantiate `ui/main_window.MainWindow(config=config)`
9. Enter Qt event loop (`app.exec_()`)

## Layer Overview

```
┌─────────────────────────────────────────┐
│                main.py                  │  Entry point
├─────────────────────────────────────────┤
│              ui/ (PyQt5)                │  Presentation layer
│  MainWindow → [7 tab widgets] + Tray    │
├─────────────────────────────────────────┤
│              core/ (Pure Python)        │  Business logic layer
│  firewall · ids · anomaly · geo         │
│  blocklist · scheduler · notifier       │
├─────────────────────────────────────────┤
│              utils/ (Shared helpers)    │  Cross-cutting concerns
│  logger · config_loader · exporter      │
│  validators                             │
├─────────────────────────────────────────┤
│              api/ (Optional Flask)      │  REST interface layer
│  server.py — runs in daemon QThread     │
└─────────────────────────────────────────┘
```

## Core Layer (`core/`) — No Qt Imports Allowed
Each module is a pure Python class/singleton with no PyQt5 dependency.

| Module | Responsibility |
|---|---|
| `firewall.py` | Cross-platform firewall commands; detects OS at import, exposes `enable()`, `disable()`, `block_ip()`, `unblock_ip()`, `block_port()`, `list_rules()` |
| `blocklist.py` | SQLite CRUD singleton; `get_db()` factory creates tables on first call; thread-safe with `threading.Lock` |
| `ids.py` | `IDSEngine(QObject)` — extends QObject to emit Qt signals; uses psutil polling in `QThread`; sliding window stored in `collections.defaultdict(deque)` |
| `anomaly.py` | `AnomalyDetector` wrapping `IsolationForest`; loads/saves model at `anomaly_model.pkl`; handles cold start with minimum 50 samples |
| `geo.py` | `GeoLocator` singleton; checks geo_cache table first, falls back to ip-api.com; private RFC-1918 ranges return "Local Network" immediately |
| `scheduler.py` | `RuleScheduler` running `schedule` library in daemon thread; persists rules to SQLite |
| `notifier.py` | `Notifier` — calls plyer, smtplib, optional Twilio; rate-limits email 1/hour/IP |

## UI Layer (`ui/`) — PyQt5 Widgets Only
Tabs communicate with core via:
- **Qt signals/slots** — IDSEngine emits, tabs connect in `__init__`
- **Direct method calls** — for one-shot actions (block IP button → `firewall.block_ip()`)
- **QTimer** — periodic UI refresh (dashboard polls psutil every 2 seconds via `QTimer.singleShot`)

| Widget | Purpose |
|---|---|
| `main_window.py` | `QMainWindow` hosting `QTabWidget`; status bar; connects IDS signals to tab slots |
| `dashboard_tab.py` | `QTableWidget` showing live connections + embedded graph |
| `rules_tab.py` | CRUD UI for firewall rules |
| `alerts_tab.py` | Alert log with filters, geo column, export button |
| `blocklist_tab.py` | Manual IP block/unblock with import/export |
| `scheduler_tab.py` | Time-based rule builder |
| `threat_map_tab.py` | `QWebEngineView` with Leaflet.js; fallback `QTableWidget` if WebEngine missing |
| `settings_tab.py` | Form reflecting all `config.yaml` keys; Save button rewrites YAML |
| `tray.py` | `QSystemTrayIcon` with context menu |

## API Layer (`api/server.py`) — Optional Flask
- Instantiated only when `config.api.enabled == True`
- Runs in a `QThread` (or `threading.Thread(daemon=True)`)
- Shares `core/blocklist` singleton for reads/writes
- API key checked via `request.headers.get("X-API-Key")`

## Key Threading Patterns

### Background polling (IDS / scheduler)
```python
class IDSWorker(QThread):
    def run(self):
        while not self._stop_event.is_set():
            connections = psutil.net_connections()
            self.engine.process(connections)   # emits Qt signals
            time.sleep(2)
```

### Safe GUI updates from signals
```python
# In MainWindow.__init__:
self.ids_engine.ip_blocked.connect(self.dashboard_tab.on_ip_blocked)
# Signal emitted from QThread → Qt auto-queues across thread boundary
```

## Signal Catalog (`core/ids.py`)
| Signal | Payload | Consumer |
|---|---|---|
| `new_connection` | `(ip: str, port: int, proto: str)` | DashboardTab |
| `ip_flagged` | `(ip: str, count: int)` | AlertsTab, Notifier |
| `ip_blocked` | `(ip: str, reason: str)` | BlocklistTab, StatusBar, Notifier |
| `anomaly_detected` | `(ip: str, score: float)` | AlertsTab, Notifier |
