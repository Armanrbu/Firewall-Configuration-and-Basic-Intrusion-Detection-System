# Architecture

## Pattern
**Layered monolith** with clear separation between UI, core logic, utilities, and API.

```
main.py (entry point)
  ├── utils/config_loader.py     → loads config.yaml
  ├── utils/logger.py            → initialises logging
  ├── core/blocklist.py          → initialises SQLite DB
  ├── core/whitelist.py          → loads whitelist.txt
  ├── core/scheduler.py          → starts background scheduler thread
  └── ui/main_window.py          → launches Qt GUI
        ├── 7 tabs (QWidget subclasses)
        ├── IDS worker (QThread)
        ├── API server (daemon thread)
        └── System tray icon
```

## Data Flow

### Connection Monitoring Pipeline
```
psutil.net_connections() → IDSWorker (QThread)
  → IDSEngine.feed(ConnectionEvent)
    → threshold check → on_ip_flagged signal
    → port scan check → on_port_scan signal
    → anomaly detection → on_anomaly signal
  → auto-block → core.firewall.block_ip()
  → record in DB → core.blocklist.add_alert() / add_block()
  → UI update → Qt signals → AlertsTab / BlocklistTab refresh
  → notifications → core.notifier (desktop/email/SMS)
```

### Firewall Log Parsing (Windows)
```
pfirewall.log → IDSWorker._monitor_log() → regex IP extraction → feed()
```

## Key Abstractions

### IDSEngine (`core/ids.py`)
Pure Python IDS logic — no Qt dependency. Tracks connections per IP using sliding time windows. Detects repeated connections, port scans, and ML anomalies.

### IDSWorker (`core/ids.py`)
Qt QObject wrapper around IDSEngine. Adds psutil-based live monitoring and emits pyqtSignals for UI integration. Runs in a QThread.

### AnomalyDetector (`core/anomaly.py`)
Isolation Forest ML model for anomaly detection. Trains on connection count + port diversity features. Falls back to threshold comparison when scikit-learn is unavailable.

### Notifier (`core/notifier.py`)
Central notification dispatcher — desktop (plyer), email (smtplib), SMS (Twilio). All methods are fail-safe.

### RuleScheduler (`core/scheduler.py`)
Background thread + `schedule` library for time-based firewall rules. Persists rules to SQLite.

## Entry Points
- **GUI:** `python main.py` → `main()` → QApplication + MainWindow
- **API:** Optional Flask REST server — `api/server.py` on `127.0.0.1:5000`
- **Console:** `netguard` via setuptools entry_points

## Threading Model
- **Main thread:** Qt event loop (GUI)
- **IDS thread:** QThread running IDSWorker (psutil polling + log parsing)
- **Scheduler thread:** daemon thread running `schedule` library loop
- **API thread:** daemon thread running Flask dev server
- **Email/SMS threads:** short-lived daemon threads per notification
