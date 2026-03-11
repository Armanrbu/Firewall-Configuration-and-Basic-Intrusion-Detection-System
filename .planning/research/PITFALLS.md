# NetGuard IDS — Common Pitfalls & Mitigations

## 🔴 CRITICAL

### 1. Qt GUI Methods Called from Non-Main Thread
**Problem:** Calling any `QWidget` method (`.setText()`, `.addItem()`, `.update()`) from a `QThread` causes undefined behavior and crashes on some platforms.

**Mitigation:** Never touch widgets directly from a thread. Always communicate via Qt signals/slots — Qt queues cross-thread signal delivery automatically.
```python
# WRONG — crashes or corrupts UI:
def run(self):
    self.table_widget.addRow(...)  # direct widget call from thread

# RIGHT — emit a signal, connect slot in main thread:
class IDSWorker(QThread):
    row_ready = pyqtSignal(dict)
    def run(self):
        self.row_ready.emit(row_data)
```

### 2. netsh / iptables Require Elevated Privileges
**Problem:** `subprocess.run(["netsh", ...])` raises `PermissionError` or returns non-zero exit code when not run as Administrator (Windows) or root (Linux).

**Mitigation:** Wrap all firewall subprocess calls in `try/except` and surface a user-facing error. Show a warning dialog on startup if privileges are insufficient. Never let the exception propagate to Qt's event loop uncaught.
```python
try:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
except (subprocess.CalledProcessError, PermissionError, FileNotFoundError) as e:
    logger.error("Firewall command failed: %s", e)
    return FirewallResult(success=False, error=str(e))
```

### 3. Isolation Forest Cold Start
**Problem:** `IsolationForest.fit()` requires training data. On first run there are zero connection samples, causing `NotFittedError` when `predict()` is called.

**Mitigation:** Require a minimum sample threshold (e.g., 50 connections) before fitting. Gate all `predict()` calls with `self._is_fitted` flag. Load persisted model from `anomaly_model.pkl` if it exists.
```python
if len(self._samples) < MIN_SAMPLES:
    return None  # not enough data yet
```

---

## 🟡 MODERATE

### 4. PyQtWebEngine Availability
**Problem:** `PyQtWebEngine` is a separate package not always installed. Importing `QWebEngineView` without it raises `ImportError`.

**Mitigation:** Guard the import; fall back to a `QTableWidget` listing blocked IPs when WebEngine is unavailable.
```python
try:
    from PyQt5.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False
```

### 5. ip-api.com Rate Limiting
**Problem:** ip-api.com limits free tier to 45 requests/minute. Rapid lookups during a connection spike will hit `429 Too Many Requests`.

**Mitigation:** Always check `geo_cache` SQLite table first (cache TTL: 7 days). Use `time.sleep(1.5)` between API calls in the geolocation worker. Log rate-limit responses and return `"Unknown"` gracefully.

### 6. Windows Firewall Log Not Enabled
**Problem:** `pfirewall.log` may not exist if Windows Firewall logging has never been configured, causing `FileNotFoundError` in the IDS log-tail thread.

**Mitigation:** Handle `FileNotFoundError` and `PermissionError` when opening the log file. Display a setup reminder in the UI. Prefer psutil-based connection monitoring (always available) over log tailing.

### 7. SQLite Concurrent Writes
**Problem:** Multiple threads (IDS worker, scheduler, API server) writing to SQLite simultaneously can cause `sqlite3.OperationalError: database is locked`.

**Mitigation:** Use a single `threading.Lock` in `core/blocklist.py` around all write operations. Alternatively, open the connection with `check_same_thread=False` and `timeout=5` for reader threads.

---

## 🟢 MINOR

### 8. plyer Notification Behavior Varies by OS
**Problem:** `plyer.notification.notify()` behaves differently on Windows (system tray balloon), Linux (libnotify), and macOS (NSUserNotification). Some Linux distros without a notification daemon silently fail.

**Mitigation:** Always wrap `plyer` calls in `try/except Exception`. Log the failure but do not re-raise. The app must continue working without desktop notifications.

### 9. schedule Library Thread Safety
**Problem:** The `schedule` library's job list is a module-level global. Adding jobs from multiple threads without synchronization can corrupt the job queue.

**Mitigation:** Only add/remove jobs from the scheduler thread using a `queue.Queue` command channel. The scheduler thread dequeues commands at the top of each loop iteration before running pending jobs.

### 10. Optional Import at Module Level vs Function Level
**Problem:** If optional dependencies (flask, scikit-learn, reportlab, twilio) are imported at module level, any `ImportError` will prevent the entire module from loading, breaking unrelated functionality.

**Mitigation:** Import optional dependencies inside the function/method that uses them (lazy import), or use a module-level `try/except` with a `HAS_X` flag and guard all usages.
```python
# Module level:
try:
    import sklearn
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Usage:
def detect(self, features):
    if not HAS_SKLEARN:
        logger.warning("scikit-learn not installed — ML detection disabled")
        return None
```

### 11. Config Reload Race Condition
**Problem:** If `config.yaml` is reloaded while a background thread reads a config value, a partial read could occur.

**Mitigation:** Reload into a new dict object and replace the reference atomically. Use `threading.RLock` if fine-grained access is needed.
