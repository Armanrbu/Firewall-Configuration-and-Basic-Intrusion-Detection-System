# Concerns & Technical Debt

## Security
1. **API key stored in plaintext** — `config.yaml` has `api_key: "change-me-in-settings"`. Should require `.env` for API key storage with a warning if default is used.
2. **Flask debug server in production** — `api/server.py` uses `app.run()` (Werkzeug dev server), not a production WSGI server. Bound to localhost only, which mitigates this.
3. **No HTTPS on API** — API runs plain HTTP. Acceptable for localhost-only but would need TLS for network exposure.
4. **SMTP password in config** — Email password stored in `config.yaml`. Should exclusively use `.env`.

## Architecture
5. **Singleton DB connection** — `core/blocklist.py` uses a module-level `_con` singleton. Not thread-safe despite `check_same_thread=False`. Multiple threads writing simultaneously could cause issues.
6. **No DB migration system** — Schema changes require manual handling. No versioning of the SQLite schema.
7. **Log file monitoring is Windows-specific** — `IDSWorker._monitor_log()` parses Windows firewall log format. Linux equivalent not implemented.

## Testing Gaps
8. **No GUI tests** — No QApplication tests; all Qt components are untested.
9. **No API tests** — Flask endpoints have no test coverage.
10. **No integration tests** — Only unit tests exist. No end-to-end workflow tests.
11. **No anomaly detector tests** — ML model training/prediction untested.

## Code Quality
12. **`__import__` usage in main_window.py** — Uses `__import__("core.blocklist", ...)` instead of a normal import. Harder to read and maintain.
13. **Mixed import styles** — Some modules import at top level, others use deferred imports inside functions for circular dependency avoidance.
14. **Geo lookup over plain HTTP** — `core/geo.py` uses `http://` not `https://` for ip-api.com. Data in transit is not encrypted.

## Fragile Areas
15. **IDS worker thread lifecycle** — No graceful shutdown mechanism for the IDS QThread. Could leak on app close.
16. **Scheduler rule persistence** — Rules stored in SQLite but the scheduler `_load_from_db` / `_save_to_db` methods tie scheduler state to DB state. Crash during save could lose rules.
17. **Whitelist file-based** — `whitelist.txt` is a flat file; no UI for managing whitelist entries directly (must edit file or use core API).

## Performance
18. **Dashboard polls every 2 seconds** — `psutil.net_connections()` called every 2s plus table rebuild. Could be expensive on systems with many connections.
19. **No connection log pruning** — `connection_log` table grows unbounded. No auto-cleanup or retention policy.
20. **Geolocation lookups per-alert** — Each alert row triggers a geo lookup in `_populate()`. Could batch these.
