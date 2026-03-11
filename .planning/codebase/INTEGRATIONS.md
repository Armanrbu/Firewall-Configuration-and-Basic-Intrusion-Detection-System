# External Integrations

## ip-api.com (Geolocation)
- **Module:** `core/geo.py`
- **Protocol:** HTTP GET to `http://ip-api.com/json/{ip}`
- **Auth:** None (free tier, no API key)
- **Rate limit:** ip-api.com has a 45 requests/minute limit on free tier
- **Timeout:** 3 seconds
- **Caching:** Results cached in SQLite `geo_cache` table (via `core/blocklist.py`)
- **Fallback:** Private IPs return hardcoded local result; errors return "Unknown" placeholder

## OS Firewall Commands
- **Module:** `core/firewall.py`
- **Windows:** `netsh advfirewall` (status), PowerShell `New-NetFirewallRule`/`Remove-NetFirewallRule` (block/unblock)
- **Linux:** `iptables` commands
- **Requires:** Admin/root privileges
- **Timeout:** 20 seconds per command
- **Rule prefix:** `NetGuard_` to identify managed rules

## Email (SMTP)
- **Module:** `core/notifier.py`
- **Protocol:** SMTP_SSL (port 465 default)
- **Provider:** Configurable, defaults to `smtp.gmail.com`
- **Auth:** Username/password from `config.yaml` `email` section
- **Rate limit:** 1 email per IP per hour (internal)
- **Threading:** Sent in background daemon thread

## Twilio SMS (Optional)
- **Module:** `core/notifier.py`
- **Package:** `twilio` (optional, fail-safe import)
- **Auth:** Via Twilio Client with credentials
- **Threading:** Sent in background daemon thread

## Flask REST API (Optional)
- **Module:** `api/server.py`
- **Binding:** `127.0.0.1:{port}` (localhost only)
- **Auth:** `X-API-Key` header
- **Endpoints:** `/status`, `/blocked`, `/block`, `/unblock`, `/alerts`, `/connections`
- **Threading:** Runs in background daemon thread

## psutil (System)
- **Module:** `core/ids.py`, `ui/dashboard_tab.py`
- **Usage:** `psutil.net_connections(kind="inet")` for live connection monitoring
- **Refresh:** Every 2 seconds (dashboard), continuous in IDS worker thread

## Windows Firewall Log
- **Module:** `core/ids.py` (IDSWorker)
- **Path:** Configurable via `config.yaml` → `firewall.log_path`
- **Default:** `C:\Temp\pfirewall.log`
- **Parsing:** Regex IP extraction from log lines
