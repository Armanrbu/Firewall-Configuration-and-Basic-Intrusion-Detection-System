# Phase 2: Firewall Core

**Status:** Complete ✅
**Goal:** Cross-platform firewall backend (Windows netsh / Linux iptables), persistent SQLite blocklist, whitelist management.

## Plans

- [x] 02-01: `core/firewall.py` — Windows netsh and Linux iptables backend
- [x] 02-02: `core/blocklist.py` — SQLite schema and CRUD operations
- [x] 02-03: `core/whitelist.py` — trusted IP management

## Key Files

- `core/firewall.py`
- `core/blocklist.py`
- `core/whitelist.py`
