# NetGuard IDS — Project State

## Current Position
- **Milestone:** v1.0-netguard-ids
- **Current Phase:** 1 (Not started — ready to plan)
- **Last Action:** Project initialized with GSD scaffolding
- **Next Step:** Run `/gsd:discuss-phase 1` then `/gsd:plan-phase 1`

## Key Decisions Made
- **GUI Framework:** PyQt5 (not PySide6) — existing codebase uses PyQt5
- **Database:** SQLite via built-in sqlite3 — no ORM, direct SQL
- **ML Library:** scikit-learn Isolation Forest — fail-safe if not installed
- **Firewall Backend:** netsh (Windows) / iptables (Linux) via subprocess
- **Theme:** Dark theme (#1e1e2e background, #7c3aed accent)
- **API:** Flask on localhost:5000 — optional, toggleable
- **Config:** config.yaml + python-dotenv for secrets

## Blockers
None currently.

## Architecture Notes
- All background work must run in QThread — never block the PyQt5 main thread
- Optional dependencies (scikit-learn, flask, reportlab, twilio) wrapped in try/except at import level
- SQLite DB path: `firewall_ids.db` in project root
- Config path: `config.yaml` in project root

## Session Log
- 2026-03-11: Project initialized, GSD scaffolding added, full roadmap created (7 phases)
