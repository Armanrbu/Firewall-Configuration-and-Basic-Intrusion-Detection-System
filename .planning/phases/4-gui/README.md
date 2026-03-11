# Phase 4: GUI

**Status:** In progress 🚧
**Goal:** Full dark-theme PyQt5 tabbed interface — dashboard, blocklist, rules, alerts, scheduler, settings, threat map, system tray, splash screen.

## Plans

- [x] 04-01: `ui/main_window.py`, `ui/theme.py` — application shell and dark stylesheet
- [x] 04-02: `ui/dashboard_tab.py`, `ui/blocklist_tab.py`, `ui/rules_tab.py`
- [x] 04-03: `ui/alerts_tab.py`, `ui/scheduler_tab.py`, `ui/settings_tab.py`
- [ ] 04-04: `ui/threat_map_tab.py` — Leaflet.js world map (requires PyQtWebEngine; falls back to plain table)

## Key Files

- `ui/main_window.py`
- `ui/theme.py`
- `ui/dashboard_tab.py`
- `ui/blocklist_tab.py`
- `ui/rules_tab.py`
- `ui/alerts_tab.py`
- `ui/scheduler_tab.py`
- `ui/settings_tab.py`
- `ui/threat_map_tab.py` (partial)
- `ui/tray.py`

## Notes

- threat_map_tab.py exists but full Leaflet.js integration pending PyQtWebEngine availability
- tray.py (system tray) is implemented and complete
