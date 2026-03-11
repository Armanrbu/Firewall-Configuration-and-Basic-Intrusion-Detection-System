# Phase 3: IDS Engine

**Status:** Complete ✅
**Goal:** Real-time intrusion detection via psutil, ML anomaly detection (Isolation Forest + threshold fallback), IP geolocation cached in SQLite.

## Plans

- [x] 03-01: `core/ids.py` — QThread-based monitoring engine with Qt signals
- [x] 03-02: `core/anomaly.py` — Isolation Forest + threshold fallback
- [x] 03-03: `core/geo.py` — ip-api.com geolocation with SQLite cache

## Key Files

- `core/ids.py`
- `core/anomaly.py`
- `core/geo.py`
