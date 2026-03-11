# Phase 6: API & Exports

**Status:** Complete ✅
**Goal:** Optional Flask REST API for remote monitoring/control, CSV blocklist export, and PDF report generation.

## Plans

- [x] 06-01: `api/server.py` — Flask REST API with endpoints for blocklist and alerts
- [x] 06-02: `utils/exporter.py` — CSV and PDF (reportlab, optional) export

## Key Files

- `api/server.py`
- `api/__init__.py`
- `utils/exporter.py`

## Notes

- Flask API runs as a daemon thread — fails silently if Flask not installed
- reportlab PDF export is optional and fail-safe
