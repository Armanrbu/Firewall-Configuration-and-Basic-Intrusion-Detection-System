# Phase 7: Testing & Polish

**Status:** In progress 🚧
**Goal:** Complete pytest test suite, packaging via setup.py, README polish, and finalise remaining open items (threat map, Twilio).

## Plans

- [x] 07-01: pytest suite — `tests/conftest.py`, `test_blocklist.py`, `test_firewall.py`, `test_ids.py`, `test_validators.py`
- [ ] 07-02: Packaging (setup.py), README polish, threat_map_tab.py completion, Twilio SMS

## Key Files

- `tests/conftest.py`
- `tests/test_blocklist.py`
- `tests/test_firewall.py`
- `tests/test_ids.py`
- `tests/test_validators.py`
- `setup.py`
- `README.md`

## Remaining Work

- Complete `ui/threat_map_tab.py` (Leaflet.js map with PyQtWebEngine)
- Add Twilio SMS integration to `core/notifier.py` (optional, fail-safe)
- Verify `setup.py` installs cleanly
- Update `README.md` with accurate feature list and usage instructions
