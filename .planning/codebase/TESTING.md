# Testing

## Framework
- **pytest** — test runner
- Run: `pytest tests/ -v`

## Structure
```
tests/
├── conftest.py           # Adds project root to sys.path
├── test_blocklist.py     # SQLite storage layer (13 tests)
├── test_firewall.py      # Firewall backend (9 tests)
├── test_ids.py           # IDS engine logic (7+ tests)
└── test_validators.py    # IP/port validation (15+ tests)
```

## Test Isolation
- **Database tests:** Use `tmp_path` fixture → fresh SQLite file per test, reset singleton after
- **Firewall tests:** `unittest.mock.patch("subprocess.run")` — no actual system commands
- **IDS tests:** Use base `IDSEngine` (no Qt dependency), `auto_block=False`
- **No production DB touched** — tests never use `firewall_ids.db`

## Fixtures
```python
# blocklist — fresh DB per test
@pytest.fixture(autouse=True)
def reset_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    bl.set_db_path(db_path)
    yield
    bl._con = None

# firewall — mocked subprocess
@pytest.fixture(autouse=True)
def mock_subprocess():
    with patch("subprocess.run") as mock:
        mock.return_value = _mock_run()
        yield mock

# ids — configured engine
@pytest.fixture
def engine():
    return IDSEngine(threshold=3, window_seconds=60, ...)
```

## Test Coverage Areas
- **Blocklist:** add/remove/purge block, alerts CRUD, connection log, stats, upsert handling
- **Firewall:** block/unblock IP success/failure, block port TCP/UDP, rule naming, enable/disable
- **IDS:** threshold flagging, below-threshold no-flag, window expiry, whitelist bypass, reset IP, port scan detection
- **Validators:** valid/invalid IPv4/IPv6, CIDR, port range, private IP detection, normalisation

## What's NOT Tested
- Qt GUI components (no QApplication in tests)
- Flask API endpoints
- Anomaly detector ML model
- Notification delivery (desktop/email/SMS)
- Geolocation lookups
- Scheduler rule execution
