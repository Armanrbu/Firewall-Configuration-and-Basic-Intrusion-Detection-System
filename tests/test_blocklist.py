"""
Tests for the SQLite blocklist / storage layer.

Uses an in-memory SQLite database so tests are fast and isolated.
"""

import time
import pytest

import core.blocklist as bl


@pytest.fixture(autouse=True)
def reset_db(tmp_path):
    """Use a fresh in-memory-style DB for every test."""
    db_path = str(tmp_path / "test.db")
    bl.set_db_path(db_path)
    yield
    bl.close_all_connections()


class TestBlockedIps:
    def test_add_and_get(self):
        bl.add_block("1.2.3.4", reason="test", auto=False)
        blocked = bl.get_all_blocked()
        assert any(b["ip"] == "1.2.3.4" for b in blocked)

    def test_is_blocked(self):
        bl.add_block("5.6.7.8", reason="test")
        assert bl.is_blocked("5.6.7.8")

    def test_remove_block(self):
        bl.add_block("9.9.9.9")
        bl.remove_block("9.9.9.9")
        assert not bl.is_blocked("9.9.9.9")

    def test_auto_flag(self):
        bl.add_block("2.2.2.2", auto=True)
        blocked = bl.get_all_blocked()
        entry = next(b for b in blocked if b["ip"] == "2.2.2.2")
        assert entry["auto_blocked"] == 1

    def test_purge(self):
        bl.add_block("3.3.3.3")
        bl.purge_block("3.3.3.3")
        assert not bl.is_blocked("3.3.3.3")
        # should be gone from DB entirely
        all_blocked = bl.get_all_blocked()
        assert not any(b["ip"] == "3.3.3.3" for b in all_blocked)

    def test_duplicate_block_upsert(self):
        bl.add_block("4.4.4.4", reason="first")
        bl.add_block("4.4.4.4", reason="second")  # should not raise
        blocked = bl.get_all_blocked()
        assert sum(1 for b in blocked if b["ip"] == "4.4.4.4") == 1


class TestAlerts:
    def test_add_and_get_alert(self):
        alert_id = bl.add_alert("10.0.0.1", "Port Scan", "ports: 22,80,443")
        assert alert_id > 0
        alerts = bl.get_alerts()
        assert any(a["ip"] == "10.0.0.1" for a in alerts)

    def test_get_unresolved_only(self):
        bl.add_alert("11.0.0.1", "Repeated Connection", "")
        alerts = bl.get_alerts(unresolved_only=True)
        assert all(not a["resolved"] for a in alerts)

    def test_resolve_alert(self):
        alert_id = bl.add_alert("12.0.0.1", "Anomaly", "")
        bl.resolve_alert(alert_id)
        alerts = bl.get_alerts()
        entry = next((a for a in alerts if a["id"] == alert_id), None)
        assert entry is not None
        assert entry["resolved"] == 1

    def test_alert_limit(self):
        for i in range(20):
            bl.add_alert(f"10.0.0.{i}", "Test", "")
        alerts = bl.get_alerts(limit=5)
        assert len(alerts) <= 5


class TestConnectionLog:
    def test_log_and_get(self):
        bl.log_connection("8.8.8.8", port=443, protocol="TCP", direction="out")
        log = bl.get_connection_log(limit=100)
        assert any(e["ip"] == "8.8.8.8" for e in log)

    def test_stats_today(self):
        bl.log_connection("8.8.8.8", port=80)
        stats = bl.get_stats_today()
        assert stats["total"] >= 1


class TestThreadSafety:
    def test_concurrent_writes(self):
        import threading
        errors = []

        def writer(n):
            try:
                for i in range(10):
                    bl.add_block(f"10.{n}.0.{i}", reason="thread test")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"

    def test_get_db_returns_different_connections_per_thread(self):
        import threading
        connections = {}

        def get_conn(name):
            connections[name] = id(bl.get_db())

        t1 = threading.Thread(target=get_conn, args=("t1",))
        t2 = threading.Thread(target=get_conn, args=("t2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert connections["t1"] != connections["t2"]
