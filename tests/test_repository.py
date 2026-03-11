"""Tests for core.repository — CRUD operations via SQLAlchemy."""

from __future__ import annotations

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import HAS_SQLALCHEMY

pytestmark = pytest.mark.skipif(
    not HAS_SQLALCHEMY,
    reason="SQLAlchemy not installed",
)


@pytest.fixture
def repos():
    """Fresh in-memory repositories for each test."""
    from core.repository import reset_db, init_db, get_repositories
    reset_db()
    init_db("sqlite:///:memory:")
    r = get_repositories()
    yield r
    reset_db()


# ---------------------------------------------------------------------------
# BlocklistRepository
# ---------------------------------------------------------------------------

class TestBlocklistRepository:

    def test_add_and_get_all_blocked(self, repos) -> None:
        repos.blocklist.add_block("1.2.3.4", reason="test", auto=False)
        rows = repos.blocklist.get_all_blocked()
        assert len(rows) == 1
        assert rows[0]["ip"] == "1.2.3.4"
        assert rows[0]["reason"] == "test"

    def test_is_blocked_true(self, repos) -> None:
        repos.blocklist.add_block("10.0.0.1")
        assert repos.blocklist.is_blocked("10.0.0.1") is True

    def test_is_blocked_false(self, repos) -> None:
        assert repos.blocklist.is_blocked("192.168.1.100") is False

    def test_remove_block(self, repos) -> None:
        repos.blocklist.add_block("5.5.5.5")
        repos.blocklist.remove_block("5.5.5.5")
        assert repos.blocklist.is_blocked("5.5.5.5") is False

    def test_remove_block_sets_unblocked_at(self, repos) -> None:
        repos.blocklist.add_block("6.6.6.6")
        repos.blocklist.remove_block("6.6.6.6")
        rows = repos.blocklist.get_all_blocked()
        # Should not appear in active blocks
        ips = [r["ip"] for r in rows]
        assert "6.6.6.6" not in ips

    def test_purge_block(self, repos) -> None:
        repos.blocklist.add_block("7.7.7.7")
        repos.blocklist.purge_block("7.7.7.7")
        assert repos.blocklist.is_blocked("7.7.7.7") is False

    def test_add_block_upsert(self, repos) -> None:
        """Adding a second block for the same IP updates the record."""
        repos.blocklist.add_block("8.8.8.8", reason="first")
        repos.blocklist.add_block("8.8.8.8", reason="second")
        rows = repos.blocklist.get_all_blocked()
        ips = [r["ip"] for r in rows]
        assert ips.count("8.8.8.8") == 1

    def test_multiple_blocked_ips(self, repos) -> None:
        for i in range(5):
            repos.blocklist.add_block(f"10.0.0.{i}")
        rows = repos.blocklist.get_all_blocked()
        assert len(rows) == 5

    def test_auto_blocked_flag(self, repos) -> None:
        repos.blocklist.add_block("9.9.9.9", auto=True)
        rows = repos.blocklist.get_all_blocked()
        assert rows[0]["auto_blocked"] == 1

    def test_get_all_blocked_returns_dicts(self, repos) -> None:
        repos.blocklist.add_block("11.11.11.11")
        rows = repos.blocklist.get_all_blocked()
        assert isinstance(rows[0], dict)
        assert "ip" in rows[0]
        assert "blocked_at" in rows[0]


# ---------------------------------------------------------------------------
# AlertRepository
# ---------------------------------------------------------------------------

class TestAlertRepository:

    def test_add_alert_returns_id(self, repos) -> None:
        alert_id = repos.alerts.add_alert("1.2.3.4", "threshold", "count=15")
        assert isinstance(alert_id, int)
        assert alert_id > 0

    def test_get_alerts_returns_list(self, repos) -> None:
        repos.alerts.add_alert("1.2.3.4", "threshold")
        rows = repos.alerts.get_alerts()
        assert isinstance(rows, list)
        assert len(rows) >= 1

    def test_get_alerts_most_recent_first(self, repos) -> None:
        repos.alerts.add_alert("1.1.1.1", "type_a")
        time.sleep(0.01)
        repos.alerts.add_alert("2.2.2.2", "type_b")
        rows = repos.alerts.get_alerts()
        assert rows[0]["ip"] == "2.2.2.2"

    def test_resolve_alert(self, repos) -> None:
        alert_id = repos.alerts.add_alert("3.3.3.3", "port_scan")
        repos.alerts.resolve_alert(alert_id)
        # Should not appear in unresolved-only query
        rows = repos.alerts.get_alerts(unresolved_only=True)
        ids = [r["id"] for r in rows]
        assert alert_id not in ids

    def test_get_alerts_unresolved_only(self, repos) -> None:
        id1 = repos.alerts.add_alert("4.4.4.4", "t")
        id2 = repos.alerts.add_alert("5.5.5.5", "t")
        repos.alerts.resolve_alert(id1)
        rows = repos.alerts.get_alerts(unresolved_only=True)
        ids = [r["id"] for r in rows]
        assert id1 not in ids
        assert id2 in ids

    def test_get_alerts_since(self, repos) -> None:
        before = time.time()
        repos.alerts.add_alert("6.6.6.6", "t")
        rows = repos.alerts.get_alerts(since=before - 1)
        assert len(rows) >= 1

    def test_get_alerts_limit(self, repos) -> None:
        for i in range(10):
            repos.alerts.add_alert(f"10.0.0.{i}", "t")
        rows = repos.alerts.get_alerts(limit=3)
        assert len(rows) == 3

    def test_prune_old_alerts(self, repos) -> None:
        # Add a resolved alert with an old timestamp by manipulating directly
        from core.models import Alert
        from core.repository import _engine
        from sqlalchemy.orm import sessionmaker
        sf = sessionmaker(bind=_engine)
        with sf() as session:
            old_ts = time.time() - (100 * 86400)  # 100 days ago
            session.add(Alert(ip="7.7.7.7", type="old", timestamp=old_ts, resolved=1))
            session.commit()

        removed = repos.alerts.prune_old_alerts(max_age_days=90)
        assert removed >= 1

    def test_alert_dict_has_required_keys(self, repos) -> None:
        repos.alerts.add_alert("8.8.8.8", "anomaly", "score=0.9")
        rows = repos.alerts.get_alerts()
        assert "id" in rows[0]
        assert "ip" in rows[0]
        assert "type" in rows[0]
        assert "timestamp" in rows[0]
        assert "resolved" in rows[0]


# ---------------------------------------------------------------------------
# ConnectionLogRepository
# ---------------------------------------------------------------------------

class TestConnectionLogRepository:

    def test_log_connection(self, repos) -> None:
        repos.connection_log.log_connection("1.2.3.4", port=80, protocol="TCP")
        rows = repos.connection_log.get_connection_log()
        assert len(rows) >= 1
        assert rows[0]["ip"] == "1.2.3.4"

    def test_get_connection_log_most_recent_first(self, repos) -> None:
        repos.connection_log.log_connection("a.b.c.d".replace(".", "1."))
        time.sleep(0.01)
        repos.connection_log.log_connection("5.5.5.5", port=443)
        rows = repos.connection_log.get_connection_log()
        assert rows[0]["ip"] == "5.5.5.5"

    def test_get_connection_log_limit(self, repos) -> None:
        for i in range(10):
            repos.connection_log.log_connection(f"10.0.0.{i}")
        rows = repos.connection_log.get_connection_log(limit=4)
        assert len(rows) == 4

    def test_prune_age_based(self, repos) -> None:
        from core.models import ConnectionLog
        from core.repository import _engine
        from sqlalchemy.orm import sessionmaker
        sf = sessionmaker(bind=_engine)
        with sf() as session:
            old_ts = time.time() - (40 * 86400)  # 40 days ago
            session.add(ConnectionLog(ip="1.2.3.4", port=80, protocol="TCP",
                                      direction="in", timestamp=old_ts))
            session.commit()

        removed = repos.connection_log.prune(max_age_days=30)
        assert removed >= 1

    def test_prune_max_rows(self, repos) -> None:
        for i in range(10):
            repos.connection_log.log_connection(f"10.0.0.{i}")
        removed = repos.connection_log.prune(max_age_days=9999, max_rows=5)
        assert removed >= 5

    def test_get_stats_today(self, repos) -> None:
        repos.connection_log.log_connection("1.2.3.4")
        repos.blocklist.add_block("1.2.3.4")
        stats = repos.connection_log.get_stats_today()
        assert "total" in stats
        assert "blocked" in stats
        assert "unique_ips" in stats
        assert stats["total"] >= 1
        assert stats["blocked"] >= 1

    def test_connection_log_returns_dicts(self, repos) -> None:
        repos.connection_log.log_connection("9.9.9.9", port=22)
        rows = repos.connection_log.get_connection_log()
        assert isinstance(rows[0], dict)
        assert rows[0]["port"] == 22


# ---------------------------------------------------------------------------
# GeoCacheRepository
# ---------------------------------------------------------------------------

class TestGeoCacheRepository:

    def test_get_missing_returns_none(self, repos) -> None:
        assert repos.geo_cache.get("1.2.3.4") is None

    def test_set_and_get(self, repos) -> None:
        data = {"country": "US", "city": "New York", "lat": 40.7, "lon": -74.0}
        repos.geo_cache.set("8.8.8.8", data)
        cached = repos.geo_cache.get("8.8.8.8")
        assert cached is not None
        assert cached["country"] == "US"

    def test_update_cached_value(self, repos) -> None:
        repos.geo_cache.set("1.1.1.1", {"country": "AU"})
        repos.geo_cache.set("1.1.1.1", {"country": "NZ"})
        cached = repos.geo_cache.get("1.1.1.1")
        assert cached["country"] == "NZ"


# ---------------------------------------------------------------------------
# Repositories bundle
# ---------------------------------------------------------------------------

class TestRepositoriesBundle:

    def test_get_repositories_returns_all(self, repos) -> None:
        from core.repository import get_repositories, Repositories
        r = get_repositories()
        assert isinstance(r, Repositories)
        assert r.blocklist is not None
        assert r.alerts is not None
        assert r.connection_log is not None
        assert r.geo_cache is not None

    def test_init_db_idempotent(self) -> None:
        from core.repository import reset_db, init_db
        reset_db()
        init_db("sqlite:///:memory:")
        init_db("sqlite:///:memory:")  # second call — no-op
        reset_db()
