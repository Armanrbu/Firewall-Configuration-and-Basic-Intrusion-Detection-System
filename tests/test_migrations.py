"""
Tests for the database migration system and log pruning.
"""

import sqlite3
import time

import pytest

import core.blocklist as bl
from core.db_migrations import CURRENT_VERSION, get_schema_version, run_migrations


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    db_path = str(tmp_path / "test_mig.db")
    bl.set_db_path(db_path)
    yield
    bl.close_all_connections()


class TestMigrations:
    def test_fresh_db_gets_current_version(self):
        """A fresh database should be at CURRENT_VERSION after init."""
        con = bl.get_db()
        assert get_schema_version(con) == CURRENT_VERSION

    def test_migration_is_idempotent(self):
        """Running migrations on an already-current DB is a no-op."""
        con = bl.get_db()
        v1 = get_schema_version(con)
        run_migrations(con)
        v2 = get_schema_version(con)
        assert v1 == v2 == CURRENT_VERSION

    def test_migration_adds_new_columns(self, tmp_path):
        """Simulating a v0 DB (no schema_version), migration should add columns."""
        db_path = str(tmp_path / "v0.db")
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row

        # Create the original v0 tables (no new columns)
        con.executescript("""
            CREATE TABLE blocked_ips (
                ip TEXT PRIMARY KEY, reason TEXT,
                blocked_at REAL, unblocked_at REAL, auto_blocked INTEGER DEFAULT 0
            );
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, type TEXT,
                details TEXT, timestamp REAL, resolved INTEGER DEFAULT 0
            );
            CREATE TABLE connection_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER,
                protocol TEXT, direction TEXT, timestamp REAL
            );
            CREATE TABLE geo_cache (
                ip TEXT PRIMARY KEY, data_json TEXT, cached_at REAL
            );
        """)
        con.commit()

        # Insert some data
        con.execute(
            "INSERT INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)",
            ("1.2.3.4", "test", time.time()),
        )
        con.commit()

        # No schema_version table yet
        assert get_schema_version(con) == 0

        # Run migration
        run_migrations(con)

        # Version should be current
        assert get_schema_version(con) == CURRENT_VERSION

        # New columns should exist
        cols = {row[1] for row in con.execute("PRAGMA table_info(alerts)")}
        assert "ml_score" in cols
        assert "rule_id" in cols
        assert "action" in cols

        cols_blocked = {row[1] for row in con.execute("PRAGMA table_info(blocked_ips)")}
        assert "expires_at" in cols_blocked
        assert "status" in cols_blocked

        cols_log = {row[1] for row in con.execute("PRAGMA table_info(connection_log)")}
        assert "details_json" in cols_log

        # Original data should be intact
        row = con.execute("SELECT * FROM blocked_ips WHERE ip = '1.2.3.4'").fetchone()
        assert row is not None

        con.close()


class TestPruning:
    def test_prune_connection_log_by_age(self):
        now = time.time()
        db = bl.get_db()

        # Insert old and new entries
        for i in range(5):
            db.execute(
                "INSERT INTO connection_log (ip, port, protocol, direction, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (f"10.0.0.{i}", 80, "TCP", "in", now - 86400 * 60),  # 60 days ago
            )
        for i in range(5):
            db.execute(
                "INSERT INTO connection_log (ip, port, protocol, direction, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (f"10.1.0.{i}", 80, "TCP", "in", now),  # now
            )
        db.commit()

        deleted = bl.prune_connection_log(max_age_days=30)
        assert deleted == 5

        remaining = db.execute("SELECT COUNT(*) FROM connection_log").fetchone()[0]
        assert remaining == 5

    def test_prune_connection_log_by_max_rows(self):
        db = bl.get_db()
        now = time.time()

        for i in range(20):
            db.execute(
                "INSERT INTO connection_log (ip, port, protocol, direction, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (f"10.0.0.{i}", 80, "TCP", "in", now - i),
            )
        db.commit()

        # Use large max_age_days so age pruning doesn't trigger
        deleted = bl.prune_connection_log(max_age_days=365, max_rows=10)
        remaining = db.execute("SELECT COUNT(*) FROM connection_log").fetchone()[0]
        assert remaining == 10

    def test_prune_old_alerts(self):
        db = bl.get_db()
        now = time.time()

        # Old resolved alert
        db.execute(
            "INSERT INTO alerts (ip, type, details, timestamp, resolved) VALUES (?, ?, ?, ?, ?)",
            ("1.1.1.1", "test", "", now - 86400 * 120, 1),
        )
        # New unresolved alert
        db.execute(
            "INSERT INTO alerts (ip, type, details, timestamp, resolved) VALUES (?, ?, ?, ?, ?)",
            ("2.2.2.2", "test", "", now, 0),
        )
        # Old but unresolved alert (should NOT be pruned)
        db.execute(
            "INSERT INTO alerts (ip, type, details, timestamp, resolved) VALUES (?, ?, ?, ?, ?)",
            ("3.3.3.3", "test", "", now - 86400 * 120, 0),
        )
        db.commit()

        deleted = bl.prune_old_alerts(max_age_days=90)
        assert deleted == 1  # Only the old *resolved* one

        remaining = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert remaining == 2

    def test_prune_zero_when_empty(self):
        assert bl.prune_connection_log() == 0
        assert bl.prune_old_alerts() == 0
