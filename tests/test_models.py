"""Tests for core.models — SQLAlchemy ORM model definitions."""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import HAS_SQLALCHEMY

pytestmark = pytest.mark.skipif(
    not HAS_SQLALCHEMY,
    reason="SQLAlchemy not installed",
)


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite engine with all tables."""
    from core.models import create_db_engine, init_schema
    engine = create_db_engine("sqlite:///:memory:")
    init_schema(engine)
    return engine


class TestModelDefinitions:
    def test_all_tables_created(self, in_memory_engine) -> None:
        from core.models import Base
        table_names = set(Base.metadata.tables.keys())
        expected = {"blocked_ips", "alerts", "connection_log", "geo_cache",
                    "schema_version", "scheduled_rules"}
        assert expected.issubset(table_names)

    def test_blocked_ip_columns(self, in_memory_engine) -> None:
        from core.models import BlockedIP
        cols = {c.name for c in BlockedIP.__table__.columns}
        assert "ip" in cols
        assert "reason" in cols
        assert "blocked_at" in cols
        assert "unblocked_at" in cols
        assert "auto_blocked" in cols
        assert "expires_at" in cols
        assert "status" in cols

    def test_alert_columns(self, in_memory_engine) -> None:
        from core.models import Alert
        cols = {c.name for c in Alert.__table__.columns}
        assert {"id", "ip", "type", "details", "timestamp",
                "resolved", "ml_score", "rule_id", "action"}.issubset(cols)

    def test_connection_log_columns(self, in_memory_engine) -> None:
        from core.models import ConnectionLog
        cols = {c.name for c in ConnectionLog.__table__.columns}
        assert {"id", "ip", "port", "protocol", "direction",
                "timestamp", "details_json"}.issubset(cols)

    def test_blocked_ip_instantiation(self) -> None:
        from core.models import BlockedIP
        import time
        row = BlockedIP(ip="1.2.3.4", reason="test", blocked_at=time.time(), auto_blocked=0)
        assert row.ip == "1.2.3.4"
        assert row.reason == "test"

    def test_alert_instantiation(self, in_memory_engine) -> None:
        from core.models import Alert
        from sqlalchemy.orm import sessionmaker
        import time
        sf = sessionmaker(bind=in_memory_engine, expire_on_commit=False)
        with sf() as session:
            row = Alert(ip="5.6.7.8", type="port_scan", timestamp=time.time())
            session.add(row)
            session.commit()
            session.refresh(row)
        assert row.ip == "5.6.7.8"
        assert row.resolved == 0  # default applied on INSERT

    def test_connection_log_instantiation(self) -> None:
        from core.models import ConnectionLog
        import time
        row = ConnectionLog(ip="9.10.11.12", port=80, protocol="TCP",
                            direction="in", timestamp=time.time())
        assert row.port == 80

    def test_to_dict_blocked_ip(self) -> None:
        from core.models import BlockedIP
        import time
        row = BlockedIP(ip="1.2.3.4", reason="r", blocked_at=time.time())
        d = row.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert "blocked_at" in d
        assert "unblocked_at" in d

    def test_to_dict_alert(self) -> None:
        from core.models import Alert
        import time
        row = Alert(ip="1.1.1.1", type="threshold", timestamp=time.time())
        d = row.to_dict()
        assert d["ip"] == "1.1.1.1"
        assert "ml_score" in d

    def test_blocked_ip_primary_key(self) -> None:
        from core.models import BlockedIP
        pk_cols = [c.name for c in BlockedIP.__table__.primary_key]
        assert pk_cols == ["ip"]

    def test_alert_autoincrement_pk(self) -> None:
        from core.models import Alert
        pk_col = list(Alert.__table__.primary_key)[0]
        assert pk_col.autoincrement is True or pk_col.name == "id"

    def test_create_engine_sqlite(self) -> None:
        from core.models import create_db_engine
        engine = create_db_engine("sqlite:///:memory:")
        assert engine is not None
        engine.dispose()

    def test_init_schema_idempotent(self, in_memory_engine) -> None:
        """Calling init_schema twice doesn't raise."""
        from core.models import init_schema
        init_schema(in_memory_engine)  # second call — should be no-op
        init_schema(in_memory_engine)  # third call — still no-op
