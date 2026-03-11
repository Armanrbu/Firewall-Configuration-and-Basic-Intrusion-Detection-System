"""
SQLAlchemy ORM models for NetGuard IDS.

Defines all database tables as Python classes.
Backend-agnostic: works with SQLite (default) and PostgreSQL.

Usage:
    from core.models import Base, BlockedIP, Alert, create_db_engine
    engine = create_db_engine("sqlite:///firewall_ids.db")
    Base.metadata.create_all(engine)
"""

from __future__ import annotations

from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from sqlalchemy import (
        Column, Float, Integer, String, Text,
        create_engine as _sa_create_engine,
    )
    from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    logger.warning("SQLAlchemy not installed; ORM models unavailable. Run: pip install sqlalchemy")


if HAS_SQLALCHEMY:

    class Base(DeclarativeBase):
        """Base class for all ORM models."""
        pass

    class BlockedIP(Base):
        """Blocked IP records."""
        __tablename__ = "blocked_ips"

        ip = Column(String, primary_key=True, nullable=False)
        reason = Column(Text, default="")
        blocked_at = Column(Float, nullable=True)
        unblocked_at = Column(Float, nullable=True)
        auto_blocked = Column(Integer, default=0)
        expires_at = Column(Float, nullable=True)            # added in migration v1
        status = Column(String, default="active")            # added in migration v1

        def to_dict(self) -> dict[str, Any]:
            return {
                "ip": self.ip,
                "reason": self.reason,
                "blocked_at": self.blocked_at,
                "unblocked_at": self.unblocked_at,
                "auto_blocked": self.auto_blocked,
                "expires_at": self.expires_at,
                "status": self.status,
            }

    class Alert(Base):
        """IDS alert log."""
        __tablename__ = "alerts"

        id = Column(Integer, primary_key=True, autoincrement=True)
        ip = Column(String, nullable=False)
        type = Column(String, nullable=False)
        details = Column(Text, default="")
        timestamp = Column(Float, nullable=False)
        resolved = Column(Integer, default=0)
        ml_score = Column(Float, default=0.0)                # added in migration v1
        rule_id = Column(String, default="")                 # added in migration v1
        action = Column(String, default="logged")            # added in migration v1

        def to_dict(self) -> dict[str, Any]:
            return {
                "id": self.id,
                "ip": self.ip,
                "type": self.type,
                "details": self.details,
                "timestamp": self.timestamp,
                "resolved": self.resolved,
                "ml_score": self.ml_score,
                "rule_id": self.rule_id,
                "action": self.action,
            }

    class ConnectionLog(Base):
        """Raw connection event log."""
        __tablename__ = "connection_log"

        id = Column(Integer, primary_key=True, autoincrement=True)
        ip = Column(String, nullable=False)
        port = Column(Integer, default=0)
        protocol = Column(String, default="TCP")
        direction = Column(String, default="in")
        timestamp = Column(Float, nullable=False)
        details_json = Column(Text, nullable=True)           # added in migration v1

        def to_dict(self) -> dict[str, Any]:
            return {
                "id": self.id,
                "ip": self.ip,
                "port": self.port,
                "protocol": self.protocol,
                "direction": self.direction,
                "timestamp": self.timestamp,
                "details_json": self.details_json,
            }

    class GeoCache(Base):
        """IP geolocation cache."""
        __tablename__ = "geo_cache"

        ip = Column(String, primary_key=True, nullable=False)
        data_json = Column(Text, nullable=False)
        cached_at = Column(Float, nullable=False)

    class SchemaVersion(Base):
        """Tracks the current database schema version."""
        __tablename__ = "schema_version"

        version = Column(Integer, primary_key=True)

    class ScheduledRule(Base):
        """Serialised scheduled firewall rules."""
        __tablename__ = "scheduled_rules"

        rule_id = Column(Integer, primary_key=True, autoincrement=True)
        data_json = Column(Text, nullable=False)

    # -----------------------------------------------------------------------
    # Engine factory
    # -----------------------------------------------------------------------

    def create_db_engine(db_url: str = "sqlite:///firewall_ids.db"):
        """Create and return a SQLAlchemy engine.

        Args:
            db_url: Database URL string. Examples:
                ``"sqlite:///firewall_ids.db"``
                ``"sqlite:///:memory:"``
                ``"postgresql://user:pass@localhost/netguard"``
        """
        kwargs: dict[str, Any] = {"echo": False}
        if db_url.startswith("sqlite"):
            # SQLite-specific: allow use from multiple threads
            kwargs["connect_args"] = {"check_same_thread": False}
        engine = _sa_create_engine(db_url, **kwargs)
        logger.debug("SQLAlchemy engine created: %s", db_url)
        return engine

    def init_schema(engine) -> None:
        """Create all tables defined by the models (idempotent)."""
        Base.metadata.create_all(engine)

else:
    # Stubs so callers can ``from core.models import HAS_SQLALCHEMY``
    # without crashing when SQLAlchemy is not installed.
    class Base:  # type: ignore[no-redef]
        pass

    class BlockedIP:  # type: ignore[no-redef]
        pass

    class Alert:  # type: ignore[no-redef]
        pass

    class ConnectionLog:  # type: ignore[no-redef]
        pass

    class GeoCache:  # type: ignore[no-redef]
        pass

    class SchemaVersion:  # type: ignore[no-redef]
        pass

    class ScheduledRule:  # type: ignore[no-redef]
        pass

    def create_db_engine(db_url: str = "sqlite:///firewall_ids.db"):  # type: ignore[misc]
        raise ImportError("SQLAlchemy not installed. Run: pip install sqlalchemy")

    def init_schema(engine) -> None:  # type: ignore[misc]
        raise ImportError("SQLAlchemy not installed. Run: pip install sqlalchemy")
