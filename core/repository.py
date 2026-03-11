"""
Repository pattern for NetGuard IDS data access.

Provides CRUD operations on all tables via SQLAlchemy ORM sessions.
Return types match the existing ``core.blocklist`` contract (``list[dict]``,
``int``, ``bool``) so callers can migrate transparently.

Usage:
    from core.repository import init_db, get_repositories

    init_db("sqlite:///firewall_ids.db")
    repos = get_repositories()
    repos.blocklist.add_block("1.2.3.4", reason="port scan")
    rows = repos.blocklist.get_all_blocked()
"""

from __future__ import annotations

import datetime
import time
from typing import Any, NamedTuple

from utils.logger import get_logger
from core.models import HAS_SQLALCHEMY

logger = get_logger(__name__)

if not HAS_SQLALCHEMY:
    logger.warning("SQLAlchemy not installed; Repository classes unavailable.")


# ---------------------------------------------------------------------------
# Repository classes
# ---------------------------------------------------------------------------

class BlocklistRepository:
    """CRUD operations for the blocked_ips table."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    def add_block(self, ip: str, reason: str = "", auto: bool = False) -> None:
        """Record an IP as blocked (insert or replace)."""
        from core.models import BlockedIP
        with self._sf() as session:
            existing = session.get(BlockedIP, ip)
            if existing:
                existing.reason = reason
                existing.blocked_at = time.time()
                existing.unblocked_at = None
                existing.auto_blocked = int(auto)
                existing.status = "active"
            else:
                session.add(BlockedIP(
                    ip=ip,
                    reason=reason,
                    blocked_at=time.time(),
                    auto_blocked=int(auto),
                    status="active",
                ))
            session.commit()
        logger.info("Blocked IP recorded: %s (auto=%s)", ip, auto)

    def remove_block(self, ip: str) -> None:
        """Mark an IP as unblocked (sets unblocked_at)."""
        from core.models import BlockedIP
        with self._sf() as session:
            row = session.get(BlockedIP, ip)
            if row:
                row.unblocked_at = time.time()
                row.status = "unblocked"
                session.commit()
        logger.info("IP unblocked: %s", ip)

    def get_all_blocked(self) -> list[dict[str, Any]]:
        """Return all currently blocked IPs (unblocked_at IS NULL)."""
        from core.models import BlockedIP
        from sqlalchemy import select
        with self._sf() as session:
            rows = session.execute(
                select(BlockedIP)
                .where(BlockedIP.unblocked_at == None)  # noqa: E711
                .order_by(BlockedIP.blocked_at.desc())
            ).scalars().all()
            return [r.to_dict() for r in rows]

    def is_blocked(self, ip: str) -> bool:
        """Return True if *ip* is currently blocked."""
        from core.models import BlockedIP
        from sqlalchemy import select
        with self._sf() as session:
            row = session.execute(
                select(BlockedIP).where(
                    BlockedIP.ip == ip,
                    BlockedIP.unblocked_at == None,  # noqa: E711
                )
            ).scalar_one_or_none()
            return row is not None

    def purge_block(self, ip: str) -> None:
        """Permanently delete a block record."""
        from core.models import BlockedIP
        with self._sf() as session:
            row = session.get(BlockedIP, ip)
            if row:
                session.delete(row)
                session.commit()


class AlertRepository:
    """CRUD operations for the alerts table."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    def add_alert(self, ip: str, alert_type: str, details: str = "") -> int:
        """Insert an alert record and return its new ID."""
        from core.models import Alert
        with self._sf() as session:
            row = Alert(
                ip=ip,
                type=alert_type,
                details=details,
                timestamp=time.time(),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            alert_id: int = row.id  # type: ignore[assignment]
        logger.info("Alert recorded: [%s] %s — %s", alert_type, ip, details)
        return alert_id

    def get_alerts(
        self,
        limit: int = 100,
        unresolved_only: bool = False,
        since: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return alert records ordered by most recent first."""
        from core.models import Alert
        from sqlalchemy import select
        stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
        if unresolved_only:
            stmt = stmt.where(Alert.resolved == 0)
        if since is not None:
            stmt = stmt.where(Alert.timestamp >= since)
        with self._sf() as session:
            rows = session.execute(stmt).scalars().all()
            return [r.to_dict() for r in rows]

    def resolve_alert(self, alert_id: int) -> None:
        """Mark an alert as resolved."""
        from core.models import Alert
        with self._sf() as session:
            row = session.get(Alert, alert_id)
            if row:
                row.resolved = 1
                session.commit()

    def prune_old_alerts(self, max_age_days: int = 90) -> int:
        """Delete resolved alerts older than *max_age_days*. Returns rows deleted."""
        from core.models import Alert
        from sqlalchemy import delete
        cutoff = time.time() - (max_age_days * 86400)
        with self._sf() as session:
            result = session.execute(
                delete(Alert).where(Alert.resolved == 1, Alert.timestamp < cutoff)
            )
            session.commit()
            deleted: int = result.rowcount
        if deleted:
            logger.info("Pruned %d old resolved alerts.", deleted)
        return deleted


class ConnectionLogRepository:
    """CRUD operations for the connection_log table."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    def log_connection(
        self,
        ip: str,
        port: int = 0,
        protocol: str = "TCP",
        direction: str = "in",
    ) -> None:
        """Insert a connection log entry."""
        from core.models import ConnectionLog
        with self._sf() as session:
            session.add(ConnectionLog(
                ip=ip, port=port, protocol=protocol,
                direction=direction, timestamp=time.time(),
            ))
            session.commit()

    def get_connection_log(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return connection log entries ordered most-recent first."""
        from core.models import ConnectionLog
        from sqlalchemy import select
        with self._sf() as session:
            rows = session.execute(
                select(ConnectionLog)
                .order_by(ConnectionLog.timestamp.desc())
                .limit(limit)
            ).scalars().all()
            return [r.to_dict() for r in rows]

    def get_stats_today(self) -> dict[str, int]:
        """Return today's connection statistics."""
        from core.models import ConnectionLog, BlockedIP
        from sqlalchemy import select, func
        today_start = datetime.datetime.combine(
            datetime.date.today(), datetime.time.min
        ).timestamp()
        with self._sf() as session:
            total = session.execute(
                select(func.count()).where(ConnectionLog.timestamp >= today_start)
                .select_from(ConnectionLog)
            ).scalar() or 0
            blocked = session.execute(
                select(func.count()).where(BlockedIP.blocked_at >= today_start)
                .select_from(BlockedIP)
            ).scalar() or 0
            unique = session.execute(
                select(func.count(ConnectionLog.ip.distinct()))
                .where(ConnectionLog.timestamp >= today_start)
            ).scalar() or 0
        return {"total": total, "blocked": blocked, "unique_ips": unique}

    def prune(self, max_age_days: int = 30, max_rows: int = 100_000) -> int:
        """Delete old/excess connection log entries. Returns rows deleted."""
        from core.models import ConnectionLog
        from sqlalchemy import delete, select, func
        deleted = 0

        cutoff = time.time() - (max_age_days * 86400)
        with self._sf() as session:
            result = session.execute(
                delete(ConnectionLog).where(ConnectionLog.timestamp < cutoff)
            )
            session.commit()
            deleted += result.rowcount

        # Row-count pruning
        with self._sf() as session:
            total = session.execute(
                select(func.count()).select_from(ConnectionLog)
            ).scalar() or 0
            if total > max_rows:
                excess = total - max_rows
                # Get IDs of oldest rows
                oldest_ids = session.execute(
                    select(ConnectionLog.id)
                    .order_by(ConnectionLog.timestamp.asc())
                    .limit(excess)
                ).scalars().all()
                if oldest_ids:
                    session.execute(
                        delete(ConnectionLog).where(ConnectionLog.id.in_(oldest_ids))
                    )
                    session.commit()
                    deleted += len(oldest_ids)

        if deleted:
            logger.info("Pruned %d connection log entries.", deleted)
        return deleted


class GeoCacheRepository:
    """Read/write the geolocation cache."""

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    def get(self, ip: str) -> dict[str, Any] | None:
        """Return cached geo data for *ip*, or None."""
        import json
        from core.models import GeoCache
        with self._sf() as session:
            row = session.get(GeoCache, ip)
            if row is None:
                return None
            try:
                return json.loads(row.data_json)
            except Exception:
                return None

    def set(self, ip: str, data: dict[str, Any]) -> None:
        """Cache geo data for *ip*."""
        import json
        from core.models import GeoCache
        with self._sf() as session:
            existing = session.get(GeoCache, ip)
            if existing:
                existing.data_json = json.dumps(data)
                existing.cached_at = time.time()
            else:
                session.add(GeoCache(
                    ip=ip,
                    data_json=json.dumps(data),
                    cached_at=time.time(),
                ))
            session.commit()


# ---------------------------------------------------------------------------
# Convenience bundle
# ---------------------------------------------------------------------------

class Repositories(NamedTuple):
    """Bundle of all repository instances for easy access."""
    blocklist: BlocklistRepository
    alerts: AlertRepository
    connection_log: ConnectionLogRepository
    geo_cache: GeoCacheRepository


# ---------------------------------------------------------------------------
# Singleton session factory
# ---------------------------------------------------------------------------

_engine = None
_SessionFactory = None


def init_db(db_url: str = "sqlite:///firewall_ids.db") -> None:
    """Initialise the SQLAlchemy engine and create tables.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _engine, _SessionFactory
    if _engine is not None:
        return

    if not HAS_SQLALCHEMY:
        logger.warning("SQLAlchemy not installed; repository init skipped.")
        return

    from core.models import create_db_engine, init_schema
    from sqlalchemy.orm import sessionmaker

    _engine = create_db_engine(db_url)
    init_schema(_engine)
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)
    logger.info("Repository layer initialised with: %s", db_url)


def reset_db() -> None:
    """Reset the repository singleton (for testing)."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None


def _get_session_factory():
    """Return the active session factory, initialising with defaults if needed."""
    global _SessionFactory
    if _SessionFactory is None:
        init_db()
    return _SessionFactory


def get_repositories() -> Repositories:
    """Return all repository instances wired to the active session factory."""
    sf = _get_session_factory()
    return Repositories(
        blocklist=BlocklistRepository(sf),
        alerts=AlertRepository(sf),
        connection_log=ConnectionLogRepository(sf),
        geo_cache=GeoCacheRepository(sf),
    )
