"""
Persistent storage layer using SQLite.

Tables:
  blocked_ips    — blocked IP records
  alerts         — IDS alert log
  connection_log — raw connection events
  geo_cache      — geolocation cache
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

_DB_PATH = "firewall_ids.db"
_local = threading.local()
_connections_lock = threading.Lock()
_all_connections: list[sqlite3.Connection] = []
_generation = 0


def get_db(path: str | None = None) -> sqlite3.Connection:
    """Return a per-thread SQLite connection (lazily initialised)."""
    db_path = path or _DB_PATH
    gen = getattr(_local, "generation", -1)
    if gen != _generation:
        _local.connection = None
        _local.generation = _generation
    con = getattr(_local, "connection", None)
    if con is None:
        con = _init_db(db_path)
        _local.connection = con
        _local.generation = _generation
        with _connections_lock:
            _all_connections.append(con)
    return con


def set_db_path(path: str) -> None:
    """Allow tests or the app to override the DB path before first use."""
    global _DB_PATH
    close_all_connections()
    _DB_PATH = path


def close_db() -> None:
    """Close the current thread's database connection."""
    con = getattr(_local, "connection", None)
    if con is not None:
        with _connections_lock:
            try:
                _all_connections.remove(con)
            except ValueError:
                pass
        try:
            con.close()
        except Exception:
            pass
        _local.connection = None


def close_all_connections() -> None:
    """Close all tracked database connections (for shutdown)."""
    global _generation
    _generation += 1
    with _connections_lock:
        for con in _all_connections:
            try:
                con.close()
            except Exception:
                pass
        _all_connections.clear()


def _init_db(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip           TEXT PRIMARY KEY,
            reason       TEXT,
            blocked_at   REAL,
            unblocked_at REAL,
            auto_blocked INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT,
            type       TEXT,
            details    TEXT,
            timestamp  REAL,
            resolved   INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS connection_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT,
            port      INTEGER,
            protocol  TEXT,
            direction TEXT,
            timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip        TEXT PRIMARY KEY,
            data_json TEXT,
            cached_at REAL
        );
    """)
    con.commit()

    # Run schema migrations
    from core.db_migrations import run_migrations
    run_migrations(con)

    logger.info("SQLite DB initialised at %s", path)
    return con


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

def add_block(ip: str, reason: str = "", auto: bool = False) -> None:
    """Record an IP as blocked."""
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, auto_blocked) VALUES (?, ?, ?, ?)",
        (ip, reason, time.time(), int(auto)),
    )
    db.commit()
    logger.info("Blocked IP recorded: %s (auto=%s)", ip, auto)


def remove_block(ip: str) -> None:
    """Mark an IP as unblocked (sets unblocked_at)."""
    db = get_db()
    db.execute(
        "UPDATE blocked_ips SET unblocked_at = ? WHERE ip = ?",
        (time.time(), ip),
    )
    db.commit()
    logger.info("IP unblocked: %s", ip)


def get_all_blocked() -> list[dict[str, Any]]:
    """Return all currently blocked IPs (unblocked_at IS NULL)."""
    db = get_db()
    cur = db.execute(
        "SELECT * FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY blocked_at DESC"
    )
    return [dict(row) for row in cur.fetchall()]


def is_blocked(ip: str) -> bool:
    """Return True if *ip* is currently blocked."""
    db = get_db()
    cur = db.execute(
        "SELECT 1 FROM blocked_ips WHERE ip = ? AND unblocked_at IS NULL", (ip,)
    )
    return cur.fetchone() is not None


def purge_block(ip: str) -> None:
    """Permanently delete a block record."""
    db = get_db()
    db.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    db.commit()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def add_alert(ip: str, alert_type: str, details: str = "") -> int:
    """Insert an alert record and return its ID."""
    db = get_db()
    cur = db.execute(
        "INSERT INTO alerts (ip, type, details, timestamp) VALUES (?, ?, ?, ?)",
        (ip, alert_type, details, time.time()),
    )
    db.commit()
    logger.info("Alert recorded: [%s] %s — %s", alert_type, ip, details)
    return cur.lastrowid  # type: ignore[return-value]


def get_alerts(
    limit: int = 100,
    unresolved_only: bool = False,
    since: float | None = None,
) -> list[dict[str, Any]]:
    """Return alert records ordered by most recent first."""
    db = get_db()
    clauses: list[str] = []
    params: list[Any] = []
    if unresolved_only:
        clauses.append("resolved = 0")
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    cur = db.execute(
        f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", params
    )
    return [dict(row) for row in cur.fetchall()]


def resolve_alert(alert_id: int) -> None:
    db = get_db()
    db.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
    db.commit()


# ---------------------------------------------------------------------------
# Connection log
# ---------------------------------------------------------------------------

def log_connection(
    ip: str,
    port: int = 0,
    protocol: str = "TCP",
    direction: str = "in",
) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO connection_log (ip, port, protocol, direction, timestamp) VALUES (?, ?, ?, ?, ?)",
        (ip, port, protocol, direction, time.time()),
    )
    db.commit()


def get_connection_log(limit: int = 500) -> list[dict[str, Any]]:
    db = get_db()
    cur = db.execute(
        "SELECT * FROM connection_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    return [dict(row) for row in cur.fetchall()]


def get_stats_today() -> dict[str, int]:
    """Return today's statistics."""
    db = get_db()
    import datetime
    today_start = datetime.datetime.combine(
        datetime.date.today(), datetime.time.min
    ).timestamp()
    total = db.execute(
        "SELECT COUNT(*) FROM connection_log WHERE timestamp >= ?", (today_start,)
    ).fetchone()[0]
    blocked = db.execute(
        "SELECT COUNT(*) FROM blocked_ips WHERE blocked_at >= ?", (today_start,)
    ).fetchone()[0]
    unique = db.execute(
        "SELECT COUNT(DISTINCT ip) FROM connection_log WHERE timestamp >= ?", (today_start,)
    ).fetchone()[0]
    return {"total": total, "blocked": blocked, "unique_ips": unique}


# ---------------------------------------------------------------------------
# Pruning / retention
# ---------------------------------------------------------------------------

def prune_connection_log(
    max_age_days: int = 30,
    max_rows: int = 100_000,
) -> int:
    """Delete connection log entries older than *max_age_days* or exceeding *max_rows*.

    Returns the total number of rows deleted.
    """
    db = get_db()
    deleted = 0

    # Age-based pruning
    cutoff = time.time() - (max_age_days * 86400)
    cur = db.execute("DELETE FROM connection_log WHERE timestamp < ?", (cutoff,))
    deleted += cur.rowcount
    db.commit()

    # Row-count pruning (keep the newest *max_rows*)
    total = db.execute("SELECT COUNT(*) FROM connection_log").fetchone()[0]
    if total > max_rows:
        excess = total - max_rows
        db.execute(
            "DELETE FROM connection_log WHERE id IN "
            "(SELECT id FROM connection_log ORDER BY timestamp ASC LIMIT ?)",
            (excess,),
        )
        deleted += excess
        db.commit()

    if deleted:
        logger.info("Pruned %d connection log entries.", deleted)
    return deleted


def prune_old_alerts(max_age_days: int = 90) -> int:
    """Delete resolved alerts older than *max_age_days*.

    Returns the number of rows deleted.
    """
    db = get_db()
    cutoff = time.time() - (max_age_days * 86400)
    cur = db.execute(
        "DELETE FROM alerts WHERE resolved = 1 AND timestamp < ?", (cutoff,)
    )
    db.commit()
    deleted = cur.rowcount
    if deleted:
        logger.info("Pruned %d old resolved alerts.", deleted)
    return deleted
