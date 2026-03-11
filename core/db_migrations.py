"""
Simple versioned database migration system.

Each migration is a function that takes a sqlite3.Connection and applies
schema changes. Migrations are idempotent and run in order.
The ``schema_version`` table tracks which version the database is at.
"""

from __future__ import annotations

import sqlite3

from utils.logger import get_logger

logger = get_logger(__name__)

CURRENT_VERSION = 1


def get_schema_version(con: sqlite3.Connection) -> int:
    """Return current schema version (0 if no version table exists)."""
    try:
        row = con.execute("SELECT version FROM schema_version").fetchone()
        if row is None:
            return 0
        return row[0] if isinstance(row, tuple) else row["version"]
    except sqlite3.OperationalError:
        return 0


def run_migrations(con: sqlite3.Connection) -> None:
    """Run all pending migrations up to *CURRENT_VERSION*."""
    con.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)"
    )

    current = get_schema_version(con)

    if current < 1:
        _migrate_v1(con)
        logger.info("Applied database migration v1.")

    if current < CURRENT_VERSION:
        con.execute("DELETE FROM schema_version")
        con.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (CURRENT_VERSION,)
        )
        con.commit()
        logger.info("Database schema at version %d.", CURRENT_VERSION)


# ---------------------------------------------------------------------------
# Individual migrations
# ---------------------------------------------------------------------------


def _migrate_v1(con: sqlite3.Connection) -> None:
    """v1: Add supplementary columns for v2 features."""
    _add_column_if_missing(con, "alerts", "ml_score", "REAL DEFAULT 0.0")
    _add_column_if_missing(con, "alerts", "rule_id", "TEXT DEFAULT ''")
    _add_column_if_missing(con, "alerts", "action", "TEXT DEFAULT 'logged'")
    _add_column_if_missing(con, "blocked_ips", "expires_at", "REAL")
    _add_column_if_missing(con, "blocked_ips", "status", "TEXT DEFAULT 'active'")
    _add_column_if_missing(con, "connection_log", "details_json", "TEXT")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_column_if_missing(
    con: sqlite3.Connection,
    table: str,
    column: str,
    col_type: str,
) -> None:
    """Add a column to *table* only if it does not already exist."""
    existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
