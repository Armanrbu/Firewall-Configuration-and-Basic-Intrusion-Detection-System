"""
Centralised logging setup with rotating file handler.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Any


_configured = False
_root_logger: logging.Logger | None = None


def setup_logging(
    level: str = "INFO",
    log_file: str = "netguard.log",
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> None:
    """Configure root-level logging with both console and rotating file handlers."""
    global _configured
    if _configured:
        return
    _configured = True

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(numeric_level)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        fh.setLevel(numeric_level)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as exc:
        root.warning("Could not open log file %s: %s", log_file, exc)


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger (sets up logging with defaults if not yet configured)."""
    global _configured
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
