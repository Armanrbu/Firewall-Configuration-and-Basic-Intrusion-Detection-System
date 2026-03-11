"""
Centralised logging setup with rotating file handler.

Supports two log formats:
  - "human" (default): human-readable text logs
  - "json": structured JSON logs for machine parsing (ELK, Loki, CloudWatch)
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import traceback
from typing import Any


_configured = False
_root_logger: logging.Logger | None = None

_HUMAN_FMT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter for machine parsing.

    Each log line is a JSON object with keys:
      timestamp, level, logger, message
    Optional keys: exception, ip, extra
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, _DATE_FMT),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Propagate extra fields
        if hasattr(record, "ip"):
            log_entry["ip"] = record.ip  # type: ignore[attr-defined]
        return json.dumps(log_entry, default=str)


def setup_logging(
    level: str = "INFO",
    log_file: str = "netguard.log",
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
    log_format: str = "human",
) -> None:
    """Configure root-level logging with both console and rotating file handlers.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to the rotating log file.
        max_bytes: Max file size before rotation.
        backup_count: Number of backup files to keep.
        log_format: "human" for text logs, "json" for structured JSON logs.
    """
    global _configured
    if _configured:
        return
    _configured = True

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    if log_format == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(_HUMAN_FMT, datefmt=_DATE_FMT)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(numeric_level)
    ch.setFormatter(formatter)
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
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError as exc:
        root.warning("Could not open log file %s: %s", log_file, exc)


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger (sets up logging with defaults if not yet configured)."""
    global _configured
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
