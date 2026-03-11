"""Tests for the logger module including JsonFormatter and setup_logging."""

from __future__ import annotations

import json
import logging
import pytest

from utils.logger import JsonFormatter, setup_logging, get_logger


# ---------------------------------------------------------------------------
# JsonFormatter tests
# ---------------------------------------------------------------------------

class TestJsonFormatter:
    """Tests for the JsonFormatter class."""

    def _make_record(
        self,
        msg: str = "test message",
        level: int = logging.INFO,
        name: str = "test.logger",
        exc_info: tuple | None = None,
    ) -> logging.LogRecord:
        """Helper to create a LogRecord for testing."""
        record = logging.LogRecord(
            name=name,
            level=level,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=exc_info,
        )
        return record

    def test_output_is_valid_json(self) -> None:
        """JsonFormatter.format() returns a string parseable by json.loads()."""
        fmt = JsonFormatter()
        record = self._make_record("hello world")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_required_keys_present(self) -> None:
        """JSON output contains timestamp, level, logger, and message keys."""
        fmt = JsonFormatter()
        record = self._make_record("check keys", level=logging.WARNING, name="my.mod")
        parsed = json.loads(fmt.format(record))
        assert parsed["level"] == "WARNING"
        assert parsed["logger"] == "my.mod"
        assert parsed["message"] == "check keys"
        assert "timestamp" in parsed

    def test_exception_included(self) -> None:
        """Exception info is included when an exception is present."""
        fmt = JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = self._make_record("error happened", level=logging.ERROR, exc_info=exc_info)
        parsed = json.loads(fmt.format(record))
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]
        assert "boom" in parsed["exception"]

    def test_no_exception_key_when_absent(self) -> None:
        """No 'exception' key when there's no exception."""
        fmt = JsonFormatter()
        record = self._make_record("no error")
        parsed = json.loads(fmt.format(record))
        assert "exception" not in parsed

    def test_extra_ip_field(self) -> None:
        """Extra 'ip' field on the record appears in JSON output."""
        fmt = JsonFormatter()
        record = self._make_record("ip event")
        record.ip = "192.168.1.1"  # type: ignore[attr-defined]
        parsed = json.loads(fmt.format(record))
        assert parsed["ip"] == "192.168.1.1"

    def test_different_levels(self) -> None:
        """All standard log levels are correctly serialised."""
        fmt = JsonFormatter()
        for level_name in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            level = getattr(logging, level_name)
            record = self._make_record(f"{level_name} msg", level=level)
            parsed = json.loads(fmt.format(record))
            assert parsed["level"] == level_name

    def test_message_with_special_characters(self) -> None:
        """Messages with quotes, newlines, and unicode are correctly escaped."""
        fmt = JsonFormatter()
        record = self._make_record('line1\nline2 "quoted" — emoji 🔥')
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "emoji 🔥" in parsed["message"]
        assert '"quoted"' in parsed["message"]


# ---------------------------------------------------------------------------
# setup_logging tests
# ---------------------------------------------------------------------------

class TestSetupLogging:
    """Tests for setup_logging and get_logger functions."""

    def test_get_logger_returns_logger(self) -> None:
        """get_logger returns a logging.Logger instance."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_get_logger_idempotent(self) -> None:
        """Calling get_logger twice with the same name returns the same logger."""
        a = get_logger("test.same")
        b = get_logger("test.same")
        assert a is b
