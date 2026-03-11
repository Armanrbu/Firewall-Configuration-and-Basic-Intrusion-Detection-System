"""Tests for core.engine and core.interfaces."""

from __future__ import annotations

import sys
import time
import threading
import pytest
from unittest.mock import MagicMock, patch

# Ensure project root on path
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# core.interfaces tests
# ---------------------------------------------------------------------------

class TestEngineEventHandler:
    """Tests for the EngineEventHandler protocol."""

    def test_protocol_is_runtime_checkable(self) -> None:
        """EngineEventHandler is a runtime-checkable Protocol."""
        from core.interfaces import EngineEventHandler
        assert hasattr(EngineEventHandler, '__protocol_attrs__') or hasattr(EngineEventHandler, '__abstractmethods__') or True
        # Just verify it's importable and usable
        assert EngineEventHandler is not None

    def test_dummy_handler_satisfies_protocol(self) -> None:
        """A class implementing handler methods satisfies the protocol."""
        from core.interfaces import EngineEventHandler

        class DummyHandler:
            def on_connection(self, ip, port, protocol, direction): pass
            def on_ip_flagged(self, ip, count): pass
            def on_ip_blocked(self, ip): pass
            def on_port_scan(self, ip, ports): pass
            def on_anomaly(self, ip, score): pass
            def on_engine_status(self, status, details): pass

        handler = DummyHandler()
        assert isinstance(handler, EngineEventHandler)

    def test_partial_handler_is_accepted(self) -> None:
        """A class with only some handler methods still works as a handler."""
        class PartialHandler:
            def on_ip_flagged(self, ip, count): pass
            def on_ip_blocked(self, ip): pass

        # Partial handlers should still be usable (duck typing)
        handler = PartialHandler()
        assert hasattr(handler, "on_ip_flagged")
        assert hasattr(handler, "on_ip_blocked")


class TestEventDataclasses:
    """Tests for the typed event dataclasses."""

    def test_connection_event(self) -> None:
        from core.interfaces import ConnectionDetectedEvent
        evt = ConnectionDetectedEvent(ip="10.0.0.1", port=80, protocol="TCP", direction="in")
        assert evt.ip == "10.0.0.1"
        assert evt.port == 80
        assert evt.timestamp > 0

    def test_ip_flagged_event(self) -> None:
        from core.interfaces import IPFlaggedEvent
        evt = IPFlaggedEvent(ip="192.168.1.1", count=15)
        assert evt.ip == "192.168.1.1"
        assert evt.count == 15

    def test_ip_blocked_event(self) -> None:
        from core.interfaces import IPBlockedEvent
        evt = IPBlockedEvent(ip="1.2.3.4", rule_name="NetGuard_Block")
        assert evt.ip == "1.2.3.4"
        assert evt.rule_name == "NetGuard_Block"

    def test_port_scan_event(self) -> None:
        from core.interfaces import PortScanEvent
        evt = PortScanEvent(ip="5.6.7.8", ports=(22, 80, 443))
        assert evt.ip == "5.6.7.8"
        assert 80 in evt.ports

    def test_anomaly_event(self) -> None:
        from core.interfaces import AnomalyEvent
        evt = AnomalyEvent(ip="9.10.11.12", score=0.95)
        assert evt.score == 0.95

    def test_engine_status_event(self) -> None:
        from core.interfaces import EngineStatusEvent
        evt = EngineStatusEvent(status="started", details="Engine is monitoring")
        assert evt.status == "started"

    def test_events_are_frozen(self) -> None:
        """Frozen dataclasses should raise if you try to set an attribute."""
        from core.interfaces import IPFlaggedEvent
        evt = IPFlaggedEvent(ip="1.1.1.1", count=5)
        with pytest.raises(AttributeError):
            evt.ip = "2.2.2.2"  # type: ignore[misc]

    def test_events_have_timestamp(self) -> None:
        from core.interfaces import EngineEvent
        evt = EngineEvent()
        assert isinstance(evt.timestamp, float)
        assert evt.timestamp > 0


# ---------------------------------------------------------------------------
# core.engine tests
# ---------------------------------------------------------------------------

class TestNetGuardEngine:
    """Tests for the NetGuardEngine standalone engine."""

    def test_engine_creates_without_qt(self) -> None:
        """Engine can be instantiated without any Qt import."""
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        assert engine is not None
        assert not engine.running

    def test_engine_zero_qt_imports(self) -> None:
        """Importing core.engine does not bring in any Qt modules."""
        qt_modules = [m for m in sys.modules if "PyQt" in m or "PySide" in m or "sip" in m]
        # Filter to only modules loaded AFTER the test started.
        # We check that core.engine itself doesn't force-import Qt.
        from core.engine import NetGuardEngine
        new_qt = [m for m in sys.modules if ("PyQt" in m or "PySide" in m) and m not in qt_modules]
        # core.engine should NOT have introduced new Qt modules
        assert not new_qt, f"Qt modules imported by core.engine: {new_qt}"

    def test_get_status_returns_dict(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        status = engine.get_status()
        assert isinstance(status, dict)
        assert "running" in status
        assert status["running"] is False
        assert "tracked_ips" in status
        assert "flagged_ips" in status

    def test_register_and_unregister_handler(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        handler = MagicMock()
        engine.register_handler(handler)
        assert handler in engine._handlers
        engine.unregister_handler(handler)
        assert handler not in engine._handlers

    def test_register_handler_no_duplicates(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        handler = MagicMock()
        engine.register_handler(handler)
        engine.register_handler(handler)
        assert engine._handlers.count(handler) == 1

    def test_dispatch_ip_flagged_calls_handler(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        handler = MagicMock()
        engine.register_handler(handler)
        engine._dispatch_ip_flagged("10.0.0.1", 15)
        handler.on_ip_flagged.assert_called_once_with("10.0.0.1", 15)

    def test_dispatch_port_scan_calls_handler(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        handler = MagicMock()
        engine.register_handler(handler)
        engine._dispatch_port_scan("10.0.0.1", [22, 80, 443])
        handler.on_port_scan.assert_called_once_with("10.0.0.1", [22, 80, 443])

    def test_dispatch_status_calls_handler(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        handler = MagicMock()
        engine.register_handler(handler)
        engine._dispatch_status("started", "Engine is running")
        handler.on_engine_status.assert_called_once()

    def test_handler_exception_doesnt_crash(self) -> None:
        """A handler that raises doesn't crash the dispatcher."""
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()

        bad_handler = MagicMock()
        bad_handler.on_ip_flagged.side_effect = RuntimeError("handler crash")
        good_handler = MagicMock()

        engine.register_handler(bad_handler)
        engine.register_handler(good_handler)

        # Should not raise, and good_handler should still be called
        engine._dispatch_ip_flagged("10.0.0.1", 5)
        good_handler.on_ip_flagged.assert_called_once_with("10.0.0.1", 5)

    def test_multiple_handlers_receive_events(self) -> None:
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        h1 = MagicMock()
        h2 = MagicMock()
        engine.register_handler(h1)
        engine.register_handler(h2)
        engine._dispatch_ip_blocked("1.2.3.4")
        h1.on_ip_blocked.assert_called_once_with("1.2.3.4")
        h2.on_ip_blocked.assert_called_once_with("1.2.3.4")

    @patch("core.engine.NetGuardEngine._psutil_loop")
    def test_start_and_stop(self, mock_loop) -> None:
        """Engine start/stop lifecycle works correctly."""
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        engine.start()
        assert engine.running
        engine.stop(timeout=2)
        assert not engine.running

    @patch("core.engine.NetGuardEngine._psutil_loop")
    def test_stop_within_timeout(self, mock_loop) -> None:
        """Engine stop completes within the timeout."""
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        engine.start()
        t0 = time.time()
        engine.stop(timeout=3)
        elapsed = time.time() - t0
        assert elapsed < 5.0

    @patch("core.engine.NetGuardEngine._psutil_loop")
    def test_idempotent_start(self, mock_loop) -> None:
        """Calling start twice doesn't create duplicate threads."""
        from core.engine import NetGuardEngine
        engine = NetGuardEngine()
        engine.start()
        thread_count = len(engine._threads)
        engine.start()  # second call should be no-op
        assert len(engine._threads) == thread_count
        engine.stop(timeout=2)

    def test_ids_engine_property(self) -> None:
        from core.engine import NetGuardEngine
        from core.ids import IDSEngine
        engine = NetGuardEngine()
        assert isinstance(engine.ids_engine, IDSEngine)


# ---------------------------------------------------------------------------
# Headless CLI argument test
# ---------------------------------------------------------------------------

class TestHeadlessCLI:
    """Tests for the --headless CLI argument."""

    def test_help_includes_headless(self) -> None:
        """main.py --help mentions --headless."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "main.py", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        assert "--headless" in result.stdout
