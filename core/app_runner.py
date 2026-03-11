"""
Unified application runner — Plan 04-04: Frontend integration.

Boots the NetGuardEngine ONCE and wires the same engine/EventBus instance
into whichever frontends are enabled (GUI, FastAPI, Typer-monitor).

Design:
    AppRunner owns the engine lifecycle.
    Frontends call AppRunner.get_engine() / AppRunner.get_bus() to share state.
    The GUI bridges EventBus events → Qt signals via a lightweight adapter.

Usage (headless):
    runner = AppRunner(config)
    runner.start()
    runner.wait_until_stopped()  # blocks (Ctrl-C handled)
    runner.stop()

Usage (GUI):
    runner = AppRunner(config)
    runner.start()
    # PySide6 QApplication.exec() runs the GUI event loop
    runner.stop()
"""

from __future__ import annotations

import threading
import time
from typing import Any, TYPE_CHECKING

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.engine import NetGuardEngine
    from core.event_bus import EventBus

logger = get_logger(__name__)

_runner_lock = threading.Lock()
_global_runner: AppRunner | None = None


class AppRunner:
    """Single owner of the engine + EventBus.  All frontends share one instance."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._engine: NetGuardEngine | None = None
        self._api_server: Any | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Boot the engine (and optional FastAPI server) once."""
        if self._running:
            return

        from core.engine import NetGuardEngine
        from core.scheduler import get_scheduler

        get_scheduler().start()

        self._engine = NetGuardEngine(config=self._config)
        self._engine.start()
        self._running = True
        logger.info("AppRunner started (engine + scheduler).")

        # Optional FastAPI server
        api_cfg = self._config.get("api", {})
        if api_cfg.get("enabled", False):
            try:
                from api.server import APIServer
                self._api_server = APIServer(
                    api_key=api_cfg.get("api_key", ""),
                    port=int(api_cfg.get("port", 5000)),
                )
                self._api_server.start()
            except Exception as exc:
                logger.warning("API server could not start: %s", exc)

    def stop(self) -> None:
        """Gracefully stop engine and API server."""
        if not self._running:
            return
        self._running = False

        if self._api_server:
            try:
                self._api_server.stop()
            except Exception:
                pass

        if self._engine:
            self._engine.stop()

        from core.scheduler import get_scheduler
        try:
            get_scheduler().stop()
        except Exception:
            pass
        logger.info("AppRunner stopped.")

    def wait_until_stopped(self) -> None:
        """Block the calling thread until the engine's stop event fires (headless mode)."""
        if self._engine is None:
            return
        try:
            self._engine._stop_event.wait()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Accessors for frontends
    # ------------------------------------------------------------------

    @property
    def engine(self) -> NetGuardEngine:
        if self._engine is None:
            raise RuntimeError("AppRunner has not been started yet.")
        return self._engine

    @property
    def running(self) -> bool:
        return self._running

    def get_bus(self) -> EventBus:
        """Return the shared EventBus singleton."""
        from core.event_bus import get_event_bus
        return get_event_bus()

    def get_status(self) -> dict[str, Any]:
        """Return a unified status dict suitable for any frontend."""
        engine_status = self._engine.get_status() if self._engine else {}
        api_ok = self._api_server is not None and getattr(self._api_server, "running", False)
        return {
            **engine_status,
            "app_running": self._running,
            "api_server": api_ok,
        }


# ---------------------------------------------------------------------------
# Global singleton helpers
# ---------------------------------------------------------------------------

def get_runner() -> AppRunner:
    global _global_runner
    with _runner_lock:
        if _global_runner is None:
            _global_runner = AppRunner()
    return _global_runner


def set_runner(runner: AppRunner) -> None:
    """Register a pre-configured runner as the global singleton (for tests)."""
    global _global_runner
    with _runner_lock:
        _global_runner = runner


def reset_runner() -> None:
    """Clear the global singleton (for test isolation)."""
    global _global_runner
    with _runner_lock:
        _global_runner = None
