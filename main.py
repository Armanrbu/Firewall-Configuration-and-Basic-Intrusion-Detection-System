"""
🛡️ NetGuard IDS — Advanced Firewall & Intrusion Detection System
================================================================
Entry point: python main.py          (GUI mode)
             python main.py --headless  (server / daemon mode)

Loads configuration, sets up logging, initialises the SQLite database,
and either launches the Qt GUI or runs the engine headless.
"""

from __future__ import annotations

import argparse
import os
import sys


def _bootstrap() -> None:
    """Ensure the project root is on sys.path (for editable installs / direct runs)."""
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetGuard IDS — Advanced Firewall & Intrusion Detection System",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run the engine without the GUI (server / daemon mode)",
    )
    return parser.parse_args()


def main() -> int:
    _bootstrap()
    args = _parse_args()

    # Load .env file if present (optional dependency)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    # Load configuration
    from utils.config_loader import load as load_config
    config = load_config("config.yaml")

    # Configure logging early
    from utils.logger import setup_logging
    logging_cfg = config.get("logging", {})
    setup_logging(
        level=logging_cfg.get("level", "INFO"),
        log_file=logging_cfg.get("file", "netguard.log"),
        max_bytes=logging_cfg.get("max_bytes", 10_485_760),
        backup_count=logging_cfg.get("backup_count", 5),
        log_format=logging_cfg.get("format", "human"),
    )

    from utils.logger import get_logger
    logger = get_logger("main")
    logger.info("Starting NetGuard IDS…")

    # Initialise the database
    from core.blocklist import get_db
    get_db()

    # Startup log pruning
    from core.blocklist import prune_connection_log, prune_old_alerts
    retention = config.get("database", {}).get("retention", {})
    pruned = prune_connection_log(
        max_age_days=retention.get("connection_log_days", 30),
        max_rows=retention.get("connection_log_max_rows", 100_000),
    )
    pruned_alerts = prune_old_alerts(
        max_age_days=retention.get("alert_log_days", 90),
    )
    if pruned or pruned_alerts:
        logger.info("Startup pruning: %d log entries, %d old alerts removed", pruned, pruned_alerts)

    # Load whitelist
    from core.whitelist import load as load_whitelist
    load_whitelist()

    # Register cleanup handlers
    import atexit
    import signal

    def _cleanup():
        from core.scheduler import get_scheduler as _gs
        try:
            _gs().stop()
        except Exception:
            pass
        from core.blocklist import close_all_connections
        try:
            close_all_connections()
        except Exception:
            pass

    atexit.register(_cleanup)

    # Allow Ctrl+C to terminate the app cleanly
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # Global exception handler
    def _excepthook(exc_type, exc_value, exc_tb):
        logger.critical(
            "Unhandled exception: %s: %s",
            exc_type.__name__, exc_value,
            exc_info=(exc_type, exc_value, exc_tb),
        )

    sys.excepthook = _excepthook

    # ── Branch: headless vs GUI ─────────────────────────────────────────
    if args.headless:
        return _run_headless(config, logger)
    else:
        return _run_gui(config, logger)


def _run_headless(config: dict, logger) -> int:
    """Run the engine in headless mode (no GUI, no Qt imports)."""
    from core.engine import NetGuardEngine
    from core.scheduler import get_scheduler

    # Start scheduler
    get_scheduler().start()

    engine = NetGuardEngine(config=config)
    engine.start()

    logger.info("NetGuard IDS running in headless mode. Press Ctrl+C to stop.")

    # Block until interrupted
    try:
        engine._stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        logger.info("Headless engine shut down.")

    return 0


def _run_gui(config: dict, logger) -> int:
    """Launch the Qt GUI application."""
    # Start the scheduler
    from core.scheduler import get_scheduler
    get_scheduler().start()

    try:
        from PySide6.QtWidgets import QApplication, QSplashScreen
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QPixmap, QColor
    except ImportError:
        print(
            "ERROR: PySide6 is not installed.\n"
            "Install it with: pip install PySide6>=5.15\n"
            "Or run headless: python main.py --headless",
            file=sys.stderr,
        )
        return 1

    app = QApplication(sys.argv)
    app.setApplicationName("NetGuard IDS")
    app.setOrganizationName("NetGuard")
    app.setQuitOnLastWindowClosed(False)  # allow minimize-to-tray

    # Splash screen
    splash_px = QPixmap(480, 220)
    splash_px.fill(QColor("#1e1e2e"))
    splash = QSplashScreen(splash_px, Qt.WindowStaysOnTopHint)
    from PySide6.QtGui import QPainter, QFont
    from PySide6.QtCore import QRect
    painter = QPainter(splash_px)
    painter.setPen(QColor("#7c3aed"))
    font = QFont("Segoe UI", 22, QFont.Bold)
    painter.setFont(font)
    painter.drawText(splash_px.rect(), Qt.AlignCenter, "NetGuard IDS")
    small_font = QFont("Segoe UI", 10)
    painter.setFont(small_font)
    painter.setPen(QColor("#a0aec0"))
    painter.drawText(QRect(0, 140, 480, 40), Qt.AlignCenter, "Advanced Firewall & Intrusion Detection System")
    painter.end()
    splash.setPixmap(splash_px)
    splash.show()
    app.processEvents()

    # Small delay for visual effect
    import time
    time.sleep(0.8)

    # Create and show main window
    from ui.main_window import MainWindow
    window = MainWindow(config=config)

    splash.finish(window)
    window.show()

    logger.info("NetGuard IDS is ready.")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())