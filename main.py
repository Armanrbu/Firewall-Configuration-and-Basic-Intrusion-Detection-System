"""
🛡️ NetGuard IDS — Advanced Firewall & Intrusion Detection System
================================================================
Entry point: python main.py

Loads configuration, sets up logging, initialises the SQLite database,
starts the Qt application, and launches the main window.
"""

from __future__ import annotations

import os
import sys


def _bootstrap() -> None:
    """Ensure the project root is on sys.path (for editable installs / direct runs)."""
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


def main() -> int:
    _bootstrap()

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
    )

    from utils.logger import get_logger
    logger = get_logger("main")
    logger.info("Starting NetGuard IDS…")

    # Initialise the database
    from core.blocklist import get_db
    get_db()

    # Load whitelist
    from core.whitelist import load as load_whitelist
    load_whitelist()

    # Start the scheduler
    from core.scheduler import get_scheduler
    get_scheduler().start()

    # Launch Qt application
    try:
        from PyQt5.QtWidgets import QApplication, QSplashScreen
        from PyQt5.QtCore import Qt, QTimer
        from PyQt5.QtGui import QPixmap, QColor
    except ImportError:
        print(
            "ERROR: PyQt5 is not installed.\n"
            "Install it with: pip install PyQt5>=5.15",
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
    from PyQt5.QtGui import QPainter, QFont
    painter = QPainter(splash_px)
    painter.setPen(QColor("#7c3aed"))
    font = QFont("Segoe UI", 22, QFont.Bold)
    painter.setFont(font)
    painter.drawText(splash_px.rect(), Qt.AlignCenter, "NetGuard IDS")
    small_font = QFont("Segoe UI", 10)
    painter.setFont(small_font)
    painter.setPen(QColor("#a0aec0"))
    from PyQt5.QtCore import QRect
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
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())