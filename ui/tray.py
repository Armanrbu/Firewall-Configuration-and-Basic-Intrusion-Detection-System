"""
System tray icon and balloon notifications.
"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QAction,
    QApplication,
    QMenu,
    QSystemTrayIcon,
)

from utils.logger import get_logger

logger = get_logger(__name__)


def _make_icon(color: str = "#7c3aed") -> QIcon:
    """Generate a simple coloured circle icon for the tray."""
    px = QPixmap(64, 64)
    px.fill(Qt.transparent)
    from PySide6.QtGui import QPainter, QBrush
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(4, 4, 56, 56)
    painter.end()
    return QIcon(px)


class TrayIcon(QSystemTrayIcon):
    """
    System tray icon with context menu.

    Provides:
    - Open/close main window
    - Enable/Disable Firewall shortcuts
    - Alert count badge in tooltip
    - Balloon notifications on new alerts
    """

    def __init__(self, main_window, parent=None) -> None:
        icon_path = "assets/icon.png"
        import os
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            icon = _make_icon()

        super().__init__(icon, parent)
        self._window = main_window
        self._alert_count: int = 0

        self._build_menu()
        self.setToolTip("🛡️ NetGuard IDS — Active")
        self.activated.connect(self._on_activated)

    # ------------------------------------------------------------------
    # Menu
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menu = QMenu()

        act_open = QAction("🔓 Open NetGuard", self)
        act_open.triggered.connect(self._show_window)
        menu.addAction(act_open)

        menu.addSeparator()

        act_enable = QAction("🟢 Enable Firewall", self)
        act_enable.triggered.connect(self._enable_firewall)
        menu.addAction(act_enable)

        act_disable = QAction("🔴 Disable Firewall", self)
        act_disable.triggered.connect(self._disable_firewall)
        menu.addAction(act_disable)

        menu.addSeparator()

        act_quit = QAction("❌ Exit", self)
        act_quit.triggered.connect(QApplication.instance().quit)
        menu.addAction(act_quit)

        self.setContextMenu(menu)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_alert_count(self, count: int) -> None:
        self._alert_count = count
        self.setToolTip(f"🛡️ NetGuard IDS — {count} unresolved alert(s)")

    def show_alert_balloon(self, title: str, message: str) -> None:
        if self.supportsMessages():
            self.showMessage(title, message, QSystemTrayIcon.Warning, 5000)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_window()

    def _show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()

    def _enable_firewall(self) -> None:
        from core.firewall import enable_firewall
        result = enable_firewall()
        self.show_alert_balloon(
            "Firewall",
            "Firewall ENABLED ✅" if result["success"] else f"Error: {result['message']}",
        )

    def _disable_firewall(self) -> None:
        from core.firewall import disable_firewall
        result = disable_firewall()
        self.show_alert_balloon(
            "Firewall",
            "Firewall DISABLED ⛔" if result["success"] else f"Error: {result['message']}",
        )
