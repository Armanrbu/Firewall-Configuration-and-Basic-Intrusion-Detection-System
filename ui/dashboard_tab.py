"""
Real-time traffic dashboard tab.

Displays live network connections (via psutil) and basic statistics.
"""

from __future__ import annotations

import time
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from utils.logger import get_logger

logger = get_logger(__name__)

_STATUS_COLORS: dict[str, str] = {
    "ESTABLISHED": "#22c55e",
    "LISTEN": "#3b82f6",
    "TIME_WAIT": "#eab308",
    "CLOSE_WAIT": "#f97316",
    "CLOSED": "#6b7280",
}


class StatCard(QWidget):
    """Simple labelled statistic card widget."""

    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        self._value = QLabel("0")
        self._value.setAlignment(Qt.AlignCenter)
        self._value.setStyleSheet("font-size: 22pt; font-weight: bold; color: #7c3aed;")
        self._label = QLabel(label)
        self._label.setAlignment(Qt.AlignCenter)
        self._label.setStyleSheet("color: #a0aec0; font-size: 9pt;")
        layout.addWidget(self._value)
        layout.addWidget(self._label)
        self.setStyleSheet(
            "background:#2a2a3e; border-radius:8px; border:1px solid #3a3a5c;"
        )

    def set_value(self, v: int | str) -> None:
        self._value.setText(str(v))


class DashboardTab(QWidget):
    """Real-time network traffic monitoring tab."""

    COLUMNS = ["Local Address", "Remote IP", "Port", "Status", "PID", "Process"]
    REFRESH_MS = 2000

    def __init__(self, blocklist_ips: set[str] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._flagged_ips: set[str] = blocklist_ips or set()
        self._setup_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(self.REFRESH_MS)

    def set_flagged_ips(self, ips: set[str]) -> None:
        self._flagged_ips = ips

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # Title
        title = QLabel("📊 Real-Time Network Dashboard")
        title.setObjectName("sectionTitle")
        main_layout.addWidget(title)

        # Stat cards row
        cards_layout = QHBoxLayout()
        self._card_total = StatCard("Total Connections Today")
        self._card_blocked = StatCard("Blocked Today")
        self._card_unique = StatCard("Unique IPs Today")
        self._card_active = StatCard("Active Connections")
        for card in (self._card_total, self._card_blocked, self._card_unique, self._card_active):
            cards_layout.addWidget(card)
        main_layout.addLayout(cards_layout)

        # Connection table
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        main_layout.addWidget(self._table)

        # Status line
        self._status = QLabel("Refreshing every 2 seconds…")
        self._status.setStyleSheet("color: #6b7280; font-size: 8pt;")
        main_layout.addWidget(self._status)

    # ------------------------------------------------------------------
    # Data refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        self._update_stats()
        self._update_table()
        self._status.setText(f"Last refreshed: {time.strftime('%H:%M:%S')}")

    def _update_stats(self) -> None:
        try:
            from core.blocklist import get_stats_today
            stats = get_stats_today()
            self._card_total.set_value(stats.get("total", 0))
            self._card_blocked.set_value(stats.get("blocked", 0))
            self._card_unique.set_value(stats.get("unique_ips", 0))
        except Exception as exc:
            logger.debug("Stats update error: %s", exc)

        if HAS_PSUTIL:
            try:
                conns = [c for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED"]
                self._card_active.set_value(len(conns))
            except Exception:
                pass

    def _update_table(self) -> None:
        if not HAS_PSUTIL:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as exc:
            logger.debug("net_connections error: %s", exc)
            return

        pid_map: dict[int, str] = {}

        self._table.setRowCount(0)
        for conn in conns:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            row = self._table.rowCount()
            self._table.insertRow(row)

            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote_port = str(conn.raddr.port)
            status = conn.status or ""
            pid = conn.pid or 0

            proc_name = ""
            if pid:
                if pid in pid_map:
                    proc_name = pid_map[pid]
                else:
                    try:
                        proc_name = psutil.Process(pid).name()
                        pid_map[pid] = proc_name
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "?"
                        pid_map[pid] = proc_name

            values = [local, remote_ip, remote_port, status, str(pid) if pid else "", proc_name]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self._table.setItem(row, col, item)

            # Row colouring
            if remote_ip in self._flagged_ips:
                bg = QColor("#7f1d1d")  # dark red for flagged
            else:
                color_hex = _STATUS_COLORS.get(status, "#2a2a3e")
                bg = QColor(color_hex)
                bg.setAlpha(60)
            for col in range(len(self.COLUMNS)):
                item = self._table.item(row, col)
                if item:
                    item.setBackground(bg)

        self._table.resizeColumnsToContents()
