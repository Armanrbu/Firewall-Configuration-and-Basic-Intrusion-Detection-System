"""
Alerts history tab.

Displays IDS alerts with geolocation information.
Supports filtering, resolving, blocking from alert, and export.
"""

from __future__ import annotations

import time
from typing import Any

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger

logger = get_logger(__name__)

_COUNTRY_FLAGS: dict[str, str] = {
    "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "DE": "🇩🇪", "GB": "🇬🇧",
    "FR": "🇫🇷", "IN": "🇮🇳", "BR": "🇧🇷", "JP": "🇯🇵", "KR": "🇰🇷",
    "NL": "🇳🇱", "UA": "🇺🇦", "CA": "🇨🇦", "AU": "🇦🇺", "SG": "🇸🇬",
    "LO": "🏠",  # local
}


def _flag(code: str) -> str:
    return _COUNTRY_FLAGS.get(code, "🌐")


class AlertsTab(QWidget):
    """Alert history table with geolocation and action buttons."""

    COLUMNS = ["#", "Timestamp", "IP", "Type", "🌍 Country", "City", "ISP", "Details", "Resolved"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alerts: list[dict[str, Any]] = []
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🚨 Alert History")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        # Filter bar
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)
        self._unresolved_only = QCheckBox("Unresolved only")
        self._unresolved_only.toggled.connect(self.refresh)
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.clicked.connect(self.refresh)
        btn_export_csv = QPushButton("📤 Export CSV")
        btn_export_csv.clicked.connect(self._export_csv)
        btn_export_pdf = QPushButton("📄 Export PDF")
        btn_export_pdf.clicked.connect(self._export_pdf)
        for w in (self._unresolved_only, btn_refresh, btn_export_csv, btn_export_pdf):
            filter_layout.addWidget(w)
        filter_layout.addStretch()
        layout.addWidget(filter_group)

        # Action buttons
        action_layout = QHBoxLayout()
        self._btn_resolve = QPushButton("✅ Mark Resolved")
        self._btn_resolve.setObjectName("successBtn")
        self._btn_resolve.clicked.connect(self._resolve_selected)
        self._btn_block = QPushButton("🚫 Block IP")
        self._btn_block.setObjectName("dangerBtn")
        self._btn_block.clicked.connect(self._block_from_alert)
        for b in (self._btn_resolve, self._btn_block):
            action_layout.addWidget(b)
        action_layout.addStretch()
        layout.addLayout(action_layout)

        # Splitter: table + detail panel
        splitter = QSplitter(Qt.Vertical)

        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.itemSelectionChanged.connect(self._show_detail)
        splitter.addWidget(self._table)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(180)
        self._detail.setPlaceholderText("Select an alert row to see full details…")
        splitter.addWidget(self._detail)
        splitter.setSizes([400, 150])

        layout.addWidget(splitter)

    # ------------------------------------------------------------------
    # Data management
    # ------------------------------------------------------------------

    def add_alert(self, ip: str, alert_type: str, details: str = "") -> None:
        """Called externally when a new alert is generated."""
        from core.blocklist import add_alert as db_add_alert
        db_add_alert(ip, alert_type, details)
        self.refresh()

    def refresh(self) -> None:
        from core.blocklist import get_alerts
        unresolved_only = self._unresolved_only.isChecked()
        self._alerts = get_alerts(limit=500, unresolved_only=unresolved_only)
        self._populate()

    def _populate(self) -> None:
        self._table.setRowCount(0)
        for i, alert in enumerate(self._alerts):
            row = self._table.rowCount()
            self._table.insertRow(row)
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.get("timestamp", 0)))
            ip = str(alert.get("ip", ""))

            # Geo lookup (cached)
            geo = self._get_geo(ip)
            country_code = geo.get("countryCode", "??")
            flag = _flag(country_code)
            country = f"{flag} {geo.get('country', '?')}"
            city = geo.get("city", "?")
            isp = geo.get("isp", "?")

            resolved = "✅" if alert.get("resolved") else "❌"
            values = [
                str(i + 1),
                ts,
                ip,
                str(alert.get("type", "")),
                country,
                city,
                isp,
                str(alert.get("details", ""))[:80],
                resolved,
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                item.setData(Qt.UserRole, alert.get("id"))
                self._table.setItem(row, col, item)

            if not alert.get("resolved"):
                for col in range(len(self.COLUMNS)):
                    item = self._table.item(row, col)
                    if item:
                        item.setForeground(Qt.white)

        self._table.resizeColumnsToContents()

    def _get_geo(self, ip: str) -> dict:
        try:
            from core.geo import lookup
            return lookup(ip)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _show_detail(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        ip_item = self._table.item(row, 2)
        if not ip_item:
            return
        ip = ip_item.text()
        geo = self._get_geo(ip)
        alert_id = self._table.item(row, 0).data(Qt.UserRole)

        lines = [
            f"<b>Alert ID:</b> {alert_id}",
            f"<b>IP:</b> {ip}",
            f"<b>Timestamp:</b> {self._table.item(row, 1).text()}",
            f"<b>Type:</b> {self._table.item(row, 3).text()}",
            f"<b>Details:</b> {self._table.item(row, 7).text()}",
            "",
            f"<b>Country:</b> {geo.get('country', 'N/A')} ({geo.get('countryCode', '?')})",
            f"<b>City:</b> {geo.get('city', 'N/A')}",
            f"<b>ISP:</b> {geo.get('isp', 'N/A')}",
            f"<b>Org:</b> {geo.get('org', 'N/A')}",
            f"<b>Lat/Lon:</b> {geo.get('lat', 0)}, {geo.get('lon', 0)}",
        ]
        self._detail.setHtml("<br>".join(lines))

    def _resolve_selected(self) -> None:
        from core.blocklist import resolve_alert
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        item = self._table.item(rows[0].row(), 0)
        alert_id = item.data(Qt.UserRole)
        if alert_id:
            resolve_alert(alert_id)
            self.refresh()

    def _block_from_alert(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        ip = self._table.item(rows[0].row(), 2).text()
        from utils.validators import is_valid_ip
        if not is_valid_ip(ip):
            return
        confirm = QMessageBox.question(self, "Confirm", f"Block IP {ip}?")
        if confirm == QMessageBox.Yes:
            from core.firewall import block_ip
            from core.blocklist import add_block
            result = block_ip(ip)
            if result["success"]:
                add_block(ip, "Blocked from alert")
                QMessageBox.information(self, "Blocked", f"{ip} has been blocked.")
            else:
                QMessageBox.warning(self, "Error", result.get("message", "Unknown error"))

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Alerts CSV", "alerts.csv", "CSV (*.csv)")
        if not path:
            return
        from utils.exporter import export_csv
        export_csv(self._alerts, path)
        QMessageBox.information(self, "Exported", f"Alerts exported to {path}")

    def _export_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Alerts PDF", "alerts.pdf", "PDF (*.pdf)")
        if not path:
            return
        from utils.exporter import alerts_to_pdf
        ok = alerts_to_pdf(self._alerts, path)
        if ok:
            QMessageBox.information(self, "Exported", f"PDF report saved to {path}")
        else:
            QMessageBox.warning(self, "Error", "PDF export failed. Is reportlab installed?")
