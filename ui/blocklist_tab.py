"""
Blocklist management tab.

View all blocked IPs, add/unblock manually, import/export.
"""

from __future__ import annotations

import time
from typing import Any

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger
from utils.validators import is_valid_ip

logger = get_logger(__name__)


class BlocklistTab(QWidget):
    """IP blocklist view and management."""

    COLUMNS = ["IP", "Reason", "Blocked At", "Auto?", "🌍 Country", "City"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._blocked: list[dict[str, Any]] = []
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🚫 IP Blocklist")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        # Add IP manually
        add_group = QGroupBox("Block IP Manually")
        add_layout = QHBoxLayout(add_group)
        self._ip_field = QLineEdit()
        self._ip_field.setPlaceholderText("Enter IP address…")
        self._reason_field = QLineEdit()
        self._reason_field.setPlaceholderText("Reason (optional)")
        btn_block = QPushButton("🚫 Block")
        btn_block.setObjectName("dangerBtn")
        btn_block.clicked.connect(self._block_manual)
        for w in (self._ip_field, self._reason_field, btn_block):
            add_layout.addWidget(w)
        layout.addWidget(add_group)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.clicked.connect(self.refresh)
        btn_unblock = QPushButton("🔓 Unblock Selected")
        btn_unblock.setObjectName("successBtn")
        btn_unblock.clicked.connect(self._unblock_selected)
        btn_import = QPushButton("📥 Import .txt")
        btn_import.clicked.connect(self._import_txt)
        btn_export_txt = QPushButton("📤 Export .txt")
        btn_export_txt.clicked.connect(self._export_txt)
        btn_export_csv = QPushButton("📤 Export CSV")
        btn_export_csv.clicked.connect(self._export_csv)
        btn_export_pdf = QPushButton("📄 Export PDF")
        btn_export_pdf.clicked.connect(self._export_pdf)
        for b in (btn_refresh, btn_unblock, btn_import, btn_export_txt, btn_export_csv, btn_export_pdf):
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Table
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

        self._count_label = QLabel("0 blocked IPs")
        layout.addWidget(self._count_label)

    # ------------------------------------------------------------------
    # Data management
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        from core.blocklist import get_all_blocked
        self._blocked = get_all_blocked()
        self._populate()

    def _populate(self) -> None:
        self._table.setRowCount(0)
        for entry in self._blocked:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip = entry.get("ip", "")
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("blocked_at", 0)))
            auto = "✅ Auto" if entry.get("auto_blocked") else "Manual"
            geo = self._get_geo(ip)
            country = f"{geo.get('country', '?')} ({geo.get('countryCode', '?')})"
            city = geo.get("city", "?")
            values = [ip, str(entry.get("reason", "")), ts, auto, country, city]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self._table.setItem(row, col, item)
        self._table.resizeColumnsToContents()
        self._count_label.setText(f"{len(self._blocked)} blocked IP(s)")

    def _get_geo(self, ip: str) -> dict:
        try:
            from core.geo import lookup
            return lookup(ip)
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _block_manual(self) -> None:
        ip = self._ip_field.text().strip()
        reason = self._reason_field.text().strip() or "Manual block"
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "Validation", "Please enter a valid IP address.")
            return
        from core.firewall import block_ip
        from core.blocklist import add_block
        result = block_ip(ip)
        if result["success"]:
            add_block(ip, reason, auto=False)
            self._ip_field.clear()
            self._reason_field.clear()
            self.refresh()
            QMessageBox.information(self, "Blocked", f"{ip} has been blocked.")
        else:
            QMessageBox.warning(self, "Error", result.get("message", "Unknown error"))

    def _unblock_selected(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        ip = self._table.item(rows[0].row(), 0).text()
        confirm = QMessageBox.question(self, "Confirm", f"Unblock {ip}?")
        if confirm != QMessageBox.Yes:
            return
        from core.firewall import unblock_ip
        from core.blocklist import remove_block
        result = unblock_ip(ip)
        remove_block(ip)
        self.refresh()
        msg = f"{ip} unblocked." if result["success"] else result.get("message", "")
        QMessageBox.information(self, "Unblocked", msg)

    def _import_txt(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Blocklist", "", "Text files (*.txt);;All (*)")
        if not path:
            return
        from core.firewall import block_ip
        from core.blocklist import add_block
        count = 0
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    ip = line.strip()
                    if is_valid_ip(ip):
                        block_ip(ip)
                        add_block(ip, "Imported from file")
                        count += 1
            self.refresh()
            QMessageBox.information(self, "Imported", f"{count} IPs imported.")
        except Exception as exc:
            QMessageBox.warning(self, "Import Error", str(exc))

    def _export_txt(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Blocklist", "blocklist.txt", "Text (*.txt)")
        if not path:
            return
        from utils.exporter import export_blocklist_txt
        ips = [b["ip"] for b in self._blocked]
        export_blocklist_txt(ips, path)
        QMessageBox.information(self, "Exported", f"Blocklist saved to {path}")

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "blocklist.csv", "CSV (*.csv)")
        if not path:
            return
        from utils.exporter import export_csv
        export_csv(self._blocked, path)
        QMessageBox.information(self, "Exported", f"CSV saved to {path}")

    def _export_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF", "blocklist.pdf", "PDF (*.pdf)")
        if not path:
            return
        from utils.exporter import blocklist_to_pdf
        ok = blocklist_to_pdf(self._blocked, path)
        if ok:
            QMessageBox.information(self, "Exported", f"PDF saved to {path}")
        else:
            QMessageBox.warning(self, "Error", "PDF export failed. Is reportlab installed?")
