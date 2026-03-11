"""
Firewall rules management tab.

View, add, and remove firewall rules created by NetGuard.
Supports block by IP, port, or IP+port combo.
Import/export rules to CSV.
"""

from __future__ import annotations

import csv
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
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
from utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)


class RulesTab(QWidget):
    """Firewall rules management tab."""

    COLUMNS = ["Rule Name", "Type", "Target", "Protocol", "Direction", "Action"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🔐 Firewall Rules Manager")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        # Add rule group
        add_group = QGroupBox("Add New Rule")
        add_layout = QHBoxLayout(add_group)

        self._type_combo = QComboBox()
        self._type_combo.addItems(["Block IP", "Block Port", "Block IP + Port"])
        self._type_combo.currentTextChanged.connect(self._on_type_changed)

        self._ip_field = QLineEdit()
        self._ip_field.setPlaceholderText("IP address (e.g. 1.2.3.4)")

        self._port_field = QLineEdit()
        self._port_field.setPlaceholderText("Port (e.g. 22)")
        self._port_field.setEnabled(False)

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["TCP", "UDP"])

        btn_add = QPushButton("➕ Add Rule")
        btn_add.clicked.connect(self._add_rule)

        for w in (self._type_combo, self._ip_field, self._port_field, self._proto_combo, btn_add):
            add_layout.addWidget(w)
        layout.addWidget(add_group)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.clicked.connect(self.refresh)
        btn_delete = QPushButton("🗑️ Delete Selected")
        btn_delete.setObjectName("dangerBtn")
        btn_delete.clicked.connect(self._delete_selected)
        btn_export = QPushButton("📤 Export CSV")
        btn_export.clicked.connect(self._export_csv)
        btn_import = QPushButton("📥 Import CSV")
        btn_import.clicked.connect(self._import_csv)
        for b in (btn_refresh, btn_delete, btn_export, btn_import):
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Rules table
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

    def _on_type_changed(self, text: str) -> None:
        self._ip_field.setEnabled("IP" in text)
        self._port_field.setEnabled("Port" in text)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        from core.firewall import list_rules
        result = list_rules()
        rules = result.get("rules", [])
        self._table.setRowCount(0)
        for rule in rules:
            row = self._table.rowCount()
            self._table.insertRow(row)
            # Normalise keys for cross-platform display
            name = rule.get("name") or rule.get("raw", "")
            values = [
                name,
                self._detect_type(name),
                self._detect_target(name),
                rule.get("protocol", ""),
                rule.get("direction", ""),
                rule.get("action", "DROP"),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self._table.setItem(row, col, item)
        self._table.resizeColumnsToContents()

    def _add_rule(self) -> None:
        from core.firewall import block_ip, block_port
        from core.blocklist import add_block
        rule_type = self._type_combo.currentText()
        ip = self._ip_field.text().strip()
        port_str = self._port_field.text().strip()
        proto = self._proto_combo.currentText()

        if "IP" in rule_type:
            if not is_valid_ip(ip):
                QMessageBox.warning(self, "Validation", "Please enter a valid IP address.")
                return
        if "Port" in rule_type:
            if not is_valid_port(port_str):
                QMessageBox.warning(self, "Validation", "Please enter a valid port (1–65535).")
                return

        if rule_type == "Block IP":
            result = block_ip(ip)
            if result["success"]:
                add_block(ip, "Manual rule")
        elif rule_type == "Block Port":
            result = block_port(int(port_str), proto)
        else:
            result = block_ip(ip)
            if result["success"]:
                result2 = block_port(int(port_str), proto)
                add_block(ip, f"IP+Port rule with port {port_str}/{proto}")

        msg = result.get("message", "")
        if result.get("success"):
            QMessageBox.information(self, "Rule Added", msg)
            self.refresh()
        else:
            QMessageBox.warning(self, "Error", msg)

    def _delete_selected(self) -> None:
        from core.firewall import unblock_ip, unblock_port
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        name = self._table.item(rows[0].row(), 0).text()
        target = self._table.item(rows[0].row(), 2).text()
        rule_type = self._table.item(rows[0].row(), 1).text()

        confirm = QMessageBox.question(
            self, "Confirm", f"Delete rule: {name}?"
        )
        if confirm != QMessageBox.Yes:
            return

        if is_valid_ip(target):
            unblock_ip(target)
        elif target.isdigit():
            proto = self._table.item(rows[0].row(), 3).text() or "TCP"
            unblock_port(int(target), proto)

        self.refresh()

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Rules", "rules.csv", "CSV (*.csv)")
        if not path:
            return
        from core.firewall import list_rules
        from utils.exporter import export_csv
        rules = list_rules().get("rules", [])
        export_csv(rules, path)
        QMessageBox.information(self, "Exported", f"Rules exported to {path}")

    def _import_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Rules", "", "CSV (*.csv)")
        if not path:
            return
        from core.firewall import block_ip, block_port
        from core.blocklist import add_block
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                count = 0
                for row in reader:
                    target = row.get("Target", "")
                    if is_valid_ip(target):
                        block_ip(target)
                        add_block(target, "Imported from CSV")
                        count += 1
                    elif is_valid_port(target):
                        block_port(int(target))
                        count += 1
            self.refresh()
            QMessageBox.information(self, "Imported", f"{count} rules imported.")
        except Exception as exc:
            QMessageBox.warning(self, "Import Error", str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_type(name: str) -> str:
        if "Port" in name:
            return "Port"
        if "Block" in name:
            return "IP"
        return "Unknown"

    @staticmethod
    def _detect_target(name: str) -> str:
        # NetGuard_Block_1.2.3.4 → 1.2.3.4
        parts = name.split("_")
        return parts[-1] if parts else ""
