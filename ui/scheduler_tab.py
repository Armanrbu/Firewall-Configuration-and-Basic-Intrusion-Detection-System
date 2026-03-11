"""
Time-based rule scheduler tab.

Allows users to create rules like "Block port 22 from 22:00 to 06:00 daily".
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QTime

from utils.logger import get_logger
from utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)

_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


class SchedulerTab(QWidget):
    """Time-based firewall rule scheduler UI."""

    COLUMNS = ["ID", "Action", "Target", "Type", "Protocol", "Start", "End", "Days", "Enabled"]

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

        title = QLabel("⏰ Rule Scheduler")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        # Create rule group
        create_group = QGroupBox("Create Scheduled Rule")
        form = QVBoxLayout(create_group)

        row1 = QHBoxLayout()
        self._action_combo = QComboBox()
        self._action_combo.addItems(["block", "unblock"])
        row1.addWidget(QLabel("Action:"))
        row1.addWidget(self._action_combo)

        self._type_combo = QComboBox()
        self._type_combo.addItems(["ip", "port"])
        row1.addWidget(QLabel("Target type:"))
        row1.addWidget(self._type_combo)

        self._target_field = QLineEdit()
        self._target_field.setPlaceholderText("IP or port number")
        row1.addWidget(QLabel("Target:"))
        row1.addWidget(self._target_field)

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["TCP", "UDP"])
        row1.addWidget(QLabel("Protocol:"))
        row1.addWidget(self._proto_combo)

        form.addLayout(row1)

        row2 = QHBoxLayout()
        self._start_time = QTimeEdit()
        self._start_time.setDisplayFormat("HH:mm")
        self._start_time.setTime(QTime(22, 0))
        row2.addWidget(QLabel("Start time:"))
        row2.addWidget(self._start_time)

        self._end_time = QTimeEdit()
        self._end_time.setDisplayFormat("HH:mm")
        self._end_time.setTime(QTime(6, 0))
        row2.addWidget(QLabel("End time:"))
        row2.addWidget(self._end_time)

        form.addLayout(row2)

        # Day checkboxes
        day_row = QHBoxLayout()
        day_row.addWidget(QLabel("Days:"))
        self._day_checks: dict[str, QCheckBox] = {}
        for day in _DAYS:
            cb = QCheckBox(day[:3].capitalize())
            cb.setChecked(True)
            self._day_checks[day] = cb
            day_row.addWidget(cb)
        form.addLayout(day_row)

        btn_add = QPushButton("➕ Add Scheduled Rule")
        btn_add.clicked.connect(self._add_rule)
        form.addWidget(btn_add)

        layout.addWidget(create_group)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.clicked.connect(self.refresh)
        btn_delete = QPushButton("🗑️ Delete Selected")
        btn_delete.setObjectName("dangerBtn")
        btn_delete.clicked.connect(self._delete_selected)
        for b in (btn_refresh, btn_delete):
            btn_row.addWidget(b)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Rules table
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

    # ------------------------------------------------------------------
    # Data management
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        from core.scheduler import get_scheduler
        rules = get_scheduler().get_rules()
        self._table.setRowCount(0)
        for rule in rules:
            row = self._table.rowCount()
            self._table.insertRow(row)
            days_str = ", ".join(d[:3] for d in rule.days) if rule.days else "All"
            values = [
                str(rule.rule_id),
                rule.action,
                rule.target,
                rule.target_type,
                rule.protocol,
                rule.start_time,
                rule.end_time,
                days_str,
                "✅" if rule.enabled else "❌",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self._table.setItem(row, col, item)
        self._table.resizeColumnsToContents()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _add_rule(self) -> None:
        target = self._target_field.text().strip()
        target_type = self._type_combo.currentText()

        if target_type == "ip" and not is_valid_ip(target):
            QMessageBox.warning(self, "Validation", "Invalid IP address.")
            return
        if target_type == "port" and not is_valid_port(target):
            QMessageBox.warning(self, "Validation", "Invalid port number.")
            return

        days = [d for d, cb in self._day_checks.items() if cb.isChecked()]

        from core.scheduler import ScheduledRule, get_scheduler
        rule_id = int(time.time())
        rule = ScheduledRule(
            rule_id=rule_id,
            action=self._action_combo.currentText(),
            target=target,
            target_type=target_type,
            protocol=self._proto_combo.currentText(),
            start_time=self._start_time.time().toString("HH:mm"),
            end_time=self._end_time.time().toString("HH:mm"),
            days=days,
            enabled=True,
        )
        get_scheduler().add_rule(rule)
        self._target_field.clear()
        self.refresh()
        QMessageBox.information(self, "Added", f"Scheduled rule created (ID: {rule_id}).")

    def _delete_selected(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        rule_id_str = self._table.item(rows[0].row(), 0).text()
        confirm = QMessageBox.question(self, "Confirm", f"Delete scheduled rule {rule_id_str}?")
        if confirm != QMessageBox.Yes:
            return
        from core.scheduler import get_scheduler
        get_scheduler().remove_rule(int(rule_id_str))
        self.refresh()
