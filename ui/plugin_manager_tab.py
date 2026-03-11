"""
Plugin Manager Tab — lists, enables, disables, and reloads detection plugins.

Shows all registered AbstractDetector instances (built-in + third-party),
their status, version, description, and provides enable/disable toggles,
a reload button, and an install-from-PyPI command helper.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
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

logger = get_logger(__name__)


class PluginManagerTab(QWidget):
    """
    Tab showing all registered detector plugins with enable/disable controls.

    Signals:
        plugin_toggled(name, enabled)   — emitted when a plugin's state changes
        reload_requested()              — emitted when user clicks Reload All
    """

    plugin_toggled   = Signal(str, bool)
    reload_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._disabled_plugins: set[str] = set()
        self._setup_ui()
        # Auto-refresh every 10 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(10_000)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # ── Header ──────────────────────────────────────────────────────
        title = QLabel("🔌 Detection Plugin Manager")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #4fc3f7;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Manage built-in and third-party detector plugins. "
            "Third-party plugins register via the <code>netguard.detectors</code> entry-point."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #b0bec5; font-size: 12px;")
        layout.addWidget(subtitle)

        # ── Toolbar ──────────────────────────────────────────────────────
        toolbar = QHBoxLayout()

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Filter plugins…")
        self._search.textChanged.connect(self._filter_table)
        self._search.setFixedHeight(32)
        toolbar.addWidget(self._search)

        toolbar.addStretch()

        self._reload_btn = QPushButton("↺  Reload All Plugins")
        self._reload_btn.setFixedHeight(32)
        self._reload_btn.setStyleSheet(
            "background:#1565c0; color:white; border-radius:5px; padding:0 14px;"
        )
        self._reload_btn.clicked.connect(self._on_reload)
        toolbar.addWidget(self._reload_btn)

        self._discover_btn = QPushButton("🔍  Discover Entry-Points")
        self._discover_btn.setFixedHeight(32)
        self._discover_btn.setStyleSheet(
            "background:#00695c; color:white; border-radius:5px; padding:0 14px;"
        )
        self._discover_btn.clicked.connect(self._on_discover)
        toolbar.addWidget(self._discover_btn)

        layout.addLayout(toolbar)

        # ── Plugin table ─────────────────────────────────────────────────
        grp = QGroupBox("Registered Detectors")
        grp.setStyleSheet(
            "QGroupBox{border:1px solid #37474f; border-radius:6px; margin-top:8px; color:#90caf9;}"
            "QGroupBox::title{subcontrol-origin:margin; subcontrol-position:top left; padding:0 6px;}"
        )
        grp_layout = QVBoxLayout(grp)

        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Version", "Type", "Status", "Description", "Actions"]
        )
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet(
            "QTableWidget{background:#1a2332; color:#cfd8dc; gridline-color:#37474f; border:none;}"
            "QTableWidget::item:alternate{background:#1e2d3d;}"
            "QHeaderView::section{background:#263040; color:#90caf9; border:1px solid #37474f; padding:4px;}"
        )
        grp_layout.addWidget(self._table)
        layout.addWidget(grp)

        # ── Stats bar ────────────────────────────────────────────────────
        self._stats_label = QLabel("Plugins: 0 total | 0 enabled | 0 disabled")
        self._stats_label.setStyleSheet("color:#78909c; font-size:11px;")
        layout.addWidget(self._stats_label)

        # Install helper
        install_grp = QGroupBox("Install Third-Party Plugin")
        install_grp.setStyleSheet(
            "QGroupBox{border:1px solid #37474f; border-radius:6px; margin-top:4px; color:#90caf9;}"
            "QGroupBox::title{subcontrol-origin:margin; padding:0 6px;}"
        )
        install_layout = QHBoxLayout(install_grp)
        install_layout.addWidget(QLabel("pip install"))
        self._pip_input = QLineEdit()
        self._pip_input.setPlaceholderText("e.g. netguard-dpi-plugin==1.0.0")
        install_layout.addWidget(self._pip_input)
        self._install_btn = QPushButton("Install & Reload")
        self._install_btn.setStyleSheet(
            "background:#4a148c; color:white; border-radius:5px; padding:4px 12px;"
        )
        self._install_btn.clicked.connect(self._on_install)
        install_layout.addWidget(self._install_btn)
        layout.addWidget(install_grp)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload plugin list from DetectorRegistry."""
        try:
            from core.detector_registry import get_registry
            registry = get_registry()
            plugins = self._collect_plugin_info(registry)
            self._populate_table(plugins)
            enabled  = sum(1 for p in plugins if p["enabled"])
            self._stats_label.setText(
                f"Plugins: {len(plugins)} total | {enabled} enabled | "
                f"{len(plugins) - enabled} disabled"
            )
        except Exception as exc:
            logger.warning("PluginManagerTab.refresh error: %s", exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_plugin_info(self, registry: Any) -> list[dict]:
        plugins = []
        for name in registry.names:
            detector = registry.get(name)
            if detector is None:
                continue
            cls       = type(detector)
            doc       = (cls.__doc__ or "").strip().split("\n")[0][:80]
            plugin_type = "Third-party" if "site-packages" in getattr(
                cls.__module__, "__file__", cls.__module__ or ""
            ) else "Built-in"
            plugins.append({
                "name":    name,
                "version": getattr(detector, "version", "?"),
                "type":    plugin_type,
                "enabled": name not in self._disabled_plugins,
                "desc":    doc or "No description.",
                "obj":     detector,
            })
        return plugins

    def _populate_table(self, plugins: list[dict]) -> None:
        query = self._search.text().lower()
        visible = [p for p in plugins if query in p["name"].lower() or query in p["desc"].lower()]

        self._table.setRowCount(len(visible))
        for row, p in enumerate(visible):
            self._table.setItem(row, 0, QTableWidgetItem(p["name"]))
            self._table.setItem(row, 1, QTableWidgetItem(p["version"]))
            self._table.setItem(row, 2, QTableWidgetItem(p["type"]))

            status_item = QTableWidgetItem("● Enabled" if p["enabled"] else "○ Disabled")
            status_item.setForeground(
                Qt.GlobalColor.green if p["enabled"] else Qt.GlobalColor.red
            )
            self._table.setItem(row, 3, status_item)
            self._table.setItem(row, 4, QTableWidgetItem(p["desc"]))

            # Action button in last column
            btn = QPushButton("Disable" if p["enabled"] else "Enable")
            btn.setProperty("plugin_name", p["name"])
            btn.setProperty("currently_enabled", p["enabled"])
            btn.setStyleSheet(
                f"background:{'#b71c1c' if p['enabled'] else '#1b5e20'}; "
                "color:white; border-radius:4px; padding:2px 8px;"
            )
            btn.clicked.connect(self._on_toggle)
            self._table.setCellWidget(row, 5, btn)

    def _filter_table(self) -> None:
        self.refresh()

    def _on_toggle(self) -> None:
        btn    = self.sender()
        name   = btn.property("plugin_name")
        currently = btn.property("currently_enabled")
        new_state  = not currently
        if new_state:
            self._disabled_plugins.discard(name)
        else:
            self._disabled_plugins.add(name)
        self.plugin_toggled.emit(name, new_state)
        self.refresh()

    def _on_reload(self) -> None:
        self.reload_requested.emit()
        self.refresh()
        QMessageBox.information(self, "Reload", "Plugin registry reloaded.")

    def _on_discover(self) -> None:
        try:
            from core.detector_registry import get_registry
            count = get_registry().discover_plugins()
            self.refresh()
            QMessageBox.information(
                self, "Discovery",
                f"Entry-point discovery complete — {count} new plugin(s) loaded."
            )
        except Exception as exc:
            QMessageBox.warning(self, "Discovery Failed", str(exc))

    def _on_install(self) -> None:
        pkg = self._pip_input.text().strip()
        if not pkg:
            return
        import subprocess, sys
        reply = QMessageBox.question(
            self, "Install Plugin",
            f"Install package via pip:\n  pip install {pkg}\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                self._on_discover()
                QMessageBox.information(self, "Installed", f"Successfully installed {pkg}.")
            else:
                QMessageBox.critical(self, "Install Failed", result.stderr[:500])
        except Exception as exc:
            QMessageBox.critical(self, "Install Error", str(exc))
