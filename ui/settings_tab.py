"""
Settings tab — configure all application parameters.

Changes are saved to config.yaml when the user clicks "Save Settings".
"""

from __future__ import annotations

from typing import Any

from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger

logger = get_logger(__name__)


class SettingsTab(QWidget):
    """Application settings editor."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()
        self._load()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)

        title = QLabel("⚙️ Settings")
        title.setObjectName("sectionTitle")
        outer.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 12, 0)

        # — IDS Settings
        ids_group = QGroupBox("🕵️ IDS Settings")
        ids_form = QFormLayout(ids_group)

        self._threshold = QSpinBox()
        self._threshold.setRange(1, 10000)
        ids_form.addRow("Alert threshold (connections):", self._threshold)

        self._window = QSpinBox()
        self._window.setRange(1, 3600)
        self._window.setSuffix(" s")
        ids_form.addRow("Time window:", self._window)

        self._auto_block = QCheckBox("Auto-block IPs that exceed threshold")
        ids_form.addRow(self._auto_block)

        self._port_scan_threshold = QSpinBox()
        self._port_scan_threshold.setRange(1, 100)
        ids_form.addRow("Port scan threshold (ports in window):", self._port_scan_threshold)

        self._port_scan_window = QSpinBox()
        self._port_scan_window.setRange(1, 600)
        self._port_scan_window.setSuffix(" s")
        ids_form.addRow("Port scan time window:", self._port_scan_window)

        layout.addWidget(ids_group)

        # — Notifications
        notif_group = QGroupBox("🔔 Notifications")
        notif_form = QFormLayout(notif_group)

        self._notif_desktop = QCheckBox("Desktop notifications (plyer)")
        notif_form.addRow(self._notif_desktop)

        self._notif_email = QCheckBox("Email alerts (SMTP)")
        notif_form.addRow(self._notif_email)

        self._notif_sms = QCheckBox("SMS alerts (Twilio)")
        notif_form.addRow(self._notif_sms)

        layout.addWidget(notif_group)

        # — Email / SMTP
        email_group = QGroupBox("📧 Email Configuration")
        email_form = QFormLayout(email_group)

        self._smtp_host = QLineEdit()
        email_form.addRow("SMTP Host:", self._smtp_host)

        self._smtp_port = QSpinBox()
        self._smtp_port.setRange(1, 65535)
        email_form.addRow("SMTP Port:", self._smtp_port)

        self._smtp_user = QLineEdit()
        email_form.addRow("Username:", self._smtp_user)

        self._smtp_pass = QLineEdit()
        self._smtp_pass.setEchoMode(QLineEdit.Password)
        email_form.addRow("Password:", self._smtp_pass)

        self._smtp_to = QLineEdit()
        email_form.addRow("Recipient:", self._smtp_to)

        layout.addWidget(email_group)

        # — Firewall
        fw_group = QGroupBox("🔥 Firewall")
        fw_form = QFormLayout(fw_group)

        self._log_path = QLineEdit()
        fw_form.addRow("Log file path (Windows):", self._log_path)

        layout.addWidget(fw_group)

        # — REST API
        api_group = QGroupBox("🌐 REST API")
        api_form = QFormLayout(api_group)

        self._api_enabled = QCheckBox("Enable REST API")
        api_form.addRow(self._api_enabled)

        self._api_port = QSpinBox()
        self._api_port.setRange(1024, 65535)
        api_form.addRow("Port:", self._api_port)

        self._api_key = QLineEdit()
        api_form.addRow("API Key:", self._api_key)

        layout.addWidget(api_group)

        # — Appearance
        appearance_group = QGroupBox("🎨 Appearance")
        appearance_form = QFormLayout(appearance_group)

        self._theme = QComboBox()
        self._theme.addItems(["dark", "light"])
        appearance_form.addRow("Theme:", self._theme)

        self._minimize_to_tray = QCheckBox("Minimize to system tray on close")
        appearance_form.addRow(self._minimize_to_tray)

        layout.addWidget(appearance_group)

        layout.addStretch()
        scroll.setWidget(container)
        outer.addWidget(scroll)

        # Save button
        btn_save = QPushButton("💾 Save Settings")
        btn_save.clicked.connect(self._save)
        outer.addWidget(btn_save)

    # ------------------------------------------------------------------
    # Load / save
    # ------------------------------------------------------------------

    def _load(self) -> None:
        try:
            from utils.config_loader import current
            cfg = current()
        except Exception:
            return

        ids = cfg.get("ids", {})
        self._threshold.setValue(ids.get("alert_threshold", 10))
        self._window.setValue(ids.get("time_window_seconds", 60))
        self._auto_block.setChecked(ids.get("auto_block", True))
        self._port_scan_threshold.setValue(ids.get("port_scan_threshold", 5))
        self._port_scan_window.setValue(ids.get("port_scan_window_seconds", 30))

        notif = cfg.get("notifications", {})
        self._notif_desktop.setChecked(notif.get("desktop", True))
        self._notif_email.setChecked(notif.get("email", False))
        self._notif_sms.setChecked(notif.get("sms", False))

        email = cfg.get("email", {})
        self._smtp_host.setText(email.get("smtp_host", "smtp.gmail.com"))
        self._smtp_port.setValue(int(email.get("smtp_port", 465)))
        self._smtp_user.setText(email.get("username", ""))
        self._smtp_pass.setText(email.get("password", ""))
        self._smtp_to.setText(email.get("recipient", ""))

        fw = cfg.get("firewall", {})
        self._log_path.setText(fw.get("log_path", r"C:\Temp\pfirewall.log"))

        api = cfg.get("api", {})
        self._api_enabled.setChecked(api.get("enabled", False))
        self._api_port.setValue(int(api.get("port", 5000)))
        self._api_key.setText(api.get("api_key", ""))

        app = cfg.get("app", {})
        idx = self._theme.findText(app.get("theme", "dark"))
        if idx >= 0:
            self._theme.setCurrentIndex(idx)
        self._minimize_to_tray.setChecked(app.get("minimize_to_tray", True))

    def _save(self) -> None:
        try:
            from utils.config_loader import current, save
            cfg = current()
        except Exception:
            return

        cfg["ids"]["alert_threshold"] = self._threshold.value()
        cfg["ids"]["time_window_seconds"] = self._window.value()
        cfg["ids"]["auto_block"] = self._auto_block.isChecked()
        cfg["ids"]["port_scan_threshold"] = self._port_scan_threshold.value()
        cfg["ids"]["port_scan_window_seconds"] = self._port_scan_window.value()

        cfg["notifications"]["desktop"] = self._notif_desktop.isChecked()
        cfg["notifications"]["email"] = self._notif_email.isChecked()
        cfg["notifications"]["sms"] = self._notif_sms.isChecked()

        cfg["email"]["smtp_host"] = self._smtp_host.text()
        cfg["email"]["smtp_port"] = self._smtp_port.value()
        cfg["email"]["username"] = self._smtp_user.text()
        cfg["email"]["password"] = self._smtp_pass.text()
        cfg["email"]["recipient"] = self._smtp_to.text()

        cfg["firewall"]["log_path"] = self._log_path.text()

        cfg["api"]["enabled"] = self._api_enabled.isChecked()
        cfg["api"]["port"] = self._api_port.value()
        cfg["api"]["api_key"] = self._api_key.text()

        cfg["app"]["theme"] = self._theme.currentText()
        cfg["app"]["minimize_to_tray"] = self._minimize_to_tray.isChecked()

        from utils.config_loader import save as save_cfg
        ok = save_cfg(cfg)
        if ok:
            QMessageBox.information(self, "Saved", "Settings saved to config.yaml.\nRestart the app to apply theme changes.")
        else:
            QMessageBox.warning(self, "Error", "Failed to save settings. Is PyYAML installed?")
