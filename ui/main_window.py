"""
Main application window — tabbed interface.

Orchestrates all tabs, the IDS worker thread, system tray, and status bar.
"""

from __future__ import annotations

import time
from typing import Any

from PyQt5.QtCore import Qt, QThread, QTimer
from PyQt5.QtWidgets import (
    QLabel,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTabWidget,
    QWidget,
)

from ui.theme import get_stylesheet
from utils.logger import get_logger

logger = get_logger(__name__)


class MainWindow(QMainWindow):
    """
    Central application window.

    Layout:
        QTabWidget with all feature tabs
        QStatusBar showing firewall state, alert count, API status
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._config = config or {}
        self._ids_thread: QThread | None = None
        self._ids_worker = None
        self._tray = None
        self._api_server = None

        self.setWindowTitle("🛡️ NetGuard IDS — Advanced Firewall & Intrusion Detection System")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 780)
        self._apply_theme()
        self._setup_ui()
        self._setup_statusbar()
        self._start_ids()
        self._start_api_if_enabled()
        self._setup_tray()

        # Periodic status refresh
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_status)
        self._status_timer.start(5000)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        theme = self._config.get("app", {}).get("theme", "dark")
        self.setStyleSheet(get_stylesheet(theme))

    def _setup_ui(self) -> None:
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.North)

        # Import all tabs
        from ui.dashboard_tab import DashboardTab
        from ui.rules_tab import RulesTab
        from ui.alerts_tab import AlertsTab
        from ui.blocklist_tab import BlocklistTab
        from ui.settings_tab import SettingsTab
        from ui.scheduler_tab import SchedulerTab
        from ui.threat_map_tab import ThreatMapTab

        self._dashboard = DashboardTab()
        self._rules = RulesTab()
        self._alerts = AlertsTab()
        self._blocklist = BlocklistTab()
        self._settings = SettingsTab()
        self._scheduler = SchedulerTab()
        self._threat_map = ThreatMapTab()

        tabs: list[tuple[str, QWidget]] = [
            ("📊 Dashboard", self._dashboard),
            ("🔐 Rules", self._rules),
            ("🚨 Alerts", self._alerts),
            ("🚫 Blocklist", self._blocklist),
            ("⏰ Scheduler", self._scheduler),
            ("🗺️ Threat Map", self._threat_map),
            ("⚙️ Settings", self._settings),
        ]
        for label, widget in tabs:
            self._tabs.addTab(widget, label)

        self.setCentralWidget(self._tabs)

    def _setup_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)

        self._sb_firewall = QLabel("🔥 Firewall: checking…")
        self._sb_alerts = QLabel("🚨 Alerts: 0")
        self._sb_connections = QLabel("🌐 Connections: 0")
        self._sb_api = QLabel("🔌 API: Off")

        for lbl in (self._sb_firewall, self._sb_alerts, self._sb_connections, self._sb_api):
            sb.addPermanentWidget(lbl)

        self._refresh_status()

    def _setup_tray(self) -> None:
        minimize = self._config.get("app", {}).get("minimize_to_tray", True)
        if not minimize:
            return
        try:
            from PyQt5.QtWidgets import QSystemTrayIcon
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            from ui.tray import TrayIcon
            self._tray = TrayIcon(self)
            self._tray.show()
        except Exception as exc:
            logger.warning("Tray setup failed: %s", exc)

    # ------------------------------------------------------------------
    # IDS
    # ------------------------------------------------------------------

    def _start_ids(self) -> None:
        ids_cfg = self._config.get("ids", {})
        fw_cfg = self._config.get("firewall", {})

        try:
            from core.ids import IDSWorker
            from core.whitelist import get_all
            whitelist = set(get_all())
            self._ids_worker = IDSWorker(
                threshold=ids_cfg.get("alert_threshold", 10),
                window_seconds=ids_cfg.get("time_window_seconds", 60),
                port_scan_threshold=ids_cfg.get("port_scan_threshold", 5),
                port_scan_window=ids_cfg.get("port_scan_window_seconds", 30),
                auto_block=ids_cfg.get("auto_block", True),
                whitelist=whitelist,
                log_path=fw_cfg.get("log_path", ""),
            )
            self._ids_thread = QThread()
            self._ids_worker.moveToThread(self._ids_thread)
            self._ids_thread.started.connect(self._ids_worker.start)

            # Connect signals
            self._ids_worker.ip_flagged.connect(self._on_ip_flagged)
            self._ids_worker.ip_blocked.connect(self._on_ip_blocked)
            self._ids_worker.port_scan.connect(self._on_port_scan)
            self._ids_worker.anomaly_detected.connect(self._on_anomaly)

            self._ids_thread.start()
            logger.info("IDS worker thread started.")
        except Exception as exc:
            logger.error("Failed to start IDS: %s", exc)

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def _start_api_if_enabled(self) -> None:
        api_cfg = self._config.get("api", {})
        if not api_cfg.get("enabled", False):
            return
        try:
            from api.server import APIServer
            self._api_server = APIServer(
                api_key=api_cfg.get("api_key", ""),
                port=int(api_cfg.get("port", 5000)),
            )
            ok = self._api_server.start()
            if ok:
                self._sb_api.setText(f"🔌 API: Port {api_cfg.get('port', 5000)}")
        except Exception as exc:
            logger.warning("API server failed to start: %s", exc)

    # ------------------------------------------------------------------
    # IDS signal handlers
    # ------------------------------------------------------------------

    def _on_ip_flagged(self, ip: str, count: int) -> None:
        details = f"{count} connections detected"
        from core.blocklist import add_alert
        add_alert(ip, "Repeated Connection", details)
        self._alerts.refresh()
        self._update_alert_count()

        # Notification
        try:
            from core.notifier import get_notifier
            from core.geo import lookup
            geo = lookup(ip)
            get_notifier(self._config).notify_alert(ip, "Repeated Connection", details, geo)
        except Exception:
            pass

        # Tray balloon
        if self._tray:
            self._tray.show_alert_balloon(
                "🚨 IP Flagged",
                f"Repeated connection from {ip} ({count} attempts)",
            )

    def _on_ip_blocked(self, ip: str) -> None:
        from core.blocklist import add_block
        add_block(ip, "Auto-blocked by IDS", auto=True)
        self._blocklist.refresh()

        # Keep dashboard aware of blocked IPs
        blocked_ips = {b["ip"] for b in __import__("core.blocklist", fromlist=["get_all_blocked"]).get_all_blocked()}
        self._dashboard.set_flagged_ips(blocked_ips)

    def _on_port_scan(self, ip: str, ports: list) -> None:
        details = f"Ports: {', '.join(str(p) for p in ports[:20])}"
        from core.blocklist import add_alert
        add_alert(ip, "Port Scan", details)
        self._alerts.refresh()
        self._update_alert_count()
        if self._tray:
            self._tray.show_alert_balloon("🔍 Port Scan", f"{ip} scanned {len(ports)} ports")

    def _on_anomaly(self, ip: str) -> None:
        from core.blocklist import add_alert
        add_alert(ip, "ML Anomaly", "Isolation Forest anomaly score exceeded threshold")
        self._alerts.refresh()
        self._update_alert_count()

    # ------------------------------------------------------------------
    # Status bar refresh
    # ------------------------------------------------------------------

    def _refresh_status(self) -> None:
        # Firewall status
        try:
            from core.firewall import get_status
            result = get_status()
            profiles = result.get("profiles", {})
            if profiles:
                first_state = next(iter(profiles.values()), "?")
                icon = "🟢" if first_state == "ON" else "🔴"
                self._sb_firewall.setText(f"{icon} Firewall: {first_state}")
            else:
                self._sb_firewall.setText("🔥 Firewall: N/A")
        except Exception:
            self._sb_firewall.setText("🔥 Firewall: Error")

        # Connection count
        try:
            import psutil
            conns = [c for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED"]
            self._sb_connections.setText(f"🌐 Connections: {len(conns)}")
        except Exception:
            pass

        self._update_alert_count()

    def _update_alert_count(self) -> None:
        try:
            from core.blocklist import get_alerts
            count = len(get_alerts(unresolved_only=True))
            self._sb_alerts.setText(f"🚨 Alerts: {count}")
            if self._tray:
                self._tray.update_alert_count(count)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Window events
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        minimize = self._config.get("app", {}).get("minimize_to_tray", True)
        if minimize and self._tray and self._tray.isVisible():
            self.hide()
            event.ignore()
            return

        reply = QMessageBox.question(
            self,
            "Exit Confirmation",
            "Are you sure you want to exit NetGuard IDS?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._shutdown()
            event.accept()
        else:
            event.ignore()

    def _shutdown(self) -> None:
        if self._ids_worker:
            try:
                self._ids_worker.stop()
            except Exception:
                pass
        if self._ids_thread:
            try:
                self._ids_thread.quit()
                self._ids_thread.wait(2000)
            except Exception:
                pass
        from core.scheduler import get_scheduler
        try:
            get_scheduler().stop()
        except Exception:
            pass
        logger.info("NetGuard IDS shut down cleanly.")
