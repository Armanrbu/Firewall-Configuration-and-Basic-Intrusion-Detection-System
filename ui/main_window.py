"""
Main application window — tabbed interface.

Orchestrates all tabs, the IDS worker thread, system tray, and status bar.
"""

from __future__ import annotations

import time
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
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
        self._app_runner = None  # set by _start_engine_and_bridge
        self._bridge = None      # EventBusBridge — Qt signals from EventBus
        self._tray = None

        self.setWindowTitle("🛡️ NetGuard IDS — Advanced Firewall & Intrusion Detection System")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 780)
        self._apply_theme()
        self._setup_ui()
        self._setup_statusbar()
        self._start_engine_and_bridge()
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
        from ui.rule_editor_tab import RuleEditorTab
        from ui.plugin_manager_tab import PluginManagerTab
        from ui.flow_visualization_tab import FlowVisualizationTab

        self._dashboard    = DashboardTab()
        self._rules        = RulesTab()
        self._rule_editor  = RuleEditorTab()
        self._alerts       = AlertsTab()
        self._blocklist    = BlocklistTab()
        self._settings     = SettingsTab()
        self._scheduler    = SchedulerTab()
        self._threat_map   = ThreatMapTab()
        self._plugin_mgr   = PluginManagerTab()
        self._flow_viz     = FlowVisualizationTab()

        # Connect plugin manager signals
        self._plugin_mgr.plugin_toggled.connect(self._on_plugin_toggled)
        self._plugin_mgr.reload_requested.connect(self._on_plugins_reload)

        tabs: list[tuple[str, QWidget]] = [
            ("📊 Dashboard",      self._dashboard),
            ("🔐 Block Rules",    self._rules),
            ("📝 YAML Rules",     self._rule_editor),
            ("🚨 Alerts",          self._alerts),
            ("🚫 Blocklist",      self._blocklist),
            ("⏰ Scheduler",      self._scheduler),
            ("🗺️ Threat Map",   self._threat_map),
            ("🌐 Flow Graph",     self._flow_viz),
            ("🔌 Plugins",        self._plugin_mgr),
            ("⚙️ Settings",      self._settings),
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
            from PySide6.QtWidgets import QSystemTrayIcon
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            from ui.tray import TrayIcon
            self._tray = TrayIcon(self)
            self._tray.show()
        except Exception as exc:
            logger.warning("Tray setup failed: %s", exc)

    # ------------------------------------------------------------------
    # Engine + Bridge
    # ------------------------------------------------------------------

    def _start_engine_and_bridge(self) -> None:
        """Start AppRunner (engine + optional API) and wire EventBusBridge."""
        try:
            from core.app_runner import AppRunner, set_runner
            self._app_runner = AppRunner(config=self._config)
            self._app_runner.start()
            set_runner(self._app_runner)

            # Register DPI plugin into the detector registry
            self._start_dpi_plugin()

            # Start config file hot-reload watcher
            self._start_config_watcher()

            # Bridge EventBus events → Qt signals (thread-safe)
            from ui.event_bus_bridge import EventBusBridge
            self._bridge = EventBusBridge(parent=self)
            self._bridge.start(self._app_runner.get_bus())

            # Connect typed signals to existing handler slots
            self._bridge.ip_flagged.connect(self._on_ip_flagged)
            self._bridge.ip_blocked.connect(self._on_ip_blocked)
            self._bridge.port_scan.connect(self._on_port_scan)
            self._bridge.anomaly_detected.connect(self._on_anomaly)

            # Update status bar label if API is up
            api_cfg = self._config.get("api", {})
            if api_cfg.get("enabled", False) and self._app_runner._api_server:
                port = api_cfg.get("port", 5000)
                self._sb_api.setText(f"🔌 API: Port {port}")

            logger.info("AppRunner + EventBusBridge wired successfully.")
        except Exception as exc:
            logger.error("Failed to start engine/bridge: %s", exc)

    def _start_dpi_plugin(self) -> None:
        """Register the DPI plugin into the global DetectorRegistry."""
        try:
            from core.dpi_plugin import DPIDetector
            from core.detector_registry import get_registry
            dpi = DPIDetector(config=self._config)
            dpi.on_start()
            get_registry().register(dpi)
            logger.info("DPI plugin registered in DetectorRegistry.")
        except Exception as exc:
            logger.warning("DPI plugin registration failed (non-fatal): %s", exc)

    def _start_config_watcher(self) -> None:
        """Start the config hot-reload watcher for config.yaml + rules/."""
        try:
            import os
            from core.advanced_features import ConfigWatcher
            config_path = self._config.get("_config_path", "config.yaml")
            rules_dir   = os.path.join(os.path.dirname(config_path) or ".", "rules")
            paths = [config_path]
            if os.path.isdir(rules_dir):
                paths.append(rules_dir)
            self._config_watcher = ConfigWatcher(
                paths=paths,
                on_change=self._on_config_changed,
                poll_interval=3.0,
            )
            self._config_watcher.start()
            logger.info("ConfigWatcher started for %s", paths)
        except Exception as exc:
            logger.warning("ConfigWatcher failed to start (non-fatal): %s", exc)
            self._config_watcher = None

    # ------------------------------------------------------------------
    # Phase 6 — plugin manager callbacks
    # ------------------------------------------------------------------

    def _on_plugin_toggled(self, name: str, enabled: bool) -> None:
        """Enable or disable a detector in the registry."""
        try:
            from core.detector_registry import get_registry
            registry = get_registry()
            detector = registry.get(name)
            if detector is None:
                return
            if enabled:
                detector.on_start()
                logger.info("Plugin '%s' enabled.", name)
            else:
                detector.on_stop()
                logger.info("Plugin '%s' disabled.", name)
        except Exception as exc:
            logger.warning("Plugin toggle failed for '%s': %s", name, exc)

    def _on_plugins_reload(self) -> None:
        """Reload all plugins via entry-point discovery."""
        try:
            from core.detector_registry import get_registry
            count = get_registry().discover_plugins()
            logger.info("Plugin reload: %d new plugin(s) discovered.", count)
            # Re-register DPI in case it was cleared
            self._start_dpi_plugin()
        except Exception as exc:
            logger.warning("Plugin reload failed: %s", exc)

    def _on_config_changed(self, changed_paths: list) -> None:
        """Called by ConfigWatcher when a watched file changes."""
        logger.info("Hot-reload: config changes detected in %s", changed_paths)
        try:
            from utils.config_loader import load as load_config
            for path in changed_paths:
                p = str(path)
                if p.endswith(".yaml") and "rule" in p.lower():
                    # Reload YAML rules in engine's rule engine
                    if self._app_runner and hasattr(self._app_runner.engine, "_rule_engine"):
                        self._app_runner.engine._rule_engine.reload_rules()
                        logger.info("Rule engine hot-reloaded.")
                elif p.endswith("config.yaml"):
                    # Reload main config
                    new_cfg = load_config(p)
                    self._config.update(new_cfg)
                    logger.info("config.yaml hot-reloaded.")
        except Exception as exc:
            logger.warning("Hot-reload callback error: %s", exc)


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

    def _on_anomaly(self, ip: str, score: float = 0.0) -> None:
        from core.blocklist import add_alert
        add_alert(ip, "ML Anomaly", f"Anomaly score: {score:.4f}")
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
        # Stop the EventBus bridge first
        if self._bridge:
            try:
                self._bridge.stop()
            except Exception:
                pass

        # Stop AppRunner (engine + API + scheduler)
        if self._app_runner:
            try:
                self._app_runner.stop()
            except Exception:
                pass

        from core.blocklist import close_all_connections
        try:
            close_all_connections()
        except Exception:
            pass
        logger.info("NetGuard IDS shut down cleanly.")
