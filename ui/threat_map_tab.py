"""
Threat origin world map tab.

Uses QWebEngineView + Leaflet.js to plot blocked/flagged IPs on a map.
Falls back to a plain table if PyQtWebEngine is not available.
"""

from __future__ import annotations

import json
from typing import Any

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from PyQt5.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False
    logger.warning("PyQtWebEngine not installed; threat map will use table fallback.")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Threat Map</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    body {{ margin:0; background:#1e1e2e; }}
    #map {{ width:100%; height:100vh; }}
  </style>
</head>
<body>
<div id="map"></div>
<script>
  var map = L.map('map', {{center:[20,0], zoom:2}});
  L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    attribution: '© OpenStreetMap contributors'
  }}).addTo(map);
  var markers = {markers_json};
  markers.forEach(function(m) {{
    if (!m.lat || !m.lon) return;
    var circle = L.circleMarker([m.lat, m.lon], {{
      radius: 8, color: '#ef4444', fillColor: '#ef4444',
      fillOpacity: 0.7, weight: 2
    }});
    circle.bindPopup(
      '<b>' + m.ip + '</b><br>' +
      (m.country || '') + ' — ' + (m.city || '') + '<br>' +
      'ISP: ' + (m.isp || 'N/A') + '<br>' +
      'Alerts: ' + m.count
    );
    circle.addTo(map);
  }});
</script>
</body>
</html>"""


class ThreatMapTab(QWidget):
    """World map showing blocked/flagged IP origins."""

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

        title = QLabel("🗺️ Threat Origin Map")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        btn_refresh = QPushButton("🔄 Refresh Map")
        btn_refresh.clicked.connect(self.refresh)
        layout.addWidget(btn_refresh)

        if HAS_WEBENGINE:
            self._view = QWebEngineView()
            layout.addWidget(self._view)
        else:
            # Fallback table
            self._table = QTableWidget(0, 5)
            self._table.setHorizontalHeaderLabels(["IP", "Country", "City", "ISP", "Alerts"])
            self._table.horizontalHeader().setStretchLastSection(True)
            self._table.setAlternatingRowColors(True)
            self._table.setEditTriggers(QTableWidget.NoEditTriggers)
            self._table.verticalHeader().setVisible(False)
            layout.addWidget(self._table)
            info = QLabel("ℹ️  Install PyQtWebEngine for the interactive world map.")
            info.setStyleSheet("color:#a0aec0;")
            layout.addWidget(info)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        markers = self._build_markers()
        if HAS_WEBENGINE:
            html = _HTML_TEMPLATE.replace("{markers_json}", json.dumps(markers))
            self._view.setHtml(html)
        else:
            self._populate_table(markers)

    def _build_markers(self) -> list[dict[str, Any]]:
        from core.blocklist import get_all_blocked, get_alerts
        from core.geo import lookup

        alert_counts: dict[str, int] = {}
        for alert in get_alerts(limit=1000):
            ip = alert.get("ip", "")
            alert_counts[ip] = alert_counts.get(ip, 0) + 1

        markers: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in get_all_blocked():
            ip = entry.get("ip", "")
            if ip in seen:
                continue
            seen.add(ip)
            try:
                geo = lookup(ip)
            except Exception:
                geo = {}
            markers.append({
                "ip": ip,
                "lat": geo.get("lat", 0),
                "lon": geo.get("lon", 0),
                "country": geo.get("country", ""),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", ""),
                "count": alert_counts.get(ip, 0),
            })
        return markers

    def _populate_table(self, markers: list[dict[str, Any]]) -> None:
        self._table.setRowCount(0)
        for m in markers:
            row = self._table.rowCount()
            self._table.insertRow(row)
            values = [m["ip"], m.get("country", ""), m.get("city", ""), m.get("isp", ""), str(m.get("count", 0))]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self._table.setItem(row, col, item)
        self._table.resizeColumnsToContents()
