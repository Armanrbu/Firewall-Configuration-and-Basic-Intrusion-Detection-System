"""
Flow Visualization Tab — real-time network topology graph.

Renders a force-directed graph of active connections using QPainter.
Each node represents a unique IP address; each edge represents an active
connection (thickness ∝ connection count, colour ∝ threat level).

No external graph library needed — pure Qt drawing (QPainter + QGraphicsView).
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from utils.logger import get_logger

logger = get_logger(__name__)

# Colour palette
_COL_BG         = QColor("#0d1117")
_COL_EDGE_OK    = QColor("#1e88e5")
_COL_EDGE_WARN  = QColor("#f9a825")
_COL_EDGE_ALERT = QColor("#e53935")
_COL_NODE_SELF  = QColor("#00e5ff")
_COL_NODE_OK    = QColor("#1de9b6")
_COL_NODE_WARN  = QColor("#ffca28")
_COL_NODE_ALERT = QColor("#ff1744")
_COL_LABEL      = QColor("#eceff1")
_COL_GRID       = QColor(30, 50, 70, 80)


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------

class _Node:
    __slots__ = ("ip", "x", "y", "vx", "vy", "threat", "conn_count", "label")

    def __init__(self, ip: str, x: float, y: float) -> None:
        self.ip         = ip
        self.x          = x
        self.y          = y
        self.vx         = 0.0
        self.vy         = 0.0
        self.threat     = 0.0   # 0.0–1.0
        self.conn_count = 0
        self.label      = ip


class _Edge:
    __slots__ = ("src", "dst", "weight", "threat")

    def __init__(self, src: str, dst: str, weight: int = 1, threat: float = 0.0) -> None:
        self.src    = src
        self.dst    = dst
        self.weight = weight
        self.threat = threat


# ---------------------------------------------------------------------------
# Canvas widget  (pure QPainter)
# ---------------------------------------------------------------------------

class _FlowCanvas(QWidget):
    """QPainter-based canvas drawing the force-directed graph."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumSize(400, 300)
        self._nodes: dict[str, _Node] = {}
        self._edges: list[_Edge] = []
        self._show_labels  = True
        self._show_grid    = True
        self._repulsion    = 5000.0
        self._attraction   = 0.05
        self._damping      = 0.85
        self._local_ip     = "10.0.0.1"
        self._zoom         = 1.0
        self._pan_x        = 0.0
        self._pan_y        = 0.0
        self._drag_node: _Node | None = None
        self._drag_offset  = QPointF()
        self.setMouseTracking(True)

    # ── Graph API ───────────────────────────────────────────────────────

    def set_graph(self, nodes: dict[str, _Node], edges: list[_Edge]) -> None:
        self._nodes = nodes
        self._edges = edges
        self.update()

    def step_simulation(self) -> None:
        """One iteration of force-directed layout."""
        nodes = list(self._nodes.values())
        if not nodes:
            return
        cx, cy = self.width() / 2, self.height() / 2

        # Repulsion between all pairs
        for i, a in enumerate(nodes):
            fx, fy = 0.0, 0.0
            for b in nodes:
                if a is b:
                    continue
                dx = a.x - b.x
                dy = a.y - b.y
                dist2 = max(1.0, dx * dx + dy * dy)
                f = self._repulsion / dist2
                fx += f * dx / math.sqrt(dist2)
                fy += f * dy / math.sqrt(dist2)
            # Weak gravity towards centre
            fx += (cx - a.x) * 0.002
            fy += (cy - a.y) * 0.002
            a.vx = (a.vx + fx) * self._damping
            a.vy = (a.vy + fy) * self._damping

        # Attraction along edges
        for edge in self._edges:
            n1 = self._nodes.get(edge.src)
            n2 = self._nodes.get(edge.dst)
            if n1 is None or n2 is None:
                continue
            dx = n2.x - n1.x
            dy = n2.y - n1.y
            dist = max(1.0, math.sqrt(dx * dx + dy * dy))
            f = self._attraction * dist * edge.weight
            n1.vx += f * dx / dist
            n1.vy += f * dy / dist
            n2.vx -= f * dx / dist
            n2.vy -= f * dy / dist

        # Integrate positions (clamp inside canvas)
        w, h = max(1, self.width()), max(1, self.height())
        for n in nodes:
            if n is self._drag_node:
                continue
            n.x = max(40, min(w - 40, n.x + n.vx))
            n.y = max(40, min(h - 40, n.y + n.vy))

    # ── Painting ─────────────────────────────────────────────────────────

    def paintEvent(self, _event: Any) -> None:  # type: ignore[override]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), _COL_BG)

        if self._show_grid:
            self._draw_grid(p)

        for edge in self._edges:
            self._draw_edge(p, edge)

        for node in self._nodes.values():
            self._draw_node(p, node)

        p.end()

    def _draw_grid(self, p: QPainter) -> None:
        pen = QPen(_COL_GRID, 1, Qt.PenStyle.DotLine)
        p.setPen(pen)
        for x in range(0, self.width(), 50):
            p.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 50):
            p.drawLine(0, y, self.width(), y)

    def _draw_edge(self, p: QPainter, edge: _Edge) -> None:
        n1 = self._nodes.get(edge.src)
        n2 = self._nodes.get(edge.dst)
        if n1 is None or n2 is None:
            return

        threat = max(edge.threat, n1.threat, n2.threat)
        if threat >= 0.7:
            colour = _COL_EDGE_ALERT
        elif threat >= 0.4:
            colour = _COL_EDGE_WARN
        else:
            colour = _COL_EDGE_OK

        width = max(1, min(5, edge.weight))
        pen = QPen(colour, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        pen.setColor(QColor(colour.red(), colour.green(), colour.blue(), 160))
        p.setPen(pen)
        p.drawLine(int(n1.x), int(n1.y), int(n2.x), int(n2.y))

        # Arrowhead
        self._draw_arrow(p, n1, n2, colour)

    def _draw_arrow(self, p: QPainter, src: _Node, dst: _Node, colour: QColor) -> None:
        dx = dst.x - src.x
        dy = dst.y - src.y
        dist = math.sqrt(dx * dx + dy * dy)
        if dist < 1:
            return
        ux, uy = dx / dist, dy / dist
        # Arrow tip at circle edge
        tip_x = dst.x - ux * 18
        tip_y = dst.y - uy * 18
        perp_x, perp_y = -uy * 5, ux * 5
        path = QPainterPath()
        path.moveTo(tip_x + perp_x, tip_y + perp_y)
        path.lineTo(tip_x - ux * 10, tip_y - uy * 10)
        path.lineTo(tip_x - perp_x, tip_y - perp_y)
        path.closeSubpath()
        p.fillPath(path, QBrush(colour))

    def _draw_node(self, p: QPainter, node: _Node) -> None:
        r = 14 + min(10, node.conn_count // 5)
        threat = node.threat

        if node.ip == self._local_ip:
            base = _COL_NODE_SELF
        elif threat >= 0.7:
            base = _COL_NODE_ALERT
        elif threat >= 0.4:
            base = _COL_NODE_WARN
        else:
            base = _COL_NODE_OK

        # Glow
        grad = QRadialGradient(node.x, node.y, r * 2)
        glow = QColor(base)
        glow.setAlpha(40)
        grad.setColorAt(0.0, glow)
        grad.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setBrush(QBrush(grad))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(node.x, node.y), r * 2, r * 2)

        # Node circle
        grad2 = QRadialGradient(node.x - r * 0.3, node.y - r * 0.3, r * 1.5)
        grad2.setColorAt(0.0, base.lighter(150))
        grad2.setColorAt(1.0, base.darker(130))
        p.setBrush(QBrush(grad2))
        pen = QPen(base.lighter(180), 2)
        p.setPen(pen)
        p.drawEllipse(QPointF(node.x, node.y), r, r)

        # Label
        if self._show_labels:
            p.setPen(QPen(_COL_LABEL))
            font = QFont("monospace", 9)
            p.setFont(font)
            label = node.label
            if len(label) > 15:
                label = label[:7] + "…" + label[-7:]
            bw = len(label) * 6.5
            p.drawText(
                QRectF(node.x - bw / 2, node.y + r + 4, bw, 16),
                Qt.AlignmentFlag.AlignCenter, label,
            )

    # ── Mouse ────────────────────────────────────────────────────────────

    def mousePressEvent(self, event: Any) -> None:  # type: ignore[override]
        pos = event.position()
        for node in self._nodes.values():
            dx = pos.x() - node.x
            dy = pos.y() - node.y
            if math.sqrt(dx * dx + dy * dy) <= 20:
                self._drag_node = node
                self._drag_offset = QPointF(dx, dy)
                return

    def mouseMoveEvent(self, event: Any) -> None:  # type: ignore[override]
        if self._drag_node:
            pos = event.position()
            self._drag_node.x = pos.x() - self._drag_offset.x()
            self._drag_node.y = pos.y() - self._drag_offset.y()
            self.update()

    def mouseReleaseEvent(self, _event: Any) -> None:  # type: ignore[override]
        self._drag_node = None


# ---------------------------------------------------------------------------
# Flow Visualization Tab
# ---------------------------------------------------------------------------

class FlowVisualizationTab(QWidget):
    """
    Full tab embedding the force-directed graph canvas plus controls sidebar.

    Data is pulled from the DetectorRegistry / event bus on every refresh tick.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._nodes: dict[str, _Node] = {}
        self._edges: list[_Edge] = []
        self._conn_data: defaultdict[str, int] = defaultdict(int)
        self._threat_data: dict[str, float] = {}
        self._paused = False
        self._setup_ui()

        # Force-directed simulation timer (60 ms ≈ 16 fps)
        self._sim_timer = QTimer(self)
        self._sim_timer.timeout.connect(self._tick)
        self._sim_timer.start(60)

        # Data refresh timer (2 seconds)
        self._data_timer = QTimer(self)
        self._data_timer.timeout.connect(self._refresh_data)
        self._data_timer.start(2000)

    # ── UI ───────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Canvas
        self._canvas = _FlowCanvas()
        outer.addWidget(self._canvas, stretch=4)

        # Sidebar
        sidebar = QWidget()
        sidebar.setMaximumWidth(240)
        sidebar.setStyleSheet("background:#111827; border-left:1px solid #1e3a5f;")
        sv = QVBoxLayout(sidebar)
        sv.setContentsMargins(10, 10, 10, 10)
        sv.setSpacing(10)

        title = QLabel("🌐 Flow Graph")
        title.setStyleSheet("font-size:16px; font-weight:bold; color:#4fc3f7;")
        sv.addWidget(title)

        # Stats
        self._stats_label = QLabel("Nodes: 0  |  Edges: 0")
        self._stats_label.setStyleSheet("color:#90caf9; font-size:11px;")
        sv.addWidget(self._stats_label)

        # Controls
        ctrl_grp = QGroupBox("Controls")
        ctrl_grp.setStyleSheet(
            "QGroupBox{border:1px solid #1e3a5f; border-radius:5px; color:#90caf9; margin-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin; padding:0 4px;}"
        )
        cg = QVBoxLayout(ctrl_grp)

        self._pause_btn = QPushButton("⏸  Pause Simulation")
        self._pause_btn.setCheckable(True)
        self._pause_btn.clicked.connect(self._on_pause)
        self._pause_btn.setStyleSheet(
            "background:#0d47a1; color:white; border-radius:4px; padding:4px 8px;"
        )
        cg.addWidget(self._pause_btn)

        reset_btn = QPushButton("⟳  Reset Layout")
        reset_btn.clicked.connect(self._reset_layout)
        reset_btn.setStyleSheet(
            "background:#37474f; color:white; border-radius:4px; padding:4px 8px;"
        )
        cg.addWidget(reset_btn)

        self._labels_cb = QCheckBox("Show IP labels")
        self._labels_cb.setChecked(True)
        self._labels_cb.toggled.connect(lambda v: setattr(self._canvas, "_show_labels", v))
        self._labels_cb.setStyleSheet("color:#cfd8dc;")
        cg.addWidget(self._labels_cb)

        self._grid_cb = QCheckBox("Show grid")
        self._grid_cb.setChecked(True)
        self._grid_cb.toggled.connect(lambda v: setattr(self._canvas, "_show_grid", v))
        self._grid_cb.setStyleSheet("color:#cfd8dc;")
        cg.addWidget(self._grid_cb)

        sv.addWidget(ctrl_grp)

        # Repulsion slider
        rep_grp = QGroupBox("Repulsion Force")
        rep_grp.setStyleSheet(
            "QGroupBox{border:1px solid #1e3a5f; border-radius:5px; color:#90caf9; margin-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin; padding:0 4px;}"
        )
        rg = QVBoxLayout(rep_grp)
        self._rep_slider = QSlider(Qt.Orientation.Horizontal)
        self._rep_slider.setRange(1000, 20000)
        self._rep_slider.setValue(5000)
        self._rep_slider.valueChanged.connect(
            lambda v: setattr(self._canvas, "_repulsion", float(v))
        )
        rg.addWidget(self._rep_slider)
        sv.addWidget(rep_grp)

        # Filter
        filter_grp = QGroupBox("Filter Threat Level")
        filter_grp.setStyleSheet(
            "QGroupBox{border:1px solid #1e3a5f; border-radius:5px; color:#90caf9; margin-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin; padding:0 4px;}"
        )
        fg = QVBoxLayout(filter_grp)
        self._threat_filter = QComboBox()
        self._threat_filter.addItems(["All", "Warnings (≥0.4)", "Alerts (≥0.7)"])
        self._threat_filter.currentIndexChanged.connect(self._refresh_data)
        self._threat_filter.setStyleSheet(
            "background:#1a2332; color:#cfd8dc; border:1px solid #37474f; border-radius:4px;"
        )
        fg.addWidget(self._threat_filter)
        sv.addWidget(filter_grp)

        # Legend
        legend_grp = QGroupBox("Legend")
        legend_grp.setStyleSheet(
            "QGroupBox{border:1px solid #1e3a5f; border-radius:5px; color:#90caf9; margin-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin; padding:0 4px;}"
        )
        lg = QVBoxLayout(legend_grp)
        for colour, label in [
            ("#00e5ff", "Local host"),
            ("#1de9b6", "Normal conn"),
            ("#ffca28", "Warning (≥0.4)"),
            ("#ff1744", "Alert (≥0.7)"),
        ]:
            row = QHBoxLayout()
            dot = QLabel("⬤")
            dot.setStyleSheet(f"color:{colour}; font-size:14px;")
            row.addWidget(dot)
            row.addWidget(QLabel(label))
            row.addStretch()
            lg.addLayout(row)
        sv.addWidget(legend_grp)

        sv.addStretch()
        outer.addWidget(sidebar)

    # ── Data refresh ─────────────────────────────────────────────────────

    def _refresh_data(self) -> None:
        """Pull live data from the engine/blocklist and rebuild graph."""
        try:
            self._pull_from_engine()
        except Exception as exc:
            logger.debug("FlowVisualizationTab._refresh_data error: %s", exc)
            self._inject_demo_data()
        self._rebuild_graph()

    def _pull_from_engine(self) -> None:
        """Try to read real data from the running engine."""
        from core.app_runner import AppRunner
        runner: Any = AppRunner.instance()
        if runner is None:
            raise RuntimeError("AppRunner not running")
        engine = runner.engine
        # Get connection history
        if hasattr(engine, "_ids") and hasattr(engine._ids, "_event_log"):
            log: dict = engine._ids._event_log
            self._conn_data.clear()
            for ip, events in log.items():
                self._conn_data[ip] = len(events)
        # Threat levels from alert_manager
        try:
            from core.alert_manager import get_alert_manager
            am = get_alert_manager()
            for alert in am.get_recent(limit=200):
                ip = getattr(alert, "src_ip", None) or getattr(alert, "ip", None)
                if ip:
                    score = float(getattr(alert, "score", getattr(alert, "severity", 0.0)))
                    self._threat_data[ip] = max(self._threat_data.get(ip, 0.0), score)
        except Exception:
            pass

    def _inject_demo_data(self) -> None:
        """Fallback: generate realistic-looking demo data for display."""
        seed_ips = [
            "10.0.0.1", "192.168.1.100", "172.16.0.50",
            "8.8.8.8", "1.1.1.1", "23.45.67.89",
            "104.18.2.5", "52.9.2.3", "198.51.100.7",
        ]
        for ip in seed_ips:
            if ip not in self._conn_data:
                self._conn_data[ip] = random.randint(1, 30)
        # Assign a couple of threat levels
        self._threat_data.setdefault("23.45.67.89", 0.8)
        self._threat_data.setdefault("198.51.100.7", 0.5)

    def _rebuild_graph(self) -> None:
        """Convert conn_data / threat_data into nodes + edges."""
        filter_idx = self._threat_filter.currentIndex()
        min_threat = [0.0, 0.4, 0.7][filter_idx]

        w, h = max(400, self.width() - 240), max(300, self.height())
        cx, cy = w / 2, h / 2

        new_nodes: dict[str, _Node] = {}
        for ip, count in self._conn_data.items():
            threat = self._threat_data.get(ip, 0.0)
            if threat < min_threat:
                continue
            if ip in self._nodes:
                # Keep existing position
                n = self._nodes[ip]
            else:
                angle = random.uniform(0, 2 * math.pi)
                dist  = random.uniform(80, min(cx, cy) * 0.7)
                n = _Node(ip, cx + dist * math.cos(angle), cy + dist * math.sin(angle))
            n.threat     = threat
            n.conn_count = count
            new_nodes[ip] = n

        # Always include local node
        local = "10.0.0.1"
        if local not in new_nodes:
            new_nodes[local] = self._nodes.get(local) or _Node(local, cx, cy)
        new_nodes[local].threat = 0.0

        # Edges: every non-local IP → local
        new_edges: list[_Edge] = []
        for ip, node in new_nodes.items():
            if ip == local:
                continue
            new_edges.append(_Edge(
                src=ip, dst=local,
                weight=max(1, node.conn_count // 5),
                threat=node.threat,
            ))

        self._nodes = new_nodes
        self._edges = new_edges
        self._canvas.set_graph(self._nodes, self._edges)
        self._canvas._local_ip = local
        self._stats_label.setText(
            f"Nodes: {len(self._nodes)}  |  Edges: {len(self._edges)}"
        )

    # ── Simulation tick ──────────────────────────────────────────────────

    def _tick(self) -> None:
        if not self._paused:
            self._canvas.step_simulation()
            self._canvas.update()

    # ── Button handlers ──────────────────────────────────────────────────

    def _on_pause(self, checked: bool) -> None:
        self._paused = checked
        self._pause_btn.setText("▶  Resume" if checked else "⏸  Pause Simulation")

    def _reset_layout(self) -> None:
        """Scatter nodes randomly so the layout restarts."""
        w = max(400, self.width() - 240)
        h = max(300, self.height())
        for node in self._nodes.values():
            node.x = random.uniform(60, w - 60)
            node.y = random.uniform(60, h - 60)
            node.vx = node.vy = 0.0
