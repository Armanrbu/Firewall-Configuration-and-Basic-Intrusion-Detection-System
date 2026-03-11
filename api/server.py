"""
Optional lightweight Flask REST API.

Runs in a background daemon thread when enabled in settings.
Provides endpoints for remote monitoring and control.

Authentication: API key passed in the `X-API-Key` request header.
"""

from __future__ import annotations

import threading
import time
from functools import wraps
from typing import Any, Callable

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from flask import Flask, jsonify, request, abort
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    logger.warning("Flask not installed; REST API disabled.")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def _require_api_key(api_key: str) -> Callable:
    """Decorator factory that enforces API key authentication."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = request.headers.get("X-API-Key", "")
            if not api_key or key != api_key:
                abort(401, description="Invalid or missing API key.")
            return f(*args, **kwargs)
        return wrapper
    return decorator


def create_app(api_key: str = "") -> "Flask | None":
    """Build and return the Flask application."""
    if not HAS_FLASK:
        return None

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    require_key = _require_api_key(api_key)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get("/status")  # type: ignore[misc]
    @require_key
    def status():
        """Firewall status + basic statistics."""
        from core.firewall import get_status
        from core.blocklist import get_stats_today, get_all_blocked, get_alerts
        fw = get_status()
        stats = get_stats_today()
        return jsonify({
            "firewall": fw,
            "stats_today": stats,
            "alert_count": len(get_alerts(unresolved_only=True)),
            "blocked_count": len(get_all_blocked()),
            "timestamp": time.time(),
        })

    @app.get("/blocked")  # type: ignore[misc]
    @require_key
    def blocked():
        """List all currently blocked IPs."""
        from core.blocklist import get_all_blocked
        return jsonify(get_all_blocked())

    @app.post("/block")  # type: ignore[misc]
    @require_key
    def block():
        """Block an IP address. Body: {"ip": "x.x.x.x", "reason": "..."}"""
        from utils.validators import is_valid_ip
        from core.firewall import block_ip
        from core.blocklist import add_block
        body: dict = request.get_json(silent=True) or {}
        ip = body.get("ip", "")
        reason = body.get("reason", "API request")
        if not is_valid_ip(ip):
            return jsonify({"success": False, "message": "Invalid IP address."}), 400
        result = block_ip(ip)
        if result["success"]:
            add_block(ip, reason)
        return jsonify(result)

    @app.post("/unblock")  # type: ignore[misc]
    @require_key
    def unblock():
        """Unblock an IP address. Body: {"ip": "x.x.x.x"}"""
        from utils.validators import is_valid_ip
        from core.firewall import unblock_ip
        from core.blocklist import remove_block
        body: dict = request.get_json(silent=True) or {}
        ip = body.get("ip", "")
        if not is_valid_ip(ip):
            return jsonify({"success": False, "message": "Invalid IP address."}), 400
        result = unblock_ip(ip)
        if result["success"]:
            remove_block(ip)
        return jsonify(result)

    @app.get("/alerts")  # type: ignore[misc]
    @require_key
    def alerts():
        """Return recent alerts. Query params: limit, unresolved_only."""
        from core.blocklist import get_alerts
        limit = int(request.args.get("limit", 100))
        unresolved_only = request.args.get("unresolved_only", "false").lower() == "true"
        return jsonify(get_alerts(limit=limit, unresolved_only=unresolved_only))

    @app.get("/connections")  # type: ignore[misc]
    @require_key
    def connections():
        """Snapshot of live network connections."""
        if not HAS_PSUTIL:
            return jsonify({"error": "psutil not installed"}), 503
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                conns.append({
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "status": c.status,
                    "pid": c.pid,
                })
        return jsonify(conns)

    return app


class APIServer:
    """Manages the Flask server in a background daemon thread."""

    def __init__(self, api_key: str = "", port: int = 5000) -> None:
        self.api_key = api_key
        self.port = port
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> bool:
        if not HAS_FLASK:
            logger.warning("Flask not installed; API server not started.")
            return False
        if self._running:
            return True
        app = create_app(self.api_key)
        if app is None:
            return False
        self._running = True
        self._thread = threading.Thread(
            target=lambda: app.run(
                host="127.0.0.1",
                port=self.port,
                debug=False,
                use_reloader=False,
            ),
            daemon=True,
            name="APIServer",
        )
        self._thread.start()
        logger.info("REST API server started on port %d", self.port)
        return True

    def stop(self) -> None:
        self._running = False
        logger.info("REST API server stop requested (thread will exit on next request).")

    @property
    def running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()
