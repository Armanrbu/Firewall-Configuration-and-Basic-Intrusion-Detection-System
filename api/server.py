"""
FastAPI REST API server.

Replaces the legacy Flask server. Provides OpenAPI docs, Pydantic validation,
and a WebSocket endpoint for real-time alerts. Runs in a background thread
via Uvicorn.

Authentication: API key passed in the `X-API-Key` request header.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from fastapi import FastAPI, Depends, HTTPException, Security, WebSocket, WebSocketDisconnect
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    from api.schemas import BlockRequest, UnblockRequest, ConnectionSnapshot, StatusResponse, GenericResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI/Uvicorn not installed; REST API disabled. Run: pip install fastapi uvicorn websockets pydantic")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def create_app(api_key: str = "") -> "FastAPI | None":
    """Build and return the FastAPI application."""
    if not HAS_FASTAPI:
        return None

    from api.schemas import BlockRequest, UnblockRequest, ConnectionSnapshot, StatusResponse, GenericResponse

    app = FastAPI(
        title="NetGuard IDS API",
        description="REST and WebSocket API for NetGuard IDS v2",
        version="2.0.0",
        docs_url="/docs",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def verify_api_key(key: str | None = Security(api_key_header)) -> str:
        if api_key and key != api_key:
            raise HTTPException(status_code=401, detail="Invalid API Key")
        return key or ""

    # ------------------------------------------------------------------
    # REST Endpoints
    # ------------------------------------------------------------------

    @app.get("/status", response_model=StatusResponse)
    def status(key: str = Depends(verify_api_key)):
        """Firewall status + basic statistics."""
        from core.firewall import get_status
        from core.blocklist import get_stats_today, get_all_blocked, get_alerts
        return StatusResponse(
            firewall=get_status(),
            stats_today=get_stats_today(),
            alert_count=len(get_alerts(unresolved_only=True)),
            blocked_count=len(get_all_blocked()),
            timestamp=time.time()
        )

    @app.get("/blocked")
    def blocked(key: str = Depends(verify_api_key)):
        """List all currently blocked IPs."""
        from core.blocklist import get_all_blocked
        return get_all_blocked()

    @app.post("/block", response_model=GenericResponse)
    def block(req: BlockRequest, key: str = Depends(verify_api_key)):
        """Block an IP address."""
        from utils.validators import is_valid_ip
        from core.firewall import block_ip
        from core.blocklist import add_block
        if not is_valid_ip(req.ip):
            raise HTTPException(status_code=400, detail="Invalid IP address.")
        result = block_ip(req.ip)
        if result["success"]:
            add_block(req.ip, req.reason)
        return GenericResponse(success=result["success"], message=result.get("message"))

    @app.post("/unblock", response_model=GenericResponse)
    def unblock(req: UnblockRequest, key: str = Depends(verify_api_key)):
        """Unblock an IP address."""
        from utils.validators import is_valid_ip
        from core.firewall import unblock_ip
        from core.blocklist import remove_block
        if not is_valid_ip(req.ip):
            raise HTTPException(status_code=400, detail="Invalid IP address.")
        result = unblock_ip(req.ip)
        if result["success"]:
            remove_block(req.ip)
        return GenericResponse(success=result["success"], message=result.get("message"))

    @app.get("/alerts")
    def alerts(limit: int = 100, unresolved_only: bool = False, key: str = Depends(verify_api_key)):
        """Return recent alerts."""
        from core.blocklist import get_alerts
        return get_alerts(limit=limit, unresolved_only=unresolved_only)

    @app.get("/connections", response_model=list[ConnectionSnapshot])
    def connections(key: str = Depends(verify_api_key)):
        """Snapshot of live network connections."""
        if not HAS_PSUTIL:
            raise HTTPException(status_code=503, detail="psutil not installed")
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                conns.append(ConnectionSnapshot(
                    local=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    remote_ip=c.raddr.ip,
                    remote_port=c.raddr.port,
                    status=c.status,
                    pid=c.pid
                ))
        return conns

    # ------------------------------------------------------------------
    # WebSockets
    # ------------------------------------------------------------------

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket):
        """Streams real-time events from the EventBus to the client."""
        # Authenticate
        client_key = websocket.headers.get("X-API-Key")
        if not client_key and "api_key" in websocket.query_params:
            client_key = websocket.query_params["api_key"]
        if api_key and client_key != api_key:
            await websocket.close(code=1008)
            return

        await websocket.accept()

        from core.event_bus import get_event_bus
        bus = get_event_bus()

        import queue
        q: queue.Queue = queue.Queue()

        def _push(ev: Any) -> None:
            # Drop data if the client is too slow (prevent memory leak)
            if q.qsize() < 1000:
                q.put(ev)

        # Catch-all subscriber so we can just stream whatever the engine does
        sub_id = bus.subscribe_all(_push)

        try:
            while True:
                # Dispatch queued events
                while not q.empty():
                    ev = q.get_nowait()
                    payload = {"event": type(ev).__name__}
                    # Add dataclass/dict attributes if present
                    if hasattr(ev, "__dict__"):
                        payload.update(ev.__dict__)
                    await websocket.send_json(payload)
                    
                await asyncio.sleep(0.1)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("WebSocket error: %s", exc)
        finally:
            bus.unsubscribe_all(sub_id)

    return app


class APIServer:
    """Manages the FastAPI server via Uvicorn in a background daemon thread."""

    def __init__(self, api_key: str = "", port: int = 5000) -> None:
        self.api_key = api_key or os.environ.get("NETGUARD_API_KEY", "")
        self.port = port
        self._thread: threading.Thread | None = None
        self._server: Any = None
        self._running = False

    def start(self) -> bool:
        if not HAS_FASTAPI:
            logger.warning("FastAPI not installed; API server not started.")
            return False
        if self._thread is not None and self._thread.is_alive():
            return True

        app = create_app(self.api_key)
        if app is None:
            return False

        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._running = True

        def runner() -> None:
            # Uvicorn needs an asyncio event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._server.run()

        self._thread = threading.Thread(target=runner, daemon=True, name="APIServer")
        self._thread.start()
        logger.info("FastAPI server started on port %d", self.port)
        return True

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.should_exit = True
            logger.info("FastAPI server stop requested.")

    @property
    def running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()
