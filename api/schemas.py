"""
Pydantic models for the FastAPI server endpoints.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class BlockRequest(BaseModel):
    """Request payload to block an IP."""
    ip: str = Field(..., description="The IPv4 or IPv6 address to block", examples=["192.168.1.100"])
    reason: str = Field("API request", description="Reason for the block")


class UnblockRequest(BaseModel):
    """Request payload to unblock an IP."""
    ip: str = Field(..., description="The IPv4 or IPv6 address to unblock", examples=["192.168.1.100"])


class ConnectionSnapshot(BaseModel):
    """Snapshot of a live network connection."""
    local: str
    remote_ip: str
    remote_port: int
    status: str
    pid: int | None


class StatusResponse(BaseModel):
    """Overall system status response."""
    firewall: dict[str, Any]
    stats_today: dict[str, Any]
    alert_count: int
    blocked_count: int
    timestamp: float


class GenericResponse(BaseModel):
    """Simple generic success/error response."""
    success: bool
    message: str | None = None
