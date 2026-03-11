"""
Tests for the FastAPI REST API server (api/server.py) and schemas.
"""

from __future__ import annotations

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

try:
    from api.server import create_app, APIServer, HAS_FASTAPI
except ImportError:
    HAS_FASTAPI = False


@pytest.fixture
def app():
    if not HAS_FASTAPI:
        pytest.skip("FastAPI not installed")
    return create_app(api_key="test-key-123")


@pytest.fixture
def client(app):
    return TestClient(app)


def test_auth_missing_key(client):
    response = client.get("/status")
    assert response.status_code == 401
    assert "Invalid API Key" in response.text


def test_auth_invalid_key(client):
    response = client.get("/status", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401


@patch("core.firewall.get_status")
@patch("core.blocklist.get_stats_today")
@patch("core.blocklist.get_alerts")
@patch("core.blocklist.get_all_blocked")
def test_status_endpoint(mock_blocked, mock_alerts, mock_stats, mock_fw_status, client):
    mock_fw_status.return_value = {"active": True, "platform": "Windows"}
    mock_stats.return_value = {"blocks": 5}
    mock_alerts.return_value = ["alert1", "alert2"]
    mock_blocked.return_value = ["1.1.1.1"]

    response = client.get("/status", headers={"X-API-Key": "test-key-123"})
    assert response.status_code == 200
    data = response.json()
    assert data["alert_count"] == 2
    assert data["blocked_count"] == 1
    assert data["firewall"]["active"] is True


@patch("core.blocklist.get_all_blocked")
def test_blocked_endpoint(mock_blocked, client):
    mock_blocked.return_value = ["1.1.1.1", "2.2.2.2"]
    response = client.get("/blocked", headers={"X-API-Key": "test-key-123"})
    assert response.status_code == 200
    assert response.json() == ["1.1.1.1", "2.2.2.2"]


@patch("core.firewall.block_ip")
@patch("core.blocklist.add_block")
def test_block_endpoint_success(mock_add_block, mock_block_ip, client):
    mock_block_ip.return_value = {"success": True, "message": "Blocked"}
    
    response = client.post(
        "/block",
        json={"ip": "10.0.0.1", "reason": "test"},
        headers={"X-API-Key": "test-key-123"}
    )
    assert response.status_code == 200
    assert response.json() == {"success": True, "message": "Blocked"}
    mock_add_block.assert_called_once_with("10.0.0.1", "test")
    mock_block_ip.assert_called_once_with("10.0.0.1")


def test_block_endpoint_invalid_ip(client):
    response = client.post(
        "/block",
        json={"ip": "INVALID_IP", "reason": "test"},
        headers={"X-API-Key": "test-key-123"}
    )
    assert response.status_code == 400
    assert "Invalid IP" in response.text


@patch("core.firewall.unblock_ip")
@patch("core.blocklist.remove_block")
def test_unblock_endpoint_success(mock_remove_block, mock_unblock_ip, client):
    mock_unblock_ip.return_value = {"success": True, "message": "Unblocked"}
    
    response = client.post(
        "/unblock",
        json={"ip": "10.0.0.1"},
        headers={"X-API-Key": "test-key-123"}
    )
    assert response.status_code == 200
    assert response.json() == {"success": True, "message": "Unblocked"}
    mock_remove_block.assert_called_once_with("10.0.0.1")
    mock_unblock_ip.assert_called_once_with("10.0.0.1")


@patch("core.blocklist.get_alerts")
def test_alerts_endpoint(mock_get_alerts, client):
    mock_get_alerts.return_value = [{"id": 1, "ip_address": "8.8.8.8"}]
    
    response = client.get("/alerts?limit=10&unresolved_only=true", headers={"X-API-Key": "test-key-123"})
    assert response.status_code == 200
    assert response.json() == [{"id": 1, "ip_address": "8.8.8.8"}]
    mock_get_alerts.assert_called_once_with(limit=10, unresolved_only=True)


def test_websockets_events(client):
    # Test websocket connection
    with client.websocket_connect("/ws/events?api_key=test-key-123") as websocket:
        # If it didn't raise, we're connected successfully
        # Getting events is harder since we need to publish to the EventBus
        pass


def test_websockets_auth_failure(client):
    from fastapi import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/events?api_key=wrong-key"):
            pass
    assert exc.value.code == 1008


def test_api_server_class():
    if not HAS_FASTAPI:
        pytest.skip()
    server = APIServer(api_key="key", port=5999)
    assert server.running is False
    # don't actually start it to avoid binding ports and threads in basic unit test,
    # or we can mock uvicorn.
