from __future__ import annotations

import pytest
from agent.web import create_app
from agent.services.polling_bridge import PollingBridge


@pytest.fixture
def client(monkeypatch):
    # Mock PollingBridge.start and other system lookups to prevent background threads and actual scanning/routing errors
    monkeypatch.setattr(PollingBridge, "start", lambda self: (True, "Mock started"))
    monkeypatch.setattr(PollingBridge, "_resolve_local_ip", lambda self: "127.0.0.1")
    monkeypatch.setattr(PollingBridge, "_resolve_lan_info", lambda self, h, ip: ("test_lan_uid", "test_fingerprint"))
    
    app = create_app(["--mode", "web"])
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_index_redirects_to_devices(client) -> None:
    response = client.get("/")
    assert response.status_code == 302
    assert response.location.endswith("/devices")


def test_devices_route_renders(client) -> None:
    response = client.get("/devices")
    assert response.status_code == 200
    assert b"Devices" in response.data or b"test_lan_uid" in response.data


def test_scan_route_renders(client) -> None:
    response = client.get("/scan")
    assert response.status_code == 200


def test_ftp_route_renders(client) -> None:
    response = client.get("/ftp")
    assert response.status_code == 200


def test_api_ui_config(client) -> None:
    response = client.get("/api/ui/config")
    assert response.status_code == 200
    body = response.get_json()
    assert body["lan_uid"] == "test_lan_uid"
    assert "env" in body


def test_update_status_endpoint(client) -> None:
    response = client.get("/api/update/status")
    assert response.status_code == 200
    body = response.get_json()
    assert "current_version" in body
    assert "auto_apply" in body


def test_update_check_endpoint_listen_mode(client) -> None:
    response = client.post("/api/update/check", json={"version": "9.9.9", "command": "git pull --ff-only"})
    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert "listen mode" in body["message"].lower()
    assert "status" in body
