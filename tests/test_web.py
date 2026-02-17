from __future__ import annotations

from app.web import create_app


def test_dashboard_route_renders() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Config" in response.data


def test_overview_api_shape() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.get("/api/overview")
    assert response.status_code == 200
    body = response.get_json()
    assert "stats" in body
    assert "trend" in body


def test_ws_status_endpoint() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.get("/api/ws/status")
    assert response.status_code == 200
    body = response.get_json()
    assert "configured" in body
    assert "connected" in body


def test_ws_connect_without_url() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.post("/api/ws/connect")
    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is False


def test_update_status_endpoint() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.get("/api/update/status")
    assert response.status_code == 200
    body = response.get_json()
    assert "current_version" in body
    assert "auto_apply" in body


def test_update_check_endpoint() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.post("/api/update/check", json={"version": "9.9.9", "command": "git pull --ff-only"})
    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert "listen mode" in body["message"].lower()
    assert "status" in body


def test_dashboard_config_endpoint() -> None:
    app = create_app("config.yaml")
    client = app.test_client()
    response = client.get("/api/dashboard/config")
    assert response.status_code == 200
    body = response.get_json()
    assert "env" in body
    assert "network" in body
    assert "computers" in body
    assert "printers" in body
    assert "links" in body
