from __future__ import annotations

from typing import Any

from flask import jsonify, request

from agent.config import AppConfig
from agent.services.polling_bridge import PollingBridge


def register_polling_routes(app):
    @app.get("/api/log-jobs")
    def api_log_jobs() -> Any:
        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]
        return jsonify(
            {
                "counter": [
                    {"ip": ip, "running": value["thread"].is_alive(), "started_at": value.get("started_at", "")}
                    for ip, value in counter_jobs.items()
                ],
                "status": [
                    {"ip": ip, "running": value["thread"].is_alive(), "started_at": value.get("started_at", "")}
                    for ip, value in status_jobs.items()
                ],
            }
        )

    @app.get("/api/polling/status")
    def api_polling_status() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        return jsonify(bridge.status())

    @app.post("/api/polling/toggle")
    def api_polling_toggle() -> Any:
        body = request.get_json(silent=True) or {}
        enabled_raw = body.get("enabled", None)
        if enabled_raw is None:
            return jsonify({"ok": False, "error": "Missing enabled"}), 400
        if isinstance(enabled_raw, bool):
            enabled = enabled_raw
        else:
            enabled = str(enabled_raw).strip().lower() in {"1", "true", "yes", "on"}

        app_cfg: AppConfig = app.config["APP_CONFIG"]
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]

        app_cfg.set_value("polling.enabled", enabled)

        if enabled:
            ok, message = bridge.start()
            return jsonify({"ok": ok, "message": message, "status": bridge.status()})
        bridge.stop()
        return jsonify({"ok": True, "message": "Polling stopped", "status": bridge.status()})

    @app.post("/api/polling/trigger")
    def api_polling_trigger() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        ok, message = bridge.trigger_once()
        code = 200 if ok else 400
        return jsonify({"ok": ok, "message": message, "status": bridge.status()}), code

