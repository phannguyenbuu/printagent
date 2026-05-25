from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import jsonify, request

from agent.web_discovery import _normalize_ipv4
from agent.web_scan_helpers import create_local_ftp_for_address, resolve_target_printer
from agent.web_scan_support import (
    _detect_scan_protocol_from_html,
    _load_scan_protocol_prefs,
    _normalize_scan_protocol,
    _register_scan_root,
    _sanitize_ftp_name,
    _save_scan_protocol_prefs,
)

LOGGER = logging.getLogger(__name__)


def register_scan_misc_routes(app):
    config = app.config["APP_CONFIG"]
    api_client = app.config["API_CLIENT"]
    ricoh_service = app.config["RICOH_SERVICE"]

    @app.get("/api/scan/protocol")
    def api_scan_protocol_get() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        prefs = _load_scan_protocol_prefs()
        saved = _normalize_scan_protocol(prefs.get(ip, ""))
        detected = ""
        try:
            target = resolve_target_printer(config, api_client, ip=ip, user=user, password=password)
            html = ricoh_service.read_device_info(target)
            detected = _normalize_scan_protocol(_detect_scan_protocol_from_html(html))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Scan protocol detect failed: ip=%s error=%s", ip, exc)
        protocol = detected or saved or "FTP"
        return jsonify(
            {
                "ok": True,
                "ip": ip,
                "protocol": protocol,
                "detected": detected,
                "saved": saved,
                "options": ["FTP", "SMBv2/3", "SMBv1"],
            }
        )

    @app.post("/api/scan/protocol")
    def api_scan_protocol_set() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        protocol = _normalize_scan_protocol(str(body.get("protocol", "")).strip())
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not protocol:
            return jsonify({"ok": False, "error": "Invalid protocol"}), 400
        prefs = _load_scan_protocol_prefs()
        prefs[ip] = protocol
        _save_scan_protocol_prefs(prefs)
        LOGGER.info("Scan protocol saved: ip=%s protocol=%s", ip, protocol)
        return jsonify({"ok": True, "ip": ip, "protocol": protocol})

    @app.post("/api/scan/isolate-session")
    def api_scan_isolate_session() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]
        counter_stopped, counter_msg = _stop_job(counter_jobs, ip)
        status_stopped, status_msg = _stop_job(status_jobs, ip)
        bridge.stop()
        target = resolve_target_printer(config, api_client, ip=ip, user=user, password=password)
        try:
            ricoh_service.reset_web_session(target)
            logout_ok = True
            logout_msg = "session reset requested"
        except Exception as exc:  # noqa: BLE001
            logout_ok = False
            logout_msg = str(exc)
        LOGGER.info(
            "Scan isolate session: ip=%s polling_running=%s counter_stop=%s status_stop=%s logout_ok=%s",
            ip,
            bool(bridge.status().get("running", False)),
            counter_msg,
            status_msg,
            logout_ok,
        )
        return jsonify(
            {
                "ok": True,
                "ip": ip,
                "polling_running": bool(bridge.status().get("running", False)),
                "counter_stop": {"ok": counter_stopped, "message": counter_msg},
                "status_stop": {"ok": status_stopped, "message": status_msg},
                "logout": {"ok": logout_ok, "message": logout_msg},
            }
        )

    @app.post("/api/scan/release-session")
    def api_scan_release_session() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        status = bridge.status()
        if bool(status.get("running", False)):
            # UI can call release on load/cleanup; ignore silently when polling is already active.
            return jsonify({"ok": True, "polling_start_ok": True, "message": "Polling already running", "status": status})
        ok, message = bridge.start()
        LOGGER.info("Scan release session: polling_start_ok=%s message=%s", ok, message)
        return jsonify({"ok": True, "polling_start_ok": ok, "message": message, "status": bridge.status()})

    @app.post("/api/shares/create")
    def api_shares_create() -> Any:
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        if not username:
            return jsonify({"ok": False, "error": "Missing username"}), 400
        
        res = ricoh_service.share_manager.setup_auto_share(username)
        return jsonify(res)

    @app.post("/api/scan/setup-auto")
    def api_scan_setup_auto() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        username = str(body.get("username", "")).strip()
        fields = body.get("fields", {})

        if not ip or not username:
            return jsonify({"ok": False, "error": "Missing ip or username"}), 400

        target = resolve_target_printer(config, api_client, ip=ip)
        res = ricoh_service.setup_scan_destination(target, username, fields=fields)
        
        if res.get("ok"):
            LOGGER.info("Auto-scan setup success: ip=%s username=%s", ip, username)
        else:
            LOGGER.warning("Auto-scan setup failed: ip=%s username=%s error=%s", ip, username, res.get("error"))
            
        return jsonify(res)

