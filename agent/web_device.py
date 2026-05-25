from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from flask import jsonify, request

from agent.services.api_client import Printer
from agent.web_collect import (
    _build_live_overview,
    _collector_service_for,
    _counter_worker,
    _emit_ui_event,
    _resolve_printer,
    _start_job,
    _status_worker,
    _stop_job,
)
from agent.web_discovery import (
    CACHE_TTL_SECONDS,
    DEFAULT_IGNORE_PREFIXES,
    _load_devices_cache,
    _load_printers,
    _normalize_ipv4,
    _normalize_mac,
    _save_devices_cache,
    _scan_devices_payload,
)

LOGGER = logging.getLogger(__name__)


def register_device_routes(app):
    config = app.config["APP_CONFIG"]
    api_client = app.config["API_CLIENT"]
    ricoh_service = app.config["RICOH_SERVICE"]
    toshiba_service = app.config["TOSHIBA_SERVICE"]

    def _resolve_target_printer(ip: str, user: str = "", password: str = "") -> Printer:
        devices = _load_printers(api_client)
        target = _resolve_printer(ip, devices)
        if not target:
            target = Printer(
                name="Local Printer",
                ip=ip,
                user=config.get_string("test.user"),
                password=config.get_string("test.password"),
                printer_type="ricoh",
                status="unknown",
            )
        if str(user or "").strip():
            target.user = str(user).strip()
        if str(password or "").strip():
            target.password = str(password).strip()
        if not str(target.user or "").strip():
            target.user = config.get_string("test.user")
        if target.password is None or str(target.password).strip() == "":
            target.password = config.get_string("test.password")
        return target

    @app.get("/api/overview")
    def api_overview() -> Any:
        devices = _load_printers(api_client)
        overview = _build_live_overview(ricoh_service, toshiba_service, devices)
        _emit_ui_event("overview_updated", overview)
        return jsonify(overview)

    @app.get("/api/devices")
    def api_devices() -> Any:
        ignored_prefixes = list(DEFAULT_IGNORE_PREFIXES)
        refresh_arg = str(request.args.get("refresh", "") or "").strip().lower()
        force_refresh = refresh_arg in {"1", "true", "yes", "y"}
        mode = "valid_only"

        if not force_refresh:
            cached_devices, cached_at_str = _load_devices_cache()
            if cached_devices and cached_at_str:
                try:
                    cached_at = datetime.strptime(cached_at_str, "%Y-%m-%d %H:%M:%S")
                    age = (datetime.now() - cached_at).total_seconds()
                    if age < CACHE_TTL_SECONDS:
                        return jsonify(
                            {
                                "devices": cached_devices,
                                "cached": True,
                                "cached_at": cached_at_str,
                                "filter_mode": mode,
                            }
                        )
                except Exception:  # noqa: BLE001
                    pass

        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode, force_refresh=force_refresh)
        _save_devices_cache(payload)
        return jsonify(
            {
                "devices": payload,
                "cached": False,
                "cached_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "filter_mode": mode,
            }
        )

    @app.post("/api/devices/refresh")
    def api_devices_refresh() -> Any:
        ignored_prefixes = list(DEFAULT_IGNORE_PREFIXES)
        mode = "valid_only"
        # Button refresh always forces a full subnet scan to populate ARP cache.
        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode, force_refresh=True)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_devices_cache(payload)
        return jsonify({"ok": True, "devices": payload, "cached": False, "cached_at": now, "filter_mode": mode})

    @app.post("/api/devices/action")
    def api_action() -> Any:
        request_data = request.get_json(silent=True) or {}
        ip = str(request_data.get("ip", "")).strip()
        action = str(request_data.get("action", "")).strip().lower()
        trace_id = f"device-action-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not action:
            return jsonify({"ok": False, "error": "Missing action"}), 400
        LOGGER.info("Device action request: trace_id=%s ip=%s action=%s remote_addr=%s", trace_id, ip, action, request.remote_addr or "-")

        target = _resolve_target_printer(ip=ip)
        collector = _collector_service_for(target, ricoh_service, toshiba_service)

        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]

        try:
            if action == "status":
                payload = collector.process_status(target, should_post=False)
                _emit_ui_event("device_status", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "counter":
                payload = collector.process_counter(target, should_post=False)
                _emit_ui_event("device_counter", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "device_info":
                payload = collector.process_device_info(target, should_post=False)
                _emit_ui_event("device_info", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "enable_machine":
                if not str(target.user or "").strip():
                    target.user = config.get_string("test.user") or "admin"
                if target.password is None or str(target.password).strip() == "":
                    target.password = config.get_string("test.password") or "admin"
                LOGGER.info(
                    "Device action apply: trace_id=%s ip=%s action=%s user=%s has_password=%s",
                    trace_id,
                    ip,
                    action,
                    str(target.user or ""),
                    bool(str(target.password or "").strip()),
                )
                ricoh_service.enable_machine(target)
                LOGGER.info("Device action success: trace_id=%s ip=%s action=%s", trace_id, ip, action)
                _emit_ui_event("machine_enabled", {"ip": target.ip, "name": target.name})
                return jsonify({"ok": True, "action": action, "message": "Machine enabled successfully (EasySecurity OFF)"})
            if action in {"lock_machine", "disable_machine"}:
                if not str(target.user or "").strip():
                    target.user = config.get_string("test.user") or "admin"
                if target.password is None or str(target.password).strip() == "":
                    target.password = config.get_string("test.password") or "admin"
                LOGGER.info(
                    "Device action apply: trace_id=%s ip=%s action=%s user=%s has_password=%s",
                    trace_id,
                    ip,
                    action,
                    str(target.user or ""),
                    bool(str(target.password or "").strip()),
                )
                ricoh_service.disable_machine(target)
                LOGGER.info("Device action success: trace_id=%s ip=%s action=%s", trace_id, ip, action)
                _emit_ui_event("machine_locked", {"ip": target.ip, "name": target.name})
                _emit_ui_event("machine_disabled", {"ip": target.ip, "name": target.name})
                return jsonify({"ok": True, "action": action, "message": "Machine disabled successfully (UserCode profile applied)"})
            if action == "address_list":
                trace_id = f"action-scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
                payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                if isinstance(payload, dict):
                    payload.setdefault("debug", {})
                    if isinstance(payload["debug"], dict):
                        payload["debug"]["trace_id"] = trace_id
                _emit_ui_event("address_list", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "address_create":
                name = str(request_data.get("name", "")).strip()
                email = str(request_data.get("email", "")).strip()
                folder = str(request_data.get("folder", "")).strip()
                user_code = str(request_data.get("user_code", "")).strip()
                fields = request_data.get("fields", {})
                if not name:
                    return jsonify({"ok": False, "error": "Missing name"}), 400
                if fields is not None and not isinstance(fields, dict):
                    return jsonify({"ok": False, "error": "fields must be object"}), 400
                payload = ricoh_service.create_address_user_wizard(
                    target,
                    name=name,
                    email=email,
                    folder=folder,
                    user_code=user_code,
                    fields=fields if isinstance(fields, dict) else None,
                )
                _emit_ui_event("address_create", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "address_modify":
                registration_no = str(request_data.get("registration_no", "")).strip()
                name = str(request_data.get("name", "")).strip()
                email = str(request_data.get("email", "")).strip()
                folder = str(request_data.get("folder", "")).strip()
                user_code = str(request_data.get("user_code", "")).strip()
                fields = request_data.get("fields", {})
                if not registration_no:
                    return jsonify({"ok": False, "error": "Missing registration_no"}), 400
                if fields is not None and not isinstance(fields, dict):
                    return jsonify({"ok": False, "error": "fields must be object"}), 400
                payload = ricoh_service.modify_address_user_wizard(
                    target,
                    registration_no=registration_no,
                    name=name,
                    email=email,
                    folder=folder,
                    user_code=user_code,
                    fields=fields if isinstance(fields, dict) else None,
                )
                _emit_ui_event("address_modify", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "log_counter_start":
                ok, message = _start_job(
                    counter_jobs,
                    ip,
                    lambda stop_event: _counter_worker(ricoh_service, toshiba_service, target, stop_event),
                )
                _emit_ui_event("counter_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": counter_jobs.get(ip, {})})
            if action == "log_counter_stop":
                ok, message = _stop_job(counter_jobs, ip)
                _emit_ui_event("counter_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "log_status_start":
                ok, message = _start_job(
                    status_jobs,
                    ip,
                    lambda stop_event: _status_worker(ricoh_service, toshiba_service, target, stop_event),
                )
                _emit_ui_event("status_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": status_jobs.get(ip, {})})
            if action == "log_status_stop":
                ok, message = _stop_job(status_jobs, ip)
                _emit_ui_event("status_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "exit":
                c_ok, c_message = _stop_job(counter_jobs, ip)
                s_ok, s_message = _stop_job(status_jobs, ip)
                if not c_ok and not s_ok:
                    _emit_ui_event("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
                    return jsonify({"ok": True, "action": action, "message": "No running log jobs"})
                _emit_ui_event("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
                return jsonify(
                    {
                        "ok": True,
                        "action": action,
                        "message": f"Stopped jobs: counter={c_message}, status={s_message}",
                    }
                )
            if action == "job_status":
                return jsonify(
                    {
                        "ok": True,
                        "action": action,
                        "counter_running": bool(counter_jobs.get(ip) and counter_jobs[ip]["thread"].is_alive()),
                        "status_running": bool(status_jobs.get(ip) and status_jobs[ip]["thread"].is_alive()),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Device action failed: trace_id=%s ip=%s action=%s", trace_id, ip, action)
            return jsonify({"ok": False, "error": str(exc), "action": action}), 500

        return jsonify({"ok": False, "error": f"Unsupported action: {action}"}), 400

    @app.get("/api/devices/machine-state")
    def api_device_machine_state() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        trace_id = f"machine-state-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        user_arg = str(request.args.get("user", "")).strip()
        password_arg = str(request.args.get("password", "")).strip()

        base_target = _resolve_target_printer(ip=ip, user=user_arg, password=password_arg)
        resolved_user = str(base_target.user or "").strip()
        resolved_password = str(base_target.password or "").strip()
        config_user = str(config.get_string("test.user") or "").strip()
        config_password = str(config.get_string("test.password") or "").strip()

        attempts: list[tuple[str, str, str]] = []
        # Priority: explicit query -> resolved target -> test credential -> admin/admin.
        if user_arg or password_arg:
            attempts.append(("query", user_arg, password_arg))
        if resolved_user or resolved_password:
            attempts.append(("resolved", resolved_user, resolved_password))
        if config_user or config_password:
            attempts.append(("config", config_user, config_password))
        attempts.append(("admin_default", "admin", "admin"))

        # Deduplicate same credential pairs.
        unique_attempts: list[tuple[str, str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for label, user_value, password_value in attempts:
            pair = (str(user_value or ""), str(password_value or ""))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique_attempts.append((label, pair[0], pair[1]))

        last_error = ""
        last_auth_user = ""
        last_auth_password = ""
        last_auth_attempt = ""
        for label, user_value, password_value in unique_attempts:
            target = _resolve_target_printer(ip=ip, user=user_value, password=password_value)
            target.user = user_value
            target.password = password_value
            LOGGER.info(
                "Machine state request: trace_id=%s ip=%s attempt=%s user=%s has_password=%s remote_addr=%s",
                trace_id,
                ip,
                label,
                str(target.user or ""),
                bool(str(target.password or "").strip()),
                request.remote_addr or "-",
            )
            try:
                state = ricoh_service.read_machine_control_state(target)
            except Exception as exc:  # noqa: BLE001
                state = {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": "/web/entry/en/websys/config/getUserAuthenticationManager.cgi",
                    "status": "error",
                    "state": "error",
                    "auth_ok": False,
                    "error": str(exc),
                }
                LOGGER.warning(
                    "Machine state exception: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    exc,
                )

            state_status_raw = str(state.get("status") or state.get("state") or "").strip().lower()
            if state_status_raw in {"enabled"}:
                state_status = "enable"
            elif state_status_raw in {"disabled"}:
                state_status = "disable"
            elif state_status_raw in {"enable", "disable", "error"}:
                state_status = state_status_raw
            elif "error" in state:
                state_status = "error"
            else:
                state_status = "enable" if bool(state.get("enabled", False)) else "disable"
            state["status"] = state_status
            state["state"] = state_status

            if state_status == "error":
                error_text = str(state.get("error") or "Unable to read machine state").strip()
                state["error"] = error_text
                last_error = error_text
                if bool(state.get("auth_ok", False)):
                    last_auth_user = str(target.user or "").strip()
                    last_auth_password = str(target.password or "").strip()
                    last_auth_attempt = label
                LOGGER.warning(
                    "Machine state attempt failed: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    error_text,
                )
                continue

            auth_user = str(target.user or "").strip()
            auth_password = str(target.password or "").strip()
            LOGGER.info(
                "Machine state success: trace_id=%s ip=%s attempt=%s status=%s method=%s auth_user=%s has_password=%s",
                trace_id,
                ip,
                label,
                state_status,
                str(state.get("method", "")),
                auth_user,
                bool(auth_password),
            )
            return jsonify(
                {
                    "ok": True,
                    "ip": ip,
                    "state": state,
                    "trace_id": trace_id,
                    "auth_attempt": label,
                    "auth_user": auth_user,
                    "auth_password": auth_password,
                }
            )

        error_text = last_error or "Unable to read machine state"
        return jsonify(
            {
                "ok": True,
                "error": error_text,
                "ip": ip,
                "trace_id": trace_id,
                "auth_attempt": last_auth_attempt,
                "auth_user": last_auth_user,
                "auth_password": last_auth_password,
                "state": {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": "/web/entry/en/websys/config/getUserAuthenticationManager.cgi",
                    "status": "error",
                    "state": "error",
                    "auth_ok": bool(last_auth_user or last_auth_password),
                    "error": error_text,
                },
            }
        )

    @app.get("/api/device/interface")
    def api_device_interface() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        trace_id = f"iface-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        base_target = _resolve_target_printer(ip=ip, user=user, password=password)
        resolved_user = str(base_target.user or "").strip()
        resolved_password = str(base_target.password or "").strip()
        config_user = str(config.get_string("test.user") or "").strip()
        config_password = str(config.get_string("test.password") or "").strip()

        attempts: list[tuple[str, str, str]] = []
        if user or password:
            attempts.append(("query", user, password))
        if resolved_user or resolved_password:
            attempts.append(("resolved", resolved_user, resolved_password))
        if config_user or config_password:
            attempts.append(("config", config_user, config_password))
        attempts.append(("admin_default", "admin", "admin"))
        attempts.append(("guest", "", ""))

        unique_attempts: list[tuple[str, str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for label, user_value, password_value in attempts:
            pair = (str(user_value or ""), str(password_value or ""))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique_attempts.append((label, pair[0], pair[1]))

        last_error = ""
        for label, user_value, password_value in unique_attempts:
            target = _resolve_target_printer(ip=ip, user=user_value, password=password_value)
            target.user = user_value
            target.password = password_value
            try:
                html = ricoh_service.read_network_interface(target)
                raw_macs = re.findall(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", html or "")
                macs = []
                for item in raw_macs:
                    normalized = _normalize_mac(item)
                    if normalized and normalized not in macs:
                        macs.append(normalized)
                LOGGER.info(
                    "Device interface success: trace_id=%s ip=%s attempt=%s macs=%s",
                    trace_id,
                    ip,
                    label,
                    len(macs),
                )
                return jsonify({"ok": True, "ip": ip, "macs": macs, "raw_len": len(html or ""), "trace_id": trace_id, "auth_attempt": label})
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                LOGGER.warning(
                    "Device interface attempt failed: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    exc,
                )
        return jsonify({"ok": False, "error": last_error or "Unable to read interface", "ip": ip, "trace_id": trace_id})

    from agent.web_polling import register_polling_routes

    register_polling_routes(app)
