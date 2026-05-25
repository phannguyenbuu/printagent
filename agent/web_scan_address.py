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


def register_scan_address_routes(app):
    config = app.config["APP_CONFIG"]
    api_client = app.config["API_CLIENT"]
    ricoh_service = app.config["RICOH_SERVICE"]

    @app.get("/api/scan/address-list")
    def api_scan_address_list() -> Any:
        ip = str(request.args.get("ip", "")).strip()
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        mode = str(request.args.get("mode", "")).strip().lower()
        trace_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        if not ip:
            LOGGER.warning("Scan address list rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        LOGGER.info(
            "Scan address list request: trace_id=%s ip=%s mode=%s user_provided=%s password_provided=%s remote_addr=%s",
            trace_id,
            ip,
            mode or "-",
            bool(user),
            bool(password),
            request.remote_addr or "-",
        )
        if mode == "adrslistall":
            try:
                # Popup Scan tab uses fixed credential as requested.
                effective_user = "admin"
                effective_password = "admin"
                target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
                target.user = effective_user
                target.password = effective_password
                session = ricoh_service.create_http_client_auth_form_only(target)
                html = ricoh_service.authenticate_and_get(session, target, "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL")
                if ("Address List" not in html and "adrsList" not in html) or "login.cgi" in html:
                    html = ricoh_service.authenticate_and_get(session, target, "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL")
                entries = ricoh_service.parse_address_list(html)
                
                # Extract wimToken from html if present
                wim_token = ricoh_service._extract_hidden_inputs(html).get("wimToken", "")
                if not wim_token:
                    wim_token = ricoh_service._extract_wim_token(html)
                
                ajax_raw = ""
                ajax_entries = []
                try:
                    ajax_raw = ricoh_service.get_address_list_ajax_with_client(session, target, wim_token=wim_token)
                    ajax_entries = ricoh_service.parse_ajax_address_list(ajax_raw)
                    if ajax_entries:
                        summary = entries[0] if entries else None
                        merged_by_reg: dict[str, Any] = {}
                        merged_order: list[str] = []

                        def _score(item: Any) -> int:
                            score = 0
                            if str(getattr(item, "name", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "email_address", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "folder", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "user_code", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            return score

                        for source in [entries[1:] if len(entries) > 1 else [], ajax_entries]:
                            for item in source:
                                reg = str(getattr(item, "registration_no", "") or "").strip()
                                name_key = str(getattr(item, "name", "") or "").strip().lower()
                                if reg and reg != "-":
                                    # Some devices may return duplicated registration_no for newly-created rows.
                                    # Keep per (registration_no, name) so we do not collapse distinct entries.
                                    key = f"reg::{reg}::name::{name_key}"
                                else:
                                    key = f"name::{name_key}"
                                if key not in merged_by_reg:
                                    merged_by_reg[key] = item
                                    merged_order.append(key)
                                else:
                                    if _score(item) >= _score(merged_by_reg[key]):
                                        merged_by_reg[key] = item

                        merged_entries = [merged_by_reg[key] for key in merged_order]
                        entries = ([summary] if summary else []) + merged_entries
                except Exception:  # noqa: BLE001
                    ajax_raw = ""
                    ajax_entries = []
                # If LIST_ALL + AJAX still yields only summary, fallback to full parser flow.
                non_summary = max(0, len(entries) - 1)
                if non_summary == 0:
                    try:
                        fallback_payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                        if isinstance(fallback_payload, dict):
                            fallback_payload.setdefault("debug", {})
                            if isinstance(fallback_payload["debug"], dict):
                                fallback_payload["debug"]["mode"] = "adrsListAll_fallback_process_address_list"
                                fallback_payload["debug"]["trace_id"] = trace_id
                        return jsonify({"ok": True, "payload": fallback_payload})
                    except Exception:  # noqa: BLE001
                        pass
                payload = {
                    "printer_name": target.name,
                    "ip": target.ip,
                    "html": html,
                    "easysecurity_html": "",
                    "address_list": [
                        {
                            "type": item.type,
                            "registration_no": item.registration_no,
                            "name": item.name,
                            "user_code": item.user_code,
                            "date_last_used": item.date_last_used,
                            "email_address": item.email_address,
                            "folder": item.folder,
                            "entry_id": getattr(item, "entry_id", "") or "",
                        }
                        for item in entries
                    ],
                    "debug": {
                        "trace_id": trace_id,
                        "mode": "adrsListAll",
                        "html_len": len(html),
                        "entries": len(entries),
                        "ajax_len": len(ajax_raw),
                        "ajax_entries": len(ajax_entries),
                    },
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
                return jsonify({"ok": True, "payload": payload})
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Scan address list adrsListAll failed: trace_id=%s ip=%s", trace_id, ip)
                return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

        def _looks_like_login_endpoint_500(exc: Exception) -> bool:
            text = str(exc or "").lower()
            return (
                "500 server error" in text
                and "login.cgi" in text
                and "websys/webarch" in text
            )
        try:
            # Force login-first flow for address list: if caller does not provide credentials,
            # default to admin/admin before fetching address list.
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            LOGGER.info(
                "Scan address list single attempt: trace_id=%s ip=%s printer_name=%s effective_user=%s has_password=%s",
                trace_id,
                target.ip,
                target.name,
                bool(str(target.user or "").strip()),
                bool(str(target.password or "").strip()),
            )
            payload = ricoh_service.process_address_list(target, trace_id=trace_id)
            if isinstance(payload, dict):
                payload.setdefault("debug", {})
                if isinstance(payload["debug"], dict):
                    payload["debug"]["trace_id"] = trace_id
                    payload["debug"]["auth_mode"] = "single_attempt"
                    payload["debug"]["auth_round"] = 1
            return jsonify({"ok": True, "payload": payload})
        except Exception as exc:  # noqa: BLE001
            if _looks_like_login_endpoint_500(exc):
                LOGGER.warning(
                    "Scan address list login endpoint 500, fallback to no-auth: trace_id=%s ip=%s",
                    trace_id,
                    ip,
                )
                try:
                    target = resolve_target_printer(config, api_client, ip=ip, user="", password="")
                    target.user = ""
                    target.password = ""
                    payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                    if isinstance(payload, dict):
                        payload.setdefault("debug", {})
                        if isinstance(payload["debug"], dict):
                            payload["debug"]["trace_id"] = trace_id
                            payload["debug"]["auth_mode"] = "fallback_no_auth_after_login_500"
                            payload["debug"]["auth_round"] = 2
                    return jsonify({"ok": True, "payload": payload})
                except Exception as fallback_exc:  # noqa: BLE001
                    LOGGER.exception(
                        "Scan address list fallback no-auth failed: trace_id=%s ip=%s",
                        trace_id,
                        ip,
                    )
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": str(fallback_exc),
                                "trace_id": trace_id,
                                "primary_error": str(exc),
                            }
                        ),
                        500,
                    )
            LOGGER.exception("Scan address list failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-create")
    def api_scan_address_create() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-create-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip:
            LOGGER.warning("Scan address create rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not name:
            LOGGER.warning("Scan address create rejected: trace_id=%s ip=%s reason=missing_name", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing name"}), 400
        if fields is not None and not isinstance(fields, dict):
            LOGGER.warning("Scan address create rejected: trace_id=%s ip=%s reason=invalid_fields_type", trace_id, ip)
            return jsonify({"ok": False, "error": "fields must be object"}), 400
        try:
            # Address-create flow is FTP-first by design.
            selected_protocol = "FTP"
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address create request: trace_id=%s ip=%s name=%s email_set=%s folder_set=%s user_code_set=%s fields_count=%s auth_mode=%s",
                trace_id,
                ip,
                name,
                bool(email),
                bool(folder),
                bool(user_code),
                len(fields) if isinstance(fields, dict) else 0,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            ftp_payload: dict[str, Any] | None = None
            folder_final = folder
            if selected_protocol == "FTP":
                ftp_payload = create_local_ftp_for_address(config, ricoh_service, name, printer_ip=ip)
                LOGGER.info(
                    "Scan address create FTP step: trace_id=%s ip=%s ftp_name=%s ftp_url=%s ftp_ok=%s",
                    trace_id,
                    ip,
                    str(ftp_payload.get("ftp_name", "")).strip(),
                    str(ftp_payload.get("upload_url", "") or ftp_payload.get("ftp_url", "")).strip(),
                    bool(ftp_payload.get("ok", False)),
                )
                if not bool(ftp_payload.get("ok", False)):
                    LOGGER.warning(
                        "Scan address create FTP setup failed: trace_id=%s ip=%s name=%s error=%s",
                        trace_id,
                        ip,
                        name,
                        str((ftp_payload.get("result") or {}).get("error", "")).strip(),
                    )
                    return jsonify(
                        {
                            "ok": False,
                            "error": "FTP setup failed before address creation",
                            "trace_id": trace_id,
                            "protocol": selected_protocol,
                            "ftp": ftp_payload,
                        }
                    ), 500
                folder_final = str(ftp_payload.get("upload_url", "") or ftp_payload.get("ftp_url", "")).strip() or folder_final
                LOGGER.info(
                    "Scan address create folder overridden by FTP: trace_id=%s ip=%s folder=%s",
                    trace_id,
                    ip,
                    folder_final,
                )
                ftp_warning = str(ftp_payload.get("warning", "") or "").strip()
                if ftp_warning:
                    LOGGER.warning(
                        "Scan address create FTP warning: trace_id=%s ip=%s warning=%s",
                        trace_id,
                        ip,
                        ftp_warning,
                    )
            merged_fields: dict[str, Any] = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            payload = ricoh_service.create_address_user_wizard(
                target,
                name=name,
                email=email,
                folder=folder_final,
                user_code=user_code,
                fields=merged_fields,
            )
            LOGGER.info(
                "Scan address create success: trace_id=%s ip=%s http_status=%s verify_count=%s",
                trace_id,
                ip,
                payload.get("http_status") if isinstance(payload, dict) else "-",
                payload.get("verify_count") if isinstance(payload, dict) else "-",
            )
            return jsonify(
                {
                    "ok": True,
                    "payload": payload,
                    "trace_id": trace_id,
                    "protocol": selected_protocol,
                    "folder_used": folder_final,
                    "ftp": ftp_payload,
                }
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address create failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-delete")
    def api_scan_address_delete() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-delete-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        confirm = bool(body.get("confirm", False))
        if not ip:
            LOGGER.warning("Scan address delete rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not registration_no and not entry_id:
            LOGGER.warning("Scan address delete rejected: trace_id=%s ip=%s reason=missing_registration_no", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing registration_no or entry_id"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address delete request: trace_id=%s ip=%s registration_no=%s entry_id=%s auth_mode=%s",
                trace_id,
                ip,
                registration_no,
                entry_id,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            payload = ricoh_service.delete_address_entries(
                target,
                [registration_no],
                entry_ids=[entry_id] if entry_id else None,
                verify=not confirm,
            )
            LOGGER.info(
                "Scan address delete success: trace_id=%s ip=%s deleted_count=%s",
                trace_id,
                ip,
                payload.get("deleted_count") if isinstance(payload, dict) else "-",
            )
            return jsonify({"ok": True, "payload": payload, "trace_id": trace_id})
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address delete failed: trace_id=%s ip=%s registration_no=%s", trace_id, ip, registration_no)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-modify")
    def api_scan_address_modify() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-modify-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip:
            LOGGER.warning("Scan address modify rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not registration_no:
            LOGGER.warning("Scan address modify rejected: trace_id=%s ip=%s reason=missing_registration_no", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing registration_no"}), 400
        if fields is not None and not isinstance(fields, dict):
            LOGGER.warning("Scan address modify rejected: trace_id=%s ip=%s reason=invalid_fields_type", trace_id, ip)
            return jsonify({"ok": False, "error": "fields must be object"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address modify request: trace_id=%s ip=%s registration_no=%s name_set=%s email_set=%s folder_set=%s user_code_set=%s fields_count=%s auth_mode=%s",
                trace_id,
                ip,
                registration_no,
                bool(name),
                bool(email),
                bool(folder),
                bool(user_code),
                len(fields) if isinstance(fields, dict) else 0,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            LOGGER.info(
                "Scan address modify (recreate) request: trace_id=%s ip=%s registration_no=%s entry_id=%s",
                trace_id,
                ip,
                registration_no,
                entry_id,
            )
            if entry_id:
                ricoh_service.delete_address_entries(target, [registration_no], entry_ids=[entry_id], verify=False)
            else:
                ricoh_service.delete_address_entries(target, [registration_no], verify=False)
            create_payload = ricoh_service.create_address_user_wizard(
                target,
                name=name,
                email=email,
                folder=folder,
                user_code=user_code,
                fields=fields if isinstance(fields, dict) else None,
                desired_registration_no=registration_no,
                allow_auto_update=False,
            )
            return jsonify(
                {
                    "ok": True,
                    "payload": create_payload,
                    "trace_id": trace_id,
                    "recreated": True,
                    "message": "Entry recreated (requested to keep registration_no when possible).",
                }
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address modify failed: trace_id=%s ip=%s registration_no=%s", trace_id, ip, registration_no)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

