from __future__ import annotations

import hashlib
import json
import logging
import time as time_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename
from sqlalchemy import select

from app_helpers import (
    ONLINE_STALE_SECONDS,
    _request_api_token,
    _resolve_request_lead,
    _validate_polling_auth,
    _resolve_lan_uid_with_session,
)
from utils import (
    UI_TZ,
    _to_text,
    _to_int,
    _parse_timestamp,
    _safe_path_token,
    _safe_relative_path_parts,
)
from serializers import (
    _refresh_stale_agent_offline,
    _upsert_lan_and_agent,
    _upsert_printer_from_polling,
    _apply_printer_enabled_state,
)
from models import Printer, PrinterControlCommand

LOGGER = logging.getLogger(__name__)

SCAN_UPLOAD_ROOT = Path("storage/uploads/scans")


def register_polling_aux_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str], drive_sync: Any, cfg: Any) -> None:

    @app.get("/api/polling/controls")
    def polling_controls() -> Any:
        agent_uid = _to_text(request.args.get("agent_uid"))
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(
                session,
                lead_valid,
                {
                    "lead": lead_valid,
                    "lan_uid": _to_text(request.args.get("lan_uid")),
                    "agent_uid": agent_uid,
                    "hostname": "",
                    "local_ip": "",
                    "gateway_ip": _to_text(request.args.get("gateway_ip")),
                    "gateway_mac": _to_text(request.args.get("gateway_mac")),
                },
            )
            stmt = select(Printer).where(Printer.lead == lead_valid, Printer.lan_uid == lan_uid).order_by(Printer.id.asc())
            if agent_uid:
                stmt = stmt.where(Printer.agent_uid == agent_uid)
            rows = session.execute(stmt).scalars().all()
            pending_cmds = session.execute(
                select(PrinterControlCommand)
                .where(
                    PrinterControlCommand.lead == lead_valid,
                    PrinterControlCommand.lan_uid == lan_uid,
                    PrinterControlCommand.status == "pending",
                )
                .order_by(PrinterControlCommand.requested_at.asc(), PrinterControlCommand.id.asc())
            ).scalars().all()
            pending_by_printer: dict[int, PrinterControlCommand] = {}
            for cmd in pending_cmds:
                if cmd.printer_id in pending_by_printer:
                    continue
                pending_by_printer[int(cmd.printer_id)] = cmd
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "rows": [
                    {
                        "id": int(r.id),
                        "ip": r.ip,
                        "printer_name": r.printer_name,
                        "enabled": bool(r.enabled),
                        "enabled_changed_at": r.enabled_changed_at.isoformat() if r.enabled_changed_at else "",
                        "command": (
                            {
                                "id": int(pending_by_printer[int(r.id)].id),
                                "desired_enabled": bool(pending_by_printer[int(r.id)].desired_enabled),
                                "command_type": pending_by_printer[int(r.id)].command_type or "enable_disable",
                                "auth_user": pending_by_printer[int(r.id)].auth_user or "",
                                "auth_password": pending_by_printer[int(r.id)].auth_password or "",
                                "driver_brand": pending_by_printer[int(r.id)].driver_brand or "",
                                "driver_model": pending_by_printer[int(r.id)].driver_model or "",
                                "driver_name": pending_by_printer[int(r.id)].driver_name or "",
                                "driver_url": pending_by_printer[int(r.id)].driver_url or "",
                            }
                            if int(r.id) in pending_by_printer
                            else None
                        ),
                    }
                    for r in rows
                ],
            }
        )

    @app.post("/api/polling/control-result")
    def polling_control_result() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error

        command_id = _to_int(body.get("command_id"))
        if command_id is None or command_id <= 0:
            return jsonify({"ok": False, "error": "Missing command_id"}), 400
        ok_value = bool(body.get("ok", False))
        error_message = _to_text(body.get("error"))
        responded_at = datetime.now(timezone.utc)

        with session_factory() as session:
            command = session.get(PrinterControlCommand, int(command_id))
            if command is None:
                return jsonify({"ok": False, "error": "Command not found"}), 404
            if command.lead != lead:
                return jsonify({"ok": False, "error": "Lead mismatch"}), 400
            if command.status != "pending":
                return jsonify({"ok": True, "status": command.status, "id": int(command.id)})

            printer = session.get(Printer, int(command.printer_id))
            if printer is None:
                command.status = "failed"
                command.error_message = "Printer not found"
                command.responded_at = responded_at
                session.commit()
                return jsonify({"ok": False, "error": "Printer not found"}), 404

            if command.command_type == "fetch_address_book":
                if ok_value:
                    command.status = "success"
                    command.error_message = ""
                    command.responded_at = responded_at
                    address_book_data = body.get("address_book_data")
                    if isinstance(address_book_data, dict):
                        printer.address_book_sync = {
                            "status": "success",
                            "timestamp": responded_at.isoformat(),
                            "address_list": address_book_data.get("address_list") or [],
                        }
                else:
                    command.status = "failed"
                    command.error_message = error_message or "Fetch address book failed"
                    command.responded_at = responded_at
                    printer.address_book_sync = {
                        "status": "error",
                        "timestamp": responded_at.isoformat(),
                        "error": command.error_message,
                    }
            else:
                if ok_value:
                    command.status = "success"
                    command.error_message = ""
                    command.responded_at = responded_at
                    _apply_printer_enabled_state(session, printer, bool(command.desired_enabled), responded_at)
                else:
                    command.status = "failed"
                    command.error_message = error_message or "Agent lock/unlock failed"
                    command.responded_at = responded_at
            session.commit()

        return jsonify(
            {
                "ok": True,
                "id": int(command_id),
                "status": "success" if ok_value else "failed",
                "responded_at": responded_at.isoformat(),
            }
        )

    @app.post("/api/polling/inventory")
    def ingest_inventory() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("inventory: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("inventory: unauthorized lead=%s ip=%s", _to_text(body.get("lead")), request.remote_addr)
            return auth_error

        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(session, lead, body)
            agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
            hostname = _to_text(body.get("hostname"))
            local_ip = _to_text(body.get("local_ip"))
            local_mac = _to_text(body.get("local_mac"))
            app_version = _to_text(body.get("app_version"))
            run_mode = _to_text(body.get("run_mode")) or "web"
            web_port = _to_int(body.get("web_port")) or 9173
            ftp_ports = _to_text(body.get("ftp_ports"))
            ftp_sites = body.get("ftp_sites") if isinstance(body.get("ftp_sites"), list) else None
            timestamp = _parse_timestamp(body.get("timestamp"))
            devices = body.get("devices") if isinstance(body.get("devices"), list) else []
            inserted = 0
            updated = 0
            _refresh_stale_agent_offline(session=session, lead=lead, stale_seconds=ONLINE_STALE_SECONDS)
            _upsert_lan_and_agent(
                session=session,
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                lan_name="",
                subnet_cidr="",
                gateway_ip="",
                gateway_mac="",
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
                app_version=app_version,
                run_mode=run_mode,
                web_port=web_port,
                ftp_ports=ftp_ports,
                ftp_sites=ftp_sites,
            )
            for item in devices:
                if not isinstance(item, dict):
                    continue
                printer_name = _to_text(item.get("printer_name")) or _to_text(item.get("name"))
                ip = _to_text(item.get("ip"))
                existed = None
                if ip:
                    existed = session.execute(
                        select(Printer).where(Printer.lead == lead, Printer.lan_uid == lan_uid, Printer.ip == ip).limit(1)
                    ).scalar_one_or_none()
                elif printer_name:
                    existed = session.execute(
                        select(Printer)
                        .where(
                            Printer.lead == lead,
                            Printer.lan_uid == lan_uid,
                            Printer.agent_uid == agent_uid,
                            Printer.printer_name == printer_name,
                            Printer.ip == "",
                        )
                        .limit(1)
                    ).scalar_one_or_none()
                _upsert_printer_from_polling(
                    session=session,
                    lead=lead,
                    lan_uid=lan_uid,
                    agent_uid=agent_uid,
                    printer_name=printer_name,
                    ip=ip,
                    event_time=timestamp,
                    touch_seen=False,
                    mark_online_on_create=False,
                    mac_address=_to_text(item.get("mac_address")),
                    auth_user=_to_text(item.get("auth_user") or item.get("user")),
                    auth_password=_to_text(item.get("auth_password") or item.get("password")),
                )
                if existed is None:
                    inserted += 1
                else:
                    updated += 1
            session.commit()

        LOGGER.info(
            "inventory: lead=%s lan=%s agent=%s devices=%s inserted=%s updated=%s",
            lead,
            lan_uid,
            agent_uid,
            len(devices),
            inserted,
            updated,
        )
        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "devices": len(devices),
                "inserted": inserted,
                "updated": updated,
            }
        )

    @app.get("/api/scan-uploads")
    def list_scan_uploads() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({"lead": request.args.get("lead")}, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error

        limit = _to_int(request.args.get("limit")) or 200
        limit = max(1, min(limit, 1000))
        root = SCAN_UPLOAD_ROOT / _safe_path_token(lead_valid)
        rows: list[dict[str, Any]] = []
        if root.exists():
            files = [p for p in root.rglob("*") if p.is_file()]
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for pth in files[:limit]:
                try:
                    st = pth.stat()
                except Exception:
                    continue
                rel = str(pth.relative_to(SCAN_UPLOAD_ROOT).as_posix())
                rows.append({
                    "path": rel,
                    "file_name": pth.name,
                    "size": int(getattr(st, "st_size", 0) or 0),
                    "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                })
        return jsonify({"ok": True, "lead": lead_valid, "rows": rows})

    @app.post("/api/polling/scan-upload")
    def ingest_scan_upload() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead(
            {"lead": request.form.get("lead")},
            lead_key_map,
            sent_token,
        )
        if not ok_auth:
            return auth_error

        upload = request.files.get("file")
        if upload is None:
            return jsonify({"ok": False, "error": "Missing file"}), 400

        original_name = secure_filename(upload.filename or "scan.bin")
        if not original_name:
            original_name = "scan.bin"

        lan_uid = _safe_path_token(_to_text(request.form.get("lan_uid")) or "legacy-lan")
        agent_uid = _safe_path_token(_to_text(request.form.get("agent_uid")) or "legacy-agent")
        hostname = _to_text(request.form.get("hostname"))
        local_ip = _to_text(request.form.get("local_ip"))
        source_path = _to_text(request.form.get("source_path"))
        source_root = _to_text(request.form.get("source_root"))
        source_root_label = _safe_path_token(_to_text(request.form.get("source_root_label")) or "scan-root")
        source_relative_parts = _safe_relative_path_parts(request.form.get("source_relative_path"))
        fingerprint = _to_text(request.form.get("fingerprint"))
        event_time = _parse_timestamp(request.form.get("timestamp"))

        if source_relative_parts:
            sync_mode = "mirror"
            dest_name = source_relative_parts[-1]
            target_dir = SCAN_UPLOAD_ROOT / _safe_path_token(lead_valid) / lan_uid / agent_uid / source_root_label
            for part in source_relative_parts[:-1]:
                target_dir = target_dir / part
            target_dir.mkdir(parents=True, exist_ok=True)
            dest_path = target_dir / dest_name
            drive_remote_parts = [_safe_path_token(lead_valid), lan_uid, agent_uid, source_root_label, *source_relative_parts]
        else:
            sync_mode = "append"
            date_folder = event_time.astimezone(UI_TZ).strftime("%Y%m%d")
            target_dir = SCAN_UPLOAD_ROOT / _safe_path_token(lead_valid) / lan_uid / agent_uid / date_folder
            target_dir.mkdir(parents=True, exist_ok=True)

            stamp = event_time.astimezone(UI_TZ).strftime("%H%M%S")
            digest_seed = f"{fingerprint}|{source_path}|{event_time.isoformat()}|{original_name}"
            digest = hashlib.sha1(digest_seed.encode("utf-8")).hexdigest()[:10]
            dest_name = f"{stamp}_{digest}_{original_name}"
            dest_path = target_dir / dest_name
            index = 1
            while dest_path.exists():
                dest_path = target_dir / f"{stamp}_{digest}_{index}_{original_name}"
                index += 1
            drive_remote_parts = [_safe_path_token(lead_valid), lan_uid, agent_uid, date_folder, dest_path.name]

        temp_path = target_dir / f".upload-{time_module.time_ns()}-{dest_name}"
        upload.save(temp_path)
        temp_path.replace(dest_path)
        file_size = int(dest_path.stat().st_size if dest_path.exists() else 0)
        relative_path = str(dest_path.as_posix())

        # Replicate to public static folder for Dropbox-style direct web access
        try:
            import shutil
            original_folder_name = "default"
            if source_root:
                # Handle both Windows backslash and Posix forward slash
                source_root_clean = source_root.replace("\\", "/")
                original_folder_name = Path(source_root_clean).name or "default"
            
            safe_lan_uid = _safe_path_token(lan_uid)
            safe_folder_name = _safe_path_token(original_folder_name)
            static_scans_dir = Path("static/scans") / safe_lan_uid / safe_folder_name
            static_scans_dir.mkdir(parents=True, exist_ok=True)
            static_scans_path = static_scans_dir / dest_path.name
            shutil.copy2(dest_path, static_scans_path)
            LOGGER.info("Replicated scan to public static path: %s", static_scans_path)
            
            # Save metadata file with upload stats
            try:
                meta_path = static_scans_path.with_name(f"{static_scans_path.name}.meta.json")
                upload_completed_at = datetime.now(timezone.utc)
                duration_seconds = (upload_completed_at - event_time).total_seconds()
                if duration_seconds < 0:
                    duration_seconds = 0.0
                
                meta_data = {
                    "upload_started_at": event_time.isoformat(),
                    "upload_completed_at": upload_completed_at.isoformat(),
                    "upload_duration": round(duration_seconds, 2),
                    "client_ip": local_ip or "",
                    "hostname": hostname or "",
                }
                with open(meta_path, "w", encoding="utf-8") as meta_f:
                    json.dump(meta_data, meta_f, ensure_ascii=False, indent=2)
                LOGGER.info("Saved scan upload metadata to: %s", meta_path)
            except Exception as meta_exc:
                LOGGER.warning("Failed to save scan upload metadata: %s", meta_exc)
        except Exception as static_exc:
            LOGGER.warning("Failed to replicate scan to static/scans directory: %s", static_exc)

        drive_sync_payload = drive_sync.disabled_result().as_dict()
        if drive_sync.enabled:
            try:
                drive_sync_result = drive_sync.upload_scan(
                    dest_path,
                    remote_parts=drive_remote_parts,
                    source_path=source_path,
                )
                drive_sync_payload = drive_sync_result.as_dict()
            except Exception as exc:  # noqa: BLE001
                drive_sync_payload = {"enabled": True, "ok": False, "error": str(exc)}
                LOGGER.warning(
                    "scan-upload drive sync failed: lead=%s lan=%s agent=%s file=%s error=%s",
                    lead_valid,
                    lan_uid,
                    agent_uid,
                    relative_path,
                    exc,
                )

        LOGGER.info(
            "scan-upload: lead=%s lan=%s agent=%s host=%s ip=%s file=%s size=%s source=%s source_root=%s mode=%s drive_ok=%s",
            lead_valid,
            lan_uid,
            agent_uid,
            hostname,
            local_ip,
            relative_path,
            file_size,
            source_path,
            source_root,
            sync_mode,
            drive_sync_payload.get("ok", False),
        )
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "path": relative_path,
                "size": file_size,
                "timestamp": event_time.isoformat(),
                "sync_mode": sync_mode,
                "source_root": source_root,
                "source_root_label": source_root_label,
                "source_relative_path": "/".join(source_relative_parts),
                "drive_sync": drive_sync_payload,
            }
        )
