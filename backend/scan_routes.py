from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from utils import _to_text, _normalize_mac, _safe_path_token
from app_helpers import (
    _resolve_scan_host_agent_for_printer,
    _queue_scan_folder_command_for_agent,
)
from device_core_routes import _resolve_printer_control_target

LOGGER = logging.getLogger(__name__)


def register_scan_routes(app: Flask, session_factory: Any) -> None:

    @app.post("/api/devices/<device_ref>/scan-folder")
    def device_scan_folder(device_ref: str) -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            provided_mac = _to_text(body.get("mac_id") or body.get("mac"))
            requested_mac = _normalize_mac(provided_mac)
            if provided_mac and not requested_mac:
                return jsonify({"ok": False, "error": "Invalid mac_id"}), 400
            printer_mac = _normalize_mac(printer.mac_address)
            if requested_mac and printer_mac and requested_mac != printer_mac:
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": f"Body mac_id {requested_mac} does not match path printer {printer_mac}",
                            "mac_id": printer_mac,
                        }
                    ),
                    409,
                )
            agent, warning_parts, agent_error = _resolve_scan_host_agent_for_printer(
                session,
                printer=printer,
            )
            if agent_error is not None:
                payload, status = agent_error
                return jsonify(payload), status
            queue_body = dict(body)
            if printer_mac:
                queue_body["mac_id"] = printer_mac
            payload, status = _queue_scan_folder_command_for_agent(
                session,
                agent=agent,
                body=queue_body,
                printer=printer,
                initial_warnings=warning_parts,
            )
        return jsonify(payload), status

    @app.get("/api/scans/files")
    def list_email_scan_files() -> Any:
        lan_uid = request.args.get("lan_uid", "").strip()
        email = request.args.get("email", "").strip()
        if not lan_uid or not email:
            return jsonify({"ok": False, "error": "Missing lan_uid or email"}), 400

        lan_uid_safe = _safe_path_token(lan_uid)
        email_safe = _safe_path_token(email)
        static_dir = Path("static/scans") / lan_uid_safe / email_safe

        rows: list[dict[str, Any]] = []
        if static_dir.exists():
            files = [p for p in static_dir.iterdir() if p.is_file() and not p.name.endswith(".meta.json")]
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for pth in files:
                try:
                    st = pth.stat()
                except Exception:
                    continue
                
                # Check for metadata file
                upload_duration = None
                upload_completed_at = None
                meta_path = pth.with_name(f"{pth.name}.meta.json")
                if meta_path.exists():
                    try:
                        with open(meta_path, "r", encoding="utf-8") as meta_f:
                            meta_data = json.load(meta_f)
                            upload_duration = meta_data.get("upload_duration")
                            upload_completed_at = meta_data.get("upload_completed_at")
                    except Exception:
                        pass
                
                rows.append({
                    "name": pth.name,
                    "size": int(st.st_size),
                    "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                    "url": f"/static/scans/{lan_uid_safe}/{email_safe}/{pth.name}",
                    "upload_duration": upload_duration,
                    "upload_completed_at": upload_completed_at
                })
        return jsonify({"ok": True, "rows": rows})
