from __future__ import annotations

import logging
import time as time_module
from datetime import datetime, timezone, timedelta
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select, func

from utils import _to_text, _normalize_mac
from serializers import (
    _refresh_stale_offline,
)
from app_helpers import _serialize_audit_payload_iso
from models import Printer, PrinterControlCommand

LOGGER = logging.getLogger(__name__)


def _resolve_printer_control_target(session: Any, device_ref: Any) -> Printer | None:
    normalized_mac = _normalize_mac(device_ref)
    if normalized_mac:
        return (
            session.execute(
                select(Printer)
                .where(func.upper(Printer.mac_address) == normalized_mac)
                .order_by(Printer.updated_at.desc(), Printer.id.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
    raw_ref = _to_text(device_ref).strip()
    if raw_ref.isdigit():
        return session.get(Printer, int(raw_ref))
    if raw_ref:
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_ref):
            return (
                session.execute(
                    select(Printer)
                    .where(Printer.ip == raw_ref)
                    .order_by(Printer.updated_at.desc(), Printer.id.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
    return None


def register_device_core_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.get("/api/devices")
    @app.get("/api/devices/list")
    def devices_list() -> Any:
        lead = _to_text(request.args.get("lead"))
        with session_factory() as session:
            _refresh_stale_offline(session=session, lead=lead)
            session.commit()
            stmt = select(Printer).order_by(Printer.lan_uid.asc(), Printer.printer_name.asc(), Printer.ip.asc())
            if lead:
                stmt = stmt.where(Printer.lead == lead)
            raw_rows = session.execute(stmt).scalars().all()
            deduped: dict[str, Printer] = {}
            for r in raw_rows:
                ip_key = _to_text(r.ip)
                if ip_key:
                    key = f"{_to_text(r.lead)}|ip:{ip_key}"
                else:
                    key = f"{_to_text(r.lead)}|name:{_to_text(r.agent_uid).lower()}:{_to_text(r.printer_name).lower()}"
                previous = deduped.get(key)
                if previous is None:
                    deduped[key] = r
                    continue
                prev_updated = previous.updated_at or datetime.fromtimestamp(0, tz=timezone.utc)
                cur_updated = r.updated_at or datetime.fromtimestamp(0, tz=timezone.utc)
                if cur_updated >= prev_updated:
                    deduped[key] = r
            rows = sorted(deduped.values(), key=lambda x: (_to_text(x.lan_uid), _to_text(x.printer_name), _to_text(x.ip)))
        return jsonify(
            {
                "rows": [
                    {
                        "id": int(r.id),
                        "lead": r.lead,
                        "lan_uid": r.lan_uid,
                        "agent_uid": r.agent_uid,
                        "printer_name": r.printer_name,
                        "ip": r.ip,
                        "enabled": bool(r.enabled),
                        "enabled_changed_at": r.enabled_changed_at.isoformat() if r.enabled_changed_at else "",
                        "is_online": bool(r.is_online),
                        "online_changed_at": r.online_changed_at.isoformat() if r.online_changed_at else "",
                        "last_seen_at": r.updated_at.isoformat() if r.updated_at else "",
                        "label": f"{r.lan_uid} / {r.printer_name}",
                        "mac_id": r.mac_address or "",
                        "user": r.auth_user or "",
                        "password": r.auth_password or "",
                        "address_book_sync": r.address_book_sync,
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
                    }
                    for r in rows
                ]
            }
        )

    def _submit_printer_control_command(
        device_ref: Any,
        *,
        enabled: bool,
        action_name: str = "",
    ) -> Any:
        requested_at = datetime.now(timezone.utc)
        action_label = _to_text(action_name).lower() or ("unlock" if enabled else "lock")
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found", "action": action_label}), 404
            printer_id_value = int(printer.id)
            printer_mac_value = _normalize_mac(printer.mac_address) or printer.mac_address or ""

            pending = session.execute(
                select(PrinterControlCommand).where(
                    PrinterControlCommand.printer_id == printer.id,
                    PrinterControlCommand.status == "pending",
                )
            ).scalars().all()
            for cmd in pending:
                cmd.status = "failed"
                cmd.error_message = "Superseded by newer command"
                cmd.responded_at = requested_at

            command = PrinterControlCommand(
                printer_id=printer.id,
                lead=printer.lead,
                lan_uid=printer.lan_uid,
                agent_uid=printer.agent_uid,
                printer_name=printer.printer_name,
                ip=printer.ip,
                desired_enabled=enabled,
                auth_user=printer.auth_user,
                auth_password=printer.auth_password,
                status="pending",
                error_message="",
                requested_at=requested_at,
                responded_at=None,
            )
            session.add(command)
            session.commit()
            command_id = int(command.id)

        timeout_seconds = 25
        deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)
        while datetime.now(timezone.utc) < deadline:
            with session_factory() as session:
                current = session.get(PrinterControlCommand, command_id)
                if current is None:
                    break
                if current.status == "success":
                    changed_at = current.responded_at or datetime.now(timezone.utc)
                    return jsonify(
                        {
                            "ok": True,
                            "id": printer_id_value,
                            "mac_id": printer_mac_value,
                            "enabled": enabled,
                            "action": action_label,
                            "changed_at": changed_at.isoformat(),
                            "command_id": command_id,
                        }
                    )
                if current.status == "failed":
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": current.error_message or "Control command failed",
                                "action": action_label,
                                "command_id": command_id,
                            }
                        ),
                        409,
                    )
            time_module.sleep(0.5)

        with session_factory() as session:
            timeout_cmd = session.get(PrinterControlCommand, command_id)
            if timeout_cmd is not None and timeout_cmd.status == "pending":
                timeout_cmd.status = "failed"
                timeout_cmd.error_message = "Timeout waiting agent lock/unlock result"
                timeout_cmd.responded_at = datetime.now(timezone.utc)
                session.commit()
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "Timeout waiting agent lock/unlock result",
                    "action": action_label,
                    "command_id": command_id,
                }
            ),
            504,
        )

    def _submit_printer_fetch_address_book_command(device_ref: Any) -> Any:
        requested_at = datetime.now(timezone.utc)
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            printer_id_value = int(printer.id)
            printer_mac_value = _normalize_mac(printer.mac_address) or printer.mac_address or ""

            pending = session.execute(
                select(PrinterControlCommand).where(
                    PrinterControlCommand.printer_id == printer.id,
                    PrinterControlCommand.status == "pending",
                )
            ).scalars().all()
            for cmd in pending:
                cmd.status = "failed"
                cmd.error_message = "Superseded by newer command"
                cmd.responded_at = requested_at

            command = PrinterControlCommand(
                printer_id=printer.id,
                lead=printer.lead,
                lan_uid=printer.lan_uid,
                agent_uid=printer.agent_uid,
                printer_name=printer.printer_name,
                ip=printer.ip,
                desired_enabled=printer.enabled,
                command_type="fetch_address_book",
                auth_user=printer.auth_user or "",
                auth_password=printer.auth_password or "",
                status="pending",
                error_message="",
                requested_at=requested_at,
                responded_at=None,
            )
            session.add(command)
            session.commit()
            command_id = int(command.id)

        return jsonify(
            {
                "ok": True,
                "status": "pending",
                "command_id": command_id,
                "printer_id": printer_id_value,
                "mac_id": printer_mac_value,
            }
        )

    @app.patch("/api/devices/<device_ref>/enable")
    def device_set_enable(device_ref: str) -> Any:
        body = request.get_json(silent=True) or {}
        enabled_raw = body.get("enabled", True)
        enabled = enabled_raw if isinstance(enabled_raw, bool) else str(enabled_raw).strip().lower() in {"1", "true", "yes", "on"}
        return _submit_printer_control_command(
            device_ref,
            enabled=enabled,
            action_name="unlock" if enabled else "lock",
        )

    @app.post("/api/devices/<device_ref>/unlock")
    def device_unlock(device_ref: str) -> Any:
        return _submit_printer_control_command(
            device_ref,
            enabled=True,
            action_name="unlock",
        )

    @app.post("/api/devices/<device_ref>/lock")
    def device_lock(device_ref: str) -> Any:
        return _submit_printer_control_command(
            device_ref,
            enabled=False,
            action_name="lock",
        )

    @app.patch("/api/devices/<device_ref>/credentials")
    def device_update_credentials(device_ref: str) -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        auth_user = str(body.get("auth_user", "")).strip()
        auth_password = str(body.get("auth_password", "")).strip()
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            printer.auth_user = auth_user
            printer.auth_password = auth_password
            session.commit()
            return jsonify({"ok": True, "auth_user": printer.auth_user})

    @app.post("/api/devices/<device_ref>/fetch-address-book")
    def device_fetch_address_book(device_ref: str) -> Any:
        return _submit_printer_fetch_address_book_command(device_ref)

    @app.get("/api/commands/<int:command_id>/status")
    def get_command_status(command_id: int) -> Any:
        with session_factory() as session:
            cmd = session.get(PrinterControlCommand, command_id)
            if cmd is None:
                return jsonify({"ok": False, "error": "Command not found"}), 404
            if cmd.status == "success":
                pr = session.get(Printer, cmd.printer_id)
                return jsonify(
                    {
                        "ok": True,
                        "status": "success",
                        "command_id": command_id,
                        "id": int(cmd.printer_id),
                        "address_book_sync": pr.address_book_sync if pr else None,
                    }
                )
            if cmd.status == "failed":
                return (
                    jsonify(
                        {
                            "ok": False,
                            "status": "failed",
                            "command_id": command_id,
                            "error": cmd.error_message or "Command failed",
                        }
                    ),
                    409,
                )
            return jsonify(
                {
                    "ok": True,
                    "status": "pending",
                    "command_id": command_id,
                }
            )
