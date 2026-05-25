from __future__ import annotations

import logging
import time as time_module
from datetime import datetime, timezone, timedelta
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select

from utils import _to_text
from app_helpers import _serialize_audit_payload_iso
from serializers import (
    _refresh_stale_offline,
)
from models import Printer, PrinterEnableLog, PrinterOnlineLog, PrinterControlCommand
from device_core_routes import _resolve_printer_control_target

LOGGER = logging.getLogger(__name__)


def register_device_detail_routes(app: Flask, session_factory: Any) -> None:

    @app.get("/api/devices/<int:printer_id>/events")
    def device_events(printer_id: int) -> Any:
        with session_factory() as session:
            printer = session.get(Printer, printer_id)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            _refresh_stale_offline(
                session=session,
                lead=printer.lead,
                lan_uid=printer.lan_uid,
                agent_uid=printer.agent_uid,
            )
            session.commit()
            printer = session.get(Printer, printer_id)
            logs = session.execute(
                select(PrinterEnableLog)
                .where(PrinterEnableLog.printer_id == printer_id)
                .order_by(PrinterEnableLog.changed_at.desc(), PrinterEnableLog.id.desc())
            ).scalars().all()
            online_logs = session.execute(
                select(PrinterOnlineLog)
                .where(PrinterOnlineLog.printer_id == printer_id)
                .order_by(PrinterOnlineLog.changed_at.desc(), PrinterOnlineLog.id.desc())
            ).scalars().all()
        events: list[dict[str, Any]] = []
        events.extend(
            {
                "id": f"enable-{int(e.id)}",
                "kind": "enable",
                "value": "Enabled" if bool(e.enabled) else "Disabled",
                "changed_at": e.changed_at.isoformat() if e.changed_at else "",
                **_serialize_audit_payload_iso(e.created_at, e.updated_at),
            }
            for e in logs
        )
        events.extend(
            {
                "id": f"online-{int(e.id)}",
                "kind": "online",
                "value": "Online" if bool(e.is_online) else "Offline",
                "changed_at": e.changed_at.isoformat() if e.changed_at else "",
                **_serialize_audit_payload_iso(e.created_at, e.updated_at),
            }
            for e in online_logs
        )
        events.sort(key=lambda x: str(x.get("changed_at", "")), reverse=True)
        return jsonify(
            {
                "printer": {
                    "id": int(printer.id),
                    "lead": printer.lead,
                    "lan_uid": printer.lan_uid,
                    "mac_id": printer.mac_address or "",
                    "agent_uid": printer.agent_uid,
                    "printer_name": printer.printer_name,
                    "ip": printer.ip,
                    "enabled": bool(printer.enabled),
                    "enabled_changed_at": printer.enabled_changed_at.isoformat() if printer.enabled_changed_at else "",
                    "is_online": bool(printer.is_online),
                    "online_changed_at": printer.online_changed_at.isoformat() if printer.online_changed_at else "",
                    "last_seen_at": printer.updated_at.isoformat() if printer.updated_at else "",
                    "auth_user": printer.auth_user or "",
                    "auth_password": printer.auth_password or "",
                    "address_book_sync": printer.address_book_sync,
                    **_serialize_audit_payload_iso(printer.created_at, printer.updated_at),
                },
                "events": events,
            }
        )

    @app.post("/api/devices/<device_ref>/install-driver")
    def device_install_driver(device_ref: str) -> Any:
        body = request.get_json(silent=True) or {}
        brand = str(body.get("brand", "")).strip()
        model = str(body.get("model", "")).strip()
        driver_name = str(body.get("driver_name", "")).strip()
        driver_url = str(body.get("driver_url", "")).strip()

        if not brand or not model or not driver_name or not driver_url:
            return jsonify({"ok": False, "error": "brand, model, driver_name, and driver_url are required"}), 400

        all_urls = [driver_url]
        try:
            from pathlib import Path
            import json
            brand_clean = brand.lower().strip()
            catalog_file = Path("storage/drivers") / f"{brand_clean}.json"
            if catalog_file.exists():
                with open(catalog_file, encoding="utf-8") as f:
                    catalog_data = json.load(f)
                
                model_obj = None
                if isinstance(catalog_data, list):
                    for item in catalog_data:
                        if str(item.get("model", "")).strip().lower() == model.lower().strip():
                            model_obj = item
                            break
                
                if model_obj:
                    model_links = []
                    drivers_field = model_obj.get("drivers")
                    if isinstance(drivers_field, dict):
                        for u in drivers_field.values():
                            if isinstance(u, str):
                                model_links.append(u.strip())
                    elif isinstance(drivers_field, list):
                        for d in drivers_field:
                            if isinstance(d, dict) and "download_url" in d:
                                model_links.append(str(d["download_url"]).strip())
                    
                    if not model_links:
                        all_links_field = model_obj.get("all_links")
                        if isinstance(all_links_field, list):
                            for u in all_links_field:
                                if isinstance(u, str):
                                    model_links.append(u.strip())
                    
                    generic_keywords = [
                        "diagnostic", "diagnostictool", "diagnostic_tool", "utility", 
                        "webinstaller", "web_installer", "installer", "easysetup", 
                        "easy_setup", "opkpcl6", "opkps", "mmdspcl6", "mmd2pcl6", "xps"
                    ]
                    
                    import os
                    for u in model_links:
                        if not u or u in all_urls:
                            continue
                        
                        filename = os.path.basename(u.split("?")[0]).lower()
                        if any(k in filename for k in generic_keywords):
                            continue
                            
                        all_urls.append(u)
        except Exception as e:
            LOGGER.warning("Failed to collect alternative driver URLs in device_install_driver: %s", e)
            
        driver_url_combined = ";".join(all_urls)

        requested_at = datetime.now(timezone.utc)
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            
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
                command_type="install_driver",
                driver_brand=brand,
                driver_model=model,
                driver_name=driver_name,
                driver_url=driver_url_combined,
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

        deadline = datetime.now(timezone.utc) + timedelta(seconds=15)
        while datetime.now(timezone.utc) < deadline:
            with session_factory() as session:
                current = session.get(PrinterControlCommand, command_id)
                if current is None:
                    break
                if current.status == "success":
                    return jsonify({
                        "ok": True,
                        "status": "success",
                        "message": f"Successfully installed driver {driver_name}",
                        "command_id": command_id,
                    }), 200
                if current.status == "failed":
                    return jsonify({
                        "ok": False,
                        "status": "failed",
                        "error": current.error_message or "Execution failed on agent",
                        "command_id": command_id,
                    }), 502
            time_module.sleep(0.5)

        return jsonify({
            "ok": True,
            "status": "pending",
            "message": "Driver installation command queued. Check back for results.",
            "command_id": command_id,
        }), 202
