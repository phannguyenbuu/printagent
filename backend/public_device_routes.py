from __future__ import annotations

from app_helpers import _serialize_audit_payload_iso

import logging
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select, func

from utils import _to_text, _to_int
from models import DeviceInfor

LOGGER = logging.getLogger(__name__)


def register_public_device_routes(app: Flask, session_factory: Any) -> None:

    @app.get("/machinelist/")
    def public_machine_list() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        with session_factory() as session:
            stmt = select(DeviceInfor).where(DeviceInfor.lan_uid != "").order_by(
                DeviceInfor.updated_at.desc(), DeviceInfor.id.desc()
            )
            if lead:
                stmt = stmt.where(DeviceInfor.lead == lead)
            if lan_uid:
                stmt = stmt.where(DeviceInfor.lan_uid == lan_uid)
            records = session.execute(stmt).scalars().all()
            seen: set[tuple[str, str, str]] = set()
            machines: list[dict[str, Any]] = []
            for row in records:
                mac_id = _to_text(row.mac_id).replace("-", ":").upper()
                dedupe_token = mac_id or f"IP:{_to_text(row.ip)}"
                dedupe_key = (_to_text(row.lead), _to_text(row.lan_uid), dedupe_token)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                counter_data = row.counter_data if isinstance(row.counter_data, dict) else {}
                status_data = row.status_data if isinstance(row.status_data, dict) else {}
                machines.append(
                    {
                        "lead": row.lead,
                        "lan_uid": row.lan_uid,
                        "mac_id": mac_id,
                        "agent_uid": row.agent_uid,
                        "printer_name": row.printer_name,
                        "ip": row.ip,
                        "counter_total": _to_int(counter_data.get("total")) or 0,
                        "system_status": _to_text(status_data.get("system_status")),
                        "toner_black": status_data.get("toner_black"),
                        "last_counter_at": row.last_counter_at.isoformat() if row.last_counter_at else "",
                        "last_status_at": row.last_status_at.isoformat() if row.last_status_at else "",
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
                    }
                )
            machines.sort(key=lambda x: (_to_text(x.get("lead")), _to_text(x.get("lan_uid")), _to_text(x.get("mac_id"))))
            return jsonify(
                {
                    "ok": True,
                    "count": len(machines),
                    "machines": machines,
                }
            )

    @app.get("/networklist/")
    def public_network_list() -> Any:
        lead = _to_text(request.args.get("lead"))
        with session_factory() as session:
            stmt = (
                select(
                    DeviceInfor.lead,
                    DeviceInfor.lan_uid,
                    func.count(DeviceInfor.id),
                    func.max(DeviceInfor.updated_at),
                )
                .where(DeviceInfor.lan_uid != "")
                .group_by(DeviceInfor.lead, DeviceInfor.lan_uid)
                .order_by(DeviceInfor.lead.asc(), DeviceInfor.lan_uid.asc())
            )
            if lead:
                stmt = stmt.where(DeviceInfor.lead == lead)
            rows = session.execute(stmt).all()
            networks: list[dict[str, Any]] = []
            for lead_value, lan_uid_value, machine_count, last_seen in rows:
                networks.append(
                    {
                        "lead": _to_text(lead_value),
                        "lan_uid": _to_text(lan_uid_value),
                        "machine_count": int(machine_count or 0),
                        "last_seen_at": last_seen.isoformat() if last_seen else "",
                    }
                )
            return jsonify(
                {
                    "ok": True,
                    "count": len(networks),
                    "networks": networks,
                }
            )

    @app.get("/all/")
    def public_all_data() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        with session_factory() as session:
            stmt = select(DeviceInfor).order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
            if lead:
                stmt = stmt.where(DeviceInfor.lead == lead)
            if lan_uid:
                stmt = stmt.where(DeviceInfor.lan_uid == lan_uid)
            records = session.execute(stmt).scalars().all()
            seen: set[tuple[str, str, str]] = set()
            rows: list[dict[str, Any]] = []
            for row in records:
                mac_id = _to_text(row.mac_id).replace("-", ":").upper()
                machine_uid = mac_id or f"IP:{_to_text(row.ip)}"
                dedupe_key = (_to_text(row.lead), _to_text(row.lan_uid), machine_uid)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                counter_data = row.counter_data if isinstance(row.counter_data, dict) else {}
                status_data = row.status_data if isinstance(row.status_data, dict) else {}
                rows.append(
                    {
                        "lead": row.lead,
                        "lan_uid": row.lan_uid,
                        "machine_uid": machine_uid,
                        "mac_id": mac_id or _to_text(row.mac_id),
                        "agent_uid": row.agent_uid,
                        "printer_name": row.printer_name,
                        "ip": row.ip,
                        "counter": counter_data,
                        "status": status_data,
                        "counter_data": counter_data,
                        "status_data": status_data,
                        "last_counter_at": row.last_counter_at.isoformat() if row.last_counter_at else "",
                        "last_status_at": row.last_status_at.isoformat() if row.last_status_at else "",
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
                    }
                )
            rows.sort(key=lambda x: (_to_text(x.get("lead")), _to_text(x.get("lan_uid")), _to_text(x.get("machine_uid"))))
            return jsonify(
                {
                    "ok": True,
                    "count": len(rows),
                    "rows": rows,
                }
            )
