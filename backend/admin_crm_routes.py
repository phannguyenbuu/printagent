from __future__ import annotations

import logging
import hashlib
import time as time_module
import json
from typing import Any

from flask import Flask, jsonify, request, render_template
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from utils import _to_text, _to_int, _apply_date_filters
from serializers import (
    _serialize_lead_model,
    _serialize_workspace_model,
    _serialize_location_model,
    _serialize_repair_model,
    _serialize_material_model,
)
from models import Lead, Workspace, Location, RepairRequest, Material, UserAccount

LOGGER = logging.getLogger(__name__)


def _parse_string_id_list(value: object) -> list[str]:
    if value is None:
        return []
    raw_items: list[object]
    if isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    elif isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return []
        if text_value.startswith("[") and text_value.endswith("]"):
            try:
                parsed = json.loads(text_value)
            except Exception:
                parsed = None
            if isinstance(parsed, list):
                raw_items = parsed
            else:
                raw_items = [part for part in text_value.replace("\n", ",").replace(";", ",").split(",")]
        else:
            raw_items = [part for part in text_value.replace("\n", ",").replace(";", ",").split(",")]
    else:
        raw_items = [value]
    seen: set[str] = set()
    result: list[str] = []
    for item in raw_items:
        text_item = _to_text(item).strip()
        if not text_item or text_item in seen:
            continue
        seen.add(text_item)
        result.append(text_item)
    return result


def _parse_int_id_list(value: object) -> list[int]:
    result: list[int] = []
    for item in _parse_string_id_list(value):
        parsed = _to_int(item)
        if not parsed:
            raise ValueError(f"Invalid numeric id: {item}")
        if parsed not in result:
            result.append(parsed)
    return result


def _user_rows_for_ids(session: Any, user_ids: list[int]) -> list[UserAccount]:
    if not user_ids:
        return []
    rows = session.execute(
        select(UserAccount).where(UserAccount.id.in_(user_ids)).order_by(UserAccount.id.asc())
    ).scalars().all()
    found = {int(row.id): row for row in rows}
    missing = [str(user_id) for user_id in user_ids if user_id not in found]
    if missing:
        raise ValueError(f"Unknown userIds: {', '.join(missing)}")
    return [found[user_id] for user_id in user_ids]


def register_admin_crm_routes(app: Flask, session_factory: Any) -> None:

    @app.get("/api/leads/list")
    def list_leads_crud() -> Any:
        name = _to_text(request.args.get("name"))
        with session_factory() as session:
            stmt = select(Lead).order_by(Lead.name.asc())
            if name:
                stmt = stmt.where(Lead.name.ilike(f"%{name}%"))
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_lead_model(r) for r in rows]})

    @app.post("/api/leads")
    def create_lead() -> Any:
        body = request.get_json(silent=True) or {}
        lead_id = _to_text(body.get("id"))
        if not lead_id:
            lead_id = _to_text(body.get("name")).lower().replace(" ", "-")
        with session_factory() as session:
            new_lead = Lead(
                id=lead_id,
                name=_to_text(body.get("name")),
                email=_to_text(body.get("email")),
                phone=_to_text(body.get("phone")),
                notes=_to_text(body.get("notes")),
            )
            session.add(new_lead)
            session.commit()
            return jsonify({"ok": True, "row": _serialize_lead_model(new_lead)})

    @app.patch("/api/leads/<string:lead_id>")
    def update_lead(lead_id: str) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            lead_obj = session.get(Lead, lead_id)
            if not lead_obj:
                return jsonify({"ok": False, "error": "Lead not found"}), 404
            if "name" in body: lead_obj.name = _to_text(body.get("name"))
            if "email" in body: lead_obj.email = _to_text(body.get("email"))
            if "phone" in body: lead_obj.phone = _to_text(body.get("phone"))
            if "notes" in body: lead_obj.notes = _to_text(body.get("notes"))
            session.commit()
            return jsonify({"ok": True, "row": _serialize_lead_model(lead_obj)})

    @app.delete("/api/leads/<string:lead_id>")
    def delete_lead(lead_id: str) -> Any:
        with session_factory() as session:
            lead_obj = session.get(Lead, lead_id)
            if not lead_obj:
                return jsonify({"ok": False, "error": "Lead not found"}), 404
            session.delete(lead_obj)
            session.commit()
        return jsonify({"ok": True, "id": lead_id})

    @app.get("/leads")
    def leads_page() -> Any:
        return render_template("leads.html", active_tab="leads", page_title="Leads Management")

    @app.get("/workspaces")
    def workspaces_page() -> Any:
        return render_template("workspaces.html", active_tab="workspaces", page_title="Workspaces")

    @app.get("/api/workspaces")
    def list_workspaces() -> Any:
        name = _to_text(request.args.get("name"))
        address = _to_text(request.args.get("address"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = (
                select(Workspace)
                .options(selectinload(Workspace.users), selectinload(Workspace.locations))
                .order_by(Workspace.name.asc())
            )
            if name:
                stmt = stmt.where(Workspace.name.ilike(f"%{name}%"))
            if address:
                stmt = stmt.where(Workspace.address.ilike(f"%{address}%"))
            stmt = _apply_date_filters(stmt, Workspace, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_workspace_model(r) for r in rows]})

    @app.get("/locations")
    def locations_page() -> Any:
        return render_template("locations.html", active_tab="locations", page_title="Locations")

    @app.get("/api/locations")
    def list_locations() -> Any:
        name = _to_text(request.args.get("name"))
        workspace_id = _to_text(request.args.get("workspace_id"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(Location).options(selectinload(Location.workspace)).order_by(Location.name.asc())
            if name:
                stmt = stmt.where(Location.name.ilike(f"%{name}%"))
            if workspace_id:
                stmt = stmt.where(Location.workspace_id == workspace_id)
            stmt = _apply_date_filters(stmt, Location, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_location_model(r) for r in rows]})

    @app.get("/repairs")
    def repairs_page() -> Any:
        return render_template("repairs.html", active_tab="repairs", page_title="Repair Requests")

    @app.get("/api/repairs")
    def list_repairs() -> Any:
        machine = _to_text(request.args.get("machine"))
        status = _to_text(request.args.get("status"))
        priority = _to_text(request.args.get("priority"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(RepairRequest).order_by(RepairRequest.created_at.desc())
            if machine:
                stmt = stmt.where(RepairRequest.machine_name.ilike(f"%{machine}%"))
            if status:
                stmt = stmt.where(RepairRequest.status == status)
            if priority:
                stmt = stmt.where(RepairRequest.priority == priority)
            stmt = _apply_date_filters(stmt, RepairRequest, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_repair_model(r) for r in rows]})

    @app.get("/materials")
    def materials_page() -> Any:
        return render_template("materials.html", active_tab="materials", page_title="Materials")

    @app.get("/scan")
    def scan_page() -> Any:
        return render_template(
            "scan.html",
            active_tab="scan",
            page_title="Scan",
            google_drive_url="https://drive.google.com/drive/folders/1rJSkHoctsxnXAeisWZC-n0Hc3hnC0tCM",
        )

    @app.get("/api/materials")
    def list_materials() -> Any:
        name = _to_text(request.args.get("name"))
        repair_id = _to_text(request.args.get("repair_id"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(Material).order_by(Material.name.asc())
            if name:
                stmt = stmt.where(Material.name.ilike(f"%{name}%"))
            if repair_id:
                stmt = stmt.where(Material.repair_request_id == repair_id)
            stmt = _apply_date_filters(stmt, Material, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_material_model(r) for r in rows]})

    @app.post("/api/workspaces")
    def create_workspace() -> Any:
        body = request.get_json(silent=True) or {}
        ws_id = _to_text(body.get("id"))
        if not ws_id:
            digest = hashlib.sha1(f"ws-{time_module.time()}".encode()).hexdigest()[:8]
            ws_id = f"ws-{digest}"
        with session_factory() as session:
            try:
                user_ids = _parse_int_id_list(body.get("userIds") if "userIds" in body else body.get("user_ids"))
                new_ws = Workspace(
                    id=ws_id,
                    name=_to_text(body.get("name")),
                    logo=_to_text(body.get("logo")),
                    color=_to_text(body.get("color")),
                    address=_to_text(body.get("address")),
                )
                session.add(new_ws)
                if user_ids:
                    new_ws.users = _user_rows_for_ids(session, user_ids)
                session.commit()
                session.refresh(new_ws)
                return jsonify({"ok": True, "row": _serialize_workspace_model(new_ws)})
            except ValueError as exc:
                session.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400

    @app.patch("/api/workspaces/<string:ws_id>")
    def update_workspace(ws_id: str) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            ws = session.get(Workspace, ws_id)
            if not ws:
                return jsonify({"ok": False, "error": "Workspace not found"}), 404
            try:
                if "name" in body: ws.name = _to_text(body.get("name"))
                if "logo" in body: ws.logo = _to_text(body.get("logo"))
                if "color" in body: ws.color = _to_text(body.get("color"))
                if "address" in body: ws.address = _to_text(body.get("address"))
                if "userIds" in body or "user_ids" in body:
                    user_ids = _parse_int_id_list(body.get("userIds") if "userIds" in body else body.get("user_ids"))
                    ws.users = _user_rows_for_ids(session, user_ids)
                session.commit()
                session.refresh(ws)
                return jsonify({"ok": True, "row": _serialize_workspace_model(ws)})
            except ValueError as exc:
                session.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400

    @app.delete("/api/workspaces/<string:ws_id>")
    def delete_workspace(ws_id: str) -> Any:
        with session_factory() as session:
            ws = session.get(Workspace, ws_id)
            if not ws:
                return jsonify({"ok": False, "error": "Workspace not found"}), 404
            session.delete(ws)
            session.commit()
        return jsonify({"ok": True, "id": ws_id})

    @app.post("/api/locations")
    def create_location() -> Any:
        body = request.get_json(silent=True) or {}
        loc_id = _to_text(body.get("id"))
        if not loc_id:
            digest = hashlib.sha1(f"loc-{time_module.time()}".encode()).hexdigest()[:8]
            loc_id = f"loc-{digest}"
        with session_factory() as session:
            workspace_id = _to_text(body.get("workspace_id")).strip() or None
            if workspace_id and not session.get(Workspace, workspace_id):
                return jsonify({"ok": False, "error": "Workspace not found"}), 400
            new_loc = Location(
                id=loc_id,
                name=_to_text(body.get("name")),
                address=_to_text(body.get("address")),
                room=_to_text(body.get("room")),
                phone=_to_text(body.get("phone")),
                machine_count=_to_int(body.get("machine_count")) or 0,
                workspace_id=workspace_id,
            )
            session.add(new_loc)
            session.commit()
            return jsonify({"ok": True, "row": _serialize_location_model(new_loc)})

    @app.patch("/api/locations/<string:loc_id>")
    def update_location(loc_id: str) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            loc = session.get(Location, loc_id)
            if not loc:
                return jsonify({"ok": False, "error": "Location not found"}), 404
            if "name" in body: loc.name = _to_text(body.get("name"))
            if "address" in body: loc.address = _to_text(body.get("address"))
            if "room" in body: loc.room = _to_text(body.get("room"))
            if "phone" in body: loc.phone = _to_text(body.get("phone"))
            if "machine_count" in body: loc.machine_count = _to_int(body.get("machine_count"))
            if "workspace_id" in body:
                workspace_id = _to_text(body.get("workspace_id")).strip() or None
                if workspace_id and not session.get(Workspace, workspace_id):
                    return jsonify({"ok": False, "error": "Workspace not found"}), 400
                loc.workspace_id = workspace_id
            session.commit()
            return jsonify({"ok": True, "row": _serialize_location_model(loc)})

    @app.delete("/api/locations/<string:loc_id>")
    def delete_location(loc_id: str) -> Any:
        with session_factory() as session:
            loc = session.get(Location, loc_id)
            if not loc:
                return jsonify({"ok": False, "error": "Location not found"}), 404
            session.delete(loc)
            session.commit()
        return jsonify({"ok": True, "id": loc_id})

    @app.post("/api/materials")
    def create_material() -> Any:
        body = request.get_json(silent=True) or {}
        mat_id = _to_text(body.get("id"))
        if not mat_id:
            digest = hashlib.sha1(f"mat-{time_module.time()}".encode()).hexdigest()[:8]
            mat_id = f"mat-{digest}"
        with session_factory() as session:
            repair_request_id = _to_text(body.get("repair_request_id")).strip() or None
            if repair_request_id and not session.get(RepairRequest, repair_request_id):
                return jsonify({"ok": False, "error": "Repair request not found"}), 400
            new_mat = Material(
                id=mat_id,
                repair_request_id=repair_request_id,
                name=_to_text(body.get("name")),
                quantity=_to_int(body.get("quantity")) or 1,
                unit_price=_to_int(body.get("unit_price")) or 0,
                total_price=_to_int(body.get("total_price")) or 0,
            )
            session.add(new_mat)
            session.commit()
            return jsonify({"ok": True, "row": _serialize_material_model(new_mat)})

    @app.patch("/api/materials/<string:mat_id>")
    def update_material(mat_id: str) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            mat = session.get(Material, mat_id)
            if not mat:
                return jsonify({"ok": False, "error": "Material not found"}), 404
            if "repair_request_id" in body:
                repair_request_id = _to_text(body.get("repair_request_id")).strip() or None
                if repair_request_id and not session.get(RepairRequest, repair_request_id):
                    return jsonify({"ok": False, "error": "Repair request not found"}), 400
                mat.repair_request_id = repair_request_id
            if "name" in body: mat.name = _to_text(body.get("name"))
            if "quantity" in body: mat.quantity = _to_int(body.get("quantity"))
            if "unit_price" in body: mat.unit_price = _to_int(body.get("unit_price"))
            if "total_price" in body: mat.total_price = _to_int(body.get("total_price"))
            session.commit()
            return jsonify({"ok": True, "row": _serialize_material_model(mat)})

    @app.delete("/api/materials/<string:mat_id>")
    def delete_material(mat_id: str) -> Any:
        with session_factory() as session:
            mat = session.get(Material, mat_id)
            if not mat:
                return jsonify({"ok": False, "error": "Material not found"}), 404
            session.delete(mat)
            session.commit()
        return jsonify({"ok": True, "id": mat_id})
