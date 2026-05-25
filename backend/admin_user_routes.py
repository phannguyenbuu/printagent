from __future__ import annotations

import logging
import json
import os
import hashlib
import re
from typing import Any
from pathlib import Path

from flask import Flask, jsonify, request, render_template
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import IntegrityError

from utils import _to_text, _to_int, _apply_date_filters
from serializers import (
    _serialize_user_model,
    _serialize_network_model,
    _user_type_value,
    _serialize_workspace_model,
)
from app_helpers import _coalesce_request_lead
from models import UserAccount, Workspace, UserWorkspace, NetworkInfo, UserType

LOGGER = logging.getLogger(__name__)


def _normalize_user_type(value: object, default: str = UserType.SUPPORT.value, allow_empty: bool = False) -> str:
    raw = _to_text(value).strip().lower()
    if not raw:
        return "" if allow_empty else default
    if raw in {"tech", "technician", "worker"}:
        return UserType.TECH.value
    if raw in {"support", "supplier", "admin", "account", "customer", "leader"}:
        return UserType.SUPPORT.value
    return "" if allow_empty else default


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


def _workspace_rows_for_ids(session: Any, workspace_ids: list[str]) -> list[Workspace]:
    if not workspace_ids:
        return []
    rows = session.execute(
        select(Workspace).where(Workspace.id.in_(workspace_ids)).order_by(Workspace.id.asc())
    ).scalars().all()
    found = {row.id: row for row in rows}
    missing = [workspace_id for workspace_id in workspace_ids if workspace_id not in found]
    if missing:
        raise ValueError(f"Unknown workspaceIds: {', '.join(missing)}")
    return [found[workspace_id] for workspace_id in workspace_ids]


DRIVERS_CATALOG_ROOT = Path("storage/drivers")
_DRIVERS_CACHE: dict[str, Any] = {}


def register_admin_user_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.get("/users")
    def users_page() -> Any:
        return render_template("users.html", active_tab="users", page_title="User Accounts")

    @app.get("/api/users")
    def list_users() -> Any:
        lead = _to_text(request.args.get("lead"))
        username = _to_text(request.args.get("username"))
        fullname = _to_text(request.args.get("fullname"))
        requested_type = _to_text(request.args.get("type"))
        legacy_role = _to_text(request.args.get("role"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(UserAccount).options(selectinload(UserAccount.workspaces)).order_by(UserAccount.username.asc())
            if lead:
                stmt = stmt.where(UserAccount.lead == lead)
            if username:
                stmt = stmt.where(UserAccount.username.ilike(f"%{username}%"))
            if fullname:
                stmt = stmt.where(UserAccount.full_name.ilike(f"%{fullname}%"))
            if requested_type or legacy_role:
                normalized_type = _normalize_user_type(requested_type or legacy_role, allow_empty=True)
                if not normalized_type:
                    return jsonify({"ok": False, "error": "User type must be tech or support"}), 400
                stmt = stmt.where(UserAccount.user_type == normalized_type)
            stmt = _apply_date_filters(stmt, UserAccount, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_user_model(r) for r in rows]})

    @app.post("/api/users")
    def create_user() -> Any:
        body = request.get_json(silent=True) or {}
        lead = _coalesce_request_lead(body.get("lead"), lead_key_map)
        username = _to_text(body.get("username"))
        if not username:
            return jsonify({"ok": False, "error": "Username is required"}), 400
        email = _to_text(body.get("email"))
        if not email:
            return jsonify({"ok": False, "error": "Email is required"}), 400
        type_payload = body.get("type") if "type" in body else body.get("user_type", body.get("role"))
        normalized_type = _normalize_user_type(type_payload, allow_empty=True)
        if type_payload is not None and not normalized_type:
            return jsonify({"ok": False, "error": "User type must be tech or support"}), 400
        if not normalized_type:
            normalized_type = UserType.SUPPORT.value
            
        with session_factory() as session:
            password = _to_text(body.get("password"))
            if not password:
                return jsonify({"ok": False, "error": "Password is required"}), 400
            
            pw_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$"
            if not re.match(pw_regex, password):
                return jsonify({
                    "ok": False, 
                    "error": "Password must be at least 8 characters long, include uppercase, lowercase, and a special character"
                }), 400

            existing = session.execute(
                select(UserAccount).where(UserAccount.email == email)
            ).scalar_one_or_none()
            if existing:
                return jsonify({"ok": False, "error": "Email already registered"}), 400
            existing_username = session.execute(
                select(UserAccount).where(UserAccount.lead == lead, UserAccount.username == username)
            ).scalar_one_or_none()
            if existing_username:
                return jsonify({"ok": False, "error": "Username already exists for this lead"}), 400

            new_user = UserAccount(
                lead=lead,
                username=username,
                password=_to_text(body.get("password")),
                full_name=_to_text(body.get("full_name")),
                email=email,
                phone_number=_to_text(body.get("phone_number")),
                user_type=normalized_type,
                role=normalized_type,
                is_active=bool(body.get("is_active", True)),
                notes=_to_text(body.get("notes")),
            )
            session.add(new_user)
            if "workspaceIds" in body or "workspace_ids" in body:
                try:
                    workspace_ids = _parse_string_id_list(body.get("workspaceIds") if "workspaceIds" in body else body.get("workspace_ids"))
                    new_user.workspaces = _workspace_rows_for_ids(session, workspace_ids)
                except ValueError as exc:
                    session.rollback()
                    return jsonify({"ok": False, "error": str(exc)}), 400
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return jsonify({"ok": False, "error": "User already exists"}), 400
            session.refresh(new_user)
            return jsonify({"ok": True, "user": _serialize_user_model(new_user)})

    @app.patch("/api/users/<int:user_id>")
    def update_user(user_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            user = session.get(UserAccount, user_id)
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            if "username" in body:
                next_username = _to_text(body.get("username"))
                if not next_username:
                    return jsonify({"ok": False, "error": "Username is required"}), 400
                existing_username = session.execute(
                    select(UserAccount).where(
                        UserAccount.lead == user.lead,
                        UserAccount.username == next_username,
                        UserAccount.id != user.id,
                    )
                ).scalar_one_or_none()
                if existing_username:
                    return jsonify({"ok": False, "error": "Username already exists for this lead"}), 400
                user.username = next_username
            if "password" in body:
                next_password = _to_text(body.get("password"))
                if next_password:
                    user.password = next_password
            if "full_name" in body: user.full_name = _to_text(body.get("full_name"))
            if "email" in body:
                next_email = _to_text(body.get("email"))
                if not next_email:
                    return jsonify({"ok": False, "error": "Email is required"}), 400
                existing_email = session.execute(
                    select(UserAccount).where(UserAccount.email == next_email, UserAccount.id != user.id)
                ).scalar_one_or_none()
                if existing_email:
                    return jsonify({"ok": False, "error": "Email already registered"}), 400
                user.email = next_email
            if "phone_number" in body: user.phone_number = _to_text(body.get("phone_number"))
            if "type" in body or "user_type" in body or "role" in body:
                normalized_type = _normalize_user_type(
                    body.get("type") if "type" in body else body.get("user_type", body.get("role")),
                    allow_empty=True,
                )
                if not normalized_type:
                    return jsonify({"ok": False, "error": "User type must be tech or support"}), 400
                user.user_type = normalized_type
                user.role = normalized_type
            if "is_active" in body: user.is_active = bool(body.get("is_active"))
            if "notes" in body: user.notes = _to_text(body.get("notes"))
            if "workspaceIds" in body or "workspace_ids" in body:
                try:
                    workspace_ids = _parse_string_id_list(body.get("workspaceIds") if "workspaceIds" in body else body.get("workspace_ids"))
                    user.workspaces = _workspace_rows_for_ids(session, workspace_ids)
                except ValueError as exc:
                    session.rollback()
                    return jsonify({"ok": False, "error": str(exc)}), 400
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return jsonify({"ok": False, "error": "User already exists"}), 400
            session.refresh(user)
            return jsonify({"ok": True, "user": _serialize_user_model(user)})

    @app.delete("/api/users/<int:user_id>")
    def delete_user(user_id: int) -> Any:
        with session_factory() as session:
            user = session.get(UserAccount, user_id)
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            session.delete(user)
            session.commit()
        return jsonify({"ok": True, "id": user_id})

    @app.get("/api/user/workspaces")
    def list_user_workspaces() -> Any:
        user_id = _to_int(request.args.get("user_id"))
        if not user_id:
            return jsonify({"ok": False, "error": "Missing user_id"}), 400
        with session_factory() as session:
            user = session.get(UserAccount, user_id)
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            stmt = (
                select(Workspace)
                .options(selectinload(Workspace.users), selectinload(Workspace.locations))
                .join(UserWorkspace, UserWorkspace.workspace_id == Workspace.id)
                .where(UserWorkspace.user_id == user_id)
                .order_by(Workspace.name.asc(), Workspace.id.asc())
            )
            rows = session.execute(stmt).scalars().all()
            return jsonify({
                "ok": True,
                "user_id": user_id,
                "rows": [_serialize_workspace_model(row) for row in rows],
            })

    @app.get("/api/workspace/users")
    def list_workspace_users() -> Any:
        workspace_id = _to_text(request.args.get("workspace_id"))
        if not workspace_id:
            return jsonify({"ok": False, "error": "Missing workspace_id"}), 400
        with session_factory() as session:
            ws = session.get(Workspace, workspace_id)
            if not ws:
                return jsonify({"ok": False, "error": "Workspace not found"}), 404
            stmt = (
                select(UserAccount)
                .options(selectinload(UserAccount.workspaces))
                .join(UserWorkspace, UserWorkspace.user_id == UserAccount.id)
                .where(UserWorkspace.workspace_id == workspace_id)
                .order_by(UserAccount.username.asc(), UserAccount.id.asc())
            )
            rows = session.execute(stmt).scalars().all()
            return jsonify({
                "ok": True,
                "workspace_id": workspace_id,
                "rows": [_serialize_user_model(row) for row in rows],
            })

    @app.get("/companies")
    def networks_page() -> Any:
        return render_template("networks.html", active_tab="companies", page_title="Companies / Networks")

    @app.get("/api/networks")
    def list_networks() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        name = _to_text(request.args.get("name"))
        office = _to_text(request.args.get("office"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(NetworkInfo).order_by(NetworkInfo.network_name.asc())
            if lead:
                stmt = stmt.where(NetworkInfo.lead == lead)
            if lan_uid:
                stmt = stmt.where(NetworkInfo.lan_uid.ilike(f"%{lan_uid}%"))
            if name:
                stmt = stmt.where(NetworkInfo.network_name.ilike(f"%{name}%"))
            if office:
                stmt = stmt.where(NetworkInfo.office_name.ilike(f"%{office}%"))
            stmt = _apply_date_filters(stmt, NetworkInfo, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_network_model(r) for r in rows]})

    @app.post("/api/networks")
    def create_network() -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            new_net = NetworkInfo(
                lead=_coalesce_request_lead(body.get("lead"), lead_key_map),
                lan_uid=_to_text(body.get("lan_uid")),
                network_id=_to_text(body.get("network_id")),
                network_name=_to_text(body.get("network_name")),
                office_name=_to_text(body.get("office_name")),
                real_address=_to_text(body.get("real_address")),
                notes=_to_text(body.get("notes")),
            )
            session.add(new_net)
            session.commit()
            return jsonify({"ok": True, "network": _serialize_network_model(new_net)})

    @app.patch("/api/networks/<int:net_id>")
    def update_network(net_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            net = session.get(NetworkInfo, net_id)
            if not net:
                return jsonify({"ok": False, "error": "Network not found"}), 404
            if "lan_uid" in body: net.lan_uid = _to_text(body.get("lan_uid"))
            if "network_id" in body: net.network_id = _to_text(body.get("network_id"))
            if "network_name" in body: net.network_name = _to_text(body.get("network_name"))
            if "office_name" in body: net.office_name = _to_text(body.get("office_name"))
            if "real_address" in body: net.real_address = _to_text(body.get("real_address"))
            if "notes" in body: net.notes = _to_text(body.get("notes"))
            session.commit()
            return jsonify({"ok": True, "network": _serialize_network_model(net)})

    @app.delete("/api/networks/<int:net_id>")
    def delete_network(net_id: int) -> Any:
        with session_factory() as session:
            net = session.get(NetworkInfo, net_id)
            if not net:
                return jsonify({"ok": False, "error": "Network not found"}), 404
            session.delete(net)
            session.commit()
        return jsonify({"ok": True, "id": net_id})

    @app.get("/tasks")
    def tasks_page_ui() -> Any:
        return render_template("tasks.html", active_tab="tasks", page_title="Support Tasks")

    @app.get("/drivers")
    def drivers_page_ui() -> Any:
        return render_template("drivers.html", active_tab="drivers", page_title="Printer Drivers")

    @app.get("/api/drivers/<brand>")
    def api_get_drivers_catalog(brand: str) -> Any:
        brand_clean = brand.lower().strip()
        allowed = {"ricoh", "toshiba", "fujifilm"}
        if brand_clean not in allowed:
            return jsonify({"ok": False, "error": f"Unknown brand '{brand_clean}'. Allowed: {sorted(allowed)}"}), 400

        if brand_clean in _DRIVERS_CACHE:
            return jsonify({"ok": True, "brand": brand_clean, "data": _DRIVERS_CACHE[brand_clean]})

        catalog_file = DRIVERS_CATALOG_ROOT / f"{brand_clean}.json"
        if not catalog_file.exists():
            return jsonify({"ok": False, "error": f"Driver catalog for '{brand_clean}' not found on server"}), 404

        try:
            with open(catalog_file, encoding="utf-8") as f:
                data = json.load(f)
            _DRIVERS_CACHE[brand_clean] = data
            return jsonify({"ok": True, "brand": brand_clean, "count": len(data) if isinstance(data, list) else None, "data": data})
        except Exception as exc:
            LOGGER.error("drivers catalog load error brand=%s: %s", brand_clean, exc)
            return jsonify({"ok": False, "error": "Failed to load catalog"}), 500
