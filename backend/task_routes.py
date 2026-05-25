from __future__ import annotations

import logging
import hashlib
import time as time_module
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select, func

from utils import _to_text, _to_int, _normalize_mac, _parse_timestamp, _apply_date_filters
from app_helpers import (
    _request_api_token,
    _resolve_request_lead,
    _resolve_lead_from_token,
    _safe_task_status,
    _safe_task_priority,
)
from serializers import _serialize_task_model
from models import Task, TaskStatus

LOGGER = logging.getLogger(__name__)


def register_task_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.get("/api/tasks")
    def list_tasks() -> Any:
        lead = _to_text(request.args.get("lead"))
        sent_token = _request_api_token()
        if not lead and sent_token:
            ok_auth, resolved_lead, _ = _resolve_lead_from_token(lead_key_map, sent_token)
            if ok_auth:
                lead = resolved_lead
        agent_uid = _to_text(request.args.get("agent_uid"))
        mac = _normalize_mac(request.args.get("mac_id") or request.args.get("mac"))
        status_filter = _to_text(request.args.get("status")).lower()
        priority = _to_text(request.args.get("priority"))
        machine = _to_text(request.args.get("machine"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))

        with session_factory() as session:
            stmt = select(Task)
            if lead:
                stmt = stmt.where(Task.lead == lead)
            if agent_uid:
                stmt = stmt.where(Task.agent_uid == agent_uid)
            if mac:
                stmt = stmt.where(func.upper(Task.mac_id) == mac)
            if status_filter:
                stmt = stmt.where(Task.status == status_filter)
            if priority:
                stmt = stmt.where(Task.priority == priority)
            if machine:
                stmt = stmt.where(Task.machine_name.ilike(f"%{machine}%"))
            
            stmt = _apply_date_filters(stmt, Task, date_from, date_to)
            
            stmt = stmt.order_by(Task.status_updated_at.desc(), Task.id.desc())
            rows = session.execute(stmt).scalars().all()
            return jsonify(
                {
                    "ok": True,
                    "lead": lead,
                    "count": len(rows),
                    "tasks": [_serialize_task_model(row) for row in rows],
                    "rows": [_serialize_task_model(row) for row in rows],
                }
            )

    @app.post("/api/tasks")
    def create_task() -> Any:
        body = request.get_json(silent=True) or {}
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead(body, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error
        agent_uid = _to_text(body.get("agent_uid"))
        if not agent_uid:
            return jsonify({"ok": False, "error": "Missing parameter: agent_uid"}), 400
        title = _to_text(body.get("title"))
        if not title:
            return jsonify({"ok": False, "error": "Missing title"}), 400
        normalized_mac = _normalize_mac(body.get("mac_id") or body.get("mac"))
        if not normalized_mac:
            normalized_mac = _to_text(body.get("ip"))
        if not normalized_mac:
            return jsonify({"ok": False, "error": "Missing mac_id or ip"}), 400
        status_value = _safe_task_status(body.get("status"))
        priority_value = _safe_task_priority(body.get("priority"))
        status_updated = _parse_timestamp(body.get("status_updated_at")) or datetime.now(timezone.utc)
        completed_at = _parse_timestamp(body.get("completed_at"))
        if status_value == TaskStatus.DONE.value and completed_at is None:
            completed_at = status_updated
        reported_at = _parse_timestamp(body.get("reported_at")) or datetime.now(timezone.utc)
        task_key = _to_text(body.get("task_key"))
        if not task_key:
            digest = hashlib.sha1(f"{lead}-{agent_uid}-{time_module.time()}".encode("utf-8")).hexdigest()[:10]
            task_key = f"TASK-{lead.upper()}-{digest}"
        new_task = Task(
            lead=lead,
            lan_uid=_to_text(body.get("lan_uid")),
            agent_uid=agent_uid,
            network_id=_to_text(body.get("network_id")),
            task_key=task_key,
            mac_id=normalized_mac,
            machine_name=_to_text(body.get("machine_name")),
            title=title,
            description=_to_text(body.get("description")),
            status=status_value,
            priority=priority_value,
            reporter_id=_to_int(body.get("reporter_id")),
            assignee_id=_to_int(body.get("assignee_id")),
            customer_id=_to_int(body.get("customer_id")),
            reported_at=reported_at,
            assigned_at=_parse_timestamp(body.get("assigned_at")),
            due_at=_parse_timestamp(body.get("due_at")),
            completed_at=completed_at,
            status_updated_at=status_updated,
            status_reason=_to_text(body.get("status_reason")),
        )
        with session_factory() as session:
            session.add(new_task)
            session.flush()
            session.refresh(new_task)
            payload = _serialize_task_model(new_task)
            session.commit()
            return jsonify({"ok": True, "task": payload})

    @app.patch("/api/tasks/<int:task_id>")
    def update_task(task_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead(body, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        with session_factory() as session:
            task = session.execute(
                select(Task).where(Task.lead == lead, Task.id == task_id)
            ).scalar_one_or_none()
            if task is None:
                return jsonify({"ok": False, "error": "Task not found"}), 404
            if "agent_uid" in body:
                task.agent_uid = _to_text(body.get("agent_uid"))
            if "lan_uid" in body:
                task.lan_uid = _to_text(body.get("lan_uid"))
            if "network_id" in body:
                task.network_id = _to_text(body.get("network_id"))
            if "task_key" in body:
                task.task_key = _to_text(body.get("task_key"))
            if "mac_id" in body or "mac" in body:
                normalized_mac = _normalize_mac(body.get("mac_id") or body.get("mac"))
                if normalized_mac:
                    task.mac_id = normalized_mac
            if "title" in body:
                task.title = _to_text(body.get("title"))
            if "description" in body:
                task.description = _to_text(body.get("description"))
            if "machine_name" in body:
                task.machine_name = _to_text(body.get("machine_name"))
            status_updated_custom = _parse_timestamp(body.get("status_updated_at"))
            if "status" in body:
                new_status = _safe_task_status(body.get("status"))
                if new_status != task.status:
                    task.status = new_status
                    task.status_updated_at = status_updated_custom or datetime.now(timezone.utc)
            elif status_updated_custom:
                task.status_updated_at = status_updated_custom
            if "priority" in body:
                task.priority = _safe_task_priority(body.get("priority"))
            if "status_reason" in body:
                task.status_reason = _to_text(body.get("status_reason"))
            if "reporter_id" in body:
                task.reporter_id = _to_int(body.get("reporter_id"))
            if "assignee_id" in body:
                task.assignee_id = _to_int(body.get("assignee_id"))
            if "customer_id" in body:
                task.customer_id = _to_int(body.get("customer_id"))
            if "assigned_at" in body:
                task.assigned_at = _parse_timestamp(body.get("assigned_at"))
            if "due_at" in body:
                task.due_at = _parse_timestamp(body.get("due_at"))
            if "completed_at" in body:
                task.completed_at = _parse_timestamp(body.get("completed_at"))
            if task.status == TaskStatus.DONE.value and not task.completed_at:
                task.completed_at = status_updated_custom or datetime.now(timezone.utc)
            session.add(task)
            session.flush()
            payload = _serialize_task_model(task)
            session.commit()
            return jsonify({"ok": True, "task": payload})

    @app.delete("/api/tasks/<int:task_id>")
    def delete_task(task_id: int) -> Any:
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        with session_factory() as session:
            row = session.execute(select(Task).where(Task.lead == lead, Task.id == task_id)).scalar_one_or_none()
            if row is None:
                return jsonify({"ok": False, "error": "Task not found"}), 404
            session.delete(row)
            session.commit()
        return jsonify({"ok": True, "id": task_id})
