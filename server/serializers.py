from __future__ import annotations
from typing import Any
from datetime import datetime, date, timezone
from models import Task, UserAccount, NetworkInfo, Workspace, Location, RepairRequest, Material, Lead
from utils import UI_TZ, _format_datetime, _format_date

def _serialize_task_model(task: Task) -> dict[str, Any]:
    return {
        "id": int(task.id),
        "lead": task.lead,
        "lan_uid": task.lan_uid,
        "agent_uid": task.agent_uid,
        "network_id": task.network_id,
        "task_key": task.task_key,
        "mac_id": task.mac_id,
        "machine_name": task.machine_name,
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "priority": task.priority,
        "status_reason": task.status_reason,
        "reporter_id": int(task.reporter_id) if task.reporter_id else None,
        "reporter_name": task.reporter.full_name if task.reporter else "",
        "assignee_id": int(task.assignee_id) if task.assignee_id else None,
        "assignee_name": task.assignee.full_name if task.assignee else "",
        "customer_id": int(task.customer_id) if task.customer_id else None,
        "customer_name": task.customer.full_name if task.customer else "",
        "reported_at": _format_datetime(task.reported_at),
        "assigned_at": _format_datetime(task.assigned_at),
        "due_at": _format_datetime(task.due_at),
        "completed_at": _format_datetime(task.completed_at),
        "status_updated_at": _format_datetime(task.status_updated_at),
        "created_at": _format_date(task.created_at),
        "updated_at": _format_datetime(task.updated_at),
    }

def _serialize_user_model(user: UserAccount) -> dict[str, Any]:
    return {
        "id": int(user.id),
        "lead": user.lead,
        "username": user.username,
        "password": user.password or "",
        "full_name": user.full_name,
        "email": user.email,
        "phone_number": user.phone_number,
        "role": user.role,
        "is_active": user.is_active,
        "notes": user.notes,
        "created_at": _format_date(user.created_at),
        "updated_at": _format_datetime(user.updated_at),
    }

def _serialize_network_model(net: NetworkInfo) -> dict[str, Any]:
    return {
        "id": int(net.id),
        "lead": net.lead,
        "lan_uid": net.lan_uid,
        "network_id": net.network_id,
        "network_name": net.network_name,
        "office_name": net.office_name,
        "real_address": net.real_address,
        "notes": net.notes,
        "created_at": _format_date(net.created_at),
        "updated_at": _format_datetime(net.updated_at),
    }

def _serialize_workspace_model(ws: Workspace) -> dict[str, Any]:
    return {
        "id": ws.id,
        "name": ws.name,
        "logo": ws.logo,
        "color": ws.color,
        "address": ws.address,
        "created_at": _format_date(ws.created_at),
    }

def _serialize_location_model(loc: Location) -> dict[str, Any]:
    return {
        "id": loc.id,
        "name": loc.name,
        "address": loc.address,
        "phone": loc.phone,
        "machine_count": loc.machine_count,
        "workspace_id": loc.workspace_id,
        "created_at": _format_date(loc.created_at),
    }

def _serialize_repair_model(rep: RepairRequest) -> dict[str, Any]:
    return {
        "id": rep.id,
        "machine_name": rep.machine_name,
        "location_id": rep.location_id,
        "workspace_id": rep.workspace_id,
        "description": rep.description,
        "priority": rep.priority,
        "status": rep.status,
        "created_by": rep.created_by,
        "assigned_to": rep.assigned_to,
        "labor_cost": rep.labor_cost,
        "note": rep.note,
        "contact_phone": rep.contact_phone,
        "created_at": _format_date(rep.created_at),
        "updated_at": _format_datetime(rep.updated_at),
        "accepted_at": _format_datetime(rep.accepted_at),
        "completed_at": _format_datetime(rep.completed_at),
    }

def _serialize_material_model(mat: Material) -> dict[str, Any]:
    return {
        "id": mat.id,
        "repair_request_id": mat.repair_request_id,
        "name": mat.name,
        "quantity": mat.quantity,
        "unit_price": mat.unit_price,
        "total_price": mat.total_price,
        "created_at": _format_date(mat.created_at),
    }

def _serialize_lead_model(lead: Lead) -> dict[str, Any]:
    return {
        "id": lead.id,
        "name": lead.name,
        "email": lead.email,
        "phone": lead.phone,
        "notes": lead.notes,
        "created_at": _format_date(lead.created_at),
    }
