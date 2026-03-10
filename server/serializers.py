from __future__ import annotations

from typing import Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from models import (
    LanSite, AgentNode, Printer, PrinterEnableLog, PrinterOnlineLog, 
    CounterInfor, CounterBaseline, DeviceInfor, DeviceInforHistory,
    Task, UserAccount, NetworkInfo, Workspace, Location, RepairRequest, Material, Lead
)
from utils import (
    UI_TZ, _to_text, _normalize_mac, _to_int, _apply_baseline, 
    _format_datetime, _format_date, _apply_common_filters
)

def _resolve_day_window(page: int) -> tuple[datetime, datetime, datetime]:
    now_local = datetime.now(UI_TZ)
    today_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    day_start_local = today_start_local - timedelta(days=max(0, page - 1))
    day_end_local = day_start_local + timedelta(days=1)
    return (
        day_start_local.astimezone(timezone.utc),
        day_end_local.astimezone(timezone.utc),
        today_start_local,
    )


def _upsert_lan_and_agent(
    session: Any,
    lead: str,
    lan_uid: str,
    agent_uid: str,
    lan_name: str,
    subnet_cidr: str,
    gateway_ip: str,
    gateway_mac: str,
    hostname: str,
    local_ip: str,
    local_mac: str,
    fingerprint_signature: str = "",
) -> str:
    lan = None
    if fingerprint_signature:
        lan = session.execute(
            select(LanSite).where(LanSite.lead == lead, LanSite.fingerprint_signature == fingerprint_signature)
        ).scalar_one_or_none()

    if lan is None:
        lan = session.execute(select(LanSite).where(LanSite.lead == lead, LanSite.lan_uid == lan_uid)).scalar_one_or_none()

    if lan is None:
        lan = LanSite(
            lead=lead,
            lan_uid=lan_uid,
            lan_name=lan_name,
            subnet_cidr=subnet_cidr,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            fingerprint_signature=fingerprint_signature,
        )
        session.add(lan)
    else:
        lan_uid = lan.lan_uid
        lan.lan_name = lan_name or lan.lan_name
        lan.subnet_cidr = subnet_cidr or lan.subnet_cidr
        lan.gateway_ip = gateway_ip or lan.gateway_ip
        lan.gateway_mac = gateway_mac or lan.gateway_mac
        if fingerprint_signature:
            lan.fingerprint_signature = fingerprint_signature

    agent = session.execute(
        select(AgentNode).where(AgentNode.lead == lead, AgentNode.lan_uid == lan_uid, AgentNode.agent_uid == agent_uid)
    ).scalar_one_or_none()
    if agent is None:
        session.add(
            AgentNode(
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
            )
        )
    else:
        agent.hostname = hostname or agent.hostname
        agent.local_ip = local_ip or agent.local_ip
        agent.local_mac = local_mac or agent.local_mac
        agent.last_seen_at = datetime.now(timezone.utc)

    return lan_uid


def _upsert_printer_from_polling(
    session: Any,
    lead: str,
    lan_uid: str,
    agent_uid: str,
    printer_name: str,
    ip: str,
    event_time: datetime,
    touch_seen: bool = True,
    mark_online_on_create: bool = True,
    mac_address: str = "",
    auth_user: str = "",
    auth_password: str = "",
) -> Printer:
    printer_ip = _to_text(ip)
    printer_mac = _to_text(mac_address)
    printer_name_value = _to_text(printer_name) or "Unknown Printer"
    row = None
    if printer_ip:
        row = session.execute(
            select(Printer).where(Printer.lead == lead, Printer.lan_uid == lan_uid, Printer.ip == printer_ip).limit(1)
        ).scalar_one_or_none()
    if row is None:
        row = session.execute(
            select(Printer)
            .where(
                Printer.lead == lead,
                Printer.lan_uid == lan_uid,
                Printer.agent_uid == agent_uid,
                Printer.printer_name == printer_name_value,
            )
            .order_by(Printer.updated_at.desc(), Printer.id.desc())
            .limit(1)
        ).scalar_one_or_none()
    if row is None and not printer_ip:
        row = session.execute(
            select(Printer)
            .where(
                Printer.lead == lead,
                Printer.lan_uid == lan_uid,
                Printer.printer_name == printer_name_value,
                Printer.ip == "",
            )
            .order_by(Printer.updated_at.desc(), Printer.id.desc())
            .limit(1)
        ).scalar_one_or_none()
    if row is None:
        row = Printer(
            lead=lead,
            lan_uid=lan_uid,
            agent_uid=agent_uid,
            printer_name=printer_name_value,
            ip=printer_ip,
            enabled=True,
            enabled_changed_at=event_time,
            is_online=bool(mark_online_on_create),
            online_changed_at=event_time,
            mac_address=printer_mac,
            auth_user=_to_text(auth_user),
            auth_password=_to_text(auth_password),
        )
        session.add(row)
        session.flush()
        session.add(
            PrinterEnableLog(
                printer_id=row.id,
                lead=lead,
                lan_uid=lan_uid,
                printer_name=row.printer_name,
                ip=printer_ip,
                enabled=True,
                changed_at=event_time,
            )
        )
        session.add(
            PrinterOnlineLog(
                printer_id=row.id,
                lead=lead,
                lan_uid=lan_uid,
                printer_name=row.printer_name,
                ip=printer_ip,
                is_online=bool(mark_online_on_create),
                changed_at=event_time,
            )
        )
        return row

    row.agent_uid = agent_uid or row.agent_uid
    row.printer_name = printer_name_value or row.printer_name
    row.ip = printer_ip if printer_ip else row.ip
    row.mac_address = printer_mac if printer_mac else row.mac_address
    if _to_text(auth_user):
        row.auth_user = _to_text(auth_user)
    if _to_text(auth_password):
        row.auth_password = _to_text(auth_password)
    if touch_seen:
        row.updated_at = datetime.now(timezone.utc)
    return row


def _resolve_public_mac(
    *,
    session: Any,
    lead: str,
    lan_uid: str,
    ip: str,
    incoming_mac: Any,
) -> str:
    normalized = _normalize_mac(incoming_mac)
    if normalized:
        return normalized
    ip_text = _to_text(ip)
    if not ip_text:
        return ""
    printer = session.execute(
        select(Printer)
        .where(Printer.lead == lead, Printer.lan_uid == lan_uid, Printer.ip == ip_text)
        .order_by(Printer.updated_at.desc(), Printer.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if printer is None:
        return ""
    return _normalize_mac(printer.mac_address)


def _set_printer_online_state(session: Any, printer: Printer, is_online: bool, changed_at: datetime) -> None:
    next_state = bool(is_online)
    if bool(printer.is_online) == next_state:
        return
    printer.is_online = next_state
    printer.online_changed_at = changed_at
    session.add(
        PrinterOnlineLog(
            printer_id=printer.id,
            lead=printer.lead,
            lan_uid=printer.lan_uid,
            printer_name=printer.printer_name,
            ip=printer.ip,
            is_online=next_state,
            changed_at=changed_at,
        )
    )


def _apply_printer_enabled_state(session: Any, printer: Printer, enabled: bool, at: datetime) -> None:
    next_state = bool(enabled)
    if bool(printer.enabled) == next_state:
        return
    printer.enabled = next_state
    printer.enabled_changed_at = at
    session.add(
        PrinterEnableLog(
            printer_id=printer.id,
            lead=printer.lead,
            lan_uid=printer.lan_uid,
            printer_name=printer.printer_name,
            ip=printer.ip,
            enabled=next_state,
            changed_at=at,
        )
    )


def _refresh_stale_offline(session: Any, lead: str = "", lan_uid: str = "", agent_uid: str = "") -> None:
    ONLINE_STALE_SECONDS = 300
    stale_before = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_STALE_SECONDS)
    stmt = select(Printer).where(Printer.is_online.is_(True), Printer.updated_at < stale_before)
    if lead:
        stmt = stmt.where(Printer.lead == lead)
    if lan_uid:
        stmt = stmt.where(Printer.lan_uid == lan_uid)
    if agent_uid:
        stmt = stmt.where(Printer.agent_uid == agent_uid)
    rows = session.execute(stmt).scalars().all()
    if not rows:
        return
    now = datetime.now(timezone.utc)
    for item in rows:
        _set_printer_online_state(session, item, False, now)

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
