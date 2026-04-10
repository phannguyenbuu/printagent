from __future__ import annotations

from typing import Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from models import (
    LanSite, AgentNode, AgentPresenceLog, Printer, PrinterEnableLog, PrinterOnlineLog, 
    CounterInfor, CounterBaseline, DeviceInfor, DeviceInforHistory,
    Task, UserAccount, NetworkInfo, Workspace, UserWorkspace, Location, RepairRequest, Material, Lead
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


def _normalize_user_type(value: object, default: str = "support") -> str:
    raw = _to_text(value).strip().lower()
    if not raw:
        return default
    if raw in {"tech", "technician", "worker"}:
        return "tech"
    if raw in {"support", "supplier", "admin", "account", "customer", "leader"}:
        return "support"
    return default


def _user_type_value(user: UserAccount) -> str:
    return _normalize_user_type(getattr(user, "user_type", "") or getattr(user, "role", ""))


def _serialize_audit_fields(
    created_at: datetime | None,
    updated_at: datetime | None,
    created_formatter=_format_date,
    updated_formatter=_format_datetime,
) -> dict[str, str]:
    created_source = created_at or updated_at
    updated_source = updated_at or created_at
    created_value = created_formatter(created_source) if created_source else ""
    updated_value = updated_formatter(updated_source) if updated_source else ""
    return {
        "created_at": created_value,
        "updated_at": updated_value,
        "createAt": created_value,
        "updateAt": updated_value,
    }


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
    app_version: str = "",
    run_mode: str = "web",
    web_port: int = 9173,
    ftp_ports: str = "",
    ftp_sites: list[dict[str, Any]] | None = None,
    fingerprint_signature: str = "",
    is_online: bool = True,
    seen_at: datetime | None = None,
) -> str:
    seen_at = seen_at or datetime.now(timezone.utc)
    lan = None
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
        agent = AgentNode(
            lead=lead,
            lan_uid=lan_uid,
            agent_uid=agent_uid,
            hostname=hostname,
            local_ip=local_ip,
            local_mac=local_mac,
            app_version=app_version,
            run_mode=run_mode or "web",
            web_port=web_port or 9173,
            ftp_ports=ftp_ports or "",
            ftp_sites=ftp_sites if ftp_sites is not None else [],
            is_online=bool(is_online),
            online_changed_at=seen_at,
        )
        session.add(agent)
        session.add(
            AgentPresenceLog(
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                hostname=hostname or "",
                local_ip=local_ip or "",
                local_mac=local_mac or "",
                app_version=app_version or "",
                run_mode=run_mode or "web",
                web_port=web_port or 9173,
                ftp_ports=ftp_ports or "",
                ftp_sites=ftp_sites if ftp_sites is not None else [],
                is_online=bool(is_online),
                changed_at=seen_at,
                last_seen_at=seen_at,
            )
        )
    else:
        agent.hostname = hostname or agent.hostname
        agent.local_ip = local_ip or agent.local_ip
        agent.local_mac = local_mac or agent.local_mac
        agent.app_version = app_version or agent.app_version
        agent.run_mode = run_mode or agent.run_mode or "web"
        agent.web_port = web_port or agent.web_port or 9173
        agent.ftp_ports = ftp_ports or agent.ftp_ports or ""
        if ftp_sites is not None:
            agent.ftp_sites = ftp_sites
        agent.last_seen_at = seen_at

        next_online = bool(is_online)
        if bool(agent.is_online) != next_online:
            agent.is_online = next_online
            agent.online_changed_at = seen_at
            session.add(
                AgentPresenceLog(
                    lead=lead,
                    lan_uid=lan_uid,
                    agent_uid=agent_uid,
                    hostname=hostname or agent.hostname or "",
                    local_ip=local_ip or agent.local_ip or "",
                    local_mac=local_mac or agent.local_mac or "",
                    app_version=app_version or agent.app_version or "",
                    run_mode=run_mode or agent.run_mode or "web",
                    web_port=web_port or agent.web_port or 9173,
                    ftp_ports=ftp_ports or agent.ftp_ports or "",
                    ftp_sites=ftp_sites if ftp_sites is not None else list(agent.ftp_sites or []),
                    is_online=next_online,
                    changed_at=seen_at,
                    last_seen_at=seen_at,
                )
            )

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


def _refresh_stale_agent_offline(
    session: Any,
    lead: str = "",
    lan_uid: str = "",
    agent_uid: str = "",
    stale_seconds: int = 300,
) -> None:
    stale_seconds = max(30, int(stale_seconds or 300))
    stale_before = datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)
    stmt = select(AgentNode).where(AgentNode.is_online.is_(True), AgentNode.last_seen_at < stale_before)
    if lead:
        stmt = stmt.where(AgentNode.lead == lead)
    if lan_uid:
        stmt = stmt.where(AgentNode.lan_uid == lan_uid)
    if agent_uid:
        stmt = stmt.where(AgentNode.agent_uid == agent_uid)
    rows = session.execute(stmt).scalars().all()
    if not rows:
        return
    now = datetime.now(timezone.utc)
    for item in rows:
        item.is_online = False
        item.online_changed_at = now
        session.add(
            AgentPresenceLog(
                lead=item.lead,
                lan_uid=item.lan_uid,
                agent_uid=item.agent_uid,
                hostname=item.hostname or "",
                local_ip=item.local_ip or "",
                local_mac=item.local_mac or "",
                app_version=item.app_version or "",
                run_mode=item.run_mode or "web",
                web_port=int(item.web_port or 9173),
                ftp_sites=list(item.ftp_sites or []),
                is_online=False,
                changed_at=now,
                last_seen_at=item.last_seen_at or now,
            )
        )

def _serialize_task_model(task: Task) -> dict[str, Any]:
    payload = {
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
    }
    payload.update(_serialize_audit_fields(task.created_at, task.updated_at))
    return payload

def _serialize_user_model(user: UserAccount) -> dict[str, Any]:
    user_type = _user_type_value(user)
    workspaces = list(getattr(user, "workspaces", []) or [])
    payload = {
        "id": int(user.id),
        "lead": user.lead,
        "username": user.username,
        "password": user.password or "",
        "full_name": user.full_name,
        "email": user.email,
        "phone_number": user.phone_number,
        "type": user_type,
        "user_type": user_type,
        "role": user_type,
        "is_active": user.is_active,
        "notes": user.notes,
        "workspaceIds": [ws.id for ws in workspaces],
        "workspaceCount": len(workspaces),
    }
    payload.update(_serialize_audit_fields(user.created_at, user.updated_at))
    return payload

def _serialize_network_model(net: NetworkInfo) -> dict[str, Any]:
    payload = {
        "id": int(net.id),
        "lead": net.lead,
        "lan_uid": net.lan_uid,
        "network_id": net.network_id,
        "network_name": net.network_name,
        "office_name": net.office_name,
        "real_address": net.real_address,
        "notes": net.notes,
    }
    payload.update(_serialize_audit_fields(net.created_at, net.updated_at))
    return payload

def _serialize_workspace_model(ws: Workspace) -> dict[str, Any]:
    users = list(getattr(ws, "users", []) or [])
    locations = list(getattr(ws, "locations", []) or [])
    payload = {
        "id": ws.id,
        "lead": "",
        "name": ws.name,
        "logo": ws.logo,
        "color": ws.color,
        "address": ws.address,
        "userIds": [int(user.id) for user in users],
        "userCount": len(users),
        "locationIds": [loc.id for loc in locations],
        "locationCount": len(locations),
    }
    payload.update(_serialize_audit_fields(ws.created_at, ws.updated_at))
    return payload

def _serialize_user_workspace_model(link: UserWorkspace) -> dict[str, Any]:
    payload = {
        "id": int(link.id),
        "user_id": int(link.user_id),
        "workspace_id": link.workspace_id,
    }
    payload.update(_serialize_audit_fields(link.created_at, link.updated_at))
    return payload

def _serialize_location_model(loc: Location) -> dict[str, Any]:
    workspace = getattr(loc, "workspace", None)
    payload = {
        "id": loc.id,
        "lead": "",
        "name": loc.name,
        "address": loc.address,
        "room": loc.room,
        "phone": loc.phone,
        "machine_count": loc.machine_count,
        "workspace_id": loc.workspace_id,
        "workspace_name": workspace.name if workspace else "",
    }
    payload.update(_serialize_audit_fields(loc.created_at, loc.updated_at))
    return payload

def _serialize_repair_model(rep: RepairRequest) -> dict[str, Any]:
    payload = {
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
        "accepted_at": _format_datetime(rep.accepted_at),
        "completed_at": _format_datetime(rep.completed_at),
    }
    payload.update(_serialize_audit_fields(rep.created_at, rep.updated_at))
    return payload

def _serialize_material_model(mat: Material) -> dict[str, Any]:
    payload = {
        "id": mat.id,
        "repair_request_id": mat.repair_request_id,
        "name": mat.name,
        "quantity": mat.quantity,
        "unit_price": mat.unit_price,
        "total_price": mat.total_price,
    }
    payload.update(_serialize_audit_fields(mat.created_at, mat.updated_at))
    return payload

def _serialize_lead_model(lead: Lead) -> dict[str, Any]:
    payload = {
        "id": lead.id,
        "name": lead.name,
        "email": lead.email,
        "phone": lead.phone,
        "notes": lead.notes,
    }
    payload.update(_serialize_audit_fields(lead.created_at, lead.updated_at))
    return payload
