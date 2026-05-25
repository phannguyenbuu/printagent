from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import time as time_module
from bisect import bisect_right
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from logging.handlers import RotatingFileHandler

from config import ServerConfig
from db import create_session_factory
from google_drive_sync import GoogleDriveSync
from utils import (
    COUNTER_KEYS,
    UI_TZ,
    _apply_baseline,
    _compute_delta_payload,
    _is_same_utc_minute,
    _normalize_counter_payload,
    _normalize_ipv4,
    _normalize_mac,
    _normalize_status_payload,
    _parse_date,
    _parse_query_datetime,
    _parse_timestamp,
    _resolve_lan_info_from_body,
    _resolve_lan_uid_from_body,
    _safe_path_token,
    _safe_relative_path_parts,
    _time_scope_start,
    _to_int,
    _to_json_value,
    _to_page,
    _to_text,
    _to_text_max,
    _write_last_data,
    _format_date,
    _format_datetime,
    _format_datetime_ui,
    _apply_common_filters,
    _apply_date_filters,
)
from serializers import (
    _serialize_task_model,
    _serialize_user_model,
    _serialize_network_model,
    _serialize_workspace_model,
    _serialize_user_workspace_model,
    _serialize_location_model,
    _serialize_repair_model,
    _serialize_material_model,
    _serialize_lead_model,
    _resolve_day_window,
    _upsert_lan_and_agent,
    _upsert_printer_from_polling,
    _resolve_public_mac,
    _set_printer_online_state,
    _apply_printer_enabled_state,
    _refresh_stale_offline,
    _refresh_stale_agent_offline,
)
from models import (
    AgentNode,
    AgentPresenceLog,
    AlertStatus,
    Base,
    CounterBaseline,
    CounterInfor,
    DeviceFeatureFlag,
    DeviceInfor,
    DeviceInforHistory,
    DeviceLockHistory,
    LanSite,
    MachineAlert,
    NetworkInfo,
    Printer,
    PrinterControlCommand,
    PrinterEnableLog,
    PrinterOnlineLog,
    StatusInfor,
    Task,
    TaskPriority,
    TaskStatus,
    UserAccount,
    UserType,
    Lead,
    Workspace,
    Location,
    RepairRequest,
    Material,
    UserWorkspace,
    LanEmail,
)

LOGGER = logging.getLogger(__name__)
UI_TZ = timezone(timedelta(hours=7))
ONLINE_STALE_SECONDS = 600
SCAN_UPLOAD_ROOT = Path("storage/uploads/scans")
LAST_DATA_FILE = Path("storage/data/last_data.json")
PUBLIC_API_FILE = Path("PUBLIC_API.md")
AGENT_RELEASE_MANIFEST_FILE = Path("storage/releases/agent_release.json")
AGENT_RELEASE_BINARY_PATH = Path("static/releases/printagent.exe")
COUNTER_KEYS = [
    "total",
    "copier_bw",
    "printer_bw",
    "fax_bw",
    "send_tx_total_bw",
    "send_tx_total_color",
    "fax_transmission_total",
    "scanner_send_bw",
    "scanner_send_color",
    "coverage_copier_bw",
    "coverage_printer_bw",
    "coverage_fax_bw",
    "a3_dlt",
    "duplex",
]
MAC_PATTERN = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_LOGGING_READY = False
TASK_STATUS_VALUES = {status.value for status in TaskStatus}
TASK_PRIORITY_VALUES = {priority.value for priority in TaskPriority}


def _format_agents_datetime_ui(value: datetime | None) -> str:
    formatted = _format_datetime_ui(value)
    return f"{formatted} GMT+7" if formatted else ""


def _isoformat_or_empty(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _serialize_audit_payload(
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


def _serialize_audit_payload_iso(created_at: datetime | None, updated_at: datetime | None) -> dict[str, str]:
    return _serialize_audit_payload(created_at, updated_at, _isoformat_or_empty, _isoformat_or_empty)


def _serialize_audit_payload_agents(created_at: datetime | None, updated_at: datetime | None) -> dict[str, str]:
    return _serialize_audit_payload(created_at, updated_at, _format_agents_datetime_ui, _format_agents_datetime_ui)


def _configure_server_logging() -> None:
    global _LOGGING_READY
    if _LOGGING_READY:
        return
    log_dir = Path(os.getenv("SERVER_LOG_DIR", "storage/logs/server"))
    log_dir.mkdir(parents=True, exist_ok=True)
    level_name = os.getenv("SERVER_LOG_LEVEL", "INFO").upper().strip() or "INFO"
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)

    api_log_path = log_dir / "api.log"
    err_log_path = log_dir / "error.log"

    if not any(getattr(h, "baseFilename", "") == str(api_log_path.resolve()) for h in root_logger.handlers):
        api_handler = RotatingFileHandler(api_log_path, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
        api_handler.setLevel(level)
        api_handler.setFormatter(formatter)
        root_logger.addHandler(api_handler)

    if not any(getattr(h, "baseFilename", "") == str(err_log_path.resolve()) for h in root_logger.handlers):
        err_handler = RotatingFileHandler(err_log_path, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
        err_handler.setLevel(logging.WARNING)
        err_handler.setFormatter(formatter)
        root_logger.addHandler(err_handler)

    _LOGGING_READY = True


def _safe_task_status(value: Any) -> str:
    normalized = _to_text(value).lower()
    if normalized in TASK_STATUS_VALUES:
        return normalized
    return TaskStatus.BACKLOG.value


def _safe_task_priority(value: Any) -> str:
    normalized = _to_text(value).lower()
    if normalized in TASK_PRIORITY_VALUES:
        return normalized
    return TaskPriority.MEDIUM.value


def _request_api_token() -> str:
    return _to_text(request.headers.get("X-API-Token")) or _to_text(request.headers.get("X-Lead-Token"))


def _validate_polling_auth(body: dict[str, Any], lead_key_map: dict[str, str], sent_token: str) -> tuple[bool, str, Any]:
    lead = _to_text(body.get("lead"))
    if not lead:
        return _resolve_lead_from_token(lead_key_map, sent_token)
    expected_token = lead_key_map.get(lead)
    if not expected_token or sent_token != expected_token:
        return False, "", (jsonify({"ok": False, "error": "Unauthorized API token"}), 401)
    return True, lead, None


def _is_agent_master_and_get_emails(session, lead: str, lan_uid: str, agent_uid: str) -> tuple[bool, list[dict]]:
    # Get all online agents in this LAN, sorted by ID (smallest ID is oldest/master)
    stale_before = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_STALE_SECONDS)
    stmt = select(AgentNode).where(
        AgentNode.lead == lead,
        AgentNode.lan_uid == lan_uid,
        AgentNode.last_seen_at >= stale_before
    ).order_by(AgentNode.id.asc())
    
    online_agents = session.execute(stmt).scalars().all()
    
    # Fallback to all agents in the LAN if none are currently registered as online
    if not online_agents:
        stmt_fallback = select(AgentNode).where(
            AgentNode.lead == lead,
            AgentNode.lan_uid == lan_uid
        ).order_by(AgentNode.id.asc())
        online_agents = session.execute(stmt_fallback).scalars().all()
        
    is_master = False
    if online_agents:
        if online_agents[0].agent_uid == agent_uid:
            is_master = True
            
    # Fetch all address book emails for this LAN
    email_stmt = select(LanEmail).where(
        LanEmail.lead == lead,
        LanEmail.lan_uid == lan_uid
    ).order_by(LanEmail.email_number.asc())
    email_rows = session.execute(email_stmt).scalars().all()
    
    emails = [
        {
            "id": em.id,
            "email": em.email,
            "email_number": em.email_number,
            "email_type": getattr(em, "email_type", "common") or "common",
            "pc_name": getattr(em, "pc_name", "") or "",
        }
        for em in email_rows
    ]
    return is_master, emails



def _default_lead_name(lead_key_map: dict[str, str]) -> str:
    keys = sorted({_to_text(key) for key in lead_key_map.keys() if _to_text(key)}, key=str.lower)
    if "default" in keys:
        return "default"
    if keys:
        return keys[0]
    return "default"


def _resolve_lead_from_token(lead_key_map: dict[str, str], sent_token: str) -> tuple[bool, str, Any]:
    token = _to_text(sent_token)
    if not token:
        return False, "", (jsonify({"ok": False, "error": "Missing X-API-Token"}), 401)
    matches = [lead for lead, expected_token in lead_key_map.items() if expected_token and expected_token == token]
    if not matches:
        return False, "", (jsonify({"ok": False, "error": "Unauthorized API token"}), 401)
    if len(matches) > 1:
        return False, "", (jsonify({"ok": False, "error": "Ambiguous API token"}), 401)
    return True, matches[0], None


def _resolve_request_lead(
    body: dict[str, Any] | None,
    lead_key_map: dict[str, str],
    sent_token: str,
    query_lead: object = None,
) -> tuple[bool, str, Any]:
    requested_lead = _to_text((body or {}).get("lead")) or _to_text(query_lead)
    if requested_lead:
        return _validate_polling_auth({"lead": requested_lead}, lead_key_map, sent_token)
    return _resolve_lead_from_token(lead_key_map, sent_token)


def _coalesce_request_lead(value: Any, lead_key_map: dict[str, str]) -> str:
    return _to_text(value) or _default_lead_name(lead_key_map)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_version_key(version: str) -> tuple[int, ...]:
    text = _to_text(version).lstrip("vV")
    if not text:
        return tuple()
    parts: list[int] = []
    for chunk in text.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits or "0"))
    return tuple(parts)


def _is_newer_version(candidate: str, current: str) -> bool:
    c1 = _parse_version_key(candidate)
    c2 = _parse_version_key(current)
    if not c1:
        return False
    width = max(len(c1), len(c2))
    c1 = c1 + (0,) * (width - len(c1))
    c2 = c2 + (0,) * (width - len(c2))
    return c1 > c2


def _load_agent_release_manifest() -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if AGENT_RELEASE_MANIFEST_FILE.exists():
        try:
            loaded = json.loads(AGENT_RELEASE_MANIFEST_FILE.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                payload = loaded
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to read agent release manifest: %s", exc)
    if not payload:
        payload = {
            "version": os.getenv("AGENT_RELEASE_VERSION", ""),
            "notes": "",
            "mandatory": False,
            "published_at": "",
            "download_url": "/static/releases/printagent.exe",
        }

    binary_path_raw = _to_text(payload.get("binary_path"))
    binary_path = Path(binary_path_raw) if binary_path_raw else AGENT_RELEASE_BINARY_PATH
    if not _to_text(payload.get("download_url")):
        payload["download_url"] = "/static/releases/printagent.exe"
    if binary_path.exists():
        try:
            payload["sha256"] = _sha256_file(binary_path)
            payload["size"] = int(binary_path.stat().st_size or 0)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to hash agent release binary: %s", exc)
            payload.setdefault("sha256", "")
            payload.setdefault("size", 0)
    else:
        payload.setdefault("sha256", "")
        payload.setdefault("size", 0)
    return payload



def _sanitize_ftp_name(value: str) -> str:
    text = _to_text(value).strip().replace(" ", "_")
    text = re.sub(r"[^A-Za-z0-9_-]", "", text)
    return text[:48]


def _scan_folder_leaf(value: str) -> str:
    text = _to_text(value).strip().rstrip("\\/")
    if not text:
        return ""
    parts = [part for part in re.split(r"[\\/]+", text) if part]
    return _to_text(parts[-1] if parts else text)


def _scan_path_is_explicit(value: str) -> bool:
    text = _to_text(value).strip()
    if not text:
        return False
    if text.startswith(("~", "\\\\", "/")):
        return True
    if "\\" in text or "/" in text:
        return True
    return bool(re.fullmatch(r"[A-Za-z]:.*", text))


def _derive_scan_site_name(*, raw_site_name: str = "", scan_path: str = "", mac_id: str = "") -> str:
    explicit = _sanitize_ftp_name(raw_site_name)
    if explicit:
        return explicit
    from_path = _sanitize_ftp_name(_scan_folder_leaf(scan_path))
    if from_path:
        return from_path
    compact_mac = re.sub(r"[^A-F0-9]", "", _normalize_mac(mac_id) or _to_text(mac_id).upper())
    if compact_mac:
        return _sanitize_ftp_name(f"scan_{compact_mac}")
    return ""


def _derive_scan_local_path(scan_path: str) -> str:
    text = _to_text(scan_path).strip()
    if not text:
        return ""
    return text if _scan_path_is_explicit(text) else ""


def _derive_scan_password(site_name: str, mac_id: str) -> str:
    safe_site = _sanitize_ftp_name(site_name) or "scan"
    compact_mac = re.sub(r"[^A-F0-9]", "", _normalize_mac(mac_id) or _to_text(mac_id).upper())
    mac_token = compact_mac[-6:] if compact_mac else "AGENT"
    return f"Scan!{mac_token}_{safe_site}"[:64]



def _serialize_scan_target_printer(printer: Printer) -> dict[str, Any]:
    return {
        "printer_name": _to_text(printer.printer_name),
        "ip": _to_text(printer.ip),
        "mac_id": _normalize_mac(printer.mac_address),
        "agent_uid": _to_text(printer.agent_uid),
        "lan_uid": _to_text(printer.lan_uid),
    }


def _resolve_scan_assignment_printer_for_agent(
    session: Any,
    *,
    agent: AgentNode,
    normalized_mac: str = "",
) -> tuple[Printer | None, list[str], tuple[dict[str, Any], int] | None]:
    agent_lead = _to_text(agent.lead)
    agent_lan_uid = _to_text(agent.lan_uid)
    agent_agent_uid = _to_text(agent.agent_uid)
    printer_stmt = (
        select(Printer)
        .where(
            func.trim(Printer.lead) == agent_lead,
        )
        .order_by(Printer.updated_at.desc(), Printer.id.desc())
    )
    printers = session.execute(printer_stmt).scalars().all()
    same_lan_printers = [
        item
        for item in printers
        if _to_text(item.lan_uid) == agent_lan_uid
    ]
    same_agent_printers = [
        item
        for item in same_lan_printers
        if _to_text(item.agent_uid) == agent_agent_uid
    ]
    warning_parts: list[str] = []
    if normalized_mac:
        printer_any_lan = next(
            (
                item
                for item in printers
                if _normalize_mac(item.mac_address) == normalized_mac
            ),
            None,
        )
        if printer_any_lan is None:
            available = [_serialize_scan_target_printer(item) for item in same_lan_printers]
            return (
                None,
                [],
                (
                    {
                        "ok": False,
                        "error": f"Printer with mac_id {normalized_mac} not found on this agent",
                        "available_printers": available,
                    },
                    404,
                ),
            )
        printer_lan_uid = _to_text(printer_any_lan.lan_uid)
        if printer_lan_uid and printer_lan_uid != agent_lan_uid:
            return (
                None,
                [],
                (
                    {
                        "ok": False,
                        "error": (
                            f"Printer mac_id {normalized_mac} belongs to lan_uid {printer_lan_uid}; "
                            f"agent {agent_agent_uid} is on lan_uid {agent_lan_uid}."
                        ),
                        "printer_lan_uid": printer_lan_uid,
                        "agent_lan_uid": agent_lan_uid,
                    },
                    409,
                ),
            )
        selected_printer_agent_uid = _to_text(printer_any_lan.agent_uid)
        if selected_printer_agent_uid and selected_printer_agent_uid != agent_agent_uid:
            warning_parts.append(
                f"Printer mac_id {normalized_mac} is currently linked to agent {selected_printer_agent_uid}; "
                f"Scan folder will be hosted on agent {agent_agent_uid}."
            )
        return printer_any_lan, warning_parts, None

    if len(same_agent_printers) > 1 or (not same_agent_printers and same_lan_printers):
        available = [_serialize_scan_target_printer(item) for item in same_lan_printers]
        error_message = (
            "Missing mac_id. This agent manages multiple printers; choose the target machine by MAC ID."
            if len(same_agent_printers) > 1
            else "Missing mac_id. No directly linked printer row was found for this agent; choose the target machine by MAC ID from the LAN list."
        )
        return (
            None,
            [],
            (
                {
                    "ok": False,
                    "error": error_message,
                    "available_printers": available,
                },
                400,
            ),
        )

    printer = same_agent_printers[0] if same_agent_printers else None
    if printer is None:
        return (
            None,
            [],
            (
                {
                    "ok": False,
                    "error": "No printer found on this agent for scan folder assignment",
                },
                404,
            ),
        )
    return printer, warning_parts, None


def _resolve_scan_host_agent_for_printer(
    session: Any,
    *,
    printer: Printer,
) -> tuple[AgentNode | None, list[str], tuple[dict[str, Any], int] | None]:
    printer_lead = _to_text(printer.lead)
    printer_lan_uid = _to_text(printer.lan_uid)
    printer_agent_uid = _to_text(printer.agent_uid)
    printer_mac = _normalize_mac(printer.mac_address) or _to_text(printer.mac_address)
    if not printer_lead or not printer_lan_uid:
        return (
            None,
            [],
            (
                {
                    "ok": False,
                    "error": "Printer identity incomplete",
                    "mac_id": printer_mac,
                    "lan_uid": printer_lan_uid,
                },
                400,
            ),
        )
    agents = session.execute(
        select(AgentNode)
        .where(func.trim(AgentNode.lead) == printer_lead)
        .order_by(AgentNode.last_seen_at.desc(), AgentNode.id.desc())
    ).scalars().all()
    same_lan_agents = [
        item
        for item in agents
        if _to_text(item.lan_uid) == printer_lan_uid
    ]
    if not same_lan_agents:
        available_agents = [
            {
                "id": int(item.id),
                "agent_uid": _to_text(item.agent_uid),
                "lan_uid": _to_text(item.lan_uid),
                "local_ip": _to_text(item.local_ip),
                "is_online": bool(item.is_online),
            }
            for item in agents[:20]
        ]
        return (
            None,
            [],
            (
                {
                    "ok": False,
                    "error": f"No agent found on lan_uid {printer_lan_uid} for printer {printer_mac or _to_text(printer.printer_name)}",
                    "mac_id": printer_mac,
                    "lan_uid": printer_lan_uid,
                    "available_agents": available_agents,
                },
                409,
            ),
        )
    eligible_agents = [item for item in same_lan_agents if _to_text(item.agent_uid)]
    if not eligible_agents:
        return (
            None,
            [],
            (
                {
                    "ok": False,
                    "error": f"No same-lan agent with a valid agent_uid was found for printer {printer_mac or _to_text(printer.printer_name)}",
                    "mac_id": printer_mac,
                    "lan_uid": printer_lan_uid,
                },
                409,
            ),
        )
    same_lan_agents = eligible_agents

    epoch = datetime.fromtimestamp(0, tz=timezone.utc)

    def _sort_dt(value: datetime | None) -> datetime:
        if value is None:
            return epoch
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    same_lan_agents.sort(
        key=lambda item: (
            1 if bool(item.is_online) else 0,
            1 if printer_agent_uid and _to_text(item.agent_uid) == printer_agent_uid else 0,
            _sort_dt(item.last_seen_at),
            _sort_dt(item.updated_at),
            int(item.id or 0),
        ),
        reverse=True,
    )
    agent = same_lan_agents[0]
    warning_parts: list[str] = []
    selected_agent_uid = _to_text(agent.agent_uid)
    if printer_agent_uid and selected_agent_uid and selected_agent_uid != printer_agent_uid:
        warning_parts.append(
            f"Printer mac_id {printer_mac} is currently linked to agent {printer_agent_uid}; "
            f"using same-lan agent {selected_agent_uid}."
        )
    if not bool(agent.is_online):
        warning_parts.append(
            f"Selected agent {selected_agent_uid or int(agent.id)} is currently offline; command will wait until the agent polls again."
        )
    return agent, warning_parts, None


def _queue_scan_folder_command_for_agent(
    session: Any,
    *,
    agent: AgentNode,
    body: dict[str, Any],
    printer: Printer | None = None,
    initial_warnings: list[str] | None = None,
) -> tuple[dict[str, Any], int]:
    action = _to_text(body.get("action")).lower() or "create"
    if action not in {"create", "update", "delete"}:
        return {"ok": False, "error": "Unsupported action"}, 400
    raw_site_name = _to_text(body.get("site_name"))
    raw_new_site_name = _to_text(body.get("new_site_name"))
    raw_scan_path = _to_text(
        body.get("scan_path")
        or body.get("scan_folder")
        or body.get("folder_path")
        or body.get("folder_name")
        or body.get("local_path")
    )
    site_name = _sanitize_ftp_name(raw_site_name)
    new_site_name = _sanitize_ftp_name(raw_new_site_name)
    local_path = _to_text(body.get("local_path"))
    raw_port = body.get("port")
    explicit_port = _to_text(raw_port) != ""
    port = _to_int(raw_port) or 2121
    ftp_user = _to_text(body.get("ftp_user"))
    ftp_password = _to_text(body.get("ftp_password"))
    normalized_mac = _normalize_mac(body.get("mac_id") or body.get("mac"))
    provided_mac = _to_text(body.get("mac_id") or body.get("mac"))
    if action == "create" and provided_mac and not normalized_mac:
        return {"ok": False, "error": "Invalid mac_id"}, 400

    agent_id = int(getattr(agent, "id", 0) or 0)
    agent_lead = _to_text(agent.lead)
    agent_lan_uid = _to_text(agent.lan_uid)
    agent_agent_uid = _to_text(agent.agent_uid)
    if not agent_lead or not agent_lan_uid or not agent_agent_uid:
        return {"ok": False, "error": "Agent identity incomplete"}, 400

    resolved_printer = printer
    if resolved_printer is not None:
        normalized_mac = normalized_mac or _normalize_mac(resolved_printer.mac_address)
    derived_scan_path = raw_scan_path
    if action == "create":
        site_name = _derive_scan_site_name(
            raw_site_name=raw_site_name or _to_text(body.get("folder_name")),
            scan_path=derived_scan_path,
            mac_id=normalized_mac,
        )
        if not site_name:
            return {"ok": False, "error": "Missing scan_path or site_name"}, 400
        if derived_scan_path:
            local_path = _derive_scan_local_path(derived_scan_path)
        if not ftp_user:
            ftp_user = f"ftp_{_sanitize_ftp_name(site_name) or 'site'}"[:64]
        if not ftp_password:
            ftp_password = _derive_scan_password(site_name, normalized_mac)
    else:
        if not site_name and normalized_mac:
            site_name = _derive_scan_site_name(mac_id=normalized_mac)
        if action == "update":
            if derived_scan_path:
                local_path = _derive_scan_local_path(derived_scan_path)
                if not new_site_name:
                    new_site_name = _derive_scan_site_name(
                        raw_site_name=raw_new_site_name,
                        scan_path=derived_scan_path,
                        mac_id=normalized_mac,
                    )
        if not site_name:
            return {"ok": False, "error": "Missing site_name or mac_id"}, 400

    warning_parts = [part for part in (initial_warnings or []) if _to_text(part)]
    if action == "create":
        if resolved_printer is None:
            resolved_printer, printer_warnings, printer_error = _resolve_scan_assignment_printer_for_agent(
                session,
                agent=agent,
                normalized_mac=normalized_mac,
            )
            if printer_error is not None:
                payload, status = printer_error
                return payload, status
            warning_parts.extend(printer_warnings)
        else:
            printer_lead = _to_text(resolved_printer.lead)
            printer_lan_uid = _to_text(resolved_printer.lan_uid)
            if printer_lead and printer_lead != agent_lead:
                return (
                    {
                        "ok": False,
                        "error": (
                            f"Printer mac_id {normalized_mac or _normalize_mac(resolved_printer.mac_address) or '-'} belongs to lead {printer_lead}; "
                            f"agent {agent_agent_uid} is on lead {agent_lead}."
                        ),
                        "printer_lead": printer_lead,
                        "agent_lead": agent_lead,
                    },
                    409,
                )
            if printer_lan_uid and printer_lan_uid != agent_lan_uid:
                return (
                    {
                        "ok": False,
                        "error": (
                            f"Printer mac_id {normalized_mac or _normalize_mac(resolved_printer.mac_address) or '-'} belongs to lan_uid {printer_lan_uid}; "
                            f"agent {agent_agent_uid} is on lan_uid {agent_lan_uid}."
                        ),
                        "printer_lan_uid": printer_lan_uid,
                        "agent_lan_uid": agent_lan_uid,
                    },
                    409,
                )
            selected_printer_agent_uid = _to_text(resolved_printer.agent_uid)
            if selected_printer_agent_uid and selected_printer_agent_uid != agent_agent_uid:
                warning_parts.append(
                    f"Printer mac_id {normalized_mac or _normalize_mac(resolved_printer.mac_address) or '-'} is currently linked to agent {selected_printer_agent_uid}; "
                    f"Scan folder will be hosted on agent {agent_agent_uid}."
                )
        if resolved_printer is None:
            return {"ok": False, "error": "No printer found on this agent for scan folder assignment"}, 404
        conflicting_port_site = _agent_ftp_site_by_port(agent, port)
        conflicting_port_name = _to_text((conflicting_port_site or {}).get("name")).lower()
        if conflicting_port_site and conflicting_port_name != site_name.lower():
            if explicit_port:
                return (
                    {
                        "ok": False,
                        "error": (
                            f"FTP port {port} is already used by site "
                            f'"{_to_text(conflicting_port_site.get("name"))}".'
                        ),
                        "port": port,
                        "site_name": _to_text(conflicting_port_site.get("name")),
                        "site_path": _to_text(conflicting_port_site.get("path")),
                    },
                    409,
                )
            next_port = _next_available_agent_ftp_port(agent, port)
            if next_port != port:
                warning_parts.append(
                    f"FTP port {port} is already used by site "
                    f'"{_to_text(conflicting_port_site.get("name"))}"; using port {next_port}.'
                )
                port = next_port
    if action in {"update", "delete"}:
        known_sites = _agent_known_ftp_site_names(agent)
        if known_sites and site_name.lower() not in known_sites:
            return {"ok": False, "error": f'FTP site "{site_name}" not found on this agent'}, 404
        if action == "update" and derived_scan_path and not local_path and new_site_name:
            current_site = _agent_ftp_site_by_name(agent, site_name)
            current_path = _to_text((current_site or {}).get("path"))
            if current_path:
                try:
                    local_path = str(Path(current_path).expanduser().parent / new_site_name)
                except Exception:
                    local_path = current_path
        if action == "update" and explicit_port:
            conflicting_port_site = _agent_ftp_site_by_port(agent, port)
            conflicting_port_name = _to_text((conflicting_port_site or {}).get("name")).lower()
            if conflicting_port_site and conflicting_port_name != site_name.lower():
                return (
                    {
                        "ok": False,
                        "error": (
                            f"FTP port {port} is already used by site "
                            f'"{_to_text(conflicting_port_site.get("name"))}".'
                        ),
                        "port": port,
                        "site_name": _to_text(conflicting_port_site.get("name")),
                        "site_path": _to_text(conflicting_port_site.get("path")),
                    },
                    409,
                )

    command = FtpControlCommand(
        lead=agent_lead,
        lan_uid=agent_lan_uid,
        agent_uid=agent_agent_uid,
        action=action,
        site_name=site_name,
        new_site_name=new_site_name,
        local_path=local_path,
        port=port,
        ftp_user=ftp_user,
        ftp_password=ftp_password,
        printer_mac_id=normalized_mac or (_normalize_mac(resolved_printer.mac_address) if resolved_printer is not None else ""),
        printer_ip=_to_text(resolved_printer.ip) if resolved_printer is not None else "",
        printer_name=_to_text(resolved_printer.printer_name) if resolved_printer is not None else "",
        printer_auth_user=_to_text(resolved_printer.auth_user) if resolved_printer is not None else "",
        printer_auth_password=_to_text(resolved_printer.auth_password) if resolved_printer is not None else "",
        status="pending",
        error_message="",
        requested_at=datetime.now(timezone.utc),
        responded_at=None,
    )
    session.add(command)
    session.commit()
    command_id = int(command.id)

    LOGGER.info(
        "scan folder command queued: agent_id=%s lead=%s lan_uid=%s action=%s site_name=%s new_site_name=%s port=%s ftp_user=%s mac_id=%s printer_ip=%s printer_agent_uid=%s",
        agent_id,
        agent_lead,
        agent_lan_uid,
        action,
        site_name,
        new_site_name or "",
        port,
        ftp_user,
        normalized_mac or (_normalize_mac(resolved_printer.mac_address) if resolved_printer is not None else ""),
        _to_text(resolved_printer.ip) if resolved_printer is not None else "",
        _to_text(resolved_printer.agent_uid) if resolved_printer is not None else "",
    )
    return (
        {
            "ok": True,
            "queued": True,
            "command_id": command_id,
            "status": "pending",
            "action": action,
            "lead": agent_lead,
            "lan_uid": agent_lan_uid,
            "agent_id": agent_id,
            "agent_uid": agent_agent_uid,
            "agent_local_ip": _to_text(agent.local_ip),
            "agent_is_online": bool(agent.is_online),
            "mac_id": normalized_mac or (_normalize_mac(resolved_printer.mac_address) if resolved_printer is not None else ""),
            "port": port,
            "scan_path": derived_scan_path or local_path or site_name,
            "site_name": site_name,
            "new_site_name": new_site_name or "",
            "printer_name": _to_text(resolved_printer.printer_name) if resolved_printer is not None else "",
            "printer_ip": _to_text(resolved_printer.ip) if resolved_printer is not None else "",
            "printer_agent_uid": _to_text(resolved_printer.agent_uid) if resolved_printer is not None else "",
            "warning": " ".join(part for part in warning_parts if _to_text(part)).strip(),
        },
        200,
    )


def _resolve_lan_uid_with_session(session: Any, lead: str, body: dict[str, Any]) -> tuple[str, str]:
    """
    Resolve the deterministic LAN UID for a request.

    The LAN identity must stay stable as:
    {lead}_{gateway_mac}_{gateway_ip}

    The database fingerprint is still captured for audit/history, but it does
    not override the derived LAN UID.
    """
    _ = session
    _ = lead
    return _resolve_lan_info_from_body(body)


def _safe_alter_table(session: Any, table_name: str, column_name: str, sql_type: str) -> None:
    res = session.execute(text(
        f"SELECT 1 FROM information_schema.columns WHERE LOWER(table_name) = LOWER('{table_name}') AND LOWER(column_name) = LOWER('{column_name}')"
    )).fetchone()
    if not res:
        LOGGER.info("Schema self-heal: Adding column %s to table %s", column_name, table_name)
        session.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN IF NOT EXISTS {column_name} {sql_type};'))

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    _configure_server_logging()
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    drive_sync = GoogleDriveSync(cfg)
    Base.metadata.create_all(bind=session_factory.kw["bind"])
    with session_factory() as session:
        # Self-heal schema drift for older deployments (PostgreSQL).
        _safe_alter_table(session, "Printer", "auth_user", "VARCHAR(128) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "Printer", "auth_password", "VARCHAR(255) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "Printer", "is_online", "BOOLEAN NOT NULL DEFAULT TRUE")
        _safe_alter_table(session, "Printer", "online_changed_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "Printer", "mac_address", "VARCHAR(64) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "Printer", "address_book_sync", "JSONB")
        
        # Self-heal UserAccount table
        _safe_alter_table(session, "UserAccount", "password", "VARCHAR(128) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "UserAccount", "user_type", "VARCHAR(32) NOT NULL DEFAULT 'support'")
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_useraccount_user_type ON "UserAccount" (user_type);'))
        _safe_alter_table(session, "Lead", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "Lead" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        _safe_alter_table(session, "Workspace", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "Workspace" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        _safe_alter_table(session, "Location", "room", "VARCHAR(128)")
        _safe_alter_table(session, "Location", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "Location" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        _safe_alter_table(session, "Material", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "Material" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        session.execute(text(
            """
            UPDATE "UserAccount"
            SET user_type = CASE
                WHEN LOWER(COALESCE(role, '')) IN ('tech', 'technician', 'worker') THEN 'tech'
                ELSE 'support'
            END
            WHERE COALESCE(user_type, '') = ''
               OR LOWER(COALESCE(user_type, '')) NOT IN ('tech', 'support')
            """
        ))
        session.execute(text(
            """
            UPDATE "UserAccount"
            SET role = CASE
                WHEN LOWER(COALESCE(user_type, '')) = 'tech' THEN 'tech'
                ELSE 'support'
            END
            WHERE LOWER(COALESCE(role, '')) NOT IN ('tech', 'support')
            """
        ))
        session.execute(text('CREATE TABLE IF NOT EXISTS "UserWorkspace" ('
                             'id SERIAL PRIMARY KEY,'
                             'user_id INTEGER NOT NULL REFERENCES "UserAccount"(id) ON DELETE CASCADE,'
                             'workspace_id VARCHAR(64) NOT NULL REFERENCES "Workspace"(id) ON DELETE CASCADE,'
                             'created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),'
                             'updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),'
                             'CONSTRAINT uq_userworkspace_user_workspace UNIQUE (user_id, workspace_id)'
                             ');'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_userworkspace_user_id ON "UserWorkspace" (user_id);'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_userworkspace_workspace_id ON "UserWorkspace" (workspace_id);'))
        
        # Self-heal LanSite table
        _safe_alter_table(session, "LanSite", "fingerprint_signature", "TEXT")
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_lansite_fingerprint ON "LanSite" (lead, fingerprint_signature);'))
        
        # Self-heal AgentNode table
        _safe_alter_table(session, "AgentNode", "last_seen_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "AgentNode", "app_version", "VARCHAR(64) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "AgentNode", "run_mode", "VARCHAR(32) NOT NULL DEFAULT 'web'")
        _safe_alter_table(session, "AgentNode", "web_port", "INTEGER NOT NULL DEFAULT 9173")
        _safe_alter_table(session, "AgentNode", "ftp_ports", "TEXT NOT NULL DEFAULT ''")
        _safe_alter_table(session, "AgentNode", "is_online", "BOOLEAN NOT NULL DEFAULT TRUE")
        _safe_alter_table(session, "AgentNode", "online_changed_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "AgentNode", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "AgentNode" SET updated_at = COALESCE(last_seen_at, created_at, updated_at, NOW());'))
        _safe_alter_table(session, "AgentPresenceLog", "ftp_ports", "TEXT NOT NULL DEFAULT ''")
        _safe_alter_table(session, "AgentPresenceLog", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "AgentPresenceLog" SET updated_at = COALESCE(changed_at, last_seen_at, created_at, updated_at, NOW());'))
        session.execute(text('UPDATE "FtpControlCommand" SET created_at = COALESCE(requested_at, created_at, NOW()), updated_at = COALESCE(responded_at, requested_at, updated_at, NOW());'))
        _safe_alter_table(session, "PrinterEnableLog", "created_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "PrinterEnableLog", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "PrinterEnableLog" SET created_at = COALESCE(changed_at, created_at, NOW()), updated_at = COALESCE(changed_at, updated_at, NOW());'))
        _safe_alter_table(session, "PrinterOnlineLog", "created_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "PrinterOnlineLog", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('UPDATE "PrinterOnlineLog" SET created_at = COALESCE(changed_at, created_at, NOW()), updated_at = COALESCE(changed_at, updated_at, NOW());'))
        _safe_alter_table(session, "PrinterControlCommand", "created_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "PrinterControlCommand", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "PrinterControlCommand", "command_type", "VARCHAR(64) NOT NULL DEFAULT 'enable_disable'")
        _safe_alter_table(session, "PrinterControlCommand", "driver_brand", "VARCHAR(64) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "PrinterControlCommand", "driver_model", "VARCHAR(128) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "PrinterControlCommand", "driver_name", "VARCHAR(255) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "PrinterControlCommand", "driver_url", "TEXT NOT NULL DEFAULT ''")
        session.execute(text('UPDATE "PrinterControlCommand" SET created_at = COALESCE(requested_at, created_at, NOW()), updated_at = COALESCE(responded_at, requested_at, updated_at, NOW());'))
        # Self-heal CounterInfor / StatusInfor for dedupe + touch-updated flow
        _safe_alter_table(session, "CounterInfor", "mac_id", "VARCHAR(64) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "CounterInfor", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        _safe_alter_table(session, "StatusInfor", "mac_id", "VARCHAR(64) NOT NULL DEFAULT ''")
        _safe_alter_table(session, "StatusInfor", "updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_counterinfor_lead_lan_agent_ip_mac ON "CounterInfor" (lead, lan_uid, agent_uid, ip, mac_id);'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_statusinfor_lead_lan_agent_ip_mac ON "StatusInfor" (lead, lan_uid, agent_uid, ip, mac_id);'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_deviceinfor_lead_lan_mac ON "DeviceInfor" (lead, lan_uid, mac_id);'))

        # Seed demo user-workspace links for existing sample accounts so the
        # login workspace picker has data on fresh deployments.
        user_workspace_count = session.execute(select(func.count()).select_from(UserWorkspace)).scalar_one()
        if int(user_workspace_count or 0) == 0:
            demo_links = {
                "supplier1": ["ws-1"],
                "supplier2": ["ws-1", "ws-4"],
                "supplier3": ["ws-4", "ws-5", "ws-1"],
                "tech1": ["ws-1", "ws-2", "ws-3"],
                "tech2": ["ws-1", "ws-2"],
            }
            usernames = list(demo_links.keys())
            users = {
                row.username: row
                for row in session.execute(
                    select(UserAccount).where(UserAccount.lead == "default", UserAccount.username.in_(usernames))
                ).scalars().all()
            }
            workspace_ids = sorted({workspace_id for values in demo_links.values() for workspace_id in values})
            workspaces = {
                row.id: row
                for row in session.execute(
                    select(Workspace).where(Workspace.id.in_(workspace_ids))
                ).scalars().all()
            }
            for username, linked_workspace_ids in demo_links.items():
                user = users.get(username)
                if not user:
                    continue
                for workspace_id in linked_workspace_ids:
                    if workspace_id not in workspaces:
                        continue
                    session.add(UserWorkspace(user_id=user.id, workspace_id=workspace_id))
            session.commit()

        # Backfill presence history once for existing AgentNode rows so the
        # backend has a baseline history even before the first new heartbeat.
        stale_before = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_STALE_SECONDS)
        existing_presence_keys = {
            (lead, lan_uid, agent_uid)
            for lead, lan_uid, agent_uid in session.execute(
                select(AgentPresenceLog.lead, AgentPresenceLog.lan_uid, AgentPresenceLog.agent_uid)
            ).all()
        }
        agent_rows = session.execute(select(AgentNode)).scalars().all()
        now = datetime.now(timezone.utc)
        for agent in agent_rows:
            key = (_to_text(agent.lead), _to_text(agent.lan_uid), _to_text(agent.agent_uid))
            if key in existing_presence_keys:
                continue
            seen_at = agent.last_seen_at if agent.last_seen_at and agent.last_seen_at.tzinfo else (
                agent.last_seen_at.replace(tzinfo=timezone.utc) if agent.last_seen_at else None
            )
            current_online = bool(seen_at and seen_at >= stale_before)
            change_at = seen_at if current_online and seen_at else now
            agent.is_online = current_online
            agent.online_changed_at = change_at
            session.add(
                AgentPresenceLog(
                    lead=agent.lead,
                    lan_uid=agent.lan_uid,
                    agent_uid=agent.agent_uid,
                    hostname=agent.hostname or "",
                    local_ip=agent.local_ip or "",
                    local_mac=agent.local_mac or "",
                    app_version=agent.app_version or "",
                    run_mode=agent.run_mode or "web",
                    web_port=int(agent.web_port or 9173),
                    is_online=current_online,
                    ftp_sites=list(agent.ftp_sites or []),
                    changed_at=change_at,
                    last_seen_at=seen_at or now,
                )
            )
        session.commit()

    lead_key_map = cfg.lead_keys()

    @app.before_request
    def _before_request_log() -> None:
        g._req_started = time_module.perf_counter()

    @app.after_request
    def _after_request_log(response: Any) -> Any:
        try:
            path = request.path or ""
            if path.startswith("/api/"):
                elapsed_ms = int((time_module.perf_counter() - float(getattr(g, "_req_started", time_module.perf_counter()))) * 1000)
                LOGGER.info(
                    "api access method=%s path=%s status=%s ms=%s ip=%s",
                    request.method,
                    path,
                    response.status_code,
                    elapsed_ms,
                    request.remote_addr,
                )
        except Exception:  # noqa: BLE001
            pass
        return response


    # Register all routes from separated modules
    from auth_routes import register_auth_routes
    from public_core_routes import register_public_core_routes
    from public_device_routes import register_public_device_routes
    from agent_routes import register_agent_routes
    from lan_routes import register_lan_routes
    from task_routes import register_task_routes
    from admin_crm_routes import register_admin_crm_routes
    from admin_user_routes import register_admin_user_routes
    from polling_core_routes import register_polling_core_routes
    from polling_aux_routes import register_polling_aux_routes
    from device_core_routes import register_device_core_routes
    from device_detail_routes import register_device_detail_routes
    from scan_routes import register_scan_routes
    from counter_core_routes import register_counter_core_routes
    from infor_routes import register_infor_routes
    from email_routes import register_email_routes
    from ui_routes import register_ui_routes

    register_auth_routes(app, session_factory)
    register_public_core_routes(app, session_factory, lead_key_map)
    register_public_device_routes(app, session_factory)
    register_agent_routes(app, session_factory, lead_key_map)
    register_lan_routes(app, session_factory)
    register_task_routes(app, session_factory, lead_key_map)
    register_admin_crm_routes(app, session_factory)
    register_admin_user_routes(app, session_factory, lead_key_map)
    register_polling_core_routes(app, session_factory, lead_key_map)
    register_polling_aux_routes(app, session_factory, lead_key_map, drive_sync, cfg)
    register_device_core_routes(app, session_factory, lead_key_map)
    register_device_detail_routes(app, session_factory)
    register_scan_routes(app, session_factory)
    register_counter_core_routes(app, session_factory)
    register_infor_routes(app, session_factory)
    register_email_routes(app, session_factory, lead_key_map)
    register_ui_routes(app, session_factory)

    return app


if __name__ == '__main__':
    _configure_server_logging()
    config = ServerConfig()
    app = create_app()
    LOGGER.info('server start host=%s port=%s debug=%s', config.host, config.port, config.debug)
    app.run(host=config.host, port=config.port, debug=config.debug)
