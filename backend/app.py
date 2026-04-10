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
    FtpControlCommand,
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
)

LOGGER = logging.getLogger(__name__)
UI_TZ = timezone(timedelta(hours=7))
ONLINE_STALE_SECONDS = 300
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
            loaded = json.loads(AGENT_RELEASE_MANIFEST_FILE.read_text(encoding="utf-8"))
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


def _normalize_ftp_site_payload(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    name = _to_text(value.get("name")).strip()
    if not name:
        return None
    return {
        "name": name,
        "path": _to_text(value.get("path")),
        "port": _to_int(value.get("port")) or 0,
        "ftp_url": _to_text(value.get("ftp_url")),
        "ftp_user": _to_text(value.get("ftp_user")),
        "ftp_password": _to_text(value.get("ftp_password")),
    }


def _normalize_ftp_sites_payload(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    sites: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        normalized = _normalize_ftp_site_payload(item)
        if not normalized:
            continue
        key = normalized["name"].lower()
        if key in seen:
            continue
        seen.add(key)
        sites.append(normalized)
    return sorted(sites, key=lambda item: (int(item.get("port", 0) or 0), str(item.get("name", ""))))


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


def _agent_known_ftp_site_names(agent: AgentNode) -> set[str]:
    raw_sites = agent.ftp_sites if isinstance(agent.ftp_sites, list) else []
    names: set[str] = set()
    for site in raw_sites:
        normalized = _normalize_ftp_site_payload(site)
        if normalized:
            names.add(str(normalized["name"]).lower())
    return names


def _agent_ftp_site_by_name(agent: AgentNode, site_name: str) -> dict[str, Any] | None:
    target = _sanitize_ftp_name(site_name).lower()
    if not target:
        return None
    raw_sites = agent.ftp_sites if isinstance(agent.ftp_sites, list) else []
    for site in raw_sites:
        normalized = _normalize_ftp_site_payload(site)
        if not normalized:
            continue
        if str(normalized.get("name", "")).strip().lower() == target:
            return normalized
    return None


def _agent_ftp_site_by_port(agent: AgentNode, port: int) -> dict[str, Any] | None:
    if int(port or 0) <= 0:
        return None
    raw_sites = agent.ftp_sites if isinstance(agent.ftp_sites, list) else []
    for site in raw_sites:
        normalized = _normalize_ftp_site_payload(site)
        if not normalized:
            continue
        if int(normalized.get("port", 0) or 0) == int(port):
            return normalized
    return None


def _agent_used_ftp_ports(agent: AgentNode) -> set[int]:
    ports: set[int] = set()
    raw_sites = agent.ftp_sites if isinstance(agent.ftp_sites, list) else []
    for site in raw_sites:
        normalized = _normalize_ftp_site_payload(site)
        if not normalized:
            continue
        port = int(normalized.get("port", 0) or 0)
        if port > 0:
            ports.add(port)
    raw_ports = _to_text(getattr(agent, "ftp_ports", ""))
    for item in raw_ports.replace("\n", ",").replace(";", ",").split(","):
        port = _to_int(item)
        if int(port or 0) > 0:
            ports.add(int(port))
    return ports


def _next_available_agent_ftp_port(agent: AgentNode, preferred_port: int = 2121) -> int:
    port = max(1, int(preferred_port or 2121))
    used = _agent_used_ftp_ports(agent)
    while port in used and port < 65535:
        port += 1
    return port


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
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_user VARCHAR(128) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_password VARCHAR(255) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT TRUE;'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS online_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS mac_address VARCHAR(64) NOT NULL DEFAULT \'\';'))
        
        # Self-heal UserAccount table
        session.execute(text('ALTER TABLE "UserAccount" ADD COLUMN IF NOT EXISTS password VARCHAR(128) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "UserAccount" ADD COLUMN IF NOT EXISTS user_type VARCHAR(32) NOT NULL DEFAULT \'support\';'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_useraccount_user_type ON "UserAccount" (user_type);'))
        session.execute(text('ALTER TABLE "Lead" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "Lead" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        session.execute(text('ALTER TABLE "Workspace" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "Workspace" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        session.execute(text('ALTER TABLE "Location" ADD COLUMN IF NOT EXISTS room VARCHAR(128);'))
        session.execute(text('ALTER TABLE "Location" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "Location" SET updated_at = COALESCE(updated_at, created_at, NOW());'))
        session.execute(text('ALTER TABLE "Material" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
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
        session.execute(text('ALTER TABLE "LanSite" ADD COLUMN IF NOT EXISTS fingerprint_signature TEXT;'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_lansite_fingerprint ON "LanSite" (lead, fingerprint_signature);'))
        
        # Self-heal AgentNode table
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS app_version VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS run_mode VARCHAR(32) NOT NULL DEFAULT \'web\';'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS web_port INTEGER NOT NULL DEFAULT 9173;'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS ftp_ports TEXT NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS ftp_sites JSONB NOT NULL DEFAULT \'[]\'::jsonb;'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT TRUE;'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS online_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "AgentNode" SET updated_at = COALESCE(last_seen_at, created_at, updated_at, NOW());'))
        session.execute(text('ALTER TABLE "AgentPresenceLog" ADD COLUMN IF NOT EXISTS ftp_ports TEXT NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "AgentPresenceLog" ADD COLUMN IF NOT EXISTS ftp_sites JSONB NOT NULL DEFAULT \'[]\'::jsonb;'))
        session.execute(text('ALTER TABLE "AgentPresenceLog" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "AgentPresenceLog" SET updated_at = COALESCE(changed_at, last_seen_at, created_at, updated_at, NOW());'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS printer_mac_id VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS printer_ip VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS printer_name VARCHAR(255) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS ftp_user VARCHAR(128) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS ftp_password VARCHAR(255) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS printer_auth_user VARCHAR(128) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS printer_auth_password VARCHAR(255) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "FtpControlCommand" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "FtpControlCommand" SET created_at = COALESCE(requested_at, created_at, NOW()), updated_at = COALESCE(responded_at, requested_at, updated_at, NOW());'))
        session.execute(text('ALTER TABLE "PrinterEnableLog" ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "PrinterEnableLog" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "PrinterEnableLog" SET created_at = COALESCE(changed_at, created_at, NOW()), updated_at = COALESCE(changed_at, updated_at, NOW());'))
        session.execute(text('ALTER TABLE "PrinterOnlineLog" ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "PrinterOnlineLog" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "PrinterOnlineLog" SET created_at = COALESCE(changed_at, created_at, NOW()), updated_at = COALESCE(changed_at, updated_at, NOW());'))
        session.execute(text('ALTER TABLE "PrinterControlCommand" ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "PrinterControlCommand" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('UPDATE "PrinterControlCommand" SET created_at = COALESCE(requested_at, created_at, NOW()), updated_at = COALESCE(responded_at, requested_at, updated_at, NOW());'))
        # Self-heal CounterInfor / StatusInfor for dedupe + touch-updated flow
        session.execute(text('ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS mac_id VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS mac_id VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
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

    @app.get("/")
    def index() -> Any:
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard() -> Any:
        return render_template("dashboard.html", active_tab="dashboard", page_title="Configuration")

    @app.get("/configs")
    def configs_page() -> Any:
        return render_template("configs.html", active_tab="configs", page_title="Display Configs")

    @app.get("/devices")
    def devices_page() -> Any:
        return redirect(url_for("infor_page"))

    @app.get("/infor")
    def infor_page() -> Any:
        return render_template("devices.html", active_tab="infor", page_title="Infor")

    @app.get("/api-docs")
    def api_docs_page() -> Any:
        markdown_text = ""
        try:
            markdown_text = PUBLIC_API_FILE.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Cannot read PUBLIC_API.md: %s", exc)
        return render_template(
            "api_docs.html",
            active_tab="api_docs",
            page_title="Public API",
            api_markdown=markdown_text,
        )

    @app.get("/lan-sites")
    def lan_sites_page() -> Any:
        return render_template("lan_sites.html", active_tab="lan_sites", page_title="Lan Network")

    @app.get("/agents")
    def agents_page() -> Any:
        manifest = _load_agent_release_manifest()
        version = _to_text(manifest.get("version")) or "unknown"
        published_at = _to_text(manifest.get("published_at"))
        release_date = ""
        if published_at:
            release_date = _format_agents_datetime_ui(_parse_timestamp(published_at))
        size_bytes = int(manifest.get("size") or 0)
        size_mb = f"{size_bytes / (1024 * 1024):.1f} MB" if size_bytes > 0 else "-"
        return render_template(
            "agents.html",
            active_tab="agents",
            page_title="Agents",
            agent_release={
                "version": version,
                "release_date": release_date,
                "size_label": size_mb,
                "download_url": _to_text(manifest.get("download_url")) or "/static/releases/printagent.exe",
                "notes": _to_text(manifest.get("notes")),
                "channel": _to_text(manifest.get("channel")) or "stable",
            },
        )

    @app.get("/api/lan-sites")
    def list_lan_sites() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        name = _to_text(request.args.get("name"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(LanSite).order_by(LanSite.created_at.desc())
            if lead:
                stmt = stmt.where(LanSite.lead == lead)
            if lan_uid:
                stmt = stmt.where(LanSite.lan_uid.ilike(f"%{lan_uid}%"))
            if name:
                stmt = stmt.where(LanSite.lan_name.ilike(f"%{name}%"))
            stmt = _apply_date_filters(stmt, LanSite, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({
                "rows": [
                    {
                        "lead": r.lead,
                        "lan_uid": r.lan_uid,
                        "lan_name": r.lan_name,
                        "subnet_cidr": r.subnet_cidr,
                        "gateway_ip": r.gateway_ip,
                        "gateway_mac": r.gateway_mac,
                        "fingerprint_signature": r.fingerprint_signature,
                        **_serialize_audit_payload(r.created_at, r.updated_at),
                    }
                    for r in rows
                ]
            })

    @app.delete("/api/lan-sites/<string:lan_uid>")
    def delete_lan_site(lan_uid: str) -> Any:
        lead = _to_text(request.args.get("lead"))
        with session_factory() as session:
            stmt = select(LanSite).where(LanSite.lan_uid == lan_uid)
            if lead:
                stmt = stmt.where(LanSite.lead == lead)
            lan = session.execute(stmt).scalar_one_or_none()
            if not lan:
                return jsonify({"ok": False, "error": "LAN Site not found"}), 404
            session.delete(lan)
            session.commit()
        return jsonify({"ok": True, "lan_uid": lan_uid})

    @app.get("/api/agents")
    def list_agents() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        status = _to_text(request.args.get("status")).lower()
        stale_seconds = _to_int(request.args.get("stale_seconds")) or ONLINE_STALE_SECONDS
        stale_seconds = max(30, stale_seconds)

        with session_factory() as session:
            _refresh_stale_agent_offline(session=session, lead=lead, lan_uid=lan_uid, agent_uid=agent_uid, stale_seconds=stale_seconds)
            session.commit()
            stmt = (
                select(AgentNode, LanSite.lan_name, LanSite.subnet_cidr, LanSite.gateway_ip)
                .join(LanSite, (AgentNode.lead == LanSite.lead) & (AgentNode.lan_uid == LanSite.lan_uid), isouter=True)
                .order_by(AgentNode.last_seen_at.desc(), AgentNode.id.desc())
            )
            if lead:
                stmt = stmt.where(AgentNode.lead == lead)
            if lan_uid:
                stmt = stmt.where(AgentNode.lan_uid.ilike(f"%{lan_uid}%"))
            if agent_uid:
                stmt = stmt.where(AgentNode.agent_uid.ilike(f"%{agent_uid}%"))
            rows = session.execute(stmt).all()

            printer_stmt = select(
                Printer.lead,
                Printer.lan_uid,
                Printer.agent_uid,
                Printer.printer_name,
                Printer.ip,
                Printer.mac_address,
                Printer.auth_user,
                Printer.auth_password,
            )
            if lead:
                printer_stmt = printer_stmt.where(Printer.lead == lead)
            if lan_uid:
                printer_stmt = printer_stmt.where(Printer.lan_uid.ilike(f"%{lan_uid}%"))
            printer_rows = session.execute(printer_stmt).all()
            printer_ips_by_lan: dict[tuple[str, str], list[str]] = {}
            printers_by_lan: dict[tuple[str, str], list[dict[str, Any]]] = {}
            seen_printers_by_lan: dict[tuple[str, str], set[tuple[str, str, str, str]]] = {}
            printers_by_agent: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
            seen_printers_by_agent: dict[tuple[str, str, str], set[tuple[str, str, str]]] = {}
            for p_lead, p_lan_uid, p_agent_uid, p_name, p_ip, p_mac, p_auth_user, p_auth_password in printer_rows:
                key = (_to_text(p_lead), _to_text(p_lan_uid))
                ip_text = _to_text(p_ip)
                mac_text = _normalize_mac(p_mac)
                if not ip_text:
                    ip_text = ""
                if ip_text:
                    bucket = printer_ips_by_lan.setdefault(key, [])
                    if ip_text not in bucket:
                        bucket.append(ip_text)
                lan_printer_row = {
                    "printer_name": _to_text(p_name),
                    "ip": ip_text,
                    "mac_id": mac_text,
                    "agent_uid": _to_text(p_agent_uid),
                    "auth_configured": bool(_to_text(p_auth_user) and _to_text(p_auth_password)),
                }
                lan_dedupe_key = (
                    _to_text(lan_printer_row.get("agent_uid")),
                    _to_text(lan_printer_row.get("mac_id")),
                    _to_text(lan_printer_row.get("ip")),
                    _to_text(lan_printer_row.get("printer_name")),
                )
                seen_lan_bucket = seen_printers_by_lan.setdefault(key, set())
                if lan_dedupe_key not in seen_lan_bucket:
                    seen_lan_bucket.add(lan_dedupe_key)
                    printers_by_lan.setdefault(key, []).append(lan_printer_row)
                agent_key = (_to_text(p_lead), _to_text(p_lan_uid), _to_text(p_agent_uid))
                dedupe_key = (mac_text, ip_text, _to_text(p_name))
                seen_bucket = seen_printers_by_agent.setdefault(agent_key, set())
                if dedupe_key in seen_bucket:
                    continue
                seen_bucket.add(dedupe_key)
                printers_by_agent.setdefault(agent_key, []).append(
                    {
                        "printer_name": _to_text(p_name),
                        "ip": ip_text,
                        "mac_id": mac_text,
                        "auth_configured": bool(_to_text(p_auth_user) and _to_text(p_auth_password)),
                    }
                )
            for key in printer_ips_by_lan:
                printer_ips_by_lan[key].sort()
            for key in printers_by_lan:
                printers_by_lan[key].sort(
                    key=lambda item: (
                        _to_text(item.get("printer_name")),
                        _to_text(item.get("ip")),
                        _to_text(item.get("mac_id")),
                        _to_text(item.get("agent_uid")),
                    )
                )
            for key in printers_by_agent:
                printers_by_agent[key].sort(
                    key=lambda item: (
                        _to_text(item.get("printer_name")),
                        _to_text(item.get("ip")),
                        _to_text(item.get("mac_id")),
                    )
                )

        result_rows: list[dict[str, Any]] = []
        for agent, lan_name, subnet_cidr, gateway_ip in rows:
            last_seen = agent.last_seen_at if agent.last_seen_at and agent.last_seen_at.tzinfo else (
                agent.last_seen_at.replace(tzinfo=timezone.utc) if agent.last_seen_at else None
            )
            online_changed_at = agent.online_changed_at if agent.online_changed_at and agent.online_changed_at.tzinfo else (
                agent.online_changed_at.replace(tzinfo=timezone.utc) if agent.online_changed_at else None
            )
            is_online = bool(agent.is_online)
            if status == "online" and not is_online:
                continue
            if status == "offline" and is_online:
                continue
            port = int(agent.web_port or 9173)
            result_rows.append(
                {
                    "id": int(agent.id),
                    "lead": agent.lead,
                    "lan_uid": agent.lan_uid,
                    "lan_name": _to_text(lan_name),
                    "subnet_cidr": _to_text(subnet_cidr),
                    "gateway_ip": _to_text(gateway_ip),
                    "agent_uid": agent.agent_uid,
                    "hostname": agent.hostname,
                    "local_ip": agent.local_ip,
                    "local_mac": agent.local_mac,
                    "app_version": agent.app_version,
                    "run_mode": agent.run_mode or "web",
                    "web_port": port,
                    "ftp_ports": _to_text(agent.ftp_ports),
                    "ftp_sites": _normalize_ftp_sites_payload(agent.ftp_sites),
                    "printer_ips": printer_ips_by_lan.get((_to_text(agent.lead), _to_text(agent.lan_uid)), []),
                    "printers": printers_by_agent.get((_to_text(agent.lead), _to_text(agent.lan_uid), _to_text(agent.agent_uid)), []),
                    "lan_printers": printers_by_lan.get((_to_text(agent.lead), _to_text(agent.lan_uid)), []),
                    "last_seen_at": _format_agents_datetime_ui(last_seen),
                    "online_changed_at": _format_agents_datetime_ui(online_changed_at),
                    "is_online": is_online,
                    "localhost_url": f"http://127.0.0.1:{port}",
                    "ftp_page_url": f"http://127.0.0.1:{port}/ftp",
                    **_serialize_audit_payload_agents(agent.created_at, agent.updated_at),
                }
            )
        return jsonify({"rows": result_rows, "stale_seconds": stale_seconds})

    @app.delete("/api/agents/<int:agent_id>")
    def delete_agent(agent_id: int) -> Any:
        lead = _to_text(request.args.get("lead"))
        with session_factory() as session:
            stmt = select(AgentNode).where(AgentNode.id == agent_id)
            if lead:
                stmt = stmt.where(AgentNode.lead == lead)
            agent = session.execute(stmt).scalar_one_or_none()
            if agent is None:
                return jsonify({"ok": False, "error": "Agent not found"}), 404
            if bool(agent.is_online):
                return jsonify({"ok": False, "error": "Agent is online; stop it before deleting"}), 409

            session.delete(agent)
            session.commit()
        LOGGER.info("agent deleted: id=%s lead=%s", agent_id, lead or "-")
        return jsonify({"ok": True, "agent_id": agent_id})

    @app.post("/api/agents/<int:agent_id>/ftp-sites")
    def queue_agent_ftp_site(agent_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        with session_factory() as session:
            agent = session.get(AgentNode, int(agent_id))
            if agent is None:
                return jsonify({"ok": False, "error": "Agent not found"}), 404
            payload, status = _queue_scan_folder_command_for_agent(
                session,
                agent=agent,
                body=body,
            )
        return jsonify(payload), status

    @app.get("/api/agents/history")
    def list_agent_history() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        status = _to_text(request.args.get("status")).lower()
        limit = _to_int(request.args.get("limit")) or 500
        limit = max(1, min(limit, 5000))
        with session_factory() as session:
            stmt = select(AgentPresenceLog).order_by(AgentPresenceLog.changed_at.desc(), AgentPresenceLog.id.desc())
            if lead:
                stmt = stmt.where(AgentPresenceLog.lead == lead)
            if lan_uid:
                stmt = stmt.where(AgentPresenceLog.lan_uid.ilike(f"%{lan_uid}%"))
            if agent_uid:
                stmt = stmt.where(AgentPresenceLog.agent_uid.ilike(f"%{agent_uid}%"))
            if status == "online":
                stmt = stmt.where(AgentPresenceLog.is_online.is_(True))
            elif status == "offline":
                stmt = stmt.where(AgentPresenceLog.is_online.is_(False))
            rows = session.execute(stmt.limit(limit)).scalars().all()
        return jsonify(
            {
                "rows": [
                    {
                        "id": int(row.id),
                        "lead": row.lead,
                        "lan_uid": row.lan_uid,
                        "agent_uid": row.agent_uid,
                        "hostname": row.hostname,
                        "local_ip": row.local_ip,
                        "local_mac": row.local_mac,
                        "app_version": row.app_version,
                        "run_mode": row.run_mode,
                        "web_port": int(row.web_port or 9173),
                        "ftp_ports": row.ftp_ports,
                        "ftp_sites": _normalize_ftp_sites_payload(row.ftp_sites),
                        "is_online": bool(row.is_online),
                        "changed_at": _format_agents_datetime_ui(row.changed_at),
                        "last_seen_at": _format_agents_datetime_ui(row.last_seen_at),
                        **_serialize_audit_payload_agents(row.created_at, row.updated_at),
                    }
                    for row in rows
                ],
                "limit": limit,
            }
        )

    @app.get("/api/agents/history/export")
    def export_agent_history() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        status = _to_text(request.args.get("status")).lower()
        limit = _to_int(request.args.get("limit")) or 5000
        limit = max(1, min(limit, 5000))
        with session_factory() as session:
            stmt = select(AgentPresenceLog).order_by(AgentPresenceLog.changed_at.desc(), AgentPresenceLog.id.desc())
            if lead:
                stmt = stmt.where(AgentPresenceLog.lead == lead)
            if lan_uid:
                stmt = stmt.where(AgentPresenceLog.lan_uid.ilike(f"%{lan_uid}%"))
            if agent_uid:
                stmt = stmt.where(AgentPresenceLog.agent_uid.ilike(f"%{agent_uid}%"))
            if status == "online":
                stmt = stmt.where(AgentPresenceLog.is_online.is_(True))
            elif status == "offline":
                stmt = stmt.where(AgentPresenceLog.is_online.is_(False))
            rows = session.execute(stmt.limit(limit)).scalars().all()

        payload = {
            "ok": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "limit": limit,
            "rows": [
                {
                    "id": int(row.id),
                    "lead": row.lead,
                    "lan_uid": row.lan_uid,
                    "agent_uid": row.agent_uid,
                    "hostname": row.hostname,
                    "local_ip": row.local_ip,
                    "local_mac": row.local_mac,
                    "app_version": row.app_version,
                    "run_mode": row.run_mode,
                    "web_port": int(row.web_port or 9173),
                    "ftp_ports": row.ftp_ports,
                    "is_online": bool(row.is_online),
                    "changed_at": _format_agents_datetime_ui(row.changed_at),
                    "last_seen_at": _format_agents_datetime_ui(row.last_seen_at),
                    **_serialize_audit_payload_agents(row.created_at, row.updated_at),
                }
                for row in rows
            ],
        }
        filename = f"agent-presence-history-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
        response = jsonify(payload)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response

    @app.get("/counter")
    def counter_page() -> Any:
        return render_template("counter.html", active_tab="counter", page_title="Counter Timelapse")

    @app.get("/status")
    def status_page() -> Any:
        return render_template("status.html", active_tab="status", page_title="Status Timelapse")

    @app.get("/heatmap")
    def heatmap_page() -> Any:
        return render_template("heatmap.html", active_tab="heatmap", page_title="Counter Heatmap")

    @app.get("/health")
    def health() -> Any:
        return jsonify({"ok": True, "service": "GoPrinx Polling Server"})

    @app.get("/api/leads")
    def list_leads() -> Any:
        with session_factory() as session:
            leads: set[str] = set()
            for model in (LanSite, CounterInfor, StatusInfor, AgentNode, Printer):
                values = session.execute(select(func.distinct(model.lead))).scalars().all()
                for value in values:
                    text = _to_text(value)
                    if text:
                        leads.add(text)
        return jsonify({"leads": sorted(leads, key=str.lower)})

    @app.post("/api/agent/register")
    def register_agent() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("register: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("register: unauthorized lead=%s ip=%s", _to_text(body.get("lead")), request.remote_addr)
            return auth_error

        with session_factory() as session:
            lan_uid, fingerprint = _resolve_lan_uid_with_session(session, lead, body)
            agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
            lan_name = _to_text(body.get("lan_name"))
            subnet_cidr = _to_text(body.get("subnet_cidr"))
            gateway_ip = _to_text(body.get("gateway_ip"))
            gateway_mac = _to_text(body.get("gateway_mac"))
            hostname = _to_text(body.get("hostname"))
            local_ip = _to_text(body.get("local_ip"))
            local_mac = _to_text(body.get("local_mac"))
            app_version = _to_text(body.get("app_version"))
            run_mode = _to_text(body.get("run_mode")) or "web"
            web_port = _to_int(body.get("web_port")) or 9173
            ftp_ports = _to_text(body.get("ftp_ports"))
            ftp_sites = _normalize_ftp_sites_payload(body.get("ftp_sites"))
            _refresh_stale_agent_offline(session=session, lead=lead, stale_seconds=ONLINE_STALE_SECONDS)
            lan_uid = _upsert_lan_and_agent(
                session=session,
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                lan_name=lan_name,
                subnet_cidr=subnet_cidr,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
                app_version=app_version,
                run_mode=run_mode,
                web_port=web_port,
                ftp_ports=ftp_ports,
                ftp_sites=ftp_sites,
                fingerprint_signature=fingerprint,
            )
            session.commit()
        LOGGER.info("register: lead=%s lan_uid=%s agent_uid=%s hostname=%s", lead, lan_uid, agent_uid, hostname)

        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
            }
        )

    @app.get("/api/agent/release")
    def get_agent_release() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error

        current_version = _to_text(request.args.get("current_version"))
        current_sha256 = _to_text(request.args.get("current_sha256")).lower()
        manifest = _load_agent_release_manifest()
        version = _to_text(manifest.get("version"))
        sha256 = _to_text(manifest.get("sha256")).lower()
        if sha256 and current_sha256:
            update_available = sha256 != current_sha256
        else:
            update_available = _is_newer_version(version, current_version)
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "version": version,
                "download_url": _to_text(manifest.get("download_url")),
                "sha256": sha256,
                "size": int(manifest.get("size") or 0),
                "published_at": _to_text(manifest.get("published_at")),
                "notes": _to_text(manifest.get("notes")),
                "mandatory": bool(manifest.get("mandatory", False)),
                "channel": _to_text(manifest.get("channel")),
                "update_available": update_available,
            }
        )

    @app.post("/api/agent/resolve-lan")
    def resolve_lan_by_mac() -> Any:
        """
        Return the deterministic LAN UID derived from lead + gateway MAC +
        gateway IP.

        Request body:
            {
                "lead": "abc123",
                "subnet": "192.168.1.0/24",
                "gateway_ip": "192.168.1.1",
                "gateway_mac": "AA:BB:CC:DD:EE:FF"
            }

        Response:
            { "ok": true, "lan_uid": "default_AA_BB_CC_DD_EE_FF_192_168_1_1" }
        """
        body = request.get_json(silent=True) or {}
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead(body, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error

        with session_factory() as session:
            lan_uid, fingerprint = _resolve_lan_uid_with_session(session, lead, body)
        if not lan_uid:
            return jsonify({"ok": True, "lan_uid": None, "reason": "no_network_identity"})
        derived_lan_uid = _resolve_lan_uid_from_body(body)

        LOGGER.info(
            "resolve-lan: lead=%s gateway_ip=%s gateway_mac=%s -> lan_uid=%s",
            lead,
            _normalize_ipv4(_to_text(body.get("gateway_ip"))),
            _normalize_mac(_to_text(body.get("gateway_mac"))),
            lan_uid,
        )
        return jsonify(
            {
                "ok": True,
                "lan_uid": lan_uid,
                "fingerprint_signature": fingerprint,
                "reason": "remapped" if lan_uid != derived_lan_uid else "derived",
            }
        )

    @app.get("/api/dashboard/summary")
    def dashboard_summary() -> Any:
        lead = _to_text(request.args.get("lead"))
        ip = _to_text(request.args.get("ip"))
        printer_name = _to_text(request.args.get("printer_name"))
        printer_type = _to_text(request.args.get("printer_type")).lower()
        time_scope = _to_text(request.args.get("time_scope")) or "month"
        datetime_from = _to_text(request.args.get("datetime_from"))
        datetime_to = _to_text(request.args.get("datetime_to"))
        favorite_only = _to_text(request.args.get("favorite")).lower() in {"1", "true", "yes", "on"}
        with session_factory() as session:
            counter_count_stmt = _apply_common_filters(select(func.count()).select_from(CounterInfor), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
            status_count_stmt = _apply_common_filters(select(func.count()).select_from(StatusInfor), StatusInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
            lead_count_stmt = _apply_common_filters(select(func.count(func.distinct(CounterInfor.lead))), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
            printer_count_stmt = _apply_common_filters(select(func.count(func.distinct(CounterInfor.ip))), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
            latest_counter_stmt = _apply_common_filters(select(func.max(CounterInfor.timestamp)), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
            latest_status_stmt = _apply_common_filters(select(func.max(StatusInfor.timestamp)), StatusInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)

            counter_count = session.scalar(counter_count_stmt) or 0
            status_count = session.scalar(status_count_stmt) or 0
            lead_count = session.scalar(lead_count_stmt) or 0
            printer_count = session.scalar(printer_count_stmt) or 0
            latest_counter = session.scalar(latest_counter_stmt)
            latest_status = session.scalar(latest_status_stmt)

            latest_rows_stmt = _apply_common_filters(
                select(CounterInfor).order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc()),
                CounterInfor,
                lead,
                ip,
                printer_name,
                printer_type,
                time_scope,
                favorite_only,
                datetime_from,
                datetime_to,
            )
            latest_rows = session.execute(latest_rows_stmt).scalars().all()
            latest_by_printer: dict[tuple[str, str, str], CounterInfor] = {}
            for row in latest_rows:
                key = (row.lead, row.lan_uid, row.ip)
                if key in latest_by_printer:
                    continue
                latest_by_printer[key] = row

            baseline_map: dict[tuple[str, str, str], dict[str, Any]] = {}
            if latest_by_printer:
                leads = sorted({k[0] for k in latest_by_printer})
                lans = sorted({k[1] for k in latest_by_printer})
                ips = sorted({k[2] for k in latest_by_printer})
                baseline_rows = session.execute(
                    select(CounterBaseline).where(
                        CounterBaseline.lead.in_(leads),
                        CounterBaseline.lan_uid.in_(lans),
                        CounterBaseline.ip.in_(ips),
                    )
                ).scalars().all()
                for item in baseline_rows:
                    baseline_map[(item.lead, item.lan_uid, item.ip)] = item.raw_payload if isinstance(item.raw_payload, dict) else {}

            latest_totals = {"total": 0, "copier_bw": 0, "printer_bw": 0, "scanner_send_bw": 0, "scanner_send_color": 0, "a3_dlt": 0, "duplex": 0}
            for key, row in latest_by_printer.items():
                base = baseline_map.get(key, {})
                latest_totals["total"] += _apply_baseline(row.total, base, "total") or 0
                latest_totals["copier_bw"] += _apply_baseline(row.copier_bw, base, "copier_bw") or 0
                latest_totals["printer_bw"] += _apply_baseline(row.printer_bw, base, "printer_bw") or 0
                latest_totals["scanner_send_bw"] += _apply_baseline(row.scanner_send_bw, base, "scanner_send_bw") or 0
                latest_totals["scanner_send_color"] += _apply_baseline(row.scanner_send_color, base, "scanner_send_color") or 0
                latest_totals["a3_dlt"] += _apply_baseline(row.a3_dlt, base, "a3_dlt") or 0
                latest_totals["duplex"] += _apply_baseline(row.duplex, base, "duplex") or 0

            trend_start = _parse_query_datetime(datetime_from) or _time_scope_start(time_scope) or (datetime.now(timezone.utc) - timedelta(days=30))
            trend_end = _parse_query_datetime(datetime_to, end_of_minute=True)
            trend_base = select(CounterInfor).where(CounterInfor.timestamp >= trend_start)
            if trend_end is not None:
                trend_base = trend_base.where(CounterInfor.timestamp <= trend_end)
            trend_stmt = _apply_common_filters(
                trend_base.order_by(CounterInfor.timestamp.asc(), CounterInfor.id.asc()),
                CounterInfor,
                lead,
                ip,
                printer_name,
                printer_type,
                "",
                favorite_only,
                datetime_from,
                datetime_to,
            )
            trend_rows = session.execute(trend_stmt).scalars().all()
            day_printer_latest: dict[tuple[str, str], CounterInfor] = {}
            for row in trend_rows:
                day_key = row.timestamp.astimezone(timezone.utc).date().isoformat()
                key = (day_key, row.ip)
                day_printer_latest[key] = row
            day_total: dict[str, int] = {}
            for (day_key, _), row in day_printer_latest.items():
                base = baseline_map.get((row.lead, row.lan_uid, row.ip), {})
                abs_total = _apply_baseline(row.total, base, "total") or 0
                day_total[day_key] = day_total.get(day_key, 0) + abs_total
            labels = sorted(day_total.keys())
            values = [day_total[k] for k in labels]

            now_utc = datetime.now(timezone.utc)
            day_from = now_utc - timedelta(days=1)
            month_from = now_utc - timedelta(days=30)
            day_rows_stmt = _apply_common_filters(
                select(CounterInfor).where(CounterInfor.timestamp >= day_from).order_by(CounterInfor.timestamp.asc(), CounterInfor.id.asc()),
                CounterInfor,
                lead,
                ip,
                printer_name,
                printer_type,
                "",
                favorite_only,
                datetime_from,
                datetime_to,
            )
            month_rows_stmt = _apply_common_filters(
                select(CounterInfor).where(CounterInfor.timestamp >= month_from).order_by(CounterInfor.timestamp.asc(), CounterInfor.id.asc()),
                CounterInfor,
                lead,
                ip,
                printer_name,
                printer_type,
                "",
                favorite_only,
                datetime_from,
                datetime_to,
            )
            day_rows = session.execute(day_rows_stmt).scalars().all()
            month_rows = session.execute(month_rows_stmt).scalars().all()

            hourly_latest: dict[tuple[str, str], CounterInfor] = {}
            for row in day_rows:
                local = row.timestamp.astimezone(UI_TZ)
                hour_key = local.strftime("%Y-%m-%d %H:00")
                hourly_latest[(hour_key, row.ip)] = row
            hourly_total: dict[str, int] = {}
            hourly_a3: dict[str, int] = {}
            hourly_a4: dict[str, int] = {}
            for (hour_key, _), row in hourly_latest.items():
                base = baseline_map.get((row.lead, row.lan_uid, row.ip), {})
                abs_total = _apply_baseline(row.total, base, "total") or 0
                abs_a3 = _apply_baseline(row.a3_dlt, base, "a3_dlt") or 0
                abs_a4 = max(abs_total - abs_a3, 0)
                hourly_total[hour_key] = hourly_total.get(hour_key, 0) + abs_total
                hourly_a3[hour_key] = hourly_a3.get(hour_key, 0) + abs_a3
                hourly_a4[hour_key] = hourly_a4.get(hour_key, 0) + abs_a4

            daily_latest: dict[tuple[str, str], CounterInfor] = {}
            for row in month_rows:
                local = row.timestamp.astimezone(UI_TZ)
                day_key = local.strftime("%Y-%m-%d")
                daily_latest[(day_key, row.ip)] = row
            daily_total: dict[str, int] = {}
            daily_copier: dict[str, int] = {}
            daily_printer: dict[str, int] = {}
            for (day_key, _), row in daily_latest.items():
                base = baseline_map.get((row.lead, row.lan_uid, row.ip), {})
                daily_total[day_key] = daily_total.get(day_key, 0) + (_apply_baseline(row.total, base, "total") or 0)
                daily_copier[day_key] = daily_copier.get(day_key, 0) + (_apply_baseline(row.copier_bw, base, "copier_bw") or 0)
                daily_printer[day_key] = daily_printer.get(day_key, 0) + (_apply_baseline(row.printer_bw, base, "printer_bw") or 0)

            latest_counter_row = session.execute(
                _apply_common_filters(
                    select(CounterInfor).order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc()).limit(1),
                    CounterInfor,
                    lead,
                    ip,
                    printer_name,
                    printer_type,
                    time_scope,
                    favorite_only,
                    datetime_from,
                    datetime_to,
                )
            ).scalar_one_or_none()
            latest_status_row = session.execute(
                _apply_common_filters(
                    select(StatusInfor).order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc()).limit(1),
                    StatusInfor,
                    lead,
                    ip,
                    printer_name,
                    printer_type,
                    time_scope,
                    favorite_only,
                    datetime_from,
                    datetime_to,
                )
            ).scalar_one_or_none()

            a3 = max(int(latest_totals["a3_dlt"]), 0)
            total_now = max(int(latest_totals["total"]), 0)
            a4 = max(total_now - a3, 0)
            duplex_now = max(int(latest_totals["duplex"]), 0)
            single_side = max(a4 - duplex_now, 0)
            printer_count_used = max(len(latest_by_printer), 1)
            avg_values = {
                "avg_total": total_now / printer_count_used,
                "avg_copier": latest_totals["copier_bw"] / printer_count_used,
                "avg_printer": latest_totals["printer_bw"] / printer_count_used,
                "avg_scan_bw": latest_totals["scanner_send_bw"] / printer_count_used,
                "avg_scan_color": latest_totals["scanner_send_color"] / printer_count_used,
                "avg_a3": a3 / printer_count_used,
                "avg_duplex": duplex_now / printer_count_used,
            }
        return jsonify(
            {
                "counter_rows": int(counter_count),
                "status_rows": int(status_count),
                "leads": int(lead_count),
                "printers": int(printer_count),
                "latest_counter_at": latest_counter.isoformat() if latest_counter else "",
                "latest_status_at": latest_status.isoformat() if latest_status else "",
                "latest_totals": latest_totals,
                "latest_counter_info": {
                    "timestamp": latest_counter_row.timestamp.isoformat() if latest_counter_row else "",
                    "printer_name": latest_counter_row.printer_name if latest_counter_row else "",
                    "ip": latest_counter_row.ip if latest_counter_row else "",
                    "begin_record_id": latest_counter_row.begin_record_id if latest_counter_row else None,
                },
                "latest_status_info": {
                    "timestamp": latest_status_row.timestamp.isoformat() if latest_status_row else "",
                    "printer_name": latest_status_row.printer_name if latest_status_row else "",
                    "ip": latest_status_row.ip if latest_status_row else "",
                    "system_status": latest_status_row.system_status if latest_status_row else "",
                    "begin_record_id": latest_status_row.begin_record_id if latest_status_row else None,
                },
                "trend": {"labels": labels, "values": values},
                "charts": {
                    "pie_a3_a4": {"labels": ["A3", "A4"], "values": [a3, a4]},
                    "pie_duplex_single": {"labels": ["Double side", "Single side / A4"], "values": [duplex_now, single_side]},
                    "hourly_total": {"labels": sorted(hourly_total.keys()), "values": [hourly_total[k] for k in sorted(hourly_total.keys())]},
                    "hourly_a3_a4": {
                        "labels": sorted(hourly_a3.keys()),
                        "a3": [hourly_a3[k] for k in sorted(hourly_a3.keys())],
                        "a4": [hourly_a4.get(k, 0) for k in sorted(hourly_a3.keys())],
                    },
                    "daily_total_month": {"labels": sorted(daily_total.keys()), "values": [daily_total[k] for k in sorted(daily_total.keys())]},
                    "daily_copier_printer": {
                        "labels": sorted(daily_total.keys()),
                        "copier": [daily_copier.get(k, 0) for k in sorted(daily_total.keys())],
                        "printer": [daily_printer.get(k, 0) for k in sorted(daily_total.keys())],
                    },
                    "average_radar": {
                        "labels": ["Total", "Copier", "Printer", "Scan BW", "Scan Color", "A3", "Duplex"],
                        "values": [
                            avg_values["avg_total"],
                            avg_values["avg_copier"],
                            avg_values["avg_printer"],
                            avg_values["avg_scan_bw"],
                            avg_values["avg_scan_color"],
                            avg_values["avg_a3"],
                            avg_values["avg_duplex"],
                        ],
                    },
                    "distribution": {
                        "labels": ["Copier", "Printer", "Scan BW", "Scan Color"],
                        "values": [
                            latest_totals["copier_bw"],
                            latest_totals["printer_bw"],
                            latest_totals["scanner_send_bw"],
                            latest_totals["scanner_send_color"],
                        ],
                    },
                },
            }
        )

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
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
                    }
                    for r in rows
                ]
            }
        )

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
                    **_serialize_audit_payload_iso(printer.created_at, printer.updated_at),
                },
                "events": events,
            }
        )

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
        raw_ref = _to_text(device_ref)
        if raw_ref.isdigit():
            return session.get(Printer, int(raw_ref))
        return None

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
            import time as _time

            _time.sleep(0.5)

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

    @app.post("/api/devices/<device_ref>/scan-folder")
    def device_scan_folder(device_ref: str) -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        with session_factory() as session:
            printer = _resolve_printer_control_target(session, device_ref)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            provided_mac = _to_text(body.get("mac_id") or body.get("mac"))
            requested_mac = _normalize_mac(provided_mac)
            if provided_mac and not requested_mac:
                return jsonify({"ok": False, "error": "Invalid mac_id"}), 400
            printer_mac = _normalize_mac(printer.mac_address)
            if requested_mac and printer_mac and requested_mac != printer_mac:
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": f"Body mac_id {requested_mac} does not match path printer {printer_mac}",
                            "mac_id": printer_mac,
                        }
                    ),
                    409,
                )
            agent, warning_parts, agent_error = _resolve_scan_host_agent_for_printer(
                session,
                printer=printer,
            )
            if agent_error is not None:
                payload, status = agent_error
                return jsonify(payload), status
            queue_body = dict(body)
            if printer_mac:
                queue_body["mac_id"] = printer_mac
            payload, status = _queue_scan_folder_command_for_agent(
                session,
                agent=agent,
                body=queue_body,
                printer=printer,
                initial_warnings=warning_parts,
            )
        return jsonify(payload), status

    @app.get("/api/counter/timelapse")
    def counter_timelapse() -> Any:
        page = _to_page(request.args.get("page"), 1)
        lead = _to_text(request.args.get("lead"))
        ip = _to_text(request.args.get("ip"))
        printer_name = _to_text(request.args.get("printer_name"))
        printer_type = _to_text(request.args.get("printer_type")).lower()
        time_scope = _to_text(request.args.get("time_scope"))
        datetime_from = _to_text(request.args.get("datetime_from"))
        datetime_to = _to_text(request.args.get("datetime_to"))
        favorite_only = _to_text(request.args.get("favorite")).lower() in {"1", "true", "yes", "on"}
        day_start_utc, day_end_utc, today_start_local = _resolve_day_window(page)
        from_dt = _parse_query_datetime(datetime_from, end_of_minute=False)
        to_dt = _parse_query_datetime(datetime_to, end_of_minute=True)
        using_specified = (time_scope == "specified") and (from_dt is not None) and (to_dt is not None)

        base_stmt = _apply_common_filters(select(CounterInfor), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
        if using_specified:
            day_stmt = base_stmt.order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
        else:
            day_stmt = (
                base_stmt.where(CounterInfor.timestamp >= day_start_utc, CounterInfor.timestamp < day_end_utc)
                .order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
            )
        with session_factory() as session:
            rows = session.execute(day_stmt).scalars().all()
            min_ts = session.scalar(_apply_common_filters(select(func.min(CounterInfor.timestamp)), CounterInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to))
            if using_specified:
                total_pages = 1
                day_start_utc = from_dt or day_start_utc
                day_end_utc = to_dt or day_end_utc
            elif min_ts:
                min_local = min_ts.astimezone(UI_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                total_pages = max(1, (today_start_local.date() - min_local.date()).days + 1)
            else:
                total_pages = 1
            baseline_keys = {(r.lead, r.lan_uid, r.ip) for r in rows}
            baselines: dict[tuple[str, str, str], dict[str, Any]] = {}
            if baseline_keys:
                leads = sorted({item[0] for item in baseline_keys})
                lans = sorted({item[1] for item in baseline_keys})
                ips = sorted({item[2] for item in baseline_keys})
                baseline_rows = session.execute(
                    select(CounterBaseline).where(
                        CounterBaseline.lead.in_(leads),
                        CounterBaseline.lan_uid.in_(lans),
                        CounterBaseline.ip.in_(ips),
                    )
                ).scalars().all()
                for b in baseline_rows:
                    baselines[(b.lead, b.lan_uid, b.ip)] = b.raw_payload if isinstance(b.raw_payload, dict) else {}
        return jsonify(
            {
                "rows": [
                    {
                        "id": r.id,
                        "lead": r.lead,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                        "printer_name": r.printer_name,
                        "ip": r.ip,
                        "begin_record_id": r.begin_record_id,
                        "is_favorite": bool(r.is_favorite),
                        "total": _apply_baseline(r.total, baselines.get((r.lead, r.lan_uid, r.ip), {}), "total"),
                        "copier_bw": _apply_baseline(r.copier_bw, baselines.get((r.lead, r.lan_uid, r.ip), {}), "copier_bw"),
                        "printer_bw": _apply_baseline(r.printer_bw, baselines.get((r.lead, r.lan_uid, r.ip), {}), "printer_bw"),
                        "fax_bw": _apply_baseline(r.fax_bw, baselines.get((r.lead, r.lan_uid, r.ip), {}), "fax_bw"),
                        "send_tx_total_bw": _apply_baseline(
                            r.send_tx_total_bw,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "send_tx_total_bw",
                        ),
                        "send_tx_total_color": _apply_baseline(
                            r.send_tx_total_color,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "send_tx_total_color",
                        ),
                        "fax_transmission_total": _apply_baseline(
                            r.fax_transmission_total,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "fax_transmission_total",
                        ),
                        "scanner_send_bw": _apply_baseline(
                            r.scanner_send_bw,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "scanner_send_bw",
                        ),
                        "scanner_send_color": _apply_baseline(
                            r.scanner_send_color,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "scanner_send_color",
                        ),
                        "coverage_copier_bw": _apply_baseline(
                            r.coverage_copier_bw,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "coverage_copier_bw",
                        ),
                        "coverage_printer_bw": _apply_baseline(
                            r.coverage_printer_bw,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "coverage_printer_bw",
                        ),
                        "coverage_fax_bw": _apply_baseline(
                            r.coverage_fax_bw,
                            baselines.get((r.lead, r.lan_uid, r.ip), {}),
                            "coverage_fax_bw",
                        ),
                        "a3_dlt": _apply_baseline(r.a3_dlt, baselines.get((r.lead, r.lan_uid, r.ip), {}), "a3_dlt"),
                        "duplex": _apply_baseline(r.duplex, baselines.get((r.lead, r.lan_uid, r.ip), {}), "duplex"),
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
                    }
                    for r in rows
                ],
                "page": page,
                "page_size": len(rows),
                "total": len(rows),
                "total_pages": total_pages,
                "day_start": day_start_utc.isoformat(),
                "day_end": day_end_utc.isoformat(),
            }
        )

    @app.get("/api/status/timelapse")
    def status_timelapse() -> Any:
        page = _to_page(request.args.get("page"), 1)
        lead = _to_text(request.args.get("lead"))
        ip = _to_text(request.args.get("ip"))
        printer_name = _to_text(request.args.get("printer_name"))
        printer_type = _to_text(request.args.get("printer_type")).lower()
        time_scope = _to_text(request.args.get("time_scope"))
        datetime_from = _to_text(request.args.get("datetime_from"))
        datetime_to = _to_text(request.args.get("datetime_to"))
        favorite_only = _to_text(request.args.get("favorite")).lower() in {"1", "true", "yes", "on"}
        day_start_utc, day_end_utc, today_start_local = _resolve_day_window(page)
        from_dt = _parse_query_datetime(datetime_from, end_of_minute=False)
        to_dt = _parse_query_datetime(datetime_to, end_of_minute=True)
        using_specified = (time_scope == "specified") and (from_dt is not None) and (to_dt is not None)

        base_stmt = _apply_common_filters(select(StatusInfor), StatusInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to)
        if using_specified:
            day_stmt = base_stmt.order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
        else:
            day_stmt = (
                base_stmt.where(StatusInfor.timestamp >= day_start_utc, StatusInfor.timestamp < day_end_utc)
                .order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
            )
        with session_factory() as session:
            rows = session.execute(day_stmt).scalars().all()
            min_ts = session.scalar(_apply_common_filters(select(func.min(StatusInfor.timestamp)), StatusInfor, lead, ip, printer_name, printer_type, time_scope, favorite_only, datetime_from, datetime_to))
            if using_specified:
                total_pages = 1
                day_start_utc = from_dt or day_start_utc
                day_end_utc = to_dt or day_end_utc
            elif min_ts:
                min_local = min_ts.astimezone(UI_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                total_pages = max(1, (today_start_local.date() - min_local.date()).days + 1)
            else:
                total_pages = 1
            baseline_keys = {(r.lead, r.lan_uid, r.ip) for r in rows}
            baselines: dict[tuple[str, str, str], dict[str, Any]] = {}
            counter_index: dict[tuple[str, str, str], dict[str, Any]] = {}
            status_counter_values: dict[int, dict[str, int | None]] = {}
            if baseline_keys:
                leads = sorted({item[0] for item in baseline_keys})
                lans = sorted({item[1] for item in baseline_keys})
                ips = sorted({item[2] for item in baseline_keys})
                baseline_rows = session.execute(
                    select(CounterBaseline).where(
                        CounterBaseline.lead.in_(leads),
                        CounterBaseline.lan_uid.in_(lans),
                        CounterBaseline.ip.in_(ips),
                    )
                ).scalars().all()
                for b in baseline_rows:
                    baselines[(b.lead, b.lan_uid, b.ip)] = b.raw_payload if isinstance(b.raw_payload, dict) else {}

                counter_rows = session.execute(
                    select(CounterInfor)
                    .where(
                        CounterInfor.lead.in_(leads),
                        CounterInfor.lan_uid.in_(lans),
                        CounterInfor.ip.in_(ips),
                        CounterInfor.timestamp <= day_end_utc,
                    )
                    .order_by(CounterInfor.timestamp.asc(), CounterInfor.id.asc())
                ).scalars().all()
                grouped: dict[tuple[str, str, str], list[CounterInfor]] = {}
                for item in counter_rows:
                    key = (item.lead, item.lan_uid, item.ip)
                    grouped.setdefault(key, []).append(item)
                for key, items in grouped.items():
                    counter_index[key] = {"times": [x.timestamp for x in items], "rows": items}

                for r in rows:
                    key = (r.lead, r.lan_uid, r.ip)
                    info = counter_index.get(key)
                    chosen: CounterInfor | None = None
                    if info:
                        idx = bisect_right(info["times"], r.timestamp) - 1
                        if idx >= 0:
                            chosen = info["rows"][idx]
                    base = baselines.get(key, {})
                    status_counter_values[r.id] = {
                        "total": _apply_baseline(chosen.total if chosen else None, base, "total"),
                        "copier_bw": _apply_baseline(chosen.copier_bw if chosen else None, base, "copier_bw"),
                        "printer_bw": _apply_baseline(chosen.printer_bw if chosen else None, base, "printer_bw"),
                        "a3_dlt": _apply_baseline(chosen.a3_dlt if chosen else None, base, "a3_dlt"),
                        "duplex": _apply_baseline(chosen.duplex if chosen else None, base, "duplex"),
                    }
        return jsonify(
            {
                "rows": [
                    {
                        "id": r.id,
                        "lead": r.lead,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                        "printer_name": r.printer_name,
                        "ip": r.ip,
                        "begin_record_id": r.begin_record_id,
                        "is_favorite": bool(r.is_favorite),
                        "system_status": r.system_status,
                        "printer_status": r.printer_status,
                        "printer_alerts": r.printer_alerts,
                        "copier_status": r.copier_status,
                        "copier_alerts": r.copier_alerts,
                        "scanner_status": r.scanner_status,
                        "scanner_alerts": r.scanner_alerts,
                        "toner_black": r.toner_black,
                        "tray_1_status": r.tray_1_status,
                        "tray_2_status": r.tray_2_status,
                        "tray_3_status": r.tray_3_status,
                        "bypass_tray_status": r.bypass_tray_status,
                        "total": (status_counter_values.get(r.id) or {}).get("total"),
                        "copier_bw": (status_counter_values.get(r.id) or {}).get("copier_bw"),
                        "printer_bw": (status_counter_values.get(r.id) or {}).get("printer_bw"),
                        "a3_dlt": (status_counter_values.get(r.id) or {}).get("a3_dlt"),
                        "duplex": (status_counter_values.get(r.id) or {}).get("duplex"),
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
                    }
                    for r in rows
                ],
                "page": page,
                "page_size": len(rows),
                "total": len(rows),
                "total_pages": total_pages,
                "day_start": day_start_utc.isoformat(),
                "day_end": day_end_utc.isoformat(),
            }
        )

    @app.delete("/api/counter/<int:row_id>")
    def delete_counter_row(row_id: int) -> Any:
        with session_factory() as session:
            row = session.get(CounterInfor, row_id)
            if row is None:
                return jsonify({"ok": False, "error": "Counter row not found"}), 404
            session.delete(row)
            session.commit()
        return jsonify({"ok": True, "id": row_id})

    @app.patch("/api/counter/<int:row_id>/favorite")
    def favorite_counter_row(row_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        is_favorite = bool(body.get("is_favorite", True))
        with session_factory() as session:
            row = session.get(CounterInfor, row_id)
            if row is None:
                return jsonify({"ok": False, "error": "Counter row not found"}), 404
            row.is_favorite = is_favorite
            session.commit()
        return jsonify({"ok": True, "id": row_id, "is_favorite": is_favorite})

    @app.delete("/api/status/<int:row_id>")
    def delete_status_row(row_id: int) -> Any:
        with session_factory() as session:
            row = session.get(StatusInfor, row_id)
            if row is None:
                return jsonify({"ok": False, "error": "Status row not found"}), 404
            session.delete(row)
            session.commit()
        return jsonify({"ok": True, "id": row_id})

    @app.patch("/api/status/<int:row_id>/favorite")
    def favorite_status_row(row_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        is_favorite = bool(body.get("is_favorite", True))
        with session_factory() as session:
            row = session.get(StatusInfor, row_id)
            if row is None:
                return jsonify({"ok": False, "error": "Status row not found"}), 404
            row.is_favorite = is_favorite
            session.commit()
        return jsonify({"ok": True, "id": row_id, "is_favorite": is_favorite})

    @app.delete("/api/infor/<int:row_id>")
    def delete_infor_row(row_id: int) -> Any:
        with session_factory() as session:
            row = session.get(DeviceInforHistory, row_id)
            if row is None:
                return jsonify({"ok": False, "error": "Infor row not found"}), 404
            lead = _to_text(row.lead)
            lan_uid = _to_text(row.lan_uid)
            machine_uid = _to_text(row.machine_uid)
            mac_id = _to_text(row.mac_id)
            ip = _to_text(row.ip)
            session.delete(row)
            session.flush()

            remain_stmt = select(func.count()).select_from(DeviceInforHistory).where(
                DeviceInforHistory.lead == lead,
                DeviceInforHistory.lan_uid == lan_uid,
                DeviceInforHistory.machine_uid == machine_uid,
            )
            remain = int(session.scalar(remain_stmt) or 0)
            if remain == 0:
                base_stmt = select(DeviceInfor).where(
                    DeviceInfor.lead == lead,
                    DeviceInfor.lan_uid == lan_uid,
                )
                if mac_id:
                    base_stmt = base_stmt.where(DeviceInfor.mac_id == mac_id)
                elif machine_uid:
                    base_stmt = base_stmt.where(DeviceInfor.mac_id == machine_uid)
                elif ip:
                    base_stmt = base_stmt.where(DeviceInfor.ip == ip)
                base_row = session.execute(base_stmt.limit(1)).scalar_one_or_none()
                if base_row is not None:
                    session.delete(base_row)

            session.commit()
        return jsonify({"ok": True, "id": row_id})

    @app.get("/api/counter/trend")
    @app.get("/api/counter/heatmap")
    def counter_trend() -> Any:
        lead = _to_text(request.args.get("lead"))
        ip_filter = _to_text(request.args.get("ip"))
        mode = _to_text(request.args.get("mode")).lower() or "day"
        if mode not in {"day", "week", "month"}:
            mode = "day"

        today_local = datetime.now(UI_TZ).date()
        if mode == "day":
            default_from = today_local
        elif mode == "week":
            default_from = today_local - timedelta(days=6)
        else:
            default_from = today_local - timedelta(days=29)
        date_from = _parse_date(request.args.get("date_from") or default_from.isoformat())
        date_to = _parse_date(request.args.get("date_to") or today_local.isoformat())
        if date_to < date_from:
            date_from, date_to = date_to, date_from
        if mode == "day":
            # Daily mode always renders minute-level variation for one day.
            date_to = date_from

        start_local = datetime.combine(date_from, time.min, tzinfo=UI_TZ)
        end_local = datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=UI_TZ)
        start_dt = start_local.astimezone(timezone.utc)
        end_dt = end_local.astimezone(timezone.utc)

        def bucket_label(dt_local: datetime) -> str:
            if mode == "day":
                return dt_local.strftime("%H:%M")
            return dt_local.strftime("%Y-%m-%d")

        labels: list[str] = []
        seen_labels: set[str] = set()
        cursor = start_local
        while cursor < end_local:
            label = bucket_label(cursor)
            if label not in seen_labels:
                labels.append(label)
                seen_labels.add(label)
            if mode == "day":
                cursor += timedelta(minutes=1)
            elif mode == "week":
                cursor += timedelta(days=1)
            else:
                cursor += timedelta(days=1)

        with session_factory() as session:
            stmt = (
                select(
                    CounterInfor.ip,
                    CounterInfor.printer_name,
                    CounterInfor.timestamp,
                    CounterInfor.total,
                )
                .where(CounterInfor.timestamp >= start_dt, CounterInfor.timestamp < end_dt)
                .order_by(CounterInfor.ip.asc(), CounterInfor.timestamp.asc(), CounterInfor.id.asc())
            )
            if lead:
                stmt = stmt.where(CounterInfor.lead == lead)
            if ip_filter:
                stmt = stmt.where(CounterInfor.ip == ip_filter)
            points = session.execute(stmt).all()

        bucket_map: dict[tuple[str, str], dict[str, dict[str, int]]] = {}
        name_map: dict[tuple[str, str], str] = {}
        for ip_val, printer_name, ts, total in points:
            if not isinstance(ts, datetime):
                continue
            ip = _to_text(ip_val)
            if not ip:
                continue
            local_ts = ts.astimezone(UI_TZ)
            label = bucket_label(local_ts)
            if label not in seen_labels:
                continue
            key = (ip, _to_text(printer_name) or ip)
            name_map[key] = _to_text(printer_name) or ip
            by_bucket = bucket_map.setdefault(key, {})
            total_value = _to_int(total) or 0
            slot = by_bucket.get(label)
            if slot is None:
                by_bucket[label] = {"first": total_value, "last": total_value}
            else:
                slot["last"] = total_value

        series: list[dict[str, Any]] = []
        for key in sorted(bucket_map.keys(), key=lambda x: (x[1].lower(), x[0])):
            ip, _ = key
            by_bucket = bucket_map[key]
            values: list[int] = []
            for label in labels:
                slot = by_bucket.get(label)
                if slot is None:
                    values.append(0)
                else:
                    diff = int(slot.get("last", 0)) - int(slot.get("first", 0))
                    values.append(diff if diff >= 0 else 0)
            series.append(
                {
                    "ip": ip,
                    "printer_name": name_map.get(key, ip),
                    "values": values,
                }
            )

        return jsonify(
            {
                "mode": mode,
                "date_from": date_from.isoformat(),
                "date_to": date_to.isoformat(),
                "labels": labels,
                "printers": len(series),
                "series": series,
            }
        )

    @app.get("/api/polling/controls")
    def polling_controls() -> Any:
        agent_uid = _to_text(request.args.get("agent_uid"))
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(
                session,
                lead_valid,
                {
                    "lead": lead_valid,
                    "lan_uid": _to_text(request.args.get("lan_uid")),
                    "agent_uid": agent_uid,
                    "hostname": "",
                    "local_ip": "",
                    "gateway_ip": _to_text(request.args.get("gateway_ip")),
                    "gateway_mac": _to_text(request.args.get("gateway_mac")),
                },
            )
            stmt = select(Printer).where(Printer.lead == lead_valid, Printer.lan_uid == lan_uid).order_by(Printer.id.asc())
            if agent_uid:
                stmt = stmt.where(Printer.agent_uid == agent_uid)
            rows = session.execute(stmt).scalars().all()
            pending_cmds = session.execute(
                select(PrinterControlCommand)
                .where(
                    PrinterControlCommand.lead == lead_valid,
                    PrinterControlCommand.lan_uid == lan_uid,
                    PrinterControlCommand.status == "pending",
                )
                .order_by(PrinterControlCommand.requested_at.asc(), PrinterControlCommand.id.asc())
            ).scalars().all()
            pending_by_printer: dict[int, PrinterControlCommand] = {}
            for cmd in pending_cmds:
                if cmd.printer_id in pending_by_printer:
                    continue
                pending_by_printer[int(cmd.printer_id)] = cmd
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "rows": [
                    {
                        "id": int(r.id),
                        "ip": r.ip,
                        "printer_name": r.printer_name,
                        "enabled": bool(r.enabled),
                        "enabled_changed_at": r.enabled_changed_at.isoformat() if r.enabled_changed_at else "",
                        "command": (
                            {
                                "id": int(pending_by_printer[int(r.id)].id),
                                "desired_enabled": bool(pending_by_printer[int(r.id)].desired_enabled),
                                "auth_user": pending_by_printer[int(r.id)].auth_user or "",
                                "auth_password": pending_by_printer[int(r.id)].auth_password or "",
                            }
                            if int(r.id) in pending_by_printer
                            else None
                        ),
                    }
                    for r in rows
                ],
            }
        )

    @app.post("/api/polling/control-result")
    def polling_control_result() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error

        command_id = _to_int(body.get("command_id"))
        if command_id is None or command_id <= 0:
            return jsonify({"ok": False, "error": "Missing command_id"}), 400
        ok_value = bool(body.get("ok", False))
        error_message = _to_text(body.get("error"))
        responded_at = datetime.now(timezone.utc)

        with session_factory() as session:
            command = session.get(PrinterControlCommand, int(command_id))
            if command is None:
                return jsonify({"ok": False, "error": "Command not found"}), 404
            if command.lead != lead:
                return jsonify({"ok": False, "error": "Lead mismatch"}), 400
            if command.status != "pending":
                return jsonify({"ok": True, "status": command.status, "id": int(command.id)})

            printer = session.get(Printer, int(command.printer_id))
            if printer is None:
                command.status = "failed"
                command.error_message = "Printer not found"
                command.responded_at = responded_at
                session.commit()
                return jsonify({"ok": False, "error": "Printer not found"}), 404

            if ok_value:
                command.status = "success"
                command.error_message = ""
                command.responded_at = responded_at
                _apply_printer_enabled_state(session, printer, bool(command.desired_enabled), responded_at)
            else:
                command.status = "failed"
                command.error_message = error_message or "Agent lock/unlock failed"
                command.responded_at = responded_at
            session.commit()

        return jsonify(
            {
                "ok": True,
                "id": int(command_id),
                "status": "success" if ok_value else "failed",
                "responded_at": responded_at.isoformat(),
            }
        )

    @app.get("/api/polling/ftp-controls")
    def polling_ftp_controls() -> Any:
        agent_uid = _to_text(request.args.get("agent_uid"))
        if not agent_uid:
            return jsonify({"ok": False, "error": "Missing agent_uid"}), 400
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(
                session,
                lead_valid,
                {
                    "lead": lead_valid,
                    "lan_uid": _to_text(request.args.get("lan_uid")),
                    "agent_uid": agent_uid,
                    "hostname": "",
                    "local_ip": "",
                    "gateway_ip": _to_text(request.args.get("gateway_ip")),
                    "gateway_mac": _to_text(request.args.get("gateway_mac")),
                },
            )
            pending_cmds = session.execute(
                select(FtpControlCommand)
                .where(
                    FtpControlCommand.lead == lead_valid,
                    FtpControlCommand.lan_uid == lan_uid,
                    FtpControlCommand.agent_uid == agent_uid,
                    FtpControlCommand.status == "pending",
                )
                .order_by(FtpControlCommand.requested_at.asc(), FtpControlCommand.id.asc())
            ).scalars().all()
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "rows": [
                    {
                        "id": int(cmd.id),
                        "action": cmd.action,
                        "site_name": cmd.site_name,
                        "new_site_name": cmd.new_site_name,
                        "local_path": cmd.local_path,
                        "port": int(cmd.port or 0),
                        "ftp_user": cmd.ftp_user,
                        "ftp_password": cmd.ftp_password,
                        "printer_mac_id": cmd.printer_mac_id,
                        "printer_ip": cmd.printer_ip,
                        "printer_name": cmd.printer_name,
                        "printer_auth_user": cmd.printer_auth_user,
                        "printer_auth_password": cmd.printer_auth_password,
                    }
                    for cmd in pending_cmds
                ],
            }
        )

    @app.post("/api/polling/ftp-control-result")
    def polling_ftp_control_result() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error

        command_id = _to_int(body.get("command_id"))
        if command_id is None or command_id <= 0:
            return jsonify({"ok": False, "error": "Missing command_id"}), 400
        ok_value = bool(body.get("ok", False))
        error_message = _to_text(body.get("error"))
        warning_message = _to_text(body.get("warning"))
        responded_at = datetime.now(timezone.utc)

        with session_factory() as session:
            command = session.get(FtpControlCommand, int(command_id))
            if command is None:
                return jsonify({"ok": False, "error": "Command not found"}), 404
            if command.lead != lead:
                return jsonify({"ok": False, "error": "Lead mismatch"}), 400
            if command.status != "pending":
                return jsonify({"ok": True, "status": command.status, "id": int(command.id)})

            if ok_value:
                command.status = "success"
                command.error_message = warning_message
                command.responded_at = responded_at
                if warning_message:
                    LOGGER.warning(
                        "ftp control completed with warning: id=%s site=%s mac_id=%s warning=%s",
                        int(command.id),
                        _to_text(command.site_name),
                        _to_text(command.printer_mac_id),
                        warning_message,
                    )
            else:
                command.status = "failed"
                command.error_message = error_message or "FTP command failed"
                command.responded_at = responded_at
            session.commit()

        return jsonify(
            {
                "ok": True,
                "id": int(command_id),
                "status": "success" if ok_value else "failed",
                "warning": warning_message if ok_value else "",
                "responded_at": responded_at.isoformat(),
            }
        )

    @app.post("/api/polling/inventory")
    def ingest_inventory() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("inventory: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("inventory: unauthorized lead=%s ip=%s", _to_text(body.get("lead")), request.remote_addr)
            return auth_error

        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(session, lead, body)
            agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
            hostname = _to_text(body.get("hostname"))
            local_ip = _to_text(body.get("local_ip"))
            local_mac = _to_text(body.get("local_mac"))
            app_version = _to_text(body.get("app_version"))
            run_mode = _to_text(body.get("run_mode")) or "web"
            web_port = _to_int(body.get("web_port")) or 9173
            ftp_ports = _to_text(body.get("ftp_ports"))
            ftp_sites = _normalize_ftp_sites_payload(body.get("ftp_sites"))
            timestamp = _parse_timestamp(body.get("timestamp"))
            devices = body.get("devices") if isinstance(body.get("devices"), list) else []
            inserted = 0
            updated = 0
            _refresh_stale_agent_offline(session=session, lead=lead, stale_seconds=ONLINE_STALE_SECONDS)
            _upsert_lan_and_agent(
                session=session,
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                lan_name="",
                subnet_cidr="",
                gateway_ip="",
                gateway_mac="",
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
                app_version=app_version,
                run_mode=run_mode,
                web_port=web_port,
                ftp_ports=ftp_ports,
                ftp_sites=ftp_sites,
            )
            for item in devices:
                if not isinstance(item, dict):
                    continue
                printer_name = _to_text(item.get("printer_name")) or _to_text(item.get("name"))
                ip = _to_text(item.get("ip"))
                existed = None
                if ip:
                    existed = session.execute(
                        select(Printer).where(Printer.lead == lead, Printer.lan_uid == lan_uid, Printer.ip == ip).limit(1)
                    ).scalar_one_or_none()
                elif printer_name:
                    existed = session.execute(
                        select(Printer)
                        .where(
                            Printer.lead == lead,
                            Printer.lan_uid == lan_uid,
                            Printer.agent_uid == agent_uid,
                            Printer.printer_name == printer_name,
                            Printer.ip == "",
                        )
                        .limit(1)
                    ).scalar_one_or_none()
                _upsert_printer_from_polling(
                    session=session,
                    lead=lead,
                    lan_uid=lan_uid,
                    agent_uid=agent_uid,
                    printer_name=printer_name,
                    ip=ip,
                    event_time=timestamp,
                    touch_seen=False,
                    mark_online_on_create=False,
                    mac_address=_to_text(item.get("mac_address")),
                    auth_user=_to_text(item.get("auth_user") or item.get("user")),
                    auth_password=_to_text(item.get("auth_password") or item.get("password")),
                )
                if existed is None:
                    inserted += 1
                else:
                    updated += 1
            session.commit()

        LOGGER.info(
            "inventory: lead=%s lan=%s agent=%s devices=%s inserted=%s updated=%s",
            lead,
            lan_uid,
            agent_uid,
            len(devices),
            inserted,
            updated,
        )
        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "devices": len(devices),
                "inserted": inserted,
                "updated": updated,
            }
        )

    @app.post("/api/polling/scan-upload")
    def ingest_scan_upload() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead(
            {"lead": request.form.get("lead")},
            lead_key_map,
            sent_token,
        )
        if not ok_auth:
            return auth_error

        upload = request.files.get("file")
        if upload is None:
            return jsonify({"ok": False, "error": "Missing file"}), 400

        original_name = secure_filename(upload.filename or "scan.bin")
        if not original_name:
            original_name = "scan.bin"

        lan_uid = _safe_path_token(_to_text(request.form.get("lan_uid")) or "legacy-lan")
        agent_uid = _safe_path_token(_to_text(request.form.get("agent_uid")) or "legacy-agent")
        hostname = _to_text(request.form.get("hostname"))
        local_ip = _to_text(request.form.get("local_ip"))
        source_path = _to_text(request.form.get("source_path"))
        source_root = _to_text(request.form.get("source_root"))
        source_root_label = _safe_path_token(_to_text(request.form.get("source_root_label")) or "scan-root")
        source_relative_parts = _safe_relative_path_parts(request.form.get("source_relative_path"))
        fingerprint = _to_text(request.form.get("fingerprint"))
        event_time = _parse_timestamp(request.form.get("timestamp"))

        if source_relative_parts:
            sync_mode = "mirror"
            dest_name = source_relative_parts[-1]
            target_dir = SCAN_UPLOAD_ROOT / _safe_path_token(lead_valid) / lan_uid / agent_uid / source_root_label
            for part in source_relative_parts[:-1]:
                target_dir = target_dir / part
            target_dir.mkdir(parents=True, exist_ok=True)
            dest_path = target_dir / dest_name
            drive_remote_parts = [_safe_path_token(lead_valid), lan_uid, agent_uid, source_root_label, *source_relative_parts]
        else:
            sync_mode = "append"
            date_folder = event_time.astimezone(UI_TZ).strftime("%Y%m%d")
            target_dir = SCAN_UPLOAD_ROOT / _safe_path_token(lead_valid) / lan_uid / agent_uid / date_folder
            target_dir.mkdir(parents=True, exist_ok=True)

            stamp = event_time.astimezone(UI_TZ).strftime("%H%M%S")
            digest_seed = f"{fingerprint}|{source_path}|{event_time.isoformat()}|{original_name}"
            digest = hashlib.sha1(digest_seed.encode("utf-8")).hexdigest()[:10]
            dest_name = f"{stamp}_{digest}_{original_name}"
            dest_path = target_dir / dest_name
            index = 1
            while dest_path.exists():
                dest_path = target_dir / f"{stamp}_{digest}_{index}_{original_name}"
                index += 1
            drive_remote_parts = [_safe_path_token(lead_valid), lan_uid, agent_uid, date_folder, dest_path.name]

        temp_path = target_dir / f".upload-{time_module.time_ns()}-{dest_name}"
        upload.save(temp_path)
        temp_path.replace(dest_path)
        file_size = int(dest_path.stat().st_size if dest_path.exists() else 0)
        relative_path = str(dest_path.as_posix())
        drive_sync_payload = drive_sync.disabled_result().as_dict()
        if drive_sync.enabled:
            try:
                drive_sync_result = drive_sync.upload_scan(
                    dest_path,
                    remote_parts=drive_remote_parts,
                    source_path=source_path,
                )
                drive_sync_payload = drive_sync_result.as_dict()
            except Exception as exc:  # noqa: BLE001
                drive_sync_payload = {"enabled": True, "ok": False, "error": str(exc)}
                LOGGER.warning(
                    "scan-upload drive sync failed: lead=%s lan=%s agent=%s file=%s error=%s",
                    lead_valid,
                    lan_uid,
                    agent_uid,
                    relative_path,
                    exc,
                )

        LOGGER.info(
            "scan-upload: lead=%s lan=%s agent=%s host=%s ip=%s file=%s size=%s source=%s source_root=%s mode=%s drive_ok=%s",
            lead_valid,
            lan_uid,
            agent_uid,
            hostname,
            local_ip,
            relative_path,
            file_size,
            source_path,
            source_root,
            sync_mode,
            drive_sync_payload.get("ok", False),
        )
        return jsonify(
            {
                "ok": True,
                "lead": lead_valid,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "path": relative_path,
                "size": file_size,
                "timestamp": event_time.isoformat(),
                "sync_mode": sync_mode,
                "source_root": source_root,
                "source_root_label": source_root_label,
                "source_relative_path": "/".join(source_relative_parts),
                "drive_sync": drive_sync_payload,
            }
        )

    @app.post("/api/polling")
    def ingest_polling() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("polling: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("polling: unauthorized lead=%s ip=%s", lead, request.remote_addr)
            return auth_error

        printer_name = _to_text(body.get("printer_name"))
        ip = _to_text(body.get("ip"))
        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(session, lead, body)
        agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
        lan_name = _to_text(body.get("lan_name"))
        subnet_cidr = _to_text(body.get("subnet_cidr"))
        gateway_ip = _to_text(body.get("gateway_ip"))
        gateway_mac = _to_text(body.get("gateway_mac"))
        hostname = _to_text(body.get("hostname"))
        local_ip = _to_text(body.get("local_ip"))
        local_mac = _to_text(body.get("local_mac"))
        app_version = _to_text(body.get("app_version"))
        run_mode = _to_text(body.get("run_mode")) or "web"
        web_port = _to_int(body.get("web_port")) or 9173
        ftp_ports = _to_text(body.get("ftp_ports"))
        ftp_sites = _normalize_ftp_sites_payload(body.get("ftp_sites"))
        timestamp = _parse_timestamp(body.get("timestamp"))
        counter_data = body.get("counter_data") if isinstance(body.get("counter_data"), dict) else {}
        status_data = body.get("status_data") if isinstance(body.get("status_data"), dict) else {}
        collector_ok = bool(body.get("collector_ok", True))
        skip_data_update = bool(body.get("skip_data_update", False))
        incoming_mac_id = _to_text(body.get("mac_id")) or _to_text(body.get("mac_address"))
        mac_id = _normalize_mac(incoming_mac_id)
        device_mac_address = mac_id
        LOGGER.info(
            "polling request: lead=%s lan=%s agent=%s printer=%s ip=%s ts=%s counter_keys=%s status_keys=%s",
            lead,
            lan_uid,
            agent_uid,
            printer_name or "-",
            ip or "-",
            timestamp.isoformat(),
            len(counter_data.keys()) if isinstance(counter_data, dict) else 0,
            len(status_data.keys()) if isinstance(status_data, dict) else 0,
        )
        logging_payload = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "remote_addr": _to_text(request.remote_addr),
            "path": "/api/polling",
            "payload": body,
        }
        LOGGER.info("polling payload json: %s", json.dumps(logging_payload, ensure_ascii=False))
        _write_last_data(logging_payload)

        inserted_counter = 0
        inserted_status = 0
        skipped_counter = 0
        skipped_status = 0
        skipped_disabled = 0
        with session_factory() as session:
            _upsert_lan_and_agent(
                session=session,
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                lan_name=lan_name,
                subnet_cidr=subnet_cidr,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
                app_version=app_version,
                run_mode=run_mode,
                web_port=web_port,
                ftp_ports=ftp_ports,
                ftp_sites=ftp_sites,
            )
            printer_row = None
            if ip or printer_name:
                printer_row = _upsert_printer_from_polling(
                    session=session,
                    lead=lead,
                    lan_uid=lan_uid,
                    agent_uid=agent_uid,
                    printer_name=printer_name,
                    ip=ip,
                    event_time=timestamp,
                    mac_address=device_mac_address,
                    auth_user=_to_text(body.get("auth_user")),
                    auth_password=_to_text(body.get("auth_password")),
                )
            if printer_row is not None and collector_ok:
                _set_printer_online_state(session=session, printer=printer_row, is_online=True, changed_at=timestamp)
            device_enabled = True if printer_row is None else bool(printer_row.enabled)
            if not device_enabled:
                skipped_disabled = 1

            public_mac_id = _resolve_public_mac(
                session=session,
                lead=lead,
                lan_uid=lan_uid,
                ip=ip,
                incoming_mac=mac_id,
            )
            root_mac_id = public_mac_id or (f"IP:{ip}" if ip else "UNKNOWN")
            infor = session.execute(
                select(DeviceInfor).where(
                    DeviceInfor.lead == lead,
                    DeviceInfor.lan_uid == lan_uid,
                    DeviceInfor.mac_id == root_mac_id,
                )
            ).scalar_one_or_none()
            prev_counter_data = infor.counter_data if infor and isinstance(infor.counter_data, dict) else {}
            prev_status_data = infor.status_data if infor and isinstance(infor.status_data, dict) else {}
            normalized_counter = _normalize_counter_payload(counter_data) if counter_data else {}
            normalized_prev_counter = _normalize_counter_payload(prev_counter_data) if prev_counter_data else {}
            normalized_status = _normalize_status_payload(status_data) if status_data else {}
            normalized_prev_status = _normalize_status_payload(prev_status_data) if prev_status_data else {}
            duplicate_counter_by_infor = bool(counter_data) and normalized_counter == normalized_prev_counter
            duplicate_status_by_infor = bool(status_data) and normalized_status == normalized_prev_status
            changed_counter = bool(counter_data) and not duplicate_counter_by_infor
            changed_status = bool(status_data) and not duplicate_status_by_infor
            changed_any = changed_counter or changed_status

            if counter_data and device_enabled:
                if duplicate_counter_by_infor:
                    skipped_counter = 1
                else:
                    begin_record_id_for_counter: int | None = None
                    latest_begin_row = session.execute(
                        select(CounterInfor.begin_record_id)
                        .where(CounterInfor.lead == lead, CounterInfor.lan_uid == lan_uid, CounterInfor.ip == ip)
                        .order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
                        .limit(1)
                    ).scalar_one_or_none()
                    if isinstance(latest_begin_row, int):
                        begin_record_id_for_counter = latest_begin_row
                    baseline_row = session.execute(
                        select(CounterBaseline).where(
                            CounterBaseline.lead == lead,
                            CounterBaseline.lan_uid == lan_uid,
                            CounterBaseline.ip == ip,
                        )
                    ).scalar_one_or_none()
                    if baseline_row is None:
                        baseline_row = CounterBaseline(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
                            baseline_timestamp=timestamp,
                            raw_payload=normalized_counter,
                        )
                        session.add(baseline_row)
                        delta_counter = {k: 0 for k in normalized_counter}
                    else:
                        baseline_payload = baseline_row.raw_payload if isinstance(baseline_row.raw_payload, dict) else {}
                        normalized_baseline = _normalize_counter_payload(baseline_payload)
                        delta_counter, has_reset = _compute_delta_payload(normalized_counter, normalized_baseline)
                        if has_reset:
                            baseline_row.baseline_timestamp = timestamp
                            baseline_row.raw_payload = normalized_counter
                            baseline_row.agent_uid = agent_uid
                            baseline_row.printer_name = printer_name or baseline_row.printer_name
                            delta_counter = {k: 0 for k in normalized_counter}
                            begin_record_id_for_counter = None

                    latest_counter_row = session.execute(
                        select(CounterInfor)
                        .where(
                            CounterInfor.lead == lead,
                            CounterInfor.lan_uid == lan_uid,
                            CounterInfor.agent_uid == agent_uid,
                            CounterInfor.ip == ip,
                            CounterInfor.mac_id == public_mac_id,
                            CounterInfor.raw_payload == delta_counter,
                        )
                        .order_by(CounterInfor.updated_at.desc(), CounterInfor.id.desc())
                        .limit(1)
                    ).scalar_one_or_none()
                    if latest_counter_row is not None:
                        latest_counter_row.updated_at = datetime.now(timezone.utc)
                        skipped_counter = 1
                    else:
                        row = CounterInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
                            mac_id=public_mac_id,
                            begin_record_id=begin_record_id_for_counter,
                            total=delta_counter.get("total"),
                            copier_bw=delta_counter.get("copier_bw"),
                            printer_bw=delta_counter.get("printer_bw"),
                            fax_bw=delta_counter.get("fax_bw"),
                            send_tx_total_bw=delta_counter.get("send_tx_total_bw"),
                            send_tx_total_color=delta_counter.get("send_tx_total_color"),
                            fax_transmission_total=delta_counter.get("fax_transmission_total"),
                            scanner_send_bw=delta_counter.get("scanner_send_bw"),
                            scanner_send_color=delta_counter.get("scanner_send_color"),
                            coverage_copier_bw=delta_counter.get("coverage_copier_bw"),
                            coverage_printer_bw=delta_counter.get("coverage_printer_bw"),
                            coverage_fax_bw=delta_counter.get("coverage_fax_bw"),
                            a3_dlt=delta_counter.get("a3_dlt"),
                            duplex=delta_counter.get("duplex"),
                            raw_payload=delta_counter,
                            updated_at=datetime.now(timezone.utc),
                        )
                        session.add(row)
                        session.flush()
                        if row.begin_record_id is None:
                            row.begin_record_id = row.id
                        inserted_counter = 1

            if status_data and device_enabled:
                if duplicate_status_by_infor:
                    skipped_status = 1
                else:
                    begin_record_id_for_status: int | None = None
                    latest_status_begin = session.execute(
                        select(StatusInfor.begin_record_id)
                        .where(StatusInfor.lead == lead, StatusInfor.lan_uid == lan_uid, StatusInfor.ip == ip)
                        .order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
                        .limit(1)
                    ).scalar_one_or_none()
                    if isinstance(latest_status_begin, int):
                        begin_record_id_for_status = latest_status_begin
                    latest_status_row = session.execute(
                        select(StatusInfor)
                        .where(
                            StatusInfor.lead == lead,
                            StatusInfor.lan_uid == lan_uid,
                            StatusInfor.agent_uid == agent_uid,
                            StatusInfor.ip == ip,
                            StatusInfor.mac_id == public_mac_id,
                            StatusInfor.raw_payload == status_data,
                        )
                        .order_by(StatusInfor.updated_at.desc(), StatusInfor.id.desc())
                        .limit(1)
                    ).scalar_one_or_none()
                    if latest_status_row is not None:
                        latest_status_row.updated_at = datetime.now(timezone.utc)
                        skipped_status = 1
                    else:
                        row = StatusInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=_to_text_max(printer_name or "Unknown Printer", 255),
                            ip=_to_text_max(ip, 64),
                            mac_id=_to_text_max(public_mac_id, 64),
                            begin_record_id=begin_record_id_for_status,
                            system_status=_to_json_value(status_data.get("system_status")),
                            printer_status=_to_json_value(status_data.get("printer_status")),
                            printer_alerts=_to_json_value(status_data.get("printer_alerts")),
                            copier_status=_to_json_value(status_data.get("copier_status")),
                            copier_alerts=_to_json_value(status_data.get("copier_alerts")),
                            scanner_status=_to_json_value(status_data.get("scanner_status")),
                            scanner_alerts=_to_json_value(status_data.get("scanner_alerts")),
                            toner_black=_to_json_value(status_data.get("toner_black")),
                            tray_1_status=_to_json_value(status_data.get("tray_1_status")),
                            tray_2_status=_to_json_value(status_data.get("tray_2_status")),
                            tray_3_status=_to_json_value(status_data.get("tray_3_status")),
                            bypass_tray_status=_to_json_value(status_data.get("bypass_tray_status")),
                            other_info=_to_json_value(status_data.get("other_info")),
                            raw_payload=status_data,
                            updated_at=datetime.now(timezone.utc),
                        )
                        session.add(row)
                        session.flush()
                        if row.begin_record_id is None:
                            row.begin_record_id = row.id
                        inserted_status = 1

            # Unified root record for downstream filtering/reporting.
            can_update_infor_data = (not skip_data_update) and bool(counter_data or status_data)
            if infor is None and can_update_infor_data:
                infor = DeviceInfor(
                    lead=lead,
                    lan_uid=lan_uid,
                    mac_id=root_mac_id,
                    agent_uid=agent_uid,
                    printer_name=printer_name or "Unknown Printer",
                    ip=ip,
                    counter_data=counter_data if isinstance(counter_data, dict) else {},
                    status_data=status_data if isinstance(status_data, dict) else {},
                    last_counter_at=timestamp if counter_data else None,
                    last_status_at=timestamp if status_data else None,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(infor)
            elif infor is not None:
                infor.agent_uid = agent_uid or infor.agent_uid
                infor.printer_name = printer_name or infor.printer_name
                infor.ip = ip or infor.ip
                if (
                    not skip_data_update
                    and counter_data
                    and isinstance(counter_data, dict)
                    and not duplicate_counter_by_infor
                ):
                    infor.counter_data = counter_data
                    infor.last_counter_at = timestamp
                if (
                    not skip_data_update
                    and status_data
                    and isinstance(status_data, dict)
                    and not duplicate_status_by_infor
                ):
                    infor.status_data = status_data
                    infor.last_status_at = timestamp
                infor.updated_at = datetime.now(timezone.utc)

            if can_update_infor_data:
                snapshot_counter = counter_data if changed_counter else (
                    infor.counter_data if (infor is not None and isinstance(infor.counter_data, dict)) else prev_counter_data
                )
                snapshot_status = status_data if changed_status else (
                    infor.status_data if (infor is not None and isinstance(infor.status_data, dict)) else prev_status_data
                )
                snapshot_counter = snapshot_counter if isinstance(snapshot_counter, dict) else {}
                snapshot_status = snapshot_status if isinstance(snapshot_status, dict) else {}

                latest_history = session.execute(
                    select(DeviceInforHistory)
                    .where(
                        DeviceInforHistory.lead == lead,
                        DeviceInforHistory.lan_uid == lan_uid,
                        DeviceInforHistory.machine_uid == root_mac_id,
                    )
                    .order_by(DeviceInforHistory.updated_at.desc(), DeviceInforHistory.id.desc())
                    .limit(1)
                ).scalar_one_or_none()

                same_counter = False
                same_status = False
                if latest_history is not None:
                    hist_counter = latest_history.counter_data if isinstance(latest_history.counter_data, dict) else {}
                    hist_status = latest_history.status_data if isinstance(latest_history.status_data, dict) else {}
                    same_counter = _normalize_counter_payload(snapshot_counter) == _normalize_counter_payload(hist_counter)
                    same_status = _normalize_status_payload(snapshot_status) == _normalize_status_payload(hist_status)

                if latest_history is not None and same_counter and same_status:
                    # Strict dedupe by lan_uid + machine_uid + (counter,status): touch old row only.
                    latest_history.agent_uid = agent_uid or latest_history.agent_uid
                    latest_history.printer_name = printer_name or latest_history.printer_name
                    latest_history.ip = ip or latest_history.ip
                    latest_history.mac_id = public_mac_id or latest_history.mac_id
                    if counter_data:
                        latest_history.last_counter_at = timestamp
                    if status_data:
                        latest_history.last_status_at = timestamp
                    latest_history.updated_at = datetime.now(timezone.utc)
                else:
                    # Any change in lan_uid/counter/status creates a new history row, keeping old rows.
                    history = DeviceInforHistory(
                        lead=lead,
                        lan_uid=lan_uid,
                        machine_uid=root_mac_id,
                        mac_id=public_mac_id,
                        agent_uid=agent_uid,
                        printer_name=printer_name or (infor.printer_name if infor is not None else "Unknown Printer"),
                        ip=ip or (infor.ip if infor is not None else ""),
                        counter_data=snapshot_counter,
                        status_data=snapshot_status,
                        last_counter_at=timestamp if counter_data else (infor.last_counter_at if infor is not None else None),
                        last_status_at=timestamp if status_data else (infor.last_status_at if infor is not None else None),
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                    )
                    session.add(history)
            session.commit()
        LOGGER.info(
            "polling: lead=%s lan=%s agent=%s printer=%s ip=%s inserted(counter=%s,status=%s) skipped(counter=%s,status=%s,disabled=%s)",
            lead,
            lan_uid,
            agent_uid,
            printer_name or "-",
            ip or "-",
            inserted_counter,
            inserted_status,
            skipped_counter,
            skipped_status,
            skipped_disabled,
        )

        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "printer_name": printer_name,
                "ip": ip,
                "timestamp": timestamp.isoformat(),
                "inserted_counter": inserted_counter,
                "inserted_status": inserted_status,
                "skipped_counter": skipped_counter,
                "skipped_status": skipped_status,
                "skipped_disabled": skipped_disabled,
                "collector_ok": collector_ok,
                "skip_data_update": skip_data_update,
            }
        )

    @app.get("/api/public/crm/printers")
    def public_crm_printers() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error

        with session_factory() as session:
            # Join Printer with AgentNode and LanSite to get full identifiers
            stmt = (
                select(Printer, AgentNode.hostname, LanSite.lan_name)
                .join(AgentNode, (Printer.lead == AgentNode.lead) & (Printer.lan_uid == AgentNode.lan_uid) & (Printer.agent_uid == AgentNode.agent_uid), isouter=True)
                .join(LanSite, (Printer.lead == LanSite.lead) & (Printer.lan_uid == LanSite.lan_uid), isouter=True)
                .where(Printer.lead == lead)
            )
            results = session.execute(stmt).all()

            output = []
            for row in results:
                p: Printer = row[0]
                hostname = row[1] or "Unknown"
                lan_name = row[2] or "Unknown"

                # Get latest counter for this printer
                latest_counter = session.execute(
                    select(CounterInfor)
                    .where(CounterInfor.lead == lead, CounterInfor.lan_uid == p.lan_uid, CounterInfor.ip == p.ip)
                    .order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
                    .limit(1)
                ).scalar_one_or_none()

                # Get latest status for this printer
                latest_status = session.execute(
                    select(StatusInfor)
                    .where(StatusInfor.lead == lead, StatusInfor.lan_uid == p.lan_uid, StatusInfor.ip == p.ip)
                    .order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
                    .limit(1)
                ).scalar_one_or_none()

                # Get baseline to calculate actual counter value
                baseline_row = session.execute(
                    select(CounterBaseline)
                    .where(CounterBaseline.lead == lead, CounterBaseline.lan_uid == p.lan_uid, CounterBaseline.ip == p.ip)
                ).scalar_one_or_none()
                base = baseline_row.raw_payload if baseline_row and isinstance(baseline_row.raw_payload, dict) else {}

                total_bw = 0
                if latest_counter:
                    total_bw = _apply_baseline(latest_counter.total, base, "total") or 0

                output.append({
                    "lan_uid": p.lan_uid,
                    "agent_uid": p.agent_uid,
                    "lan_name": lan_name,
                    "hostname": hostname,
                    "printer_name": p.printer_name,
                    "ip": p.ip,
                    "mac": p.mac_address,
                    "counter": total_bw,
                    "status": latest_status.system_status if latest_status else "Unknown",
                    "alerts": latest_status.printer_alerts if latest_status else "",
                    "toner": latest_status.toner_black if latest_status else "Unknown",
                    "last_seen_at": p.updated_at.isoformat() if p.updated_at else "",
                    **_serialize_audit_payload_iso(p.created_at, p.updated_at),
                })

        return jsonify({"ok": True, "printers": output})

    @app.get("/api/infor/list")
    def infor_list() -> Any:
        lead = _to_text(request.args.get("lead"))
        page = _to_page(request.args.get("page"), 1)
        limit = _to_int(request.args.get("limit"))
        if limit is None:
            limit = 50

        with session_factory() as session:
            _refresh_stale_offline(session=session, lead=lead)
            session.commit()
            
            history_count_stmt = select(func.count()).select_from(DeviceInforHistory)
            history_stmt = select(DeviceInforHistory).order_by(
                DeviceInforHistory.updated_at.desc(), DeviceInforHistory.id.desc()
            )
            if lead:
                history_count_stmt = history_count_stmt.where(DeviceInforHistory.lead == lead)
                history_stmt = history_stmt.where(DeviceInforHistory.lead == lead)
            
            total = session.scalar(history_count_stmt) or 0
            if limit > 0:
                history_stmt = history_stmt.limit(limit).offset((page - 1) * limit)

            history_rows = session.execute(history_stmt).scalars().all()

            rows: list[dict[str, Any]] = []
            if history_rows:
                latest_by_lan_mac: set[tuple[str, str, str]] = set()
                for h in history_rows:
                    counter_data = h.counter_data if isinstance(h.counter_data, dict) else {}
                    status_data = h.status_data if isinstance(h.status_data, dict) else {}
                    if not counter_data and not status_data:
                        continue
                    resolved_mac = _normalize_mac(h.mac_id)
                    if not resolved_mac and _to_text(h.ip):
                        resolved_mac = _resolve_public_mac(
                            session=session,
                            lead=_to_text(h.lead),
                            lan_uid=_to_text(h.lan_uid),
                            ip=_to_text(h.ip),
                            incoming_mac="",
                        )
                    machine_uid = _to_text(h.machine_uid) or resolved_mac or (f"IP:{_to_text(h.ip)}" if _to_text(h.ip) else "")
                    # Strict latest highlight is based on LAN UID + MAC ID.
                    is_latest = False
                    if resolved_mac:
                        latest_key = (_to_text(h.lead), _to_text(h.lan_uid), resolved_mac)
                        if latest_key not in latest_by_lan_mac:
                            latest_by_lan_mac.add(latest_key)
                            is_latest = True
                    rows.append(
                        {
                            "id": int(h.id),
                            "lead": h.lead,
                            "lan_uid": h.lan_uid,
                            "agent_uid": h.agent_uid,
                            "printer_name": h.printer_name,
                            "ip": h.ip,
                            "mac_id": resolved_mac or "unknown",
                            "machine_uid": machine_uid or "unknown",
                            "is_latest": is_latest,
                            "counter": counter_data,
                            "status": status_data,
                            "counter_data": counter_data,
                            "status_data": status_data,
                            "counter_total": _to_int(counter_data.get("total")) or 0,
                            "status_system": _to_text(status_data.get("system_status")) or _to_text(status_data.get("printer_status")),
                            "last_counter_at": h.last_counter_at.isoformat() if h.last_counter_at else "",
                            "last_status_at": h.last_status_at.isoformat() if h.last_status_at else "",
                            **_serialize_audit_payload_iso(h.created_at, h.updated_at),
                        }
                    )
            else:
                # Backward compatibility for environments without history rows yet.
                base_count_stmt = select(func.count()).select_from(DeviceInfor)
                base_stmt = select(DeviceInfor).order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                if lead:
                    base_count_stmt = base_count_stmt.where(DeviceInfor.lead == lead)
                    base_stmt = base_stmt.where(DeviceInfor.lead == lead)
                
                total = session.scalar(base_count_stmt) or 0
                if limit > 0:
                    base_stmt = base_stmt.limit(limit).offset((page - 1) * limit)

                for d in session.execute(base_stmt).scalars().all():
                    counter_data = d.counter_data if isinstance(d.counter_data, dict) else {}
                    status_data = d.status_data if isinstance(d.status_data, dict) else {}
                    if not counter_data and not status_data:
                        continue
                    resolved_mac = _normalize_mac(d.mac_id)
                    if not resolved_mac and _to_text(d.ip):
                        resolved_mac = _resolve_public_mac(
                            session=session,
                            lead=_to_text(d.lead),
                            lan_uid=_to_text(d.lan_uid),
                            ip=_to_text(d.ip),
                            incoming_mac="",
                        )
                    rows.append(
                        {
                            "id": int(d.id),
                            "lead": d.lead,
                            "lan_uid": d.lan_uid,
                            "agent_uid": d.agent_uid,
                            "printer_name": d.printer_name,
                            "ip": d.ip,
                            "mac_id": resolved_mac or "unknown",
                            "machine_uid": _to_text(d.mac_id) or (f"IP:{_to_text(d.ip)}" if _to_text(d.ip) else "unknown"),
                            "is_latest": bool(resolved_mac),
                            "counter": counter_data,
                            "status": status_data,
                            "counter_data": counter_data,
                            "status_data": status_data,
                            "counter_total": _to_int(counter_data.get("total")) or 0,
                            "status_system": _to_text(status_data.get("system_status")) or _to_text(status_data.get("printer_status")),
                            "last_counter_at": d.last_counter_at.isoformat() if d.last_counter_at else "",
                            "last_status_at": d.last_status_at.isoformat() if d.last_status_at else "",
                            **_serialize_audit_payload_iso(d.created_at, d.updated_at),
                        }
                    )
            
            page_size = len(rows)
            total_pages = 1
            if limit > 0:
                total_pages = max(1, (total + limit - 1) // limit)

            return jsonify({
                "rows": rows,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "limit": limit
            })

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
                        **_serialize_audit_payload_iso(row.created_at, row.updated_at),
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
                        **_serialize_audit_payload_iso(row.created_at, row.updated_at),
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

    @app.get("/api/public/device/by-mac")
    def public_device_by_mac() -> Any:
        mac_input = _to_text(request.args.get("mac_id") or request.args.get("mac"))
        if not mac_input:
            return jsonify({"ok": False, "error": "Missing parameter: mac_id"}), 400

        normalized_mac = _normalize_mac(mac_input)
        if not normalized_mac:
            return jsonify({"ok": False, "error": "Invalid mac_id"}), 400

        with session_factory() as session:
            row = session.execute(
                select(DeviceInfor)
                .where(func.upper(DeviceInfor.mac_id) == normalized_mac)
                .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            if row is None:
                printer = session.execute(
                    select(Printer)
                    .where(func.upper(Printer.mac_address) == normalized_mac)
                    .order_by(Printer.updated_at.desc(), Printer.id.desc())
                    .limit(1)
                ).scalar_one_or_none()
                if printer is not None:
                    row = session.execute(
                        select(DeviceInfor)
                        .where(
                            DeviceInfor.lead == printer.lead,
                            DeviceInfor.lan_uid == printer.lan_uid,
                            DeviceInfor.ip == printer.ip,
                        )
                        .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                        .limit(1)
                    ).scalar_one_or_none()
                    if row is None and _to_text(printer.ip):
                        row = session.execute(
                            select(DeviceInfor)
                            .where(
                                DeviceInfor.lead == printer.lead,
                                DeviceInfor.ip == printer.ip,
                            )
                            .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                            .limit(1)
                        ).scalar_one_or_none()

            if row is None:
                return jsonify({"ok": False, "error": "Device not found for mac_id"}), 404

            counter_data = row.counter_data if isinstance(row.counter_data, dict) else {}
            status_data = row.status_data if isinstance(row.status_data, dict) else {}
            return jsonify(
                {
                    "ok": True,
                    "mac_id": normalized_mac,
                    "lead": row.lead,
                    "lan_uid": row.lan_uid,
                    "agent_uid": row.agent_uid,
                    "printer_name": row.printer_name,
                    "ip": row.ip,
                    "counter": counter_data,
                    "status": status_data,
                    "counter_data": counter_data,
                    "status_data": status_data,
                    "last_counter_at": row.last_counter_at.isoformat() if row.last_counter_at else "",
                    "last_status_at": row.last_status_at.isoformat() if row.last_status_at else "",
                    **_serialize_audit_payload_iso(row.created_at, row.updated_at),
                }
            )

    @app.get("/api/public/device/online-status")
    def public_device_online_status() -> Any:
        """
        Check whether a printer/copier is currently online.

        Query params:
          mac_id  (required) – MAC address in any format, e.g. 00:26:73:7D:78:F9 or 00-26-73-7D-78-F9
          stale_seconds (optional) – seconds of silence before considered offline (default: 300)

        Response:
          {
            "ok": true,
            "mac_id": "00:26:73:7D:78:F9",
            "is_online": true,
            "printer_name": "Ricoh MP 3054",
            "ip": "192.168.1.100",
            "lead": "default",
            "lan_uid": "lanf-xxx",
            "last_seen_at": "2026-03-21T05:00:00+00:00",   # last polling timestamp
            "seconds_since_seen": 42,
            "online_source": "polling"   # "polling" | "printer_flag"
          }
        """
        mac_input = _to_text(request.args.get("mac_id") or request.args.get("mac"))
        if not mac_input:
            return jsonify({"ok": False, "error": "Missing parameter: mac_id"}), 400

        stale_seconds = max(30, min(3600, int(request.args.get("stale_seconds", ONLINE_STALE_SECONDS))))
        normalized_mac = _normalize_mac(mac_input)
        if not normalized_mac:
            return jsonify({"ok": False, "error": "Invalid mac_id"}), 400
        now_utc = datetime.now(timezone.utc)
        stale_cutoff = now_utc - timedelta(seconds=stale_seconds)

        with session_factory() as session:
            # ── Step 1: look up DeviceInfor by mac_id ──────────────────────
            dev = session.execute(
                select(DeviceInfor)
                .where(func.upper(DeviceInfor.mac_id) == normalized_mac)
                .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            # ── Step 2: fallback – look up Printer by mac_address ──────────
            printer = session.execute(
                select(Printer)
                .where(func.upper(Printer.mac_address) == normalized_mac)
                .order_by(Printer.updated_at.desc(), Printer.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            if dev is None and printer is None:
                return jsonify({"ok": False, "error": "Device not found"}), 404

            # ── Step 3: derive last_seen_at ────────────────────────────────
            # Prefer DeviceInfor.updated_at (reflects actual polling data)
            # Fallback to Printer.updated_at
            last_seen: datetime | None = None
            if dev is not None and dev.updated_at:
                last_seen = dev.updated_at if dev.updated_at.tzinfo else dev.updated_at.replace(tzinfo=timezone.utc)
            if printer is not None and printer.updated_at:
                p_seen = printer.updated_at if printer.updated_at.tzinfo else printer.updated_at.replace(tzinfo=timezone.utc)
                if last_seen is None or p_seen > last_seen:
                    last_seen = p_seen

            # ── Step 4: determine online status ────────────────────────────
            # Primary: polling freshness (updated_at within stale window)
            is_online_by_polling = last_seen is not None and last_seen >= stale_cutoff
            # Secondary: explicit Printer.is_online flag
            is_online_by_flag = bool(printer.is_online) if printer is not None else None

            # Final verdict: online if EITHER source says online
            is_online = is_online_by_polling or bool(is_online_by_flag)
            online_source = "polling" if is_online_by_polling else ("printer_flag" if is_online_by_flag else "none")

            seconds_since_seen = int((now_utc - last_seen).total_seconds()) if last_seen else None

            # ── Step 5: build response ─────────────────────────────────────
            src = dev or printer  # prefer DeviceInfor for name/ip/lead
            return jsonify({
                "ok": True,
                "mac_id": normalized_mac,
                "is_online": is_online,
                "printer_name": src.printer_name if src else "",
                "ip": src.ip if src else "",
                "lead": src.lead if src else "",
                "lan_uid": src.lan_uid if src else "",
                "last_seen_at": last_seen.isoformat() if last_seen else None,
                "seconds_since_seen": seconds_since_seen,
                "stale_threshold_seconds": stale_seconds,
                "online_source": online_source,
                # extra detail
                "is_online_by_polling": is_online_by_polling,
                "is_online_by_flag": is_online_by_flag,
                **_serialize_audit_payload_iso(
                    getattr(src, "created_at", None),
                    getattr(src, "updated_at", None),
                ),
            })


    @app.get("/api/public/network/by-lan")
    def public_network_by_lan() -> Any:
        lan_uid = _to_text(request.args.get("lan_uid"))
        lead = _to_text(request.args.get("lead"))
        if not lan_uid:
            return jsonify({"ok": False, "error": "Missing parameter: lan_uid"}), 400

        with session_factory() as session:
            stmt = (
                select(DeviceInfor)
                .where(DeviceInfor.lan_uid == lan_uid)
                .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
            )
            if lead:
                stmt = stmt.where(DeviceInfor.lead == lead)
            records = session.execute(stmt).scalars().all()
            if not records:
                return jsonify({"ok": False, "error": "No device found for lan_uid"}), 404

            seen: set[tuple[str, str, str]] = set()
            rows: list[dict[str, Any]] = []
            for row in records:
                mac_id = _to_text(row.mac_id).replace("-", ":").upper()
                dedupe_token = mac_id or f"IP:{_to_text(row.ip)}"
                dedupe_key = (_to_text(row.lead), _to_text(row.lan_uid), dedupe_token)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                counter_data = row.counter_data if isinstance(row.counter_data, dict) else {}
                status_data = row.status_data if isinstance(row.status_data, dict) else {}
                rows.append(
                    {
                        "lead": row.lead,
                        "lan_uid": row.lan_uid,
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
                        **_serialize_audit_payload_iso(row.created_at, row.updated_at),
                    }
                )
            rows.sort(key=lambda x: (_to_text(x.get("lead")), _to_text(x.get("printer_name")), _to_text(x.get("ip"))))
            return jsonify(
                {
                    "ok": True,
                    "lan_uid": lan_uid,
                    "count": len(rows),
                    "rows": rows,
                }
            )

    @app.get("/api/public/device/latest")
    def public_device_latest() -> Any:
        lan_uid = _to_text(request.args.get("lan_uid"))
        mac = _normalize_mac(request.args.get("mac"))

        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error
        if not lan_uid or not mac:
            return jsonify({"ok": False, "error": "Missing parameters: lan_uid, mac"}), 400

        with session_factory() as session:
            # 1. Find the printer by mac and lan_uid
            printer = session.execute(
                select(Printer).where(
                    Printer.lead == lead,
                    Printer.lan_uid == lan_uid,
                    func.upper(Printer.mac_address) == mac
                )
            ).scalar_one_or_none()

            if not printer:
                return jsonify({"ok": False, "error": "Printer not found with given mac and lan_uid"}), 404

            # 2. Get latest counter
            latest_counter = session.execute(
                select(CounterInfor)
                .where(CounterInfor.lead == lead, CounterInfor.lan_uid == lan_uid, CounterInfor.ip == printer.ip)
                .order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            # 3. Get latest status
            latest_status = session.execute(
                select(StatusInfor)
                .where(StatusInfor.lead == lead, StatusInfor.lan_uid == lan_uid, StatusInfor.ip == printer.ip)
                .order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            # 4. Get baseline for counter calculation
            baseline_row = session.execute(
                select(CounterBaseline)
                .where(CounterBaseline.lead == lead, CounterBaseline.lan_uid == lan_uid, CounterBaseline.ip == printer.ip)
            ).scalar_one_or_none()
            base = baseline_row.raw_payload if baseline_row and isinstance(baseline_row.raw_payload, dict) else {}

            # Prepare combined result
            result = {
                "ok": True,
                "printer_name": printer.printer_name,
                "ip": printer.ip,
                "mac": printer.mac_address,
                "lan_uid": printer.lan_uid,
                "last_seen_at": printer.updated_at.isoformat() if printer.updated_at else "",
                "counter": None,
                "status": None,
                **_serialize_audit_payload_iso(printer.created_at, printer.updated_at),
            }

            if latest_counter:
                counter_payload = latest_counter.raw_payload if isinstance(latest_counter.raw_payload, dict) else {}
                combined_counter = {}
                for key in COUNTER_KEYS:
                    val = _apply_baseline(getattr(latest_counter, key, None), base, key)
                    combined_counter[key] = val
                
                result["counter"] = {
                    "timestamp": latest_counter.timestamp.isoformat(),
                    "data": combined_counter,
                    "raw_delta": counter_payload
                }

            if latest_status:
                result["status"] = {
                    "timestamp": latest_status.timestamp.isoformat(),
                    "system_status": latest_status.system_status,
                    "printer_status": latest_status.printer_status,
                    "printer_alerts": latest_status.printer_alerts,
                    "copier_status": latest_status.copier_status,
                    "copier_alerts": latest_status.copier_alerts,
                    "scanner_status": latest_status.scanner_status,
                    "scanner_alerts": latest_status.scanner_alerts,
                    "toner_black": latest_status.toner_black,
                    "tray_1_status": latest_status.tray_1_status,
                    "tray_2_status": latest_status.tray_2_status,
                    "tray_3_status": latest_status.tray_3_status,
                    "bypass_tray_status": latest_status.bypass_tray_status,
                    "other_info": latest_status.other_info,
                    "raw_payload": latest_status.raw_payload
                }

            return jsonify(result)

    def _normalize_user_type(value: object, default: str = UserType.SUPPORT.value, allow_empty: bool = False) -> str:
        raw = _to_text(value).strip().lower()
        if not raw:
            return "" if allow_empty else default
        if raw in {"tech", "technician", "worker"}:
            return UserType.TECH.value
        if raw in {"support", "supplier", "admin", "account", "customer", "leader"}:
            return UserType.SUPPORT.value
        return "" if allow_empty else default

    def _user_type_value(user: UserAccount) -> str:
        return _normalize_user_type(
            getattr(user, "user_type", "") or getattr(user, "role", ""),
            default=UserType.SUPPORT.value,
        )

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
        payload.update(_serialize_audit_payload(task.created_at, task.updated_at))
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
        payload.update(_serialize_audit_payload(user.created_at, user.updated_at))
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
        payload.update(_serialize_audit_payload(net.created_at, net.updated_at))
        return payload
    @app.get("/api/public/agent-machines")
    def public_agent_machines() -> Any:
        lead = _coalesce_request_lead(request.args.get("lead"), lead_key_map)
        agent_uid = _to_text(request.args.get("agent_uid"))
        if not agent_uid:
            return jsonify({"ok": False, "error": "Missing parameter: agent_uid"}), 400

        with session_factory() as session:
            records = session.execute(
                select(DeviceInfor)
                .where(DeviceInfor.lead == lead, DeviceInfor.agent_uid == agent_uid)
                .order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
            ).scalars().all()

            normalized_macs: set[str] = set()
            lan_uids: set[str] = set()
            for row in records:
                normalized = _normalize_mac(row.mac_id)
                if normalized:
                    normalized_macs.add(normalized)
                if row.lan_uid:
                    lan_uids.add(row.lan_uid)

            lan_map: dict[str, LanSite] = {}
            if lan_uids:
                lan_rows = session.execute(
                    select(LanSite).where(LanSite.lead == lead, LanSite.lan_uid.in_(lan_uids))
                ).scalars().all()
                lan_map = {row.lan_uid: row for row in lan_rows}

            network_map: dict[str, NetworkInfo] = {}
            if lan_uids:
                network_rows = session.execute(
                    select(NetworkInfo).where(NetworkInfo.lead == lead, NetworkInfo.lan_uid.in_(lan_uids))
                ).scalars().all()
                for net in network_rows:
                    network_map.setdefault(net.lan_uid, net)

            features_by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
            if normalized_macs:
                feature_rows = session.execute(
                    select(DeviceFeatureFlag).where(
                        DeviceFeatureFlag.lead == lead,
                        DeviceFeatureFlag.mac_id.in_(normalized_macs),
                    )
                ).scalars().all()
                for feature in feature_rows:
                    normalized = _normalize_mac(feature.mac_id) or feature.mac_id
                    features_by_mac[normalized].append(
                        {
                            "feature": feature.feature_name,
                            "enabled": bool(feature.is_enabled),
                            "metadata": feature.metadata,
                            "last_seen_at": _format_datetime(feature.last_seen_at),
                        }
                    )

            alerts_by_mac: dict[str, MachineAlert] = {}
            if normalized_macs:
                alert_rows = session.execute(
                    select(MachineAlert)
                    .where(
                        MachineAlert.lead == lead,
                        MachineAlert.mac_id.in_(normalized_macs),
                        MachineAlert.status != AlertStatus.RESOLVED.value,
                    )
                    .order_by(MachineAlert.triggered_at.desc())
                ).scalars().all()
                for alert in alert_rows:
                    normalized = _normalize_mac(alert.mac_id)
                    if normalized and normalized not in alerts_by_mac:
                        alerts_by_mac[normalized] = alert

            lock_history_by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
            if normalized_macs:
                lock_rows = session.execute(
                    select(DeviceLockHistory)
                    .where(DeviceLockHistory.lead == lead, DeviceLockHistory.mac_id.in_(normalized_macs))
                    .order_by(DeviceLockHistory.event_at.desc())
                ).scalars().all()
                for lock in lock_rows:
                    normalized = _normalize_mac(lock.mac_id)
                    if not normalized:
                        continue
                    history = lock_history_by_mac[normalized]
                    if len(history) >= 3:
                        continue
                    history.append(
                        {
                            "action": lock.action,
                            "reason": lock.reason,
                            "source": lock.source,
                            "event_at": _format_datetime(lock.event_at),
                            "metadata": lock.metadata,
                        }
                    )

            agent_node = session.execute(
                select(AgentNode)
                .where(AgentNode.lead == lead, AgentNode.agent_uid == agent_uid)
                .limit(1)
            ).scalar_one_or_none()

            machines: list[dict[str, Any]] = []
            seen_keys: set[tuple[str, str, str]] = set()
            for row in records:
                normalized_mac = _normalize_mac(row.mac_id)
                machine_mac = normalized_mac or _to_text(row.mac_id)
                dedupe_token = machine_mac or _to_text(row.ip) or row.printer_name
                dedupe_key = (row.lead, row.lan_uid, dedupe_token)
                if dedupe_token and dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)

                counter_data = row.counter_data if isinstance(row.counter_data, dict) else {}
                status_data = row.status_data if isinstance(row.status_data, dict) else {}
                lan_info = lan_map.get(row.lan_uid)
                network_info = network_map.get(row.lan_uid)
                alert_entry = alerts_by_mac.get(normalized_mac) if normalized_mac else None
                auto_alert = (
                    {
                        "severity": alert_entry.severity,
                        "message": alert_entry.message,
                        "status": alert_entry.status,
                        "triggered_at": _format_datetime(alert_entry.triggered_at),
                        "resolved_at": _format_datetime(alert_entry.resolved_at),
                    }
                    if alert_entry
                    else None
                )

                machines.append(
                    {
                        "lead": row.lead,
                        "lan_uid": row.lan_uid,
                        "lan_name": lan_info.lan_name if lan_info else "",
                        "fingerprint_signature": lan_info.fingerprint_signature if lan_info else "",
                        "network": {
                            "network_id": network_info.network_id,
                            "network_name": network_info.network_name,
                            "office_name": network_info.office_name,
                            "real_address": network_info.real_address,
                        }
                        if network_info
                        else {},
                        "agent_uid": row.agent_uid,
                        "printer_name": row.printer_name,
                        "mac_id": machine_mac,
                        "ip": row.ip,
                        "counter_total": _to_int(counter_data.get("total")) or 0,
                        "counter_summary": {
                            "copier_bw": _to_int(counter_data.get("copier_bw")),
                            "printer_bw": _to_int(counter_data.get("printer_bw")),
                            "fax_bw": _to_int(counter_data.get("fax_bw")),
                        },
                        "status": _to_text(status_data.get("system_status") or status_data.get("printer_status")),
                        "alert": _to_text(status_data.get("printer_alerts")),
                        "toner": status_data.get("toner_black") or {},
                        "counter_data": counter_data,
                        "status_data": status_data,
                        "features": features_by_mac.get(normalized_mac or machine_mac, []),
                        "lock_history": lock_history_by_mac.get(normalized_mac or machine_mac, []),
                        "auto_alert": auto_alert,
                        "last_counter_at": _format_datetime(row.last_counter_at),
                        "last_status_at": _format_datetime(row.last_status_at),
                        "updated_at": _format_datetime(row.updated_at),
                        "created_at": _format_date(row.created_at),
                        "createAt": _format_date(row.created_at),
                        "updateAt": _format_datetime(row.updated_at),
                    }
                )

            machines.sort(
                key=lambda item: (
                    _to_text(item.get("lan_name")),
                    _to_text(item.get("printer_name")),
                    _to_text(item.get("ip")),
                )
            )

            return jsonify(
                {
                    "ok": True,
                    "lead": lead,
                    "agent_uid": agent_uid,
                    "agent": {
                        "hostname": _to_text(agent_node.hostname) if agent_node else "",
                        "local_ip": _to_text(agent_node.local_ip) if agent_node else "",
                        "local_mac": _to_text(agent_node.local_mac) if agent_node else "",
                    },
                    "count": len(machines),
                    "machines": machines,
                }
            )

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
                    # Added for compatibility with repairs.html expectations
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

    @app.post("/api/login")
    def api_login() -> Any:
        body = request.get_json(silent=True) or {}
        email = _to_text(body.get("email"))
        password = _to_text(body.get("password"))
        if not email or not password:
            return jsonify({"ok": False, "error": "Email and password are required"}), 400

        with session_factory() as session:
            user = session.execute(
                select(UserAccount).where(UserAccount.email == email)
            ).scalar_one_or_none()

            if not user or user.password != password:
                return jsonify({"ok": False, "error": "Invalid email or password"}), 401

            return jsonify({"ok": True, "user": _serialize_user_model(user)})

    @app.post("/api/login/google")
    def api_login_google() -> Any:
        body = request.get_json(silent=True) or {}
        token = body.get("token")
        if not token:
            return jsonify({"ok": False, "error": "Missing Google token"}), 400
        
        try:
            # In a real setup, we'd verify with google-auth library
            # from google.oauth2 import id_token
            # from google.auth.transport import requests as google_requests
            # idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
            # email = idinfo['email']
            # name = idinfo.get('name', '')
            
            # For demonstration/development, we'll decode the JWT loosely or use a mock verification
            # (In production, ALWAYS use id_token.verify_oauth2_token)
            import base64
            parts = token.split('.')
            if len(parts) != 3: raise ValueError("Invalid token format")
            payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
            email = payload.get('email')
            full_name = payload.get('name', email.split('@')[0])
            
            if not email:
                return jsonify({"ok": False, "error": "Invalid token payload"}), 400

            with session_factory() as session:
                user = session.execute(
                    select(UserAccount).where(UserAccount.email == email)
                ).scalar_one_or_none()
                
                if not user:
                    # Auto-register new Google user
                    user = UserAccount(
                        lead='default',
                        username=email.split('@')[0],
                        email=email,
                        full_name=full_name,
                        password=hashlib.sha256(os.urandom(16)).hexdigest(), # Random password
                        user_type=UserType.TECH.value,
                        role=UserType.TECH.value,
                        is_active=True,
                        notes='Registered via Google'
                    )
                    session.add(user)
                    session.commit()
                    session.refresh(user)
                else:
                    normalized_type = _user_type_value(user)
                    if user.user_type != normalized_type or user.role != normalized_type:
                        user.user_type = normalized_type
                        user.role = normalized_type
                        session.commit()
                        session.refresh(user)
                
                if not user.is_active:
                    return jsonify({"ok": False, "error": "Account is disabled"}), 403
                    
                return jsonify({"ok": True, "user": _serialize_user_model(user)})
        except Exception as e:
            return jsonify({"ok": False, "error": f"Google auth failed: {str(e)}"}), 401

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
            # Password validation
            password = _to_text(body.get("password"))
            if not password:
                return jsonify({"ok": False, "error": "Password is required"}), 400
            
            # 8 chars, upper, lower, special
            import re
            pw_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$"
            if not re.match(pw_regex, password):
                return jsonify({
                    "ok": False, 
                    "error": "Password must be at least 8 characters long, include uppercase, lowercase, and a special character"
                }), 400

            # Check if email exists
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

    DRIVERS_CATALOG_ROOT = Path("storage/drivers")
    _DRIVERS_CACHE: dict[str, Any] = {}

    @app.get("/api/drivers/<brand>")
    def api_get_drivers_catalog(brand: str) -> Any:
        """
        Serve driver catalog JSON for a given brand.
        Brands: ricoh | toshiba | fujifilm
        GET /api/drivers/ricoh
        GET /api/drivers/toshiba
        GET /api/drivers/fujifilm
        """
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

    return app



if __name__ == "__main__":
    _configure_server_logging()
    config = ServerConfig()
    app = create_app()
    LOGGER.info("server start host=%s port=%s debug=%s", config.host, config.port, config.debug)
    app.run(host=config.host, port=config.port, debug=config.debug)
