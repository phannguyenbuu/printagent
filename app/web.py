from __future__ import annotations

import csv
import json
import logging
import re
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, url_for

from app.config import AppConfig
from app.db import create_session_factory
from app.modules.ricoh.service import RicohService
from app.services.config_store import ConfigStore
from app.services.api_client import APIClient, Printer
from app.services.polling_bridge import PollingBridge
from app.services.updater import AutoUpdater
from app.services.ws_client import WSClient


LOGGER = logging.getLogger(__name__)
HISTORY_FILE = Path("storage/data/live_overview_history.csv")
COUNTER_LOG_FILE = Path("storage/data/log_counter.csv")
STATUS_LOG_FILE = Path("storage/data/log_status.csv")
DEVICES_CACHE_FILE = Path("storage/data/devices_cache.json")
SCAN_PROTOCOL_PREFS_FILE = Path("storage/data/scan_protocol_prefs.json")


def _env_snapshot(config: AppConfig, updater: AutoUpdater) -> dict[str, str]:
    return {
        "API_URL": config.api_url,
        "USER_TOKEN": config.user_token,
        "DATABASE_URL": config.database_url,
        "WS_URL": config.get_string("ws.url"),
        "WS_AUTO_CONNECT": str(config.get_bool("ws.auto_connect", False)).lower(),
        "UPDATE_AUTO_APPLY": str(updater.auto_apply).lower(),
        "UPDATE_DEFAULT_COMMAND": updater.default_command,
        "WEBHOOK_MODE": config.get_string("webhook.mode", "listen") or "listen",
        "WEBHOOK_LISTEN_PATH": config.get_string("webhook.listen_path", "/api/update/receive-text") or "/api/update/receive-text",
        "UPDATE_WEBHOOK_TOKEN_SET": "yes" if bool(updater.webhook_token) else "no",
        "TEST_IP": config.get_string("test.ip"),
        "TEST_USER": config.get_string("test.user"),
        "POLLING_ENABLED": str(config.get_bool("polling.enabled", False)).lower(),
        "POLLING_URL": config.get_string("polling.url"),
        "POLLING_LEAD": config.get_string("polling.lead"),
        "POLLING_TOKEN": config.get_string("polling.token"),
        "POLLING_INTERVAL_SECONDS": config.get_string("polling.interval_seconds", "60"),
        "POLLING_LAN_UID": config.get_string("polling.lan_uid"),
        "POLLING_AGENT_UID": config.get_string("polling.agent_uid"),
        "POLLING_SCAN_ENABLED": str(config.get_bool("polling.scan_enabled", True)).lower(),
        "POLLING_SCAN_INTERVAL_SECONDS": config.get_string("polling.scan_interval_seconds", "1"),
        "POLLING_SCAN_DIRS": config.get_string("polling.scan_dirs", "storage/scans/inbox"),
        "POLLING_SCAN_RECURSIVE": str(config.get_bool("polling.scan_recursive", True)).lower(),
    }


def _merge_env_overrides(snapshot: dict[str, str], overrides: dict[str, str]) -> dict[str, str]:
    merged = dict(snapshot)
    for key, value in (overrides or {}).items():
        if key in merged and str(value or "").strip():
            merged[key] = str(value)
    return merged


def _load_printers(api_client: APIClient) -> list[Printer]:
    try:
        return api_client.get_printers()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to fetch printers from API: %s", exc)
        return []


def _extract_ip(value: str) -> str:
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", value or "")
    return match.group(1) if match else ""


def _normalize_ipv4(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.fullmatch(r"(\d{1,3})(?:\.(\d{1,3})){3}", text)
    if not match:
        return ""
    parts = text.split(".")
    if any(int(part) > 255 for part in parts):
        return ""
    return ".".join(str(int(part)) for part in parts)


def _extract_port_link_id(port_name: str) -> str:
    text = str(port_name or "").strip()
    if not text:
        return ""
    # For local/WSD printers without reachable IP, use port identifier as a stable ID fallback.
    return text


def _normalize_mac(value: str) -> str:
    text = str(value or "").strip().replace("-", ":").upper()
    if not text:
        return ""
    if not re.fullmatch(r"[0-9A-F:]{17}", text):
        return ""
    parts = text.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return ""
    if text == "00:00:00:00:00:00":
        return ""
    return text


def _load_scan_protocol_prefs() -> dict[str, str]:
    try:
        if not SCAN_PROTOCOL_PREFS_FILE.exists():
            return {}
        data = json.loads(SCAN_PROTOCOL_PREFS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        normalized: dict[str, str] = {}
        for k, v in data.items():
            ip = _normalize_ipv4(str(k or "").strip())
            protocol = str(v or "").strip()
            if ip and protocol:
                normalized[ip] = protocol
        return normalized
    except Exception:  # noqa: BLE001
        return {}


def _save_scan_protocol_prefs(prefs: dict[str, str]) -> None:
    SCAN_PROTOCOL_PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_PROTOCOL_PREFS_FILE.write_text(json.dumps(prefs, ensure_ascii=True, indent=2), encoding="utf-8")


def _normalize_scan_protocol(value: str) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    if text in {"SMBV1", "SMB1", "SMBV1.0"}:
        return "SMBv1"
    if text in {"SMBV2/3", "SMBV2", "SMB2", "SMBV3", "SMB3"}:
        return "SMBv2/3"
    if text == "FTP":
        return "FTP"
    return ""


def _detect_scan_protocol_from_html(html: str) -> str:
    text = str(html or "").lower()
    has_smbv1 = any(token in text for token in ["smbv1", "smb v1", "smb1", "nt1"])
    has_smbv23 = any(token in text for token in ["smbv2", "smb v2", "smb2", "smbv3", "smb v3", "smb3", "cifs"])
    has_ftp = "ftp" in text
    if has_smbv23:
        return "SMBv2/3"
    if has_smbv1:
        return "SMBv1"
    if has_ftp:
        return "FTP"
    return ""


def _load_neighbor_mac_map() -> dict[str, str]:
    script = r"""
$ErrorActionPreference='Stop'
Get-NetNeighbor -AddressFamily IPv4 |
  Select-Object IPAddress,LinkLayerAddress,State |
  ConvertTo-Json -Depth 4
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
        payload = _safe_json_load(result.stdout)
        if isinstance(payload, dict):
            payload = [payload]
        if isinstance(payload, list):
            mapping: dict[str, str] = {}
            for item in payload:
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("IPAddress", "") or "").strip()
                mac = _normalize_mac(str(item.get("LinkLayerAddress", "") or ""))
                if ip and mac:
                    mapping[ip] = mac
            if mapping:
                return mapping
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("Get-NetNeighbor lookup failed: %s", exc)

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("arp lookup failed: %s", exc)
        return {}

    mapping: dict[str, str] = {}
    for line in result.stdout.splitlines():
        match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})\s+\w+", line)
        if not match:
            continue
        ip = match.group(1)
        mac = _normalize_mac(match.group(2))
        if mac:
            mapping[ip] = mac
    return mapping


def _resolve_device_machine_ids(service: RicohService, devices: list[Printer]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for device in devices:
        ip = str(device.ip or "").strip()
        if not ip:
            continue
        if str(device.printer_type or "").strip().lower() != "ricoh":
            continue
        try:
            payload = service.process_device_info(device, should_post=False)
            info = payload.get("device_info", {}) if isinstance(payload, dict) else {}
            if not isinstance(info, dict):
                continue
            machine_id = str(info.get("machine_id", "") or "").strip()
            if machine_id:
                mapping[ip] = machine_id
                continue
            mac_address = _normalize_mac(str(info.get("mac_address", "") or ""))
            if mac_address:
                mapping[ip] = mac_address
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Cannot resolve machine_id for %s (%s): %s", device.name, ip, exc)
    return mapping


def _save_devices_cache(devices: list[dict[str, Any]]) -> None:
    _ensure_parent(DEVICES_CACHE_FILE)
    payload = {
        "cached_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "devices": devices,
    }
    DEVICES_CACHE_FILE.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


def _load_devices_cache() -> tuple[list[dict[str, Any]], str]:
    if not DEVICES_CACHE_FILE.exists():
        return [], ""
    try:
        payload = json.loads(DEVICES_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return [], ""
    if not isinstance(payload, dict):
        return [], ""
    cached_devices = payload.get("devices", [])
    cached_at = str(payload.get("cached_at", "") or "")
    if isinstance(cached_devices, list):
        return cached_devices, cached_at
    return [], ""


def _safe_json_load(raw: str) -> Any:
    text = (raw or "").strip()
    if not text:
        return []
    try:
        import json

        return json.loads(text)
    except Exception:  # noqa: BLE001
        return []


def _load_local_windows_printers() -> list[dict[str, Any]]:
    script = r"""
$ErrorActionPreference='Stop'
$printers = Get-Printer | Select-Object Name,DriverName,PortName,PrinterStatus,WorkOffline,Type,Shared
$ports = Get-PrinterPort | Select-Object Name,PrinterHostAddress,PortMonitor
[PSCustomObject]@{
  printers = $printers
  ports = $ports
} | ConvertTo-Json -Depth 6
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Cannot read local Windows printers: %s", exc)
        return []

    payload = _safe_json_load(result.stdout)
    if not isinstance(payload, dict):
        return []

    raw_printers = payload.get("printers", [])
    raw_ports = payload.get("ports", [])
    if isinstance(raw_printers, dict):
        raw_printers = [raw_printers]
    if isinstance(raw_ports, dict):
        raw_ports = [raw_ports]

    port_map: dict[str, dict[str, Any]] = {}
    for port in raw_ports:
        if not isinstance(port, dict):
            continue
        name = str(port.get("Name", "") or "")
        if not name:
            continue
        port_map[name] = port

    devices: list[dict[str, Any]] = []
    for item in raw_printers:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name", "") or "")
        port_name = str(item.get("PortName", "") or "")
        status_raw = str(item.get("PrinterStatus", "") or "")
        work_offline = bool(item.get("WorkOffline", False))
        port_info = port_map.get(port_name, {})
        host_addr = str(port_info.get("PrinterHostAddress", "") or "")
        port_monitor = str(port_info.get("PortMonitor", "") or "")
        # Read printer IP directly from PrinterHostAddress.
        ip = _normalize_ipv4(host_addr)

        connection_type = "unknown"
        upper_port = port_name.upper()
        if "USB" in upper_port or "DOT4" in upper_port:
            connection_type = "usb"
        elif ip:
            connection_type = "ip"
        elif "WSD" in upper_port:
            connection_type = "wsd"

        status = "offline" if work_offline else "online"
        if status_raw and status_raw.lower() in {"error", "degraded", "stopped"}:
            status = "offline"

        devices.append(
            {
                "id": 0,
                "name": name or "Local Printer",
                "ip": ip,
                "mac_id": _extract_port_link_id(port_name),
                "type": "windows-local",
                "status": status,
                "user": "",
                "port_name": port_name,
                "port_monitor": port_monitor,
                "connection_type": connection_type,
                "source": "local",
                "printer_status_raw": status_raw,
            }
        )
    return devices


def _should_ignore_device(name: str, ignored_prefixes: list[str]) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    for prefix in ignored_prefixes:
        pref = str(prefix or "").strip().lower()
        if pref and lowered.startswith(pref):
            return True
    return False


def _scan_devices_payload(
    config: AppConfig,
    api_client: APIClient,
    ricoh_service: RicohService,
    ignored_prefixes: list[str],
    filter_mode: str = "all",
) -> list[dict[str, Any]]:
    def dedupe_key(item: dict[str, Any]) -> str:
        ip_val = str(item.get("ip", "") or "").strip()
        if ip_val:
            return f"ip:{ip_val}"
        name_val = str(item.get("name", "") or "").strip().lower()
        port_val = str(item.get("port_name", "") or "").strip().lower()
        return f"name:{name_val}|port:{port_val}"

    valid_only = str(filter_mode or "").strip().lower() == "valid_only"
    api_devices = _load_printers(api_client)
    local_devices = _load_local_windows_printers()
    neighbor_mac_map = _load_neighbor_mac_map()
    machine_id_map = _resolve_device_machine_ids(ricoh_service, api_devices)

    api_payload = [
        {
            "id": p.id,
            "name": p.name or "Printer",
            "ip": p.ip,
            # Keep field name mac_id for UI compatibility, but value follows legacy ref logic (machine_id).
            "mac_id": machine_id_map.get(p.ip, neighbor_mac_map.get(p.ip, "")),
            "type": p.printer_type or "unknown",
            "status": p.status or "unknown",
            "user": p.user,
            "port_name": "",
            "port_monitor": "",
            "connection_type": "ip" if p.ip else "unknown",
            "source": "api",
        }
        for p in api_devices
        if p.ip and (not valid_only or not _should_ignore_device(p.name, ignored_prefixes))
    ]

    payload: list[dict[str, Any]] = []
    existing_keys: set[str] = set()

    # Keep API rows first and unique (prefer API over local for same IP/name).
    for row in api_payload:
        key = dedupe_key(row)
        if key in existing_keys:
            continue
        payload.append(row)
        existing_keys.add(key)

    for local in local_devices:
        key = dedupe_key(local)
        if key in existing_keys:
            continue
        if valid_only and _should_ignore_device(str(local.get("name", "")), ignored_prefixes):
            continue
        ip = str(local.get("ip", "") or "")
        if ip:
            resolved = machine_id_map.get(ip, neighbor_mac_map.get(ip, ""))
            if resolved:
                local["mac_id"] = resolved
        payload.append(local)
        existing_keys.add(key)
    return payload


def _to_int(value: str | int | None) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return 0


def _resolve_printer(ip: str, devices: list[Printer]) -> Printer | None:
    return next((p for p in devices if p.ip == ip), None)


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _append_history(copier: int, printer: int, scanner: int, active: int, offline: int, total: int) -> None:
    _ensure_parent(HISTORY_FILE)
    new_file = not HISTORY_FILE.exists()
    with HISTORY_FILE.open("a", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        if new_file:
            writer.writerow(["timestamp", "copier_pages", "print_pages", "scan_pages", "active", "offline", "total"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), copier, printer, scanner, active, offline, total])


def _read_history(limit: int = 7) -> tuple[list[str], list[int], list[int], list[int]]:
    if not HISTORY_FILE.exists():
        return ([], [], [], [])
    with HISTORY_FILE.open("r", newline="", encoding="utf-8") as fp:
        rows = list(csv.DictReader(fp))
    rows = rows[-limit:]
    labels = [r["timestamp"][5:16] for r in rows]
    copier = [_to_int(r.get("copier_pages")) for r in rows]
    printer = [_to_int(r.get("print_pages")) for r in rows]
    scanner = [_to_int(r.get("scan_pages")) for r in rows]
    return labels, copier, printer, scanner


def _build_live_overview(service: RicohService, devices: list[Printer]) -> dict[str, Any]:
    ricoh_devices = [d for d in devices if d.ip and d.printer_type.lower() == "ricoh"]
    copier_pages = 0
    print_pages = 0
    scan_pages = 0
    active_count = 0
    alert_count = {"low_toner": 0, "paper_warning": 0, "scanner_notice": 0}
    details: list[dict[str, Any]] = []

    for printer in ricoh_devices:
        device_row: dict[str, Any] = {"name": printer.name, "ip": printer.ip, "ok": False}
        try:
            counter_payload = service.process_counter(printer, should_post=False)
            status_payload = service.process_status(printer, should_post=False)

            counter = counter_payload.get("counter_data", {})
            status = status_payload.get("status_data", {})

            copier_pages += _to_int(counter.get("copier_bw"))
            print_pages += _to_int(counter.get("printer_bw"))
            scan_pages += _to_int(counter.get("scanner_send_bw")) + _to_int(counter.get("scanner_send_color"))

            system_status = status.get("system_status", "")
            if system_status == "OK":
                active_count += 1

            if status.get("toner_black", "") != "OK":
                alert_count["low_toner"] += 1
            if any(k.startswith("tray_") and "status" in k for k in status):
                paper_values = [str(v).lower() for k, v in status.items() if k.startswith("tray_") and k.endswith("_status")]
                if any("empty" in v or "near" in v or "alert" in v for v in paper_values):
                    alert_count["paper_warning"] += 1
            if "scanner_alerts" in status:
                alert_count["scanner_notice"] += 1

            device_row["ok"] = True
            device_row["counter"] = {
                "copier_bw": counter.get("copier_bw", ""),
                "printer_bw": counter.get("printer_bw", ""),
                "scanner_send_bw": counter.get("scanner_send_bw", ""),
                "scanner_send_color": counter.get("scanner_send_color", ""),
            }
            device_row["status"] = status
        except Exception as exc:  # noqa: BLE001
            device_row["error"] = str(exc)
        details.append(device_row)

    total = len(ricoh_devices)
    offline = max(total - active_count, 0)
    _append_history(copier_pages, print_pages, scan_pages, active_count, offline, total)
    labels, copier_hist, print_hist, scan_hist = _read_history(limit=7)

    return {
        "stats": {
            "total_devices": total,
            "ricoh_devices": total,
            "active_devices": active_count,
            "offline_devices": offline,
            "copier_pages_total": copier_pages,
            "print_pages_total": print_pages,
            "scan_pages_total": scan_pages,
        },
        "trend": {
            "labels": labels,
            "copier_pages": copier_hist,
            "print_pages": print_hist,
            "scan_pages": scan_hist,
        },
        "alerts": [
            {"title": "Low toner", "count": alert_count["low_toner"]},
            {"title": "Paper tray warning", "count": alert_count["paper_warning"]},
            {"title": "Scanner notice", "count": alert_count["scanner_notice"]},
        ],
        "live_devices": details,
    }


def _counter_worker(service: RicohService, printer: Printer, stop_event: threading.Event) -> None:
    _ensure_parent(COUNTER_LOG_FILE)
    new_file = not COUNTER_LOG_FILE.exists()
    with COUNTER_LOG_FILE.open("a", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        if new_file:
            writer.writerow(
                [
                    "timestamp",
                    "printer_name",
                    "printer_ip",
                    "total",
                    "copier_bw",
                    "printer_bw",
                    "scanner_send_bw",
                    "scanner_send_color",
                ]
            )
        while not stop_event.is_set():
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                parsed = service.parse_counter(service.read_counter(printer))
                writer.writerow(
                    [
                        now,
                        printer.name,
                        printer.ip,
                        parsed.get("total", ""),
                        parsed.get("copier_bw", ""),
                        parsed.get("printer_bw", ""),
                        parsed.get("scanner_send_bw", ""),
                        parsed.get("scanner_send_color", ""),
                    ]
                )
            except Exception as exc:  # noqa: BLE001
                writer.writerow([now, printer.name, printer.ip, "ERROR", str(exc), "", "", ""])
            fp.flush()
            stop_event.wait(60)


def _status_worker(service: RicohService, printer: Printer, stop_event: threading.Event) -> None:
    _ensure_parent(STATUS_LOG_FILE)
    new_file = not STATUS_LOG_FILE.exists()
    with STATUS_LOG_FILE.open("a", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        if new_file:
            writer.writerow(
                [
                    "timestamp",
                    "printer_name",
                    "printer_ip",
                    "system_status",
                    "printer_status",
                    "printer_alerts",
                    "copier_status",
                    "copier_alerts",
                    "scanner_status",
                    "scanner_alerts",
                    "toner_black",
                    "tray_1_status",
                    "tray_2_status",
                    "tray_3_status",
                    "bypass_tray_status",
                    "other_info",
                ]
            )
        while not stop_event.is_set():
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                status_data = service.parse_status(service.read_status(printer))
                writer.writerow(service._prepare_csv_row(now, printer, status_data))
            except Exception as exc:  # noqa: BLE001
                writer.writerow([now, printer.name, printer.ip, "ERROR", str(exc), "", "", "", "", "", "", "", "", "", "", ""])
            fp.flush()
            stop_event.wait(30)


def _start_job(jobs: dict[str, dict[str, Any]], key: str, target: Any) -> tuple[bool, str]:
    existing = jobs.get(key)
    if existing and existing["thread"].is_alive():
        return True, "Job already running"
    stop_event = threading.Event()
    thread = threading.Thread(target=target, args=(stop_event,), daemon=True)
    jobs[key] = {"thread": thread, "stop": stop_event, "started_at": datetime.now().isoformat(timespec="seconds")}
    thread.start()
    return True, "Started"


def _stop_job(jobs: dict[str, dict[str, Any]], key: str) -> tuple[bool, str]:
    existing = jobs.get(key)
    if not existing:
        return False, "Job not running"
    existing["stop"].set()
    return True, "Stopped"


def create_app(config_path: str = "config.yaml") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    config = AppConfig.load(config_path)
    session_factory = create_session_factory(config.database_url)
    config_store = ConfigStore(session_factory)
    config_store.create_tables()
    api_client = APIClient(config)
    ricoh_service = RicohService(api_client)
    polling_bridge = PollingBridge(config, api_client, ricoh_service)
    updater = AutoUpdater(project_root=Path(__file__).resolve().parents[1])

    def _on_ws_message(message: str) -> None:
        ok, note = updater.handle_text_message(message, source="ws")
        if ok:
            LOGGER.info("Updater signal handled from ws: %s", note)
        else:
            LOGGER.warning("Updater signal failed from ws: %s", note)

    ws_client = WSClient(
        url=config.get_string("ws.url"),
        token=config.get_string("ws.token"),
        on_message_callback=_on_ws_message,
    )

    app.config["APP_CONFIG"] = config
    app.config["API_CLIENT"] = api_client
    app.config["RICOH_SERVICE"] = ricoh_service
    app.config["POLLING_BRIDGE"] = polling_bridge
    app.config["WS_CLIENT"] = ws_client
    app.config["UPDATER"] = updater
    app.config["CONFIG_STORE"] = config_store
    app.config["LOG_JOBS"] = {"counter": {}, "status": {}}

    if config.get_bool("ws.auto_connect", False) and ws_client.is_configured():
        ok, msg = ws_client.connect()
        LOGGER.info("WebSocket auto-connect: %s (%s)", ok, msg)

    p_ok, p_msg = polling_bridge.start()
    LOGGER.info("Polling bridge: %s (%s)", p_ok, p_msg)

    @app.get("/")
    def index() -> Any:
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard() -> Any:
        return render_template("dashboard.html", active_tab="dashboard", page_title="Config")

    @app.get("/api/dashboard/config")
    def api_dashboard_config() -> Any:
        store: ConfigStore = app.config["CONFIG_STORE"]
        app_cfg: AppConfig = app.config["APP_CONFIG"]
        payload = store.get_dashboard_payload()
        env_payload = _merge_env_overrides(_env_snapshot(app_cfg, updater), payload.env_overrides)
        return jsonify(
            {
                "env": env_payload,
                "network": payload.network,
                "computers": payload.computers,
                "printers": payload.printers,
                "links": payload.links,
                "env_overrides": payload.env_overrides,
                "device_filters": payload.device_filters,
            }
        )

    @app.post("/api/dashboard/env")
    def api_dashboard_env() -> Any:
        body = request.get_json(silent=True) or {}
        store: ConfigStore = app.config["CONFIG_STORE"]
        saved = store.save_env_overrides(body)
        return jsonify({"ok": True, "env_overrides": saved})

    @app.post("/api/dashboard/device-filters")
    def api_dashboard_device_filters() -> Any:
        body = request.get_json(silent=True) or {}
        prefixes = str(body.get("ignore_printer_prefixes", "") or "")
        filter_mode = str(body.get("filter_mode", "all") or "all")
        store: ConfigStore = app.config["CONFIG_STORE"]
        saved = store.save_ignore_printer_prefixes(prefixes)
        mode_saved = store.save_device_filter_mode(filter_mode)
        if DEVICES_CACHE_FILE.exists():
            DEVICES_CACHE_FILE.unlink(missing_ok=True)
        return jsonify(
            {
                "ok": True,
                "device_filters": {
                    "ignore_printer_prefixes": saved,
                    "filter_mode": mode_saved,
                },
            }
        )

    @app.post("/api/dashboard/network")
    def api_dashboard_network() -> Any:
        body = request.get_json(silent=True) or {}
        store: ConfigStore = app.config["CONFIG_STORE"]
        store.save_network(body)
        return jsonify({"ok": True})

    @app.post("/api/dashboard/computers")
    def api_dashboard_add_computer() -> Any:
        body = request.get_json(silent=True) or {}
        if not str(body.get("name", "")).strip():
            return jsonify({"ok": False, "error": "Missing computer name"}), 400
        store: ConfigStore = app.config["CONFIG_STORE"]
        row = store.add_computer(body)
        return jsonify({"ok": True, "computer": row})

    @app.delete("/api/dashboard/computers/<int:computer_id>")
    def api_dashboard_remove_computer(computer_id: int) -> Any:
        store: ConfigStore = app.config["CONFIG_STORE"]
        if not store.remove_computer(computer_id):
            return jsonify({"ok": False, "error": "Computer not found"}), 404
        return jsonify({"ok": True})

    @app.post("/api/dashboard/printers")
    def api_dashboard_add_printer() -> Any:
        body = request.get_json(silent=True) or {}
        if not str(body.get("name", "")).strip():
            return jsonify({"ok": False, "error": "Missing printer name"}), 400
        store: ConfigStore = app.config["CONFIG_STORE"]
        row = store.add_printer(body)
        return jsonify({"ok": True, "printer": row})

    @app.delete("/api/dashboard/printers/<int:printer_id>")
    def api_dashboard_remove_printer(printer_id: int) -> Any:
        store: ConfigStore = app.config["CONFIG_STORE"]
        if not store.remove_printer(printer_id):
            return jsonify({"ok": False, "error": "Printer not found"}), 404
        return jsonify({"ok": True})

    @app.put("/api/dashboard/links")
    def api_dashboard_replace_links() -> Any:
        body = request.get_json(silent=True) or {}
        links = body.get("links", [])
        if not isinstance(links, list):
            return jsonify({"ok": False, "error": "links must be a list"}), 400
        store: ConfigStore = app.config["CONFIG_STORE"]
        total = store.replace_links(links)
        return jsonify({"ok": True, "total_links": total})

    @app.get("/devices")
    def devices() -> Any:
        return render_template("devices.html", active_tab="devices", page_title="Device Manager")

    @app.get("/scan")
    def scan() -> Any:
        return render_template("scan.html", active_tab="scan", page_title="Scan")

    @app.get("/analytics")
    def analytics() -> Any:
        return render_template("analytics.html", active_tab="analytics", page_title="Counter Analytics")

    @app.get("/settings")
    def settings() -> Any:
        return redirect(url_for("dashboard"))

    def _resolve_target_printer(ip: str, user: str = "", password: str = "") -> Printer:
        devices = _load_printers(api_client)
        target = _resolve_printer(ip, devices)
        if not target:
            target = Printer(
                name="Local Printer",
                ip=ip,
                user=config.get_string("test.user"),
                password=config.get_string("test.password"),
                printer_type="ricoh",
                status="unknown",
            )
        if str(user or "").strip():
            target.user = str(user).strip()
        if str(password or "").strip():
            target.password = str(password).strip()
        if not str(target.user or "").strip():
            target.user = config.get_string("test.user")
        if target.password is None or str(target.password).strip() == "":
            target.password = config.get_string("test.password")
        return target

    @app.get("/api/scan/address-list")
    def api_scan_address_list() -> Any:
        ip = str(request.args.get("ip", "")).strip()
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        mode = str(request.args.get("mode", "")).strip().lower()
        trace_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        if not ip:
            LOGGER.warning("Scan address list rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        LOGGER.info(
            "Scan address list request: trace_id=%s ip=%s mode=%s user_provided=%s password_provided=%s remote_addr=%s",
            trace_id,
            ip,
            mode or "-",
            bool(user),
            bool(password),
            request.remote_addr or "-",
        )
        if mode == "adrslistall":
            try:
                # Popup Scan tab uses fixed credential as requested.
                effective_user = "admin"
                effective_password = "admin"
                target = _resolve_target_printer(ip=ip, user=effective_user, password=effective_password)
                target.user = effective_user
                target.password = effective_password
                session = ricoh_service.create_http_client_auth_form_only(target)
                html = ricoh_service.authenticate_and_get(session, target, "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL")
                if ("Address List" not in html and "adrsList" not in html) or "login.cgi" in html:
                    html = ricoh_service.authenticate_and_get(session, target, "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL")
                entries = ricoh_service.parse_address_list(html)
                ajax_raw = ""
                ajax_entries = []
                try:
                    ajax_raw = ricoh_service.get_address_list_ajax_with_client(session, target)
                    ajax_entries = ricoh_service.parse_ajax_address_list(ajax_raw)
                    if ajax_entries:
                        summary = entries[0] if entries else None
                        merged_by_reg: dict[str, Any] = {}
                        merged_order: list[str] = []

                        def _score(item: Any) -> int:
                            score = 0
                            if str(getattr(item, "name", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "email_address", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "folder", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            if str(getattr(item, "user_code", "") or "").strip() not in {"", "-", "---"}:
                                score += 1
                            return score

                        for source in [entries[1:] if len(entries) > 1 else [], ajax_entries]:
                            for item in source:
                                reg = str(getattr(item, "registration_no", "") or "").strip()
                                name_key = str(getattr(item, "name", "") or "").strip().lower()
                                if reg and reg != "-":
                                    # Some devices may return duplicated registration_no for newly-created rows.
                                    # Keep per (registration_no, name) so we do not collapse distinct entries.
                                    key = f"reg::{reg}::name::{name_key}"
                                else:
                                    key = f"name::{name_key}"
                                if key not in merged_by_reg:
                                    merged_by_reg[key] = item
                                    merged_order.append(key)
                                else:
                                    if _score(item) >= _score(merged_by_reg[key]):
                                        merged_by_reg[key] = item

                        merged_entries = [merged_by_reg[key] for key in merged_order]
                        entries = ([summary] if summary else []) + merged_entries
                except Exception:  # noqa: BLE001
                    ajax_raw = ""
                    ajax_entries = []
                # If LIST_ALL + AJAX still yields only summary, fallback to full parser flow.
                non_summary = max(0, len(entries) - 1)
                if non_summary == 0:
                    try:
                        fallback_payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                        if isinstance(fallback_payload, dict):
                            fallback_payload.setdefault("debug", {})
                            if isinstance(fallback_payload["debug"], dict):
                                fallback_payload["debug"]["mode"] = "adrsListAll_fallback_process_address_list"
                                fallback_payload["debug"]["trace_id"] = trace_id
                        return jsonify({"ok": True, "payload": fallback_payload})
                    except Exception:  # noqa: BLE001
                        pass
                payload = {
                    "printer_name": target.name,
                    "ip": target.ip,
                    "html": html,
                    "easysecurity_html": "",
                    "address_list": [
                        {
                            "type": item.type,
                            "registration_no": item.registration_no,
                            "name": item.name,
                            "user_code": item.user_code,
                            "date_last_used": item.date_last_used,
                            "email_address": item.email_address,
                            "folder": item.folder,
                            "entry_id": getattr(item, "entry_id", "") or "",
                        }
                        for item in entries
                    ],
                    "debug": {
                        "trace_id": trace_id,
                        "mode": "adrsListAll",
                        "html_len": len(html),
                        "entries": len(entries),
                        "ajax_len": len(ajax_raw),
                        "ajax_entries": len(ajax_entries),
                    },
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
                return jsonify({"ok": True, "payload": payload})
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Scan address list adrsListAll failed: trace_id=%s ip=%s", trace_id, ip)
                return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

        def _looks_like_login_endpoint_500(exc: Exception) -> bool:
            text = str(exc or "").lower()
            return (
                "500 server error" in text
                and "login.cgi" in text
                and "websys/webarch" in text
            )
        try:
            # Force login-first flow for address list: if caller does not provide credentials,
            # default to admin/admin before fetching address list.
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = _resolve_target_printer(ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            LOGGER.info(
                "Scan address list single attempt: trace_id=%s ip=%s printer_name=%s effective_user=%s has_password=%s",
                trace_id,
                target.ip,
                target.name,
                bool(str(target.user or "").strip()),
                bool(str(target.password or "").strip()),
            )
            payload = ricoh_service.process_address_list(target, trace_id=trace_id)
            if isinstance(payload, dict):
                payload.setdefault("debug", {})
                if isinstance(payload["debug"], dict):
                    payload["debug"]["trace_id"] = trace_id
                    payload["debug"]["auth_mode"] = "single_attempt"
                    payload["debug"]["auth_round"] = 1
            return jsonify({"ok": True, "payload": payload})
        except Exception as exc:  # noqa: BLE001
            if _looks_like_login_endpoint_500(exc):
                LOGGER.warning(
                    "Scan address list login endpoint 500, fallback to no-auth: trace_id=%s ip=%s",
                    trace_id,
                    ip,
                )
                try:
                    target = _resolve_target_printer(ip=ip, user="", password="")
                    target.user = ""
                    target.password = ""
                    payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                    if isinstance(payload, dict):
                        payload.setdefault("debug", {})
                        if isinstance(payload["debug"], dict):
                            payload["debug"]["trace_id"] = trace_id
                            payload["debug"]["auth_mode"] = "fallback_no_auth_after_login_500"
                            payload["debug"]["auth_round"] = 2
                    return jsonify({"ok": True, "payload": payload})
                except Exception as fallback_exc:  # noqa: BLE001
                    LOGGER.exception(
                        "Scan address list fallback no-auth failed: trace_id=%s ip=%s",
                        trace_id,
                        ip,
                    )
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": str(fallback_exc),
                                "trace_id": trace_id,
                                "primary_error": str(exc),
                            }
                        ),
                        500,
                    )
            LOGGER.exception("Scan address list failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-create")
    def api_scan_address_create() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-create-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip:
            LOGGER.warning("Scan address create rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not name:
            LOGGER.warning("Scan address create rejected: trace_id=%s ip=%s reason=missing_name", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing name"}), 400
        if fields is not None and not isinstance(fields, dict):
            LOGGER.warning("Scan address create rejected: trace_id=%s ip=%s reason=invalid_fields_type", trace_id, ip)
            return jsonify({"ok": False, "error": "fields must be object"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address create request: trace_id=%s ip=%s name=%s email_set=%s folder_set=%s user_code_set=%s fields_count=%s auth_mode=%s",
                trace_id,
                ip,
                name,
                bool(email),
                bool(folder),
                bool(user_code),
                len(fields) if isinstance(fields, dict) else 0,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = _resolve_target_printer(ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            merged_fields: dict[str, Any] = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            payload = ricoh_service.create_address_user_wizard(
                target,
                name=name,
                email=email,
                folder=folder,
                user_code=user_code,
                fields=merged_fields,
            )
            LOGGER.info(
                "Scan address create success: trace_id=%s ip=%s http_status=%s verify_count=%s",
                trace_id,
                ip,
                payload.get("http_status") if isinstance(payload, dict) else "-",
                payload.get("verify_count") if isinstance(payload, dict) else "-",
            )
            return jsonify({"ok": True, "payload": payload, "trace_id": trace_id})
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address create failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-delete")
    def api_scan_address_delete() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-delete-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        confirm = bool(body.get("confirm", False))
        if not ip:
            LOGGER.warning("Scan address delete rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not registration_no and not entry_id:
            LOGGER.warning("Scan address delete rejected: trace_id=%s ip=%s reason=missing_registration_no", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing registration_no or entry_id"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address delete request: trace_id=%s ip=%s registration_no=%s entry_id=%s auth_mode=%s",
                trace_id,
                ip,
                registration_no,
                entry_id,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = _resolve_target_printer(ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            payload = ricoh_service.delete_address_entries(
                target,
                [registration_no],
                entry_ids=[entry_id] if entry_id else None,
                verify=not confirm,
            )
            LOGGER.info(
                "Scan address delete success: trace_id=%s ip=%s deleted_count=%s",
                trace_id,
                ip,
                payload.get("deleted_count") if isinstance(payload, dict) else "-",
            )
            return jsonify({"ok": True, "payload": payload, "trace_id": trace_id})
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address delete failed: trace_id=%s ip=%s registration_no=%s", trace_id, ip, registration_no)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-modify")
    def api_scan_address_modify() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-modify-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip:
            LOGGER.warning("Scan address modify rejected: trace_id=%s reason=missing_ip", trace_id)
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not registration_no:
            LOGGER.warning("Scan address modify rejected: trace_id=%s ip=%s reason=missing_registration_no", trace_id, ip)
            return jsonify({"ok": False, "error": "Missing registration_no"}), 400
        if fields is not None and not isinstance(fields, dict):
            LOGGER.warning("Scan address modify rejected: trace_id=%s ip=%s reason=invalid_fields_type", trace_id, ip)
            return jsonify({"ok": False, "error": "fields must be object"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            LOGGER.info(
                "Scan address modify request: trace_id=%s ip=%s registration_no=%s name_set=%s email_set=%s folder_set=%s user_code_set=%s fields_count=%s auth_mode=%s",
                trace_id,
                ip,
                registration_no,
                bool(name),
                bool(email),
                bool(folder),
                bool(user_code),
                len(fields) if isinstance(fields, dict) else 0,
                "default_admin" if not user and not password else "provided_or_partial",
            )
            target = _resolve_target_printer(ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            LOGGER.info(
                "Scan address modify (recreate) request: trace_id=%s ip=%s registration_no=%s entry_id=%s",
                trace_id,
                ip,
                registration_no,
                entry_id,
            )
            if entry_id:
                ricoh_service.delete_address_entries(target, [registration_no], entry_ids=[entry_id], verify=False)
            else:
                ricoh_service.delete_address_entries(target, [registration_no], verify=False)
            create_payload = ricoh_service.create_address_user_wizard(
                target,
                name=name,
                email=email,
                folder=folder,
                user_code=user_code,
                fields=fields if isinstance(fields, dict) else None,
                desired_registration_no=registration_no,
                allow_auto_update=False,
            )
            return jsonify(
                {
                    "ok": True,
                    "payload": create_payload,
                    "trace_id": trace_id,
                    "recreated": True,
                    "message": "Entry recreated (requested to keep registration_no when possible).",
                }
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Scan address modify failed: trace_id=%s ip=%s registration_no=%s", trace_id, ip, registration_no)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.get("/api/scan/protocol")
    def api_scan_protocol_get() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        prefs = _load_scan_protocol_prefs()
        saved = _normalize_scan_protocol(prefs.get(ip, ""))
        detected = ""
        try:
            target = _resolve_target_printer(ip=ip, user=user, password=password)
            html = ricoh_service.read_device_info(target)
            detected = _normalize_scan_protocol(_detect_scan_protocol_from_html(html))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Scan protocol detect failed: ip=%s error=%s", ip, exc)
        protocol = detected or saved or "SMBv2/3"
        return jsonify(
            {
                "ok": True,
                "ip": ip,
                "protocol": protocol,
                "detected": detected,
                "saved": saved,
                "options": ["SMBv1", "SMBv2/3", "FTP"],
            }
        )

    @app.post("/api/scan/protocol")
    def api_scan_protocol_set() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        protocol = _normalize_scan_protocol(str(body.get("protocol", "")).strip())
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not protocol:
            return jsonify({"ok": False, "error": "Invalid protocol"}), 400
        prefs = _load_scan_protocol_prefs()
        prefs[ip] = protocol
        _save_scan_protocol_prefs(prefs)
        LOGGER.info("Scan protocol saved: ip=%s protocol=%s", ip, protocol)
        return jsonify({"ok": True, "ip": ip, "protocol": protocol})

    @app.post("/api/scan/isolate-session")
    def api_scan_isolate_session() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]
        counter_stopped, counter_msg = _stop_job(counter_jobs, ip)
        status_stopped, status_msg = _stop_job(status_jobs, ip)
        bridge.stop()
        target = _resolve_target_printer(ip=ip, user=user, password=password)
        try:
            ricoh_service.reset_web_session(target)
            logout_ok = True
            logout_msg = "session reset requested"
        except Exception as exc:  # noqa: BLE001
            logout_ok = False
            logout_msg = str(exc)
        LOGGER.info(
            "Scan isolate session: ip=%s polling_running=%s counter_stop=%s status_stop=%s logout_ok=%s",
            ip,
            bool(bridge.status().get("running", False)),
            counter_msg,
            status_msg,
            logout_ok,
        )
        return jsonify(
            {
                "ok": True,
                "ip": ip,
                "polling_running": bool(bridge.status().get("running", False)),
                "counter_stop": {"ok": counter_stopped, "message": counter_msg},
                "status_stop": {"ok": status_stopped, "message": status_msg},
                "logout": {"ok": logout_ok, "message": logout_msg},
            }
        )

    @app.post("/api/scan/release-session")
    def api_scan_release_session() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        ok, message = bridge.start()
        LOGGER.info("Scan release session: polling_start_ok=%s message=%s", ok, message)
        return jsonify({"ok": True, "polling_start_ok": ok, "message": message, "status": bridge.status()})

    @app.get("/api/overview")
    def api_overview() -> Any:
        devices = _load_printers(api_client)
        overview = _build_live_overview(ricoh_service, devices)
        ws_client.send("overview_updated", overview)
        return jsonify(overview)

    @app.get("/api/devices")
    def api_devices() -> Any:
        store: ConfigStore = app.config["CONFIG_STORE"]
        ignored_prefixes = store.get_ignore_printer_prefixes()
        refresh_arg = str(request.args.get("refresh", "") or "").strip().lower()
        force_refresh = refresh_arg in {"1", "true", "yes", "y"}
        mode = "all"

        if not force_refresh:
            cached_devices, cached_at = _load_devices_cache()
            if cached_devices:
                return jsonify(
                    {
                        "devices": cached_devices,
                        "cached": True,
                        "cached_at": cached_at,
                        "filter_mode": mode,
                    }
                )

        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode)
        _save_devices_cache(payload)
        return jsonify(
            {
                "devices": payload,
                "cached": False,
                "cached_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "filter_mode": mode,
            }
        )

    @app.post("/api/devices/refresh")
    def api_devices_refresh() -> Any:
        store: ConfigStore = app.config["CONFIG_STORE"]
        ignored_prefixes = store.get_ignore_printer_prefixes()
        mode = "all"
        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_devices_cache(payload)
        return jsonify({"ok": True, "devices": payload, "cached": False, "cached_at": now, "filter_mode": mode})

    @app.post("/api/devices/action")
    def api_action() -> Any:
        request_data = request.get_json(silent=True) or {}
        ip = str(request_data.get("ip", "")).strip()
        action = str(request_data.get("action", "")).strip().lower()
        trace_id = f"device-action-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        if not action:
            return jsonify({"ok": False, "error": "Missing action"}), 400
        LOGGER.info("Device action request: trace_id=%s ip=%s action=%s remote_addr=%s", trace_id, ip, action, request.remote_addr or "-")

        target = _resolve_target_printer(ip=ip)

        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]

        try:
            if action == "status":
                payload = ricoh_service.process_status(target, should_post=False)
                ws_client.send("device_status", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "counter":
                payload = ricoh_service.process_counter(target, should_post=False)
                ws_client.send("device_counter", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "device_info":
                payload = ricoh_service.process_device_info(target, should_post=False)
                ws_client.send("device_info", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "enable_machine":
                if not str(target.user or "").strip():
                    target.user = config.get_string("test.user") or "admin"
                if target.password is None or str(target.password).strip() == "":
                    target.password = config.get_string("test.password") or "admin"
                LOGGER.info(
                    "Device action apply: trace_id=%s ip=%s action=%s user=%s has_password=%s",
                    trace_id,
                    ip,
                    action,
                    str(target.user or ""),
                    bool(str(target.password or "").strip()),
                )
                ricoh_service.enable_machine(target)
                LOGGER.info("Device action success: trace_id=%s ip=%s action=%s", trace_id, ip, action)
                ws_client.send("machine_enabled", {"ip": target.ip, "name": target.name})
                return jsonify({"ok": True, "action": action, "message": "Machine enabled successfully (EasySecurity OFF)"})
            if action in {"lock_machine", "disable_machine"}:
                if not str(target.user or "").strip():
                    target.user = config.get_string("test.user") or "admin"
                if target.password is None or str(target.password).strip() == "":
                    target.password = config.get_string("test.password") or "admin"
                LOGGER.info(
                    "Device action apply: trace_id=%s ip=%s action=%s user=%s has_password=%s",
                    trace_id,
                    ip,
                    action,
                    str(target.user or ""),
                    bool(str(target.password or "").strip()),
                )
                ricoh_service.disable_machine(target)
                LOGGER.info("Device action success: trace_id=%s ip=%s action=%s", trace_id, ip, action)
                ws_client.send("machine_locked", {"ip": target.ip, "name": target.name})
                ws_client.send("machine_disabled", {"ip": target.ip, "name": target.name})
                return jsonify({"ok": True, "action": action, "message": "Machine disabled successfully (UserCode profile applied)"})
            if action == "address_list":
                trace_id = f"action-scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
                payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                if isinstance(payload, dict):
                    payload.setdefault("debug", {})
                    if isinstance(payload["debug"], dict):
                        payload["debug"]["trace_id"] = trace_id
                ws_client.send("address_list", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "address_create":
                name = str(request_data.get("name", "")).strip()
                email = str(request_data.get("email", "")).strip()
                folder = str(request_data.get("folder", "")).strip()
                user_code = str(request_data.get("user_code", "")).strip()
                fields = request_data.get("fields", {})
                if not name:
                    return jsonify({"ok": False, "error": "Missing name"}), 400
                if fields is not None and not isinstance(fields, dict):
                    return jsonify({"ok": False, "error": "fields must be object"}), 400
                payload = ricoh_service.create_address_user_wizard(
                    target,
                    name=name,
                    email=email,
                    folder=folder,
                    user_code=user_code,
                    fields=fields if isinstance(fields, dict) else None,
                )
                ws_client.send("address_create", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "address_modify":
                registration_no = str(request_data.get("registration_no", "")).strip()
                name = str(request_data.get("name", "")).strip()
                email = str(request_data.get("email", "")).strip()
                folder = str(request_data.get("folder", "")).strip()
                user_code = str(request_data.get("user_code", "")).strip()
                fields = request_data.get("fields", {})
                if not registration_no:
                    return jsonify({"ok": False, "error": "Missing registration_no"}), 400
                if fields is not None and not isinstance(fields, dict):
                    return jsonify({"ok": False, "error": "fields must be object"}), 400
                payload = ricoh_service.modify_address_user_wizard(
                    target,
                    registration_no=registration_no,
                    name=name,
                    email=email,
                    folder=folder,
                    user_code=user_code,
                    fields=fields if isinstance(fields, dict) else None,
                )
                ws_client.send("address_modify", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "log_counter_start":
                ok, message = _start_job(
                    counter_jobs,
                    ip,
                    lambda stop_event: _counter_worker(ricoh_service, target, stop_event),
                )
                ws_client.send("counter_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": counter_jobs.get(ip, {})})
            if action == "log_counter_stop":
                ok, message = _stop_job(counter_jobs, ip)
                ws_client.send("counter_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "log_status_start":
                ok, message = _start_job(
                    status_jobs,
                    ip,
                    lambda stop_event: _status_worker(ricoh_service, target, stop_event),
                )
                ws_client.send("status_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": status_jobs.get(ip, {})})
            if action == "log_status_stop":
                ok, message = _stop_job(status_jobs, ip)
                ws_client.send("status_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "exit":
                c_ok, c_message = _stop_job(counter_jobs, ip)
                s_ok, s_message = _stop_job(status_jobs, ip)
                if not c_ok and not s_ok:
                    ws_client.send("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
                    return jsonify({"ok": True, "action": action, "message": "No running log jobs"})
                ws_client.send("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
                return jsonify(
                    {
                        "ok": True,
                        "action": action,
                        "message": f"Stopped jobs: counter={c_message}, status={s_message}",
                    }
                )
            if action == "job_status":
                return jsonify(
                    {
                        "ok": True,
                        "action": action,
                        "counter_running": bool(counter_jobs.get(ip) and counter_jobs[ip]["thread"].is_alive()),
                        "status_running": bool(status_jobs.get(ip) and status_jobs[ip]["thread"].is_alive()),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Device action failed: trace_id=%s ip=%s action=%s", trace_id, ip, action)
            return jsonify({"ok": False, "error": str(exc), "action": action}), 500

        return jsonify({"ok": False, "error": f"Unsupported action: {action}"}), 400

    @app.get("/api/devices/machine-state")
    def api_device_machine_state() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        trace_id = f"machine-state-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        user_arg = str(request.args.get("user", "")).strip()
        password_arg = str(request.args.get("password", "")).strip()

        base_target = _resolve_target_printer(ip=ip, user=user_arg, password=password_arg)
        resolved_user = str(base_target.user or "").strip()
        resolved_password = str(base_target.password or "").strip()
        config_user = str(config.get_string("test.user") or "").strip()
        config_password = str(config.get_string("test.password") or "").strip()

        attempts: list[tuple[str, str, str]] = []
        # Priority: explicit query -> resolved target -> test credential -> admin/admin.
        if user_arg or password_arg:
            attempts.append(("query", user_arg, password_arg))
        if resolved_user or resolved_password:
            attempts.append(("resolved", resolved_user, resolved_password))
        if config_user or config_password:
            attempts.append(("config", config_user, config_password))
        attempts.append(("admin_default", "admin", "admin"))

        # Deduplicate same credential pairs.
        unique_attempts: list[tuple[str, str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for label, user_value, password_value in attempts:
            pair = (str(user_value or ""), str(password_value or ""))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique_attempts.append((label, pair[0], pair[1]))

        last_error = ""
        for label, user_value, password_value in unique_attempts:
            target = _resolve_target_printer(ip=ip, user=user_value, password=password_value)
            target.user = user_value
            target.password = password_value
            LOGGER.info(
                "Machine state request: trace_id=%s ip=%s attempt=%s user=%s has_password=%s remote_addr=%s",
                trace_id,
                ip,
                label,
                str(target.user or ""),
                bool(str(target.password or "").strip()),
                request.remote_addr or "-",
            )
            try:
                state = ricoh_service.read_machine_control_state(target)
                LOGGER.info(
                    "Machine state success: trace_id=%s ip=%s attempt=%s enabled=%s method=%s",
                    trace_id,
                    ip,
                    label,
                    bool(state.get("enabled", False)),
                    str(state.get("method", "")),
                )
                return jsonify({"ok": True, "ip": ip, "state": state, "trace_id": trace_id, "auth_attempt": label})
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                LOGGER.warning(
                    "Machine state attempt failed: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    exc,
                )

        return jsonify(
            {
                "ok": False,
                "error": last_error or "Unable to read machine state",
                "ip": ip,
                "trace_id": trace_id,
            }
        )

    @app.get("/api/device/interface")
    def api_device_interface() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        trace_id = f"iface-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        base_target = _resolve_target_printer(ip=ip, user=user, password=password)
        resolved_user = str(base_target.user or "").strip()
        resolved_password = str(base_target.password or "").strip()
        config_user = str(config.get_string("test.user") or "").strip()
        config_password = str(config.get_string("test.password") or "").strip()

        attempts: list[tuple[str, str, str]] = []
        if user or password:
            attempts.append(("query", user, password))
        if resolved_user or resolved_password:
            attempts.append(("resolved", resolved_user, resolved_password))
        if config_user or config_password:
            attempts.append(("config", config_user, config_password))
        attempts.append(("admin_default", "admin", "admin"))
        attempts.append(("guest", "", ""))

        unique_attempts: list[tuple[str, str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for label, user_value, password_value in attempts:
            pair = (str(user_value or ""), str(password_value or ""))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique_attempts.append((label, pair[0], pair[1]))

        last_error = ""
        for label, user_value, password_value in unique_attempts:
            target = _resolve_target_printer(ip=ip, user=user_value, password=password_value)
            target.user = user_value
            target.password = password_value
            try:
                html = ricoh_service.read_network_interface(target)
                raw_macs = re.findall(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", html or "")
                macs = []
                for item in raw_macs:
                    normalized = _normalize_mac(item)
                    if normalized and normalized not in macs:
                        macs.append(normalized)
                LOGGER.info(
                    "Device interface success: trace_id=%s ip=%s attempt=%s macs=%s",
                    trace_id,
                    ip,
                    label,
                    len(macs),
                )
                return jsonify({"ok": True, "ip": ip, "macs": macs, "raw_len": len(html or ""), "trace_id": trace_id, "auth_attempt": label})
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                LOGGER.warning(
                    "Device interface attempt failed: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    exc,
                )
        return jsonify({"ok": False, "error": last_error or "Unable to read interface", "ip": ip, "trace_id": trace_id})

    @app.get("/api/log-jobs")
    def api_log_jobs() -> Any:
        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]
        return jsonify(
            {
                "counter": [
                    {"ip": ip, "running": value["thread"].is_alive(), "started_at": value.get("started_at", "")}
                    for ip, value in counter_jobs.items()
                ],
                "status": [
                    {"ip": ip, "running": value["thread"].is_alive(), "started_at": value.get("started_at", "")}
                    for ip, value in status_jobs.items()
                ],
            }
        )

    @app.get("/api/ws/status")
    def api_ws_status() -> Any:
        return jsonify(ws_client.status())

    @app.get("/api/polling/status")
    def api_polling_status() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        return jsonify(bridge.status())

    @app.post("/api/polling/toggle")
    def api_polling_toggle() -> Any:
        body = request.get_json(silent=True) or {}
        enabled_raw = body.get("enabled", None)
        if enabled_raw is None:
            return jsonify({"ok": False, "error": "Missing enabled"}), 400
        if isinstance(enabled_raw, bool):
            enabled = enabled_raw
        else:
            enabled = str(enabled_raw).strip().lower() in {"1", "true", "yes", "on"}

        app_cfg: AppConfig = app.config["APP_CONFIG"]
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        store: ConfigStore = app.config["CONFIG_STORE"]

        app_cfg.set_value("polling.enabled", enabled)
        store.save_env_overrides({"POLLING_ENABLED": "true" if enabled else "false"})

        if enabled:
            ok, message = bridge.start()
            return jsonify({"ok": ok, "message": message, "status": bridge.status()})
        bridge.stop()
        return jsonify({"ok": True, "message": "Polling stopped", "status": bridge.status()})

    @app.post("/api/ws/connect")
    def api_ws_connect() -> Any:
        ok, message = ws_client.connect()
        return jsonify({"ok": ok, "message": message, "status": ws_client.status()})

    @app.post("/api/ws/disconnect")
    def api_ws_disconnect() -> Any:
        ok, message = ws_client.disconnect()
        return jsonify({"ok": ok, "message": message, "status": ws_client.status()})

    @app.post("/api/ws/send")
    def api_ws_send() -> Any:
        body = request.get_json(silent=True) or {}
        event = str(body.get("event", "manual_event")).strip()
        payload = body.get("payload", {})
        if not isinstance(payload, dict):
            return jsonify({"ok": False, "error": "payload must be an object"}), 400
        ok, message = ws_client.send(event, payload)
        return jsonify({"ok": ok, "message": message, "status": ws_client.status()})

    @app.get("/api/update/status")
    def api_update_status() -> Any:
        return jsonify(updater.status())

    @app.post("/api/update/check")
    def api_update_check() -> Any:
        mode = config.get_string("webhook.mode", "listen").strip().lower() or "listen"
        if mode == "listen":
            return (
                jsonify(
                    {
                        "ok": False,
                        "message": "Webhook is in listen mode; use webhook endpoint to receive update signals",
                        "status": updater.status(),
                    }
                ),
                400,
            )
        body = request.get_json(silent=True) or {}
        version = str(body.get("version", "")).strip()
        command = str(body.get("command", "")).strip()
        source = str(body.get("source", "api")).strip()
        ok, message = updater.handle_signal(version=version, command_text=command, source=source, raw_text=str(body))
        return jsonify({"ok": ok, "message": message, "status": updater.status()})

    @app.post("/api/update/receive-text")
    def api_update_receive_text() -> Any:
        mode = config.get_string("webhook.mode", "listen").strip().lower() or "listen"
        if mode != "listen":
            return jsonify({"ok": False, "error": f"Webhook mode is '{mode}', not listen"}), 400

        token = request.headers.get("X-Update-Token", "").strip()
        expected = updater.webhook_token
        if expected and token != expected:
            return jsonify({"ok": False, "error": "Invalid update token"}), 403

        body = request.get_json(silent=True) or {}
        text = str(body.get("text", "")).strip()
        if not text:
            return jsonify({"ok": False, "error": "Missing text"}), 400
        ok, message = updater.handle_text_message(text, source="webhook")
        return jsonify({"ok": ok, "message": message, "status": updater.status()})

    return app
