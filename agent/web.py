from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, url_for
from werkzeug.serving import make_server

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.modules.toshiba.service import ToshibaService
from app.services.api_client import APIClient, Printer
from app.services.polling_bridge import PollingBridge
from app.services.scan_drop import build_drop_folder_metadata
from app.services.updater import AutoUpdater
from app.services.runtime import default_ftp_root, get_machine_agent_uid, no_window_subprocess_kwargs
from app.utils.scanner import SubnetScanner


LOGGER = logging.getLogger(__name__)
DEFAULT_WEB_PORT = 9173
CACHE_TTL_SECONDS = 300
_LIVE_HISTORY: deque[tuple[str, int, int, int]] = deque(maxlen=7)
_DEVICES_CACHE: dict[str, Any] = {"cached_at": "", "devices": []}
_SCAN_PROTOCOL_PREFS: dict[str, str] = {}
DEFAULT_IGNORE_PREFIXES = ["RustDesk", "RuskDesk", "Microsoft", "Fax", "AnyDesk", "Foxit"]


def _env_snapshot(config: AppConfig, updater: AutoUpdater) -> dict[str, str]:
    return {
        "APP_VERSION": str(updater.status().get("current_version", "") or ""),
        "API_URL": config.api_url,
        "USER_TOKEN": config.user_token,
        "UPDATE_AUTO_APPLY": str(updater.auto_apply).lower(),
        "UPDATE_DEFAULT_COMMAND": updater.default_command,
        "WEBHOOK_MODE": config.get_string("webhook.mode", "listen") or "listen",
        "WEBHOOK_LISTEN_PATH": config.get_string("webhook.listen_path", "/api/update/receive-text") or "/api/update/receive-text",
        "TEST_IP": config.get_string("test.ip"),
        "TEST_USER": config.get_string("test.user"),
        "POLLING_ENABLED": str(config.get_bool("polling.enabled", False)).lower(),
        "POLLING_URL": config.get_string("polling.url"),
        "POLLING_LEAD": config.get_string("polling.lead"),
        "POLLING_TOKEN": config.get_string("polling.token"),
        "POLLING_INTERVAL_SECONDS": config.get_string("polling.interval_seconds", "300"),
        "POLLING_LAN_UID": config.get_string("polling.lan_uid"),
        "POLLING_AGENT_UID": get_machine_agent_uid(config.get_string("polling.agent_uid")),
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


def _clean_printer_display_name(name: str, ip: str = "") -> str:
    text = str(name or "").strip()
    if text:
        text = re.sub(r"^\s*(m[aáàạảã]y|may)\s*photo\s*", "", text, flags=re.IGNORECASE).strip(" -_()")
    if text:
        normalized = _normalize_ipv4(text)
        if normalized and (not ip or normalized == _normalize_ipv4(ip)):
            return "unknown"
        return text
    return "unknown"


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
    return dict(_SCAN_PROTOCOL_PREFS)


def _save_scan_protocol_prefs(prefs: dict[str, str]) -> None:
    _SCAN_PROTOCOL_PREFS.clear()
    for k, v in (prefs or {}).items():
        ip = _normalize_ipv4(str(k or "").strip())
        protocol = str(v or "").strip()
        if ip and protocol:
            _SCAN_PROTOCOL_PREFS[ip] = protocol


def _normalize_scan_protocol(value: str) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    if text in {"SMBV1", "SMB1", "SMBV1.0"}:
        return "SMBv1"
    if text in {"SMBV2/3", "SMBV2", "SMB2", "SMBV3", "SMB3"}:
        return "SMBv2/3"
    if text == "FTP":
        return "FTP"
    return ""


def _sanitize_ftp_name(value: str) -> str:
    text = str(value or "").strip().replace(" ", "_")
    text = re.sub(r"[^A-Za-z0-9_-]", "", text)
    return text[:48]


def _register_scan_root(config: AppConfig, scan_root: str | Path) -> dict[str, Any]:
    added, scan_dirs = config.ensure_scan_dir(scan_root)
    return {
        "scan_dir_added": added,
        "scan_dirs": scan_dirs,
    }


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
            **no_window_subprocess_kwargs(),
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
            **no_window_subprocess_kwargs(),
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


def _resolve_device_machine_ids(
    service: RicohService, devices: list[Printer], neighbor_mac_map: dict[str, str] | None = None
) -> dict[str, str]:
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
            # Persistence: Fallback to neighbor_mac_map if available
            if neighbor_mac_map and ip in neighbor_mac_map:
                mapping[ip] = neighbor_mac_map[ip]
    return mapping


def _save_devices_cache(devices: list[dict[str, Any]]) -> None:
    _DEVICES_CACHE["cached_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _DEVICES_CACHE["devices"] = list(devices or [])


def _load_devices_cache() -> tuple[list[dict[str, Any]], str]:
    cached_devices = _DEVICES_CACHE.get("devices", [])
    cached_at = str(_DEVICES_CACHE.get("cached_at", "") or "")
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
            **no_window_subprocess_kwargs(),
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
    force_refresh: bool = False,
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
    
    scan_results: dict[str, bool] = {}
    if force_refresh:
        try:
            scanner = SubnetScanner(max_workers=100)
            results = scanner.scan_subnet()
            scan_results = {r["ip"]: r["is_printer"] for r in results}
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Quick subnet scan failed: %s", exc)

    neighbor_mac_map = _load_neighbor_mac_map()
    machine_id_map = _resolve_device_machine_ids(ricoh_service, api_devices, neighbor_mac_map)

    api_payload = [
        {
            "id": p.id,
            "name": _clean_printer_display_name(p.name, p.ip),
            "ip": p.ip,
            "mac_id": machine_id_map.get(p.ip) or neighbor_mac_map.get(p.ip, ""),
            "type": p.printer_type or "unknown",
            "status": p.status or ("online" if p.ip in neighbor_mac_map else "offline"),
            "user": p.user,
            "password": p.password,
            "port_name": "",
            "port_monitor": "",
            "connection_type": "ip" if p.ip else "unknown",
            "source": "api",
        }
        for p in api_devices
        if p.ip
        and (
            not valid_only
            or (_supports_collection_vendor(p.printer_type) and not _should_ignore_device(p.name, ignored_prefixes))
        )
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

    # 3) Add network-discovered devices (only those identified as Ricoh photostatic machines)
    for ip, mac in neighbor_mac_map.items():
        if not ip or ip == "127.0.0.1":
             continue
        key = f"ip:{ip}"
        if key in existing_keys:
            continue
        
        # Signal identification:
        is_ricoh_result = scan_results.get(ip)
        is_ricoh_mac = SubnetScanner.is_ricoh_mac(mac)
        is_known_ricoh = ip in machine_id_map

        # If Show All is OFF, strictly filter for Ricoh devices.
        if valid_only and not (is_ricoh_result or is_ricoh_mac or is_known_ricoh):
             continue

        # D) Remote MAC fetch if ARP failed (useful for cross-VLAN discovery)
        if not mac:
            LOGGER.info("MAC missing for Ricoh device %s, attempting remote fetch via CGI...", ip)
            mac = ricoh_service.fetch_mac_address_direct(ip)
             
        is_ricoh = bool(is_ricoh_result or is_ricoh_mac or is_known_ricoh)
        
        display_name = "unknown"
        if is_ricoh:
            try:
                # Create a temporary printer object for name discovery
                temp_p = Printer(name="Discovery", ip=ip, user="", password="", printer_type="ricoh")
                dev_info = ricoh_service.process_device_info(temp_p, should_post=False)
                info_dict = dev_info.get("device_info", {})
                # Try common Ricoh keys for model name
                model_name = (
                    info_dict.get("Model Name")
                    or info_dict.get("Machine Name")
                    or info_dict.get("Device Name")
                    or info_dict.get("Product Name")
                    or info_dict.get("model_name")
                )
                if model_name:
                    display_name = model_name
            except Exception as e:
                LOGGER.debug("Failed to discover model name for %s: %s", ip, e)
        display_name = _clean_printer_display_name(display_name, ip)
        row = {
            "id": 0,
            "name": display_name,
            "ip": ip,
            "mac_id": mac,
            "type": "ricoh" if is_ricoh else "unknown",
            "status": "online",
            "user": "",
            "port_name": "",
            "port_monitor": "",
            "connection_type": "ip",
            "source": "network",
        }
        payload.append(row)
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


def _printer_vendor(printer: Printer | None) -> str:
    if printer is None:
        return ""
    return str(printer.printer_type or "").strip().lower()


def _supports_collection_vendor(printer_type: str) -> bool:
    return str(printer_type or "").strip().lower() in {"ricoh", "toshiba"}


def _collector_service_for(
    printer: Printer,
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
) -> RicohService | ToshibaService:
    if toshiba_service is not None and _printer_vendor(printer) == "toshiba":
        return toshiba_service
    return ricoh_service


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _append_history(copier: int, printer: int, scanner: int, active: int, offline: int, total: int) -> None:
    _LIVE_HISTORY.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), copier, printer, scanner))


def _read_history(limit: int = 7) -> tuple[list[str], list[int], list[int], list[int]]:
    rows = list(_LIVE_HISTORY)[-limit:]
    labels = [r[0][5:16] for r in rows]
    copier = [int(r[1]) for r in rows]
    printer = [int(r[2]) for r in rows]
    scanner = [int(r[3]) for r in rows]
    return labels, copier, printer, scanner


def _build_live_overview(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    devices: list[Printer],
) -> dict[str, Any]:
    live_devices = [d for d in devices if d.ip and _supports_collection_vendor(d.printer_type)]
    ricoh_count = sum(1 for device in live_devices if _printer_vendor(device) == "ricoh")
    toshiba_count = sum(1 for device in live_devices if _printer_vendor(device) == "toshiba")
    copier_pages = 0
    print_pages = 0
    scan_pages = 0
    active_count = 0
    alert_count = {"low_toner": 0, "paper_warning": 0, "scanner_notice": 0}
    details: list[dict[str, Any]] = []

    for printer in live_devices:
        vendor = _printer_vendor(printer)
        collector = _collector_service_for(printer, ricoh_service, toshiba_service)
        device_row: dict[str, Any] = {"name": printer.name, "ip": printer.ip, "ok": False}
        try:
            counter_payload = collector.process_counter(printer, should_post=False)
            status_payload = collector.process_status(printer, should_post=False)

            counter = counter_payload.get("counter_data", {})
            status = status_payload.get("status_data", {})

            copier_pages += _to_int(counter.get("copier_bw"))
            print_pages += _to_int(counter.get("printer_bw"))
            scan_pages += _to_int(counter.get("scanner_send_bw")) + _to_int(counter.get("scanner_send_color"))

            system_status = status.get("system_status", "")
            if vendor == "toshiba":
                if system_status in {"Status OK", "Ready"}:
                    active_count += 1
                if status.get("toner_black", "") not in {"", "Status OK", "Ready"}:
                    alert_count["low_toner"] += 1
                paper_values: list[str] = [
                    str(value).lower()
                    for key, value in status.items()
                    if key.endswith("_tray_status") or (key.startswith("tray_") and key.endswith("_status"))
                ]
                status_json = status.get("status_json", {})
                if isinstance(status_json, dict):
                    input_tray = status_json.get("input_tray", {})
                    if isinstance(input_tray, dict):
                        for tray_value in input_tray.values():
                            if isinstance(tray_value, dict):
                                paper_values.append(str(tray_value.get("text", "")).lower())
                                icons = tray_value.get("icons", [])
                                if isinstance(icons, list):
                                    paper_values.extend(str(icon).lower() for icon in icons)
                if any(
                    token in value
                    for value in paper_values
                    for token in ("out of paper", "almost out of paper", "cover open", "empty", "alert")
                ):
                    alert_count["paper_warning"] += 1
                scanner_alerts = status.get("scanner_alerts", [])
                if isinstance(scanner_alerts, list) and scanner_alerts:
                    alert_count["scanner_notice"] += 1
            else:
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
            device_row["type"] = vendor or "unknown"
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

    total = len(live_devices)
    offline = max(total - active_count, 0)
    _append_history(copier_pages, print_pages, scan_pages, active_count, offline, total)
    labels, copier_hist, print_hist, scan_hist = _read_history(limit=7)

    return {
        "stats": {
            "total_devices": total,
            "ricoh_devices": ricoh_count,
            "toshiba_devices": toshiba_count,
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


def _counter_worker(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    printer: Printer,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            collector = _collector_service_for(printer, ricoh_service, toshiba_service)
            collector.process_counter(printer, should_post=True)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Counter push failed: ip=%s error=%s", printer.ip, exc)
        stop_event.wait(60)


def _status_worker(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    printer: Printer,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            collector = _collector_service_for(printer, ricoh_service, toshiba_service)
            collector.process_status(printer, should_post=True)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Status push failed: ip=%s error=%s", printer.ip, exc)
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


def _emit_ui_event(_event: str, _payload: dict[str, Any]) -> None:
    return


def create_app(
    current_args: list[str] | None = None,
    shutdown_event: threading.Event | None = None,
) -> Flask:
    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    template_candidates = [
        bundle_root / "app" / "templates",
        bundle_root / "templates",
        Path(__file__).resolve().parent / "templates",
    ]
    template_dir = next((path for path in template_candidates if path.exists()), template_candidates[-1])
    static_candidates = [
        bundle_root / "app" / "static",
        bundle_root / "static",
        Path(__file__).resolve().parent / "static",
    ]
    static_dir = next((path for path in static_candidates if path.exists()), static_candidates[-1])
    app = Flask(__name__, template_folder=str(template_dir), static_folder=str(static_dir))
    config = AppConfig.load()
    api_client = APIClient(config)
    ricoh_service = RicohService(api_client, config=config)
    toshiba_service = ToshibaService(api_client)
    updater_args = list(current_args or ["--mode", "web"])
    updater = AutoUpdater(project_root=Path(__file__).resolve().parents[1], current_args=updater_args)
    web_port = int(str(os.getenv("APP_WEB_PORT", os.getenv("FLASK_PORT", str(DEFAULT_WEB_PORT))) or str(DEFAULT_WEB_PORT)))
    polling_bridge = PollingBridge(
        config,
        api_client,
        ricoh_service,
        toshiba_service=toshiba_service,
        updater=updater,
        run_mode="web",
        web_port=web_port,
        restart_callback=(shutdown_event.set if shutdown_event is not None else None),
    )

    app.config["APP_CONFIG"] = config
    app.config["API_CLIENT"] = api_client
    app.config["RICOH_SERVICE"] = ricoh_service
    app.config["TOSHIBA_SERVICE"] = toshiba_service
    app.config["POLLING_BRIDGE"] = polling_bridge
    app.config["UPDATER"] = updater
    app.config["LOG_JOBS"] = {"counter": {}, "status": {}}

    p_ok, p_msg = polling_bridge.start()
    LOGGER.info("Polling bridge: %s (%s)", p_ok, p_msg)

    @app.get("/")
    def index() -> Any:
        return redirect(url_for("devices"))

    @app.get("/dashboard")
    def dashboard() -> Any:
        return redirect(url_for("devices"))

    @app.get("/api/dashboard/config")
    def api_dashboard_config() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        hostname = socket.gethostname()
        local_ip = bridge._resolve_local_ip()
        lan_uid, fingerprint = bridge._resolve_lan_info(hostname, local_ip)
        return jsonify(
            {
                "lan_uid": lan_uid,
                "fingerprint": fingerprint,
                "env": _env_snapshot(app.config["APP_CONFIG"], updater),
            }
        )

    def _ftp_pc_candidates() -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        local_host = str(socket.gethostname() or "").strip() or "localhost"
        local_ip = _normalize_ipv4(PollingBridge._resolve_local_ip()) or "127.0.0.1"
        candidates.append(
            {
                "id": "local",
                "name": local_host,
                "ip": local_ip,
                "department": "Local Agent",
                "source": "local",
                "is_local": True,
            }
        )
        return candidates

    def _create_local_ftp_for_address(address_name: str, printer_ip: str = "") -> dict[str, Any]:
        ftp_host_info = ricoh_service.resolve_ftp_host_ip(printer_ip)
        local_ip = _normalize_ipv4(str(ftp_host_info.get("ip", "") or "")) or "127.0.0.1"
        seed_name = _sanitize_ftp_name(address_name) or "scan"
        ftp_name = _sanitize_ftp_name(f"ftp_{seed_name}") or "ftp_scan"
        ftp_root = default_ftp_root(ftp_name)
        result = ricoh_service.share_manager.create_ftp_site(site_name=ftp_name, local_path=ftp_root, port=2121)
        ftp_ok = bool(result.get("ok"))
        ftp_port = int(result.get("port") or 2121)
        ftp_url = f"ftp://{local_ip}:{ftp_port}/"
        drop_folder = build_drop_folder_metadata(ftp_root, base_url=ftp_url)
        scan_sync: dict[str, Any] = {}
        if ftp_ok:
            scan_sync = _register_scan_root(config, ftp_root)
        return {
            "ok": ftp_ok,
            "ftp_name": ftp_name,
            "ftp_root": str(ftp_root),
            "ftp_url": ftp_url,
            "upload_url": str(drop_folder.get("upload_url", "") or ftp_url),
            "upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
            "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
            "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
            "local_ip": local_ip,
            "ftp_host_ip": local_ip,
            "ftp_ip_candidates": list(ftp_host_info.get("candidates", []) or []),
            "ftp_ip_strategy": str(ftp_host_info.get("strategy", "") or ""),
            "warning": str(ftp_host_info.get("warning", "") or "").strip(),
            "result": result,
            **scan_sync,
        }

    @app.get("/api/ftp/pcs")
    def api_ftp_pcs() -> Any:
        return jsonify({"ok": True, "pcs": _ftp_pc_candidates()})

    @app.post("/api/ftp/create")
    def api_ftp_create() -> Any:
        body = request.get_json(silent=True) or {}
        local_ip = _normalize_ipv4(PollingBridge._resolve_local_ip()) or "127.0.0.1"
        computer_id = str(body.get("computer_id", "")).strip()
        ftp_name_raw = str(body.get("ftp_name", "")).strip()
        ftp_name = re.sub(r"[^A-Za-z0-9_-]", "", ftp_name_raw.replace(" ", "_"))[:48]
        ftp_path_raw = str(body.get("ftp_path", "")).strip()
        ftp_port = 0
        try:
            ftp_port = int(body.get("port") or 0)
        except Exception:  # noqa: BLE001
            ftp_port = 0
        if not computer_id:
            return jsonify({"ok": False, "error": "Missing computer_id"})

        candidates = _ftp_pc_candidates()
        selected = next((x for x in candidates if str(x.get("id")) == computer_id), None)
        if not selected:
            return jsonify({"ok": False, "error": "Computer not found"})
        if not ftp_name:
            default_name = f"ftp_{str(selected.get('name') or 'site')}"
            ftp_name = re.sub(r"[^A-Za-z0-9_-]", "", default_name.replace(" ", "_"))[:48]
        if not ftp_name:
            return jsonify({"ok": False, "error": "Missing ftp_name"})
        if not bool(selected.get("is_local")):
            return jsonify(
                {
                    "ok": False,
                    "error": "Remote PC FTP creation is not supported in this agent. Select Local Agent PC.",
                    "target": selected,
                }
            )

        ftp_root = Path(ftp_path_raw).expanduser() if ftp_path_raw else default_ftp_root(ftp_name)
        result = ricoh_service.share_manager.create_ftp_site(site_name=ftp_name, local_path=ftp_root, port=ftp_port or 2121)
        ftp_port_value = int(result.get("port") or ftp_port or 2121)
        ftp_url = f"ftp://{local_ip}:{ftp_port_value}/"
        drop_folder = build_drop_folder_metadata(ftp_root, base_url=ftp_url)
        scan_sync: dict[str, Any] = {}
        if bool(result.get("ok")):
            scan_sync = _register_scan_root(config, ftp_root)
        response = {
            "ok": bool(result.get("ok")),
            "target": selected,
            "ftp_name": ftp_name,
            "ftp_root": str(ftp_root),
            "ftp_url": ftp_url,
            "upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
            "upload_url": str(drop_folder.get("upload_url", "") or ftp_url),
            "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
            "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
            "result": result,
            "hint": "FTP is managed by the Windows FTP worker. The agent only writes config and reports status.",
            **scan_sync,
        }
        warnings = [str(item or "").strip() for item in result.get("warnings", []) if str(item or "").strip()]
        if warnings:
            response["warnings"] = warnings
            response["hint"] = (
                "FTP site is running, but Windows Firewall was not updated. "
                "Run PrintAgent as Administrator or open TCP ports manually."
            )
        LOGGER.info(
            "FTP create result: target=%s ip=%s ftp_name=%s ok=%s error=%s",
            selected.get("name", ""),
            selected.get("ip", ""),
            ftp_name,
            bool(result.get("ok")),
            str(result.get("error", "") or ""),
        )
        return jsonify(response)

    @app.get("/api/ftp/sites")
    def api_ftp_sites() -> Any:
        local_ip = _normalize_ipv4(PollingBridge._resolve_local_ip()) or "127.0.0.1"
        sites = ricoh_service.share_manager.list_ftp_sites()
        rows: list[dict[str, Any]] = []
        for site in sites:
            port = int(site.get("port", 0) or 0)
            ftp_url = f"ftp://{local_ip}:{port}/" if port > 0 else str(site.get("ftp_url", "") or "")
            drop_folder = build_drop_folder_metadata(str(site.get("path", "") or ""), base_url=ftp_url)
            rows.append(
                {
                    "name": str(site.get("name", "") or ""),
                    "path": str(site.get("path", "") or ""),
                    "port": port,
                    "ftp_url": ftp_url,
                    "upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
                    "upload_url": str(drop_folder.get("upload_url", "") or ftp_url),
                    "ftp_user": str(site.get("ftp_user", "") or ""),
                    "ftp_password": str(site.get("ftp_password", "") or ""),
                }
            )
        return jsonify(
            {
                "ok": True,
                "sites": rows,
            }
        )

    @app.post("/api/ftp/update")
    def api_ftp_update() -> Any:
        body = request.get_json(silent=True) or {}
        site_name = _sanitize_ftp_name(str(body.get("site_name", "")).strip())
        new_site_name = _sanitize_ftp_name(str(body.get("new_site_name", "")).strip()) if body.get("new_site_name") is not None else None
        local_path_raw = str(body.get("local_path", "")).strip()
        try:
            port = int(body.get("port") or 0)
        except Exception:  # noqa: BLE001
            port = 0
        if not site_name:
            return jsonify({"ok": False, "error": "Missing site_name"}), 400
        result = ricoh_service.share_manager.update_ftp_site(
            site_name,
            new_site_name=new_site_name,
            local_path=local_path_raw or None,
            port=port or None,
        )
        if bool(result.get("ok")):
            physical_path = str(result.get("physical_path", "") or local_path_raw or "").strip()
            if physical_path:
                result.update(_register_scan_root(config, physical_path))
        return jsonify(result), 200 if result.get("ok") else 400

    @app.delete("/api/ftp/sites/<path:site_name>")
    def api_ftp_delete(site_name: str) -> Any:
        safe_name = _sanitize_ftp_name(site_name)
        if not safe_name:
            return jsonify({"ok": False, "error": "Invalid site_name"}), 400
        result = ricoh_service.share_manager.delete_ftp_site(safe_name)
        return jsonify(result), 200 if result.get("ok") else 404

    @app.get("/devices")
    def devices() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        hostname = socket.gethostname()
        local_ip = bridge._resolve_local_ip()
        lan_uid, _ = bridge._resolve_lan_info(hostname, local_ip)
        return render_template("devices.html", active_tab="devices", page_title=lan_uid or "Devices")

    @app.get("/scan")
    def scan() -> Any:
        return render_template("scan.html", active_tab="scan", page_title="Scan")

    @app.get("/ftp")
    def ftp_page() -> Any:
        return render_template("ftp.html", active_tab="ftp", page_title="FTP")

    @app.get("/analytics")
    def analytics() -> Any:
        return render_template("analytics.html", active_tab="analytics", page_title="Counter Analytics")

    @app.get("/settings")
    def settings() -> Any:
        return redirect(url_for("devices"))

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
            # Address-create flow is FTP-first by design.
            selected_protocol = "FTP"
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
            ftp_payload: dict[str, Any] | None = None
            folder_final = folder
            if selected_protocol == "FTP":
                ftp_payload = _create_local_ftp_for_address(name, printer_ip=ip)
                LOGGER.info(
                    "Scan address create FTP step: trace_id=%s ip=%s ftp_name=%s ftp_url=%s ftp_ok=%s",
                    trace_id,
                    ip,
                    str(ftp_payload.get("ftp_name", "")).strip(),
                    str(ftp_payload.get("upload_url", "") or ftp_payload.get("ftp_url", "")).strip(),
                    bool(ftp_payload.get("ok", False)),
                )
                if not bool(ftp_payload.get("ok", False)):
                    LOGGER.warning(
                        "Scan address create FTP setup failed: trace_id=%s ip=%s name=%s error=%s",
                        trace_id,
                        ip,
                        name,
                        str((ftp_payload.get("result") or {}).get("error", "")).strip(),
                    )
                    return jsonify(
                        {
                            "ok": False,
                            "error": "FTP setup failed before address creation",
                            "trace_id": trace_id,
                            "protocol": selected_protocol,
                            "ftp": ftp_payload,
                        }
                    ), 500
                folder_final = str(ftp_payload.get("upload_url", "") or ftp_payload.get("ftp_url", "")).strip() or folder_final
                LOGGER.info(
                    "Scan address create folder overridden by FTP: trace_id=%s ip=%s folder=%s",
                    trace_id,
                    ip,
                    folder_final,
                )
                ftp_warning = str(ftp_payload.get("warning", "") or "").strip()
                if ftp_warning:
                    LOGGER.warning(
                        "Scan address create FTP warning: trace_id=%s ip=%s warning=%s",
                        trace_id,
                        ip,
                        ftp_warning,
                    )
            merged_fields: dict[str, Any] = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            payload = ricoh_service.create_address_user_wizard(
                target,
                name=name,
                email=email,
                folder=folder_final,
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
            return jsonify(
                {
                    "ok": True,
                    "payload": payload,
                    "trace_id": trace_id,
                    "protocol": selected_protocol,
                    "folder_used": folder_final,
                    "ftp": ftp_payload,
                }
            )
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
        protocol = detected or saved or "FTP"
        return jsonify(
            {
                "ok": True,
                "ip": ip,
                "protocol": protocol,
                "detected": detected,
                "saved": saved,
                "options": ["FTP", "SMBv2/3", "SMBv1"],
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
        status = bridge.status()
        if bool(status.get("running", False)):
            # UI can call release on load/cleanup; ignore silently when polling is already active.
            return jsonify({"ok": True, "polling_start_ok": True, "message": "Polling already running", "status": status})
        ok, message = bridge.start()
        LOGGER.info("Scan release session: polling_start_ok=%s message=%s", ok, message)
        return jsonify({"ok": True, "polling_start_ok": ok, "message": message, "status": bridge.status()})

    @app.post("/api/shares/create")
    def api_shares_create() -> Any:
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        if not username:
            return jsonify({"ok": False, "error": "Missing username"}), 400
        
        res = ricoh_service.share_manager.setup_auto_share(username)
        return jsonify(res)

    @app.post("/api/scan/setup-auto")
    def api_scan_setup_auto() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        username = str(body.get("username", "")).strip()
        fields = body.get("fields", {})

        if not ip or not username:
            return jsonify({"ok": False, "error": "Missing ip or username"}), 400

        target = _resolve_target_printer(ip=ip)
        res = ricoh_service.setup_scan_destination(target, username, fields=fields)
        
        if res.get("ok"):
            LOGGER.info("Auto-scan setup success: ip=%s username=%s", ip, username)
        else:
            LOGGER.warning("Auto-scan setup failed: ip=%s username=%s error=%s", ip, username, res.get("error"))
            
        return jsonify(res)

    @app.get("/api/overview")
    def api_overview() -> Any:
        devices = _load_printers(api_client)
        overview = _build_live_overview(ricoh_service, toshiba_service, devices)
        _emit_ui_event("overview_updated", overview)
        return jsonify(overview)

    @app.get("/api/devices")
    def api_devices() -> Any:
        ignored_prefixes = list(DEFAULT_IGNORE_PREFIXES)
        refresh_arg = str(request.args.get("refresh", "") or "").strip().lower()
        force_refresh = refresh_arg in {"1", "true", "yes", "y"}
        mode = "valid_only"

        if not force_refresh:
            cached_devices, cached_at_str = _load_devices_cache()
            if cached_devices and cached_at_str:
                try:
                    cached_at = datetime.strptime(cached_at_str, "%Y-%m-%d %H:%M:%S")
                    age = (datetime.now() - cached_at).total_seconds()
                    if age < CACHE_TTL_SECONDS:
                        return jsonify(
                            {
                                "devices": cached_devices,
                                "cached": True,
                                "cached_at": cached_at_str,
                                "filter_mode": mode,
                            }
                        )
                except Exception:  # noqa: BLE001
                    pass

        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode, force_refresh=force_refresh)
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
        ignored_prefixes = list(DEFAULT_IGNORE_PREFIXES)
        mode = "valid_only"
        # Button refresh always forces a full subnet scan to populate ARP cache.
        payload = _scan_devices_payload(config, api_client, ricoh_service, ignored_prefixes, mode, force_refresh=True)
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
        collector = _collector_service_for(target, ricoh_service, toshiba_service)

        counter_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["counter"]
        status_jobs: dict[str, dict[str, Any]] = app.config["LOG_JOBS"]["status"]

        try:
            if action == "status":
                payload = collector.process_status(target, should_post=False)
                _emit_ui_event("device_status", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "counter":
                payload = collector.process_counter(target, should_post=False)
                _emit_ui_event("device_counter", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "device_info":
                payload = collector.process_device_info(target, should_post=False)
                _emit_ui_event("device_info", payload)
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
                _emit_ui_event("machine_enabled", {"ip": target.ip, "name": target.name})
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
                _emit_ui_event("machine_locked", {"ip": target.ip, "name": target.name})
                _emit_ui_event("machine_disabled", {"ip": target.ip, "name": target.name})
                return jsonify({"ok": True, "action": action, "message": "Machine disabled successfully (UserCode profile applied)"})
            if action == "address_list":
                trace_id = f"action-scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
                payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                if isinstance(payload, dict):
                    payload.setdefault("debug", {})
                    if isinstance(payload["debug"], dict):
                        payload["debug"]["trace_id"] = trace_id
                _emit_ui_event("address_list", payload)
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
                _emit_ui_event("address_create", payload)
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
                _emit_ui_event("address_modify", payload)
                return jsonify({"ok": True, "action": action, "payload": payload})
            if action == "log_counter_start":
                ok, message = _start_job(
                    counter_jobs,
                    ip,
                    lambda stop_event: _counter_worker(ricoh_service, toshiba_service, target, stop_event),
                )
                _emit_ui_event("counter_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": counter_jobs.get(ip, {})})
            if action == "log_counter_stop":
                ok, message = _stop_job(counter_jobs, ip)
                _emit_ui_event("counter_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "log_status_start":
                ok, message = _start_job(
                    status_jobs,
                    ip,
                    lambda stop_event: _status_worker(ricoh_service, toshiba_service, target, stop_event),
                )
                _emit_ui_event("status_log_start", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message, "job": status_jobs.get(ip, {})})
            if action == "log_status_stop":
                ok, message = _stop_job(status_jobs, ip)
                _emit_ui_event("status_log_stop", {"ip": ip, "ok": ok, "message": message})
                return jsonify({"ok": ok, "action": action, "message": message})
            if action == "exit":
                c_ok, c_message = _stop_job(counter_jobs, ip)
                s_ok, s_message = _stop_job(status_jobs, ip)
                if not c_ok and not s_ok:
                    _emit_ui_event("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
                    return jsonify({"ok": True, "action": action, "message": "No running log jobs"})
                _emit_ui_event("log_stop_all", {"ip": ip, "counter": c_message, "status": s_message})
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
        last_auth_user = ""
        last_auth_password = ""
        last_auth_attempt = ""
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
            except Exception as exc:  # noqa: BLE001
                state = {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": "/web/entry/en/websys/config/getUserAuthenticationManager.cgi",
                    "status": "error",
                    "state": "error",
                    "auth_ok": False,
                    "error": str(exc),
                }
                LOGGER.warning(
                    "Machine state exception: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    exc,
                )

            state_status_raw = str(state.get("status") or state.get("state") or "").strip().lower()
            if state_status_raw in {"enabled"}:
                state_status = "enable"
            elif state_status_raw in {"disabled"}:
                state_status = "disable"
            elif state_status_raw in {"enable", "disable", "error"}:
                state_status = state_status_raw
            elif "error" in state:
                state_status = "error"
            else:
                state_status = "enable" if bool(state.get("enabled", False)) else "disable"
            state["status"] = state_status
            state["state"] = state_status

            if state_status == "error":
                error_text = str(state.get("error") or "Unable to read machine state").strip()
                state["error"] = error_text
                last_error = error_text
                if bool(state.get("auth_ok", False)):
                    last_auth_user = str(target.user or "").strip()
                    last_auth_password = str(target.password or "").strip()
                    last_auth_attempt = label
                LOGGER.warning(
                    "Machine state attempt failed: trace_id=%s ip=%s attempt=%s error=%s",
                    trace_id,
                    ip,
                    label,
                    error_text,
                )
                continue

            auth_user = str(target.user or "").strip()
            auth_password = str(target.password or "").strip()
            LOGGER.info(
                "Machine state success: trace_id=%s ip=%s attempt=%s status=%s method=%s auth_user=%s has_password=%s",
                trace_id,
                ip,
                label,
                state_status,
                str(state.get("method", "")),
                auth_user,
                bool(auth_password),
            )
            return jsonify(
                {
                    "ok": True,
                    "ip": ip,
                    "state": state,
                    "trace_id": trace_id,
                    "auth_attempt": label,
                    "auth_user": auth_user,
                    "auth_password": auth_password,
                }
            )

        error_text = last_error or "Unable to read machine state"
        return jsonify(
            {
                "ok": True,
                "error": error_text,
                "ip": ip,
                "trace_id": trace_id,
                "auth_attempt": last_auth_attempt,
                "auth_user": last_auth_user,
                "auth_password": last_auth_password,
                "state": {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": "/web/entry/en/websys/config/getUserAuthenticationManager.cgi",
                    "status": "error",
                    "state": "error",
                    "auth_ok": bool(last_auth_user or last_auth_password),
                    "error": error_text,
                },
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

        app_cfg.set_value("polling.enabled", enabled)

        if enabled:
            ok, message = bridge.start()
            return jsonify({"ok": ok, "message": message, "status": bridge.status()})
        bridge.stop()
        return jsonify({"ok": True, "message": "Polling stopped", "status": bridge.status()})

    @app.post("/api/polling/trigger")
    def api_polling_trigger() -> Any:
        bridge: PollingBridge = app.config["POLLING_BRIDGE"]
        ok, message = bridge.trigger_once()
        code = 200 if ok else 400
        return jsonify({"ok": ok, "message": message, "status": bridge.status()}), code

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


def run_web_server(app: Flask, host: str, port: int) -> tuple[Any, threading.Thread]:
    server = make_server(host, port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="agent-web-server")
    thread.start()
    LOGGER.info("Web server started on http://%s:%s", host, port)
    return server, thread


def shutdown_app_resources(app: Flask) -> None:
    bridge = app.config.get("POLLING_BRIDGE")
    if bridge is not None:
        try:
            bridge.stop()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Polling bridge stop failed", exc_info=True)

