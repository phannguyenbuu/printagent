from __future__ import annotations

from typing import Any

from agent.config import AppConfig
from agent.modules.ricoh.service import RicohService
from agent.services.api_client import APIClient, Printer
from agent.services.runtime import default_ftp_root
from agent.services.scan_drop import build_drop_folder_metadata
from agent.web_collect import _resolve_printer
from agent.web_discovery import _load_printers, _normalize_ipv4
from agent.web_scan_support import _register_scan_root, _sanitize_ftp_name


def resolve_target_printer(
    config: AppConfig,
    api_client: APIClient,
    *,
    ip: str,
    user: str = "",
    password: str = "",
) -> Printer:
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


def create_local_ftp_for_address(
    config: AppConfig,
    ricoh_service: RicohService,
    address_name: str,
    *,
    printer_ip: str = "",
) -> dict[str, Any]:
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
