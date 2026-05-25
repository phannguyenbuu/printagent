from __future__ import annotations

import logging
import re
import socket
from pathlib import Path
from typing import Any

from flask import jsonify, request

from agent.services.polling_bridge import PollingBridge
from agent.services.runtime import default_ftp_root
from agent.services.scan_drop import build_drop_folder_metadata
from agent.web_discovery import _normalize_ipv4
from agent.web_scan_support import _register_scan_root, _sanitize_ftp_name

LOGGER = logging.getLogger(__name__)


def register_ftp_routes(app):
    config = app.config["APP_CONFIG"]
    ricoh_service = app.config["RICOH_SERVICE"]

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

