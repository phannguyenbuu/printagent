from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from sqlalchemy import select

from app_helpers import (
    ONLINE_STALE_SECONDS,
    _load_agent_release_manifest,
    _format_agents_datetime_ui,
    _serialize_audit_payload_agents,
    _request_api_token,
    _resolve_request_lead,
    _resolve_lan_uid_with_session,
    _is_agent_master_and_get_emails,
    _is_newer_version,
)
from utils import (
    _to_text,
    _to_int,
    _normalize_mac,
    _normalize_ipv4,
    _resolve_lan_uid_from_body,
)
from serializers import (
    _refresh_stale_agent_offline,
    _upsert_lan_and_agent,
)
from models import AgentNode, LanSite, Printer, AgentPresenceLog

LOGGER = logging.getLogger(__name__)


def register_agent_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.get("/agents")
    def agents_page() -> Any:
        manifest = _load_agent_release_manifest()
        version = _to_text(manifest.get("version")) or "unknown"
        published_at = _to_text(manifest.get("published_at"))
        release_date = ""
        if published_at:
            from utils import _parse_timestamp, UI_TZ
            release_date = _format_agents_datetime_ui(_parse_timestamp(published_at))
        
        script_release_date = ""
        try:
            from utils import UI_TZ
            script_names = ["get_address_book.py", "scan_ricoh.py", "ricoh_address_book.py", "ricoh_wizard.py", "ricoh_web_scan.py"]
            mtimes = []
            for name in script_names:
                script_path = os.path.join(os.path.dirname(__file__), "static", "releases", name)
                if os.path.exists(script_path):
                    mtimes.append(os.path.getmtime(script_path))
            if mtimes:
                max_mtime = max(mtimes)
                dt = datetime.fromtimestamp(max_mtime, tz=UI_TZ)
                script_release_date = _format_agents_datetime_ui(dt)
        except Exception:
            pass
        if not script_release_date:
            script_release_date = release_date

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
            script_release_date=script_release_date,
        )

    @app.get("/api/agents")
    def list_agents() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        status = _to_text(request.args.get("status")).lower() or "online"
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

            lan_keys = {(_to_text(r[0].lead), _to_text(r[0].lan_uid)) for r in rows}
            master_by_lan = {}
            for l_lead, l_lan in lan_keys:
                if not l_lead or not l_lan:
                    continue
                online_stmt = select(AgentNode).where(
                    AgentNode.lead == l_lead,
                    AgentNode.lan_uid == l_lan,
                    AgentNode.is_online.is_(True)
                ).order_by(AgentNode.id.asc())
                master_agent = session.execute(online_stmt).scalars().first()
                if not master_agent:
                    fallback_stmt = select(AgentNode).where(
                        AgentNode.lead == l_lead,
                        AgentNode.lan_uid == l_lan
                    ).order_by(AgentNode.id.asc())
                    master_agent = session.execute(fallback_stmt).scalars().first()
                if master_agent:
                    master_by_lan[(l_lead, l_lan)] = master_agent.agent_uid

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
            is_master = master_by_lan.get((_to_text(agent.lead), _to_text(agent.lan_uid))) == agent.agent_uid
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
                    "printer_ips": printer_ips_by_lan.get((_to_text(agent.lead), _to_text(agent.lan_uid)), []),
                    "printers": printers_by_agent.get((_to_text(agent.lead), _to_text(agent.lan_uid), _to_text(agent.agent_uid)), []),
                    "lan_printers": printers_by_lan.get((_to_text(agent.lead), _to_text(agent.lan_uid)), []),
                    "last_seen_at": _format_agents_datetime_ui(last_seen),
                    "online_changed_at": _format_agents_datetime_ui(online_changed_at),
                    "is_online": is_online,
                    "is_master": is_master,
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
            ftp_sites = body.get("ftp_sites") if isinstance(body.get("ftp_sites"), list) else None
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
            is_master, emails = _is_agent_master_and_get_emails(session, lead, lan_uid, agent_uid)
            session.commit()
        LOGGER.info("register: lead=%s lan_uid=%s agent_uid=%s hostname=%s master=%s", lead, lan_uid, agent_uid, hostname, is_master)

        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "lan_uid": lan_uid,
                "agent_uid": agent_uid,
                "is_master": is_master,
                "emails": emails,
            }
        )

    @app.get("/api/agent/core-release")
    def get_agent_core_release() -> Any:
        sent_token = _request_api_token()
        ok_auth, lead_valid, auth_error = _resolve_request_lead({}, lead_key_map, sent_token, request.args.get("lead"))
        if not ok_auth:
            return auth_error

        current_version = _to_text(request.args.get("current_version"))
        manifest_path = Path("storage/releases/agent_core_release.json")
        payload = {}
        if manifest_path.exists():
            try:
                payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        if not payload:
            payload = {
                "version": "1.0.0",
                "download_url": "/static/releases/agent_core.zip",
                "sha256": "",
            }

        version = _to_text(payload.get("version"))
        sha256 = _to_text(payload.get("sha256")).lower()
        current_sha = _to_text(request.args.get("current_sha256")).lower()
        if sha256 and current_sha:
            update_available = sha256 != current_sha
        else:
            update_available = _is_newer_version(version, current_version)

        return jsonify({
            "ok": True,
            "version": version,
            "download_url": _to_text(payload.get("download_url")),
            "sha256": sha256,
            "update_available": update_available,
        })

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
