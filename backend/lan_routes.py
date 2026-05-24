from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select

from utils import _to_text, _format_datetime_ui, _apply_date_filters
from serializers import _refresh_stale_agent_offline
from app_helpers import _serialize_audit_payload_iso
from models import LanSite, AgentNode, LanEmail, Printer

LOGGER = logging.getLogger(__name__)


def register_lan_routes(app: Flask, session_factory: Any) -> None:

    @app.get("/api/lan-sites")
    def list_lan_sites() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        name = _to_text(request.args.get("name"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        standalone = request.args.get("standalone", "false").lower() == "true"
        # require_online is parsed but not currently applied in the filter below based on monolith
        # require_online = _to_text(request.args.get("require_online")).lower() == "true"
        with session_factory() as session:
            _refresh_stale_agent_offline(session=session, lead=lead)
            session.commit()

            stmt = select(LanSite).order_by(LanSite.created_at.desc())

            if lead:
                stmt = stmt.where(LanSite.lead == lead)
            if lan_uid:
                stmt = stmt.where(LanSite.lan_uid.ilike(f"%{lan_uid}%"))
            if name:
                stmt = stmt.where(LanSite.lan_name.ilike(f"%{name}%"))
            stmt = _apply_date_filters(stmt, LanSite, date_from, date_to)
            rows = session.execute(stmt).scalars().all()

            # Query Printers first so we can filter rows by printer presence in standalone mode
            printer_stmt = select(Printer)
            if lead:
                printer_stmt = printer_stmt.where(Printer.lead == lead)
            printer_rows = session.execute(printer_stmt).scalars().all()
            printers_by_lan: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for p in printer_rows:
                printers_by_lan[p.lan_uid].append({
                    "id": p.id,
                    "printer_name": p.printer_name,
                    "ip": p.ip,
                    "mac_id": p.mac_address,
                    "is_online": p.is_online,
                    "enabled": p.enabled,
                    "auth_user": p.auth_user or "",
                    "auth_password": p.auth_password or "",
                    "address_book_sync": p.address_book_sync,
                })

            agent_stmt = select(AgentNode)
            if lead:
                agent_stmt = agent_stmt.where(AgentNode.lead == lead)
            agent_rows = session.execute(agent_stmt).scalars().all()
            
            master_by_lan = {}
            agents_by_lan_all: dict[tuple[str, str], list[AgentNode]] = defaultdict(list)
            for a in agent_rows:
                agents_by_lan_all[(a.lead, a.lan_uid)].append(a)
            for (l_lead, l_lan), l_agents in agents_by_lan_all.items():
                l_agents_sorted = sorted(l_agents, key=lambda x: x.id)
                master_agent = next((x for x in l_agents_sorted if x.is_online), None)
                if not master_agent and l_agents_sorted:
                    master_agent = l_agents_sorted[0]
                if master_agent:
                    master_by_lan[(l_lead, l_lan)] = master_agent.agent_uid

            agents_by_lan: dict[str, list[dict[str, Any]]] = defaultdict(list)
            active_agents_by_lan: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for agent in agent_rows:
                agent_dict = {
                    "id": int(agent.id),
                    "agent_uid": agent.agent_uid,
                    "hostname": agent.hostname,
                    "local_ip": agent.local_ip,
                    "local_mac": agent.local_mac,
                    "app_version": agent.app_version,
                    "run_mode": agent.run_mode,
                    "web_port": agent.web_port,
                    "ftp_ports": agent.ftp_ports,
                    "ftp_sites": list(agent.ftp_sites or []),
                    "is_master": master_by_lan.get((agent.lead, agent.lan_uid)) == agent.agent_uid,
                    "is_online": bool(agent.is_online),
                    "updated_at": _format_datetime_ui(agent.updated_at),
                    "created_at": _format_datetime_ui(agent.created_at)
                }
                agents_by_lan[agent.lan_uid].append(agent_dict)
                if agent.is_online:
                    active_agents_by_lan[agent.lan_uid].append(agent_dict)

            if standalone:
                rows = [r for r in rows if len(printers_by_lan.get(r.lan_uid, [])) > 0]
            else:
                rows = [r for r in rows if len(active_agents_by_lan.get(r.lan_uid, [])) > 0]

            email_stmt = select(LanEmail).order_by(LanEmail.email_number.asc())
            if lead:
                email_stmt = email_stmt.where(LanEmail.lead == lead)
            email_rows = session.execute(email_stmt).scalars().all()
            emails_by_lan: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for em in email_rows:
                emails_by_lan[em.lan_uid].append({
                    "id": em.id,
                    "email": em.email,
                    "email_number": em.email_number,
                    "email_type": em.email_type,
                    "pc_name": em.pc_name,
                })


            return jsonify({
                "rows": [
                    {
                        "lead": r.lead,
                        "lan_uid": r.lan_uid,
                        "lan_name": r.lan_name,
                        "address": r.address or "",
                        "subnet_cidr": r.subnet_cidr,
                        "gateway_ip": r.gateway_ip,
                        "gateway_mac": r.gateway_mac,
                        "fingerprint_signature": r.fingerprint_signature,
                        "active_agents": len(active_agents_by_lan.get(r.lan_uid, [])),
                        "agents": active_agents_by_lan.get(r.lan_uid, []),
                        "emails": emails_by_lan.get(r.lan_uid, []),
                        "printers": printers_by_lan.get(r.lan_uid, []),
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
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

    @app.patch("/api/lan-sites/<string:lan_uid>")
    def update_lan_site(lan_uid: str) -> Any:
        lead = _to_text(request.args.get("lead"))
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        
        with session_factory() as session:
            stmt = select(LanSite).where(LanSite.lan_uid == lan_uid)
            if lead:
                stmt = stmt.where(LanSite.lead == lead)
            lan = session.execute(stmt).scalar_one_or_none()
            if not lan:
                return jsonify({"ok": False, "error": "LAN Site not found"}), 404
            
            if "lan_name" in body:
                lan.lan_name = str(body["lan_name"]).strip()
            if "address" in body:
                lan.address = str(body["address"]).strip()
                
            session.commit()
            return jsonify({
                "ok": True, 
                "lan_uid": lan_uid,
                "lan_name": lan.lan_name,
                "address": lan.address or ""
            })
