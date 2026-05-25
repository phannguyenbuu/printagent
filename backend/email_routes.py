from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from flask import Flask, jsonify, render_template, request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from models import LanEmail, LanSite

LOGGER = logging.getLogger(__name__)


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def register_email_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.get("/api/lan-emails")
    def list_lan_emails() -> Any:
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        email_query = _to_text(request.args.get("email"))
        agent_uid = _to_text(request.args.get("agent_uid"))

        with session_factory() as session:
            stmt = select(LanEmail).order_by(LanEmail.email_number.asc())
            if lead:
                stmt = stmt.where(LanEmail.lead == lead)
            if lan_uid:
                stmt = stmt.where(LanEmail.lan_uid == lan_uid)
            if email_query:
                stmt = stmt.where(LanEmail.email.ilike(f"%{email_query}%"))
            
            rows = session.execute(stmt).scalars().all()

            is_master = False
            if lead and lan_uid and agent_uid:
                try:
                    from app_helpers import _is_agent_master_and_get_emails
                    is_master, _ = _is_agent_master_and_get_emails(session, lead, lan_uid, agent_uid)
                except Exception as e:
                    LOGGER.warning("Failed to determine is_master in list_lan_emails: %s", e)

        return jsonify({
            "ok": True,
            "is_master": is_master,
            "rows": [
                {
                    "id": r.id,
                    "lead": r.lead,
                    "lan_uid": r.lan_uid,
                    "email": r.email,
                    "email_number": r.email_number,
                    "email_type": r.email_type,
                    "pc_name": r.pc_name or "",
                    "ftp_user": "goxprint",
                    "ftp_password": "gox918721",
                    "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
                }
                for r in rows
            ]
        })

    @app.post("/api/lan-emails")
    def create_lan_email() -> Any:
        body = request.get_json(silent=True) or {}
        lead = _to_text(body.get("lead"))
        lan_uid = _to_text(body.get("lan_uid"))
        email = _to_text(body.get("email")).lower()
        email_type = _to_text(body.get("email_type")) or "common"
        pc_name = _to_text(body.get("pc_name"))

        if not lead or not lan_uid or not email:
            return jsonify({"ok": False, "error": "Lead, LAN UID, and Email are required"}), 400

        with session_factory() as session:
            # Check if lan_uid actually exists
            lan_exists = session.execute(
                select(LanSite).where(LanSite.lead == lead, LanSite.lan_uid == lan_uid)
            ).scalar_one_or_none()
            if not lan_exists:
                return jsonify({"ok": False, "error": f"LAN UID '{lan_uid}' does not exist for lead '{lead}'"}), 400

            # Check if email is already registered in this LAN
            existing = session.execute(
                select(LanEmail).where(LanEmail.lead == lead, LanEmail.lan_uid == lan_uid, LanEmail.email == email)
            ).scalar_one_or_none()
            if existing:
                return jsonify({"ok": False, "error": f"Email '{email}' is already registered in this LAN"}), 400

            # Compute next email number starting from 2130
            stmt = select(func.max(LanEmail.email_number)).where(
                LanEmail.lead == lead,
                LanEmail.lan_uid == lan_uid
            )
            max_num = session.scalar(stmt)
            next_num = 2130 if max_num is None else max_num + 1

            new_email = LanEmail(
                lead=lead,
                lan_uid=lan_uid,
                email=email,
                email_number=next_num,
                email_type=email_type,
                pc_name=pc_name
            )
            session.add(new_email)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return jsonify({"ok": False, "error": "Failed to create email due to conflict"}), 409
            
            return jsonify({
                "ok": True,
                "email": {
                    "id": new_email.id,
                    "lead": new_email.lead,
                    "lan_uid": new_email.lan_uid,
                    "email": new_email.email,
                    "email_number": new_email.email_number,
                    "email_type": new_email.email_type,
                    "pc_name": new_email.pc_name or "",
                }
            })

    @app.delete("/api/lan-emails/<int:email_id>")
    def delete_lan_email(email_id: int) -> Any:
        with session_factory() as session:
            email = session.get(LanEmail, email_id)
            if not email:
                return jsonify({"ok": False, "error": "Email record not found"}), 404
            
            session.delete(email)
            session.commit()
            return jsonify({"ok": True, "id": email_id})
