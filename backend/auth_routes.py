from __future__ import annotations

import logging
import os
import json
import hashlib
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select

from utils import _to_text
from models import UserAccount, UserType
from serializers import _serialize_user_model, _user_type_value

LOGGER = logging.getLogger(__name__)


def register_auth_routes(app: Flask, session_factory: Any) -> None:

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
                    user = UserAccount(
                        lead='default',
                        username=email.split('@')[0],
                        email=email,
                        full_name=full_name,
                        password=hashlib.sha256(os.urandom(16)).hexdigest(),
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
