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
from werkzeug.utils import secure_filename
from sqlalchemy import func, select, text
from logging.handlers import RotatingFileHandler

from config import ServerConfig
from db import create_session_factory
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
    _parse_query_datetime,
    _parse_timestamp,
    _resolve_lan_info_from_body,
    _resolve_lan_uid_from_body,
    _safe_path_token,
    _time_scope_start,
    _to_int,
    _to_json_value,
    _to_page,
    _to_text,
    _to_text_max,
    _write_last_data,
    _format_date,
    _format_datetime,
)
from serializers import (
    _serialize_task_model,
    _serialize_user_model,
    _serialize_network_model,
    _serialize_workspace_model,
    _serialize_location_model,
    _serialize_repair_model,
    _serialize_material_model,
    _serialize_lead_model,
)
from models import (
    AgentNode,
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
    Lead,
    Workspace,
    Location,
    RepairRequest,
    Material,
)

LOGGER = logging.getLogger(__name__)
UI_TZ = timezone(timedelta(hours=7))
ONLINE_STALE_SECONDS = 300
SCAN_UPLOAD_ROOT = Path("storage/uploads/scans")
LAST_DATA_FILE = Path("storage/data/last_data.json")
PUBLIC_API_FILE = Path("PUBLIC_API.md")
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


def _validate_polling_auth(body: dict[str, Any], lead_key_map: dict[str, str], sent_token: str) -> tuple[bool, str, Any]:
    lead = _to_text(body.get("lead"))
    if not lead:
        return False, "", (jsonify({"ok": False, "error": "Missing lead"}), 400)
    expected_token = lead_key_map.get(lead)
    if not expected_token or sent_token != expected_token:
        return False, "", (jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401)
    return True, lead, None


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    _configure_server_logging()
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
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
        
        # Self-heal LanSite table
        session.execute(text('ALTER TABLE "LanSite" ADD COLUMN IF NOT EXISTS fingerprint_signature TEXT;'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_lansite_fingerprint ON "LanSite" (lead, fingerprint_signature);'))
        
        # Self-heal AgentNode table
        session.execute(text('ALTER TABLE "AgentNode" ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        # Self-heal CounterInfor / StatusInfor for dedupe + touch-updated flow
        session.execute(text('ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS mac_id VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "CounterInfor" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS mac_id VARCHAR(64) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "StatusInfor" ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_counterinfor_lead_lan_agent_ip_mac ON "CounterInfor" (lead, lan_uid, agent_uid, ip, mac_id);'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_statusinfor_lead_lan_agent_ip_mac ON "StatusInfor" (lead, lan_uid, agent_uid, ip, mac_id);'))
        session.execute(text('CREATE INDEX IF NOT EXISTS idx_deviceinfor_lead_lan_mac ON "DeviceInfor" (lead, lan_uid, mac_id);'))
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
                        "created_at": _format_date(r.created_at),
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

        lead = _to_text(body.get("lead"))
        if not lead:
            LOGGER.warning("register: missing lead from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Missing lead"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        expected_token = lead_key_map.get(lead)
        if not expected_token or sent_token != expected_token:
            LOGGER.warning("register: unauthorized lead=%s ip=%s", lead, request.remote_addr)
            return jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401

        lan_uid, fingerprint = _resolve_lan_info_from_body(body)
        agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
        lan_name = _to_text(body.get("lan_name"))
        subnet_cidr = _to_text(body.get("subnet_cidr"))
        gateway_ip = _to_text(body.get("gateway_ip"))
        gateway_mac = _to_text(body.get("gateway_mac"))
        hostname = _to_text(body.get("hostname"))
        local_ip = _to_text(body.get("local_ip"))
        local_mac = _to_text(body.get("local_mac"))

        with session_factory() as session:
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
            }
            for e in logs
        )
        events.extend(
            {
                "id": f"online-{int(e.id)}",
                "kind": "online",
                "value": "Online" if bool(e.is_online) else "Offline",
                "changed_at": e.changed_at.isoformat() if e.changed_at else "",
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
                },
                "events": events,
            }
        )

    @app.patch("/api/devices/<int:printer_id>/enable")
    def device_set_enable(printer_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", True))
        auth_user = _to_text(body.get("auth_user"))
        auth_password = _to_text(body.get("auth_password"))
        requested_at = datetime.now(timezone.utc)
        with session_factory() as session:
            printer = session.get(Printer, printer_id)
            if printer is None:
                return jsonify({"ok": False, "error": "Printer not found"}), 404
            if auth_user:
                printer.auth_user = auth_user
            if auth_password:
                printer.auth_password = auth_password
            if not _to_text(printer.auth_user):
                return jsonify({"ok": False, "error": "Missing auth_user"}), 400
            if not _to_text(printer.auth_password):
                return jsonify({"ok": False, "error": "Missing auth_password"}), 400

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
                            "id": printer_id,
                            "enabled": enabled,
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
                    "command_id": command_id,
                }
            ),
            504,
        )

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
        lead = _to_text(request.args.get("lead"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        lan_uid = _resolve_lan_uid_from_body(
            {
                "lead": lead,
                "lan_uid": _to_text(request.args.get("lan_uid")),
                "agent_uid": agent_uid,
                "hostname": "",
                "local_ip": "",
                "gateway_ip": "",
                "gateway_mac": "",
            }
        )
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, lead_valid, auth_error = _validate_polling_auth({"lead": lead}, lead_key_map, sent_token)
        if not ok_auth:
            return auth_error
        with session_factory() as session:
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
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
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

    @app.post("/api/polling/inventory")
    def ingest_inventory() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("inventory: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("inventory: unauthorized lead=%s ip=%s", _to_text(body.get("lead")), request.remote_addr)
            return auth_error

        lan_uid = _resolve_lan_uid_from_body(body)
        agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
        hostname = _to_text(body.get("hostname"))
        local_ip = _to_text(body.get("local_ip"))
        local_mac = _to_text(body.get("local_mac"))
        timestamp = _parse_timestamp(body.get("timestamp"))
        devices = body.get("devices") if isinstance(body.get("devices"), list) else []
        inserted = 0
        updated = 0

        with session_factory() as session:
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
        lead = _to_text(request.form.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing lead"}), 400
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, lead_valid, auth_error = _validate_polling_auth({"lead": lead}, lead_key_map, sent_token)
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
        fingerprint = _to_text(request.form.get("fingerprint"))
        event_time = _parse_timestamp(request.form.get("timestamp"))

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

        upload.save(dest_path)
        file_size = int(dest_path.stat().st_size if dest_path.exists() else 0)
        relative_path = str(dest_path.as_posix())

        LOGGER.info(
            "scan-upload: lead=%s lan=%s agent=%s host=%s ip=%s file=%s size=%s source=%s",
            lead_valid,
            lan_uid,
            agent_uid,
            hostname,
            local_ip,
            relative_path,
            file_size,
            source_path,
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
            }
        )

    @app.post("/api/polling")
    def ingest_polling() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("polling: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("polling: unauthorized lead=%s ip=%s", lead, request.remote_addr)
            return auth_error

        printer_name = _to_text(body.get("printer_name"))
        ip = _to_text(body.get("ip"))
        lan_uid = _resolve_lan_uid_from_body(body)
        agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
        lan_name = _to_text(body.get("lan_name"))
        subnet_cidr = _to_text(body.get("subnet_cidr"))
        gateway_ip = _to_text(body.get("gateway_ip"))
        gateway_mac = _to_text(body.get("gateway_mac"))
        hostname = _to_text(body.get("hostname"))
        local_ip = _to_text(body.get("local_ip"))
        local_mac = _to_text(body.get("local_mac"))
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
        lead = _to_text(request.args.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing lead parameter"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        expected_token = lead_key_map.get(lead)
        if not expected_token or sent_token != expected_token:
            return jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401

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
                    "last_seen_at": p.updated_at.isoformat() if p.updated_at else ""
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
                            "created_at": h.created_at.isoformat() if h.created_at else "",
                            "createAt": h.created_at.isoformat() if h.created_at else "",
                            "last_counter_at": h.last_counter_at.isoformat() if h.last_counter_at else "",
                            "last_status_at": h.last_status_at.isoformat() if h.last_status_at else "",
                            "updated_at": h.updated_at.isoformat() if h.updated_at else "",
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
                            "created_at": d.created_at.isoformat() if d.created_at else "",
                            "createAt": d.created_at.isoformat() if d.created_at else "",
                            "last_counter_at": d.last_counter_at.isoformat() if d.last_counter_at else "",
                            "last_status_at": d.last_status_at.isoformat() if d.last_status_at else "",
                            "updated_at": d.updated_at.isoformat() if d.updated_at else "",
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
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
                        "last_counter_at": row.last_counter_at.isoformat() if row.last_counter_at else "",
                        "last_status_at": row.last_status_at.isoformat() if row.last_status_at else "",
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
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
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

        normalized_mac = mac_input.replace("-", ":").upper()

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
                    "updated_at": row.updated_at.isoformat() if row.updated_at else "",
                }
            )

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
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
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
        lead = _to_text(request.args.get("lead"))
        lan_uid = _to_text(request.args.get("lan_uid"))
        mac = _to_text(request.args.get("mac")).replace("-", ":").upper()

        if not lead or not lan_uid or not mac:
            return jsonify({"ok": False, "error": "Missing parameters: lead, lan_uid, mac"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        expected_token = lead_key_map.get(lead)
        if not expected_token or sent_token != expected_token:
            return jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401

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
                "status": None
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

    def _serialize_task_model(task: Task) -> dict[str, Any]:
        return {
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
            "created_at": _format_date(task.created_at),
            "updated_at": _format_datetime(task.updated_at),
        }

    def _serialize_user_model(user: UserAccount) -> dict[str, Any]:
        return {
            "id": int(user.id),
            "lead": user.lead,
            "username": user.username,
            "password": user.password or "",
            "full_name": user.full_name,
            "email": user.email,
            "phone_number": user.phone_number,
            "role": user.role,
            "is_active": user.is_active,
            "notes": user.notes,
            "created_at": _format_date(user.created_at),
            "updated_at": _format_datetime(user.updated_at),
        }

    def _serialize_network_model(net: NetworkInfo) -> dict[str, Any]:
        return {
            "id": int(net.id),
            "lead": net.lead,
            "lan_uid": net.lan_uid,
            "network_id": net.network_id,
            "network_name": net.network_name,
            "office_name": net.office_name,
            "real_address": net.real_address,
            "notes": net.notes,
            "created_at": _format_date(net.created_at),
            "updated_at": _format_datetime(net.updated_at),
        }
    @app.get("/api/public/agent-machines")
    def public_agent_machines() -> Any:
        lead = _to_text(request.args.get("lead"))
        agent_uid = _to_text(request.args.get("agent_uid"))
        if not lead or not agent_uid:
            return jsonify({"ok": False, "error": "Missing parameters: lead, agent_uid"}), 400

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
        lead = _to_text(body.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing parameter: lead"}), 400
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, _, auth_error = _validate_polling_auth({"lead": lead}, lead_key_map, sent_token)
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
        lead = _to_text(body.get("lead") or request.args.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing parameter: lead"}), 400
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, _, auth_error = _validate_polling_auth({"lead": lead}, lead_key_map, sent_token)
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
        lead = _to_text(request.args.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing parameter: lead"}), 400
        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        ok_auth, _, auth_error = _validate_polling_auth({"lead": lead}, lead_key_map, sent_token)
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
            stmt = select(Workspace).order_by(Workspace.name.asc())
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
            stmt = select(Location).order_by(Location.name.asc())
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
            new_ws = Workspace(
                id=ws_id,
                name=_to_text(body.get("name")),
                logo=_to_text(body.get("logo")),
                color=_to_text(body.get("color")),
                address=_to_text(body.get("address")),
            )
            session.add(new_ws)
            session.commit()
            return jsonify({"ok": True, "row": _serialize_workspace_model(new_ws)})

    @app.patch("/api/workspaces/<string:ws_id>")
    def update_workspace(ws_id: str) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            ws = session.get(Workspace, ws_id)
            if not ws:
                return jsonify({"ok": False, "error": "Workspace not found"}), 404
            if "name" in body: ws.name = _to_text(body.get("name"))
            if "logo" in body: ws.logo = _to_text(body.get("logo"))
            if "color" in body: ws.color = _to_text(body.get("color"))
            if "address" in body: ws.address = _to_text(body.get("address"))
            session.commit()
            return jsonify({"ok": True, "row": _serialize_workspace_model(ws)})

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
            new_loc = Location(
                id=loc_id,
                name=_to_text(body.get("name")),
                address=_to_text(body.get("address")),
                phone=_to_text(body.get("phone")),
                machine_count=_to_int(body.get("machine_count")) or 0,
                workspace_id=_to_text(body.get("workspace_id")),
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
            if "phone" in body: loc.phone = _to_text(body.get("phone"))
            if "machine_count" in body: loc.machine_count = _to_int(body.get("machine_count"))
            if "workspace_id" in body: loc.workspace_id = _to_text(body.get("workspace_id"))
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
            new_mat = Material(
                id=mat_id,
                repair_request_id=_to_text(body.get("repair_request_id")),
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
            if "repair_request_id" in body: mat.repair_request_id = _to_text(body.get("repair_request_id"))
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

    def _apply_date_filters(stmt: Any, model: Any, date_from: str | None, date_to: str | None) -> Any:
        if date_from:
            try:
                dt_from = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
                stmt = stmt.where(model.created_at >= dt_from)
            except ValueError:
                pass
        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc)
                # Set to end of day if only date is provided
                if len(date_to) == 10:
                    dt_to = dt_to.replace(hour=23, minute=59, second=59)
                stmt = stmt.where(model.created_at <= dt_to)
            except ValueError:
                pass
        return stmt

    def _serialize_workspace_model(ws: Workspace) -> dict[str, Any]:
        return {
            "id": ws.id,
            "name": ws.name,
            "logo": ws.logo,
            "color": ws.color,
            "address": ws.address,
            "created_at": _format_date(ws.created_at),
        }

    def _serialize_location_model(loc: Location) -> dict[str, Any]:
        return {
            "id": loc.id,
            "name": loc.name,
            "address": loc.address,
            "phone": loc.phone,
            "machine_count": loc.machine_count,
            "workspace_id": loc.workspace_id,
            "created_at": _format_date(loc.created_at),
        }

    def _serialize_repair_model(rep: RepairRequest) -> dict[str, Any]:
        return {
            "id": rep.id,
            "machine_name": rep.machine_name,
            "location_id": rep.location_id,
            "workspace_id": rep.workspace_id,
            "description": rep.description,
            "priority": rep.priority,
            "status": rep.status,
            "created_by": rep.created_by,
            "assigned_to": rep.assigned_to,
            "labor_cost": rep.labor_cost,
            "note": rep.note,
            "contact_phone": rep.contact_phone,
            "created_at": _format_date(rep.created_at),
            "updated_at": _format_datetime(rep.updated_at),
            "accepted_at": _format_datetime(rep.accepted_at),
            "completed_at": _format_datetime(rep.completed_at),
        }

    def _serialize_material_model(mat: Material) -> dict[str, Any]:
        return {
            "id": mat.id,
            "repair_request_id": mat.repair_request_id,
            "name": mat.name,
            "quantity": mat.quantity,
            "unit_price": mat.unit_price,
            "total_price": mat.total_price,
            "created_at": _format_date(mat.created_at),
        }

    def _serialize_lead_model(lead: Lead) -> dict[str, Any]:
        return {
            "id": lead.id,
            "name": lead.name,
            "email": lead.email,
            "phone": lead.phone,
            "notes": lead.notes,
            "created_at": _format_date(lead.created_at),
        }

    @app.get("/users")
    def users_page() -> Any:
        return render_template("users.html", active_tab="users", page_title="User Accounts")

    @app.get("/api/users")
    def list_users() -> Any:
        lead = _to_text(request.args.get("lead"))
        username = _to_text(request.args.get("username"))
        fullname = _to_text(request.args.get("fullname"))
        role = _to_text(request.args.get("role"))
        date_from = _to_text(request.args.get("date_from"))
        date_to = _to_text(request.args.get("date_to"))
        with session_factory() as session:
            stmt = select(UserAccount).order_by(UserAccount.username.asc())
            if lead:
                stmt = stmt.where(UserAccount.lead == lead)
            if username:
                stmt = stmt.where(UserAccount.username.ilike(f"%{username}%"))
            if fullname:
                stmt = stmt.where(UserAccount.full_name.ilike(f"%{fullname}%"))
            if role:
                stmt = stmt.where(UserAccount.role == role)
            stmt = _apply_date_filters(stmt, UserAccount, date_from, date_to)
            rows = session.execute(stmt).scalars().all()
            return jsonify({"ok": True, "rows": [_serialize_user_model(r) for r in rows]})

    @app.post("/api/users")
    def create_user() -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            new_user = UserAccount(
                lead=_to_text(body.get("lead")),
                username=_to_text(body.get("username")),
                full_name=_to_text(body.get("full_name")),
                email=_to_text(body.get("email")),
                phone_number=_to_text(body.get("phone_number")),
                role=_to_text(body.get("role")) or "worker",
                is_active=bool(body.get("is_active", True)),
                notes=_to_text(body.get("notes")),
            )
            session.add(new_user)
            session.commit()
            return jsonify({"ok": True, "user": _serialize_user_model(new_user)})

    @app.patch("/api/users/<int:user_id>")
    def update_user(user_id: int) -> Any:
        body = request.get_json(silent=True) or {}
        with session_factory() as session:
            user = session.get(UserAccount, user_id)
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            if "username" in body: user.username = _to_text(body.get("username"))
            if "full_name" in body: user.full_name = _to_text(body.get("full_name"))
            if "email" in body: user.email = _to_text(body.get("email"))
            if "phone_number" in body: user.phone_number = _to_text(body.get("phone_number"))
            if "role" in body: user.role = _to_text(body.get("role"))
            if "is_active" in body: user.is_active = bool(body.get("is_active"))
            if "notes" in body: user.notes = _to_text(body.get("notes"))
            session.commit()
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
                lead=_to_text(body.get("lead")),
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

    @app.get("/downloads")
    def downloads_page_ui() -> Any:
        return render_template("downloads.html", active_tab="downloads", page_title="Agent Downloads")

    return app


if __name__ == "__main__":
    _configure_server_logging()
    config = ServerConfig()
    app = create_app()
    LOGGER.info("server start host=%s port=%s debug=%s", config.host, config.port, config.debug)
    app.run(host=config.host, port=config.port, debug=config.debug)
