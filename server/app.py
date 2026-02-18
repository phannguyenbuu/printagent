from __future__ import annotations

import hashlib
import logging
from bisect import bisect_right
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename
from sqlalchemy import func, select, text

from config import ServerConfig
from db import create_session_factory
from models import (
    AgentNode,
    Base,
    CounterBaseline,
    CounterInfor,
    LanSite,
    Printer,
    PrinterControlCommand,
    PrinterEnableLog,
    PrinterOnlineLog,
    StatusInfor,
)

LOGGER = logging.getLogger(__name__)
UI_TZ = timezone(timedelta(hours=7))
ONLINE_STALE_SECONDS = 300
SCAN_UPLOAD_ROOT = Path("storage/uploads/scans")
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


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except Exception:  # noqa: BLE001
        return None


def _to_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_path_token(value: str) -> str:
    text = _to_text(value)
    if not text:
        return "unknown"
    cleaned = secure_filename(text)
    return cleaned or "unknown"


def _normalize_ipv4(value: str) -> str:
    text = _to_text(value)
    parts = text.split(".")
    if len(parts) != 4:
        return ""
    try:
        nums = [int(p) for p in parts]
    except Exception:  # noqa: BLE001
        return ""
    if any(n < 0 or n > 255 for n in nums):
        return ""
    return ".".join(str(n) for n in nums)


def _parse_timestamp(value: Any) -> datetime:
    text = _to_text(value)
    if not text:
        return datetime.now(timezone.utc)
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc)


def _parse_query_datetime(value: Any, end_of_minute: bool = False) -> datetime | None:
    text = _to_text(value)
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except Exception:  # noqa: BLE001
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UI_TZ)
    if end_of_minute and len(text) <= 16:
        dt = dt.replace(second=59, microsecond=999999)
    return dt.astimezone(timezone.utc)


def _resolve_lan_uid_from_body(body: dict[str, Any]) -> str:
    raw = _to_text(body.get("lan_uid"))
    if raw and raw.lower() not in {"lan-default", "legacy-lan", "default", "lan_default"}:
        return raw

    lead = _to_text(body.get("lead"))
    local_ip = _normalize_ipv4(_to_text(body.get("local_ip")))
    gateway_ip = _normalize_ipv4(_to_text(body.get("gateway_ip")))
    gateway_mac = _to_text(body.get("gateway_mac")).replace("-", ":").upper()
    agent_uid = _to_text(body.get("agent_uid"))
    hostname = _to_text(body.get("hostname"))
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24" if local_ip else ""

    signature = "|".join(
        [
            f"lead={lead}",
            f"subnet={subnet}",
            f"gateway_ip={gateway_ip}",
            f"gateway_mac={gateway_mac}",
            f"agent_uid={agent_uid}",
            f"hostname={hostname}",
        ]
    )
    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:16]
    return f"lanf-{digest}"
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc)


def _to_page(value: Any, default: int) -> int:
    try:
        return max(1, int(str(value)))
    except Exception:  # noqa: BLE001
        return default


def _time_scope_start(scope: str) -> datetime | None:
    now = datetime.now(timezone.utc)
    key = (scope or "").strip().lower()
    if key in {"hour", "1h"}:
        return now - timedelta(hours=1)
    if key in {"day", "1d"}:
        return now - timedelta(days=1)
    if key in {"7d", "7days", "week"}:
        return now - timedelta(days=7)
    if key in {"month", "1m"}:
        return now - timedelta(days=30)
    if key in {"3months", "3m"}:
        return now - timedelta(days=90)
    if key in {"6months", "6m"}:
        return now - timedelta(days=180)
    if key in {"year", "1y"}:
        return now - timedelta(days=365)
    if key in {"all", ""}:
        return None
    return None


def _is_same_utc_minute(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return False
    l = left.astimezone(timezone.utc).replace(second=0, microsecond=0)
    r = right.astimezone(timezone.utc).replace(second=0, microsecond=0)
    return l == r


def _normalize_counter_payload(counter_data: dict[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in COUNTER_KEYS:
        value = _to_int(counter_data.get(key))
        if value is not None:
            result[key] = value
    return result


def _compute_delta_payload(current: dict[str, int], baseline: dict[str, int]) -> tuple[dict[str, int], bool]:
    delta: dict[str, int] = {}
    has_reset = False
    for key in COUNTER_KEYS:
        cur = current.get(key)
        base = baseline.get(key)
        if cur is None:
            continue
        if base is None:
            delta[key] = cur
            continue
        diff = cur - base
        if diff < 0:
            has_reset = True
            delta[key] = 0
            continue
        delta[key] = diff
    return delta, has_reset


def _apply_baseline(delta_value: int | None, baseline_payload: dict[str, Any], key: str) -> int | None:
    if delta_value is None:
        return None
    base = _to_int(baseline_payload.get(key))
    if base is None:
        base = 0
    return base + delta_value


def _apply_common_filters(
    stmt: Any,
    model: Any,
    lead: str,
    ip: str,
    printer_name: str,
    printer_type: str,
    time_scope: str,
    favorite_only: bool = False,
    datetime_from: str = "",
    datetime_to: str = "",
) -> Any:
    if lead:
        stmt = stmt.where(model.lead == lead)
    if ip:
        stmt = stmt.where(model.ip == ip)
    if printer_name:
        stmt = stmt.where(model.printer_name == printer_name)
    if printer_type in {"ricoh", "toshiba", "epson"}:
        stmt = stmt.where(func.lower(model.printer_name).like(f"%{printer_type}%"))
    from_dt = _parse_query_datetime(datetime_from, end_of_minute=False)
    to_dt = _parse_query_datetime(datetime_to, end_of_minute=True)
    if from_dt:
        stmt = stmt.where(model.timestamp >= from_dt)
    if to_dt:
        stmt = stmt.where(model.timestamp <= to_dt)
    if not from_dt and not to_dt:
        scope_start = _time_scope_start(time_scope)
        if scope_start:
            stmt = stmt.where(model.timestamp >= scope_start)
    if favorite_only:
        stmt = stmt.where(model.is_favorite.is_(True))
    return stmt


def _resolve_day_window(page: int) -> tuple[datetime, datetime, datetime]:
    now_local = datetime.now(UI_TZ)
    today_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    day_start_local = today_start_local - timedelta(days=max(0, page - 1))
    day_end_local = day_start_local + timedelta(days=1)
    return (
        day_start_local.astimezone(timezone.utc),
        day_end_local.astimezone(timezone.utc),
        today_start_local,
    )


def _upsert_lan_and_agent(
    session: Any,
    lead: str,
    lan_uid: str,
    agent_uid: str,
    lan_name: str,
    subnet_cidr: str,
    gateway_ip: str,
    gateway_mac: str,
    hostname: str,
    local_ip: str,
    local_mac: str,
) -> None:
    lan = session.execute(select(LanSite).where(LanSite.lead == lead, LanSite.lan_uid == lan_uid)).scalar_one_or_none()
    if lan is None:
        lan = LanSite(
            lead=lead,
            lan_uid=lan_uid,
            lan_name=lan_name,
            subnet_cidr=subnet_cidr,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
        )
        session.add(lan)
    else:
        lan.lan_name = lan_name or lan.lan_name
        lan.subnet_cidr = subnet_cidr or lan.subnet_cidr
        lan.gateway_ip = gateway_ip or lan.gateway_ip
        lan.gateway_mac = gateway_mac or lan.gateway_mac

    agent = session.execute(
        select(AgentNode).where(AgentNode.lead == lead, AgentNode.lan_uid == lan_uid, AgentNode.agent_uid == agent_uid)
    ).scalar_one_or_none()
    if agent is None:
        session.add(
            AgentNode(
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                hostname=hostname,
                local_ip=local_ip,
                local_mac=local_mac,
            )
        )
    else:
        agent.hostname = hostname or agent.hostname
        agent.local_ip = local_ip or agent.local_ip
        agent.local_mac = local_mac or agent.local_mac
        agent.last_seen_at = datetime.now(timezone.utc)


def _upsert_printer_from_polling(
    session: Any,
    lead: str,
    lan_uid: str,
    agent_uid: str,
    printer_name: str,
    ip: str,
    event_time: datetime,
    touch_seen: bool = True,
    mark_online_on_create: bool = True,
) -> Printer:
    printer_ip = _to_text(ip)
    printer_name_value = _to_text(printer_name) or "Unknown Printer"
    row = None
    if printer_ip:
        row = session.execute(
            select(Printer).where(Printer.lead == lead, Printer.lan_uid == lan_uid, Printer.ip == printer_ip).limit(1)
        ).scalar_one_or_none()
    if row is None:
        row = session.execute(
            select(Printer)
            .where(
                Printer.lead == lead,
                Printer.lan_uid == lan_uid,
                Printer.agent_uid == agent_uid,
                Printer.printer_name == printer_name_value,
            )
            .order_by(Printer.updated_at.desc(), Printer.id.desc())
            .limit(1)
        ).scalar_one_or_none()
    if row is None and not printer_ip:
        row = session.execute(
            select(Printer)
            .where(
                Printer.lead == lead,
                Printer.lan_uid == lan_uid,
                Printer.printer_name == printer_name_value,
                Printer.ip == "",
            )
            .order_by(Printer.updated_at.desc(), Printer.id.desc())
            .limit(1)
        ).scalar_one_or_none()
    if row is None:
        row = Printer(
            lead=lead,
            lan_uid=lan_uid,
            agent_uid=agent_uid,
            printer_name=printer_name_value,
            ip=printer_ip,
            enabled=True,
            enabled_changed_at=event_time,
            is_online=bool(mark_online_on_create),
            online_changed_at=event_time,
        )
        session.add(row)
        session.flush()
        session.add(
            PrinterEnableLog(
                printer_id=row.id,
                lead=lead,
                lan_uid=lan_uid,
                printer_name=row.printer_name,
                ip=printer_ip,
                enabled=True,
                changed_at=event_time,
            )
        )
        session.add(
            PrinterOnlineLog(
                printer_id=row.id,
                lead=lead,
                lan_uid=lan_uid,
                printer_name=row.printer_name,
                ip=printer_ip,
                is_online=bool(mark_online_on_create),
                changed_at=event_time,
            )
        )
        return row

    row.agent_uid = agent_uid or row.agent_uid
    row.printer_name = printer_name_value or row.printer_name
    row.ip = printer_ip if printer_ip else row.ip
    if touch_seen:
        row.updated_at = datetime.now(timezone.utc)
    return row


def _set_printer_online_state(session: Any, printer: Printer, is_online: bool, changed_at: datetime) -> None:
    next_state = bool(is_online)
    if bool(printer.is_online) == next_state:
        return
    printer.is_online = next_state
    printer.online_changed_at = changed_at
    session.add(
        PrinterOnlineLog(
            printer_id=printer.id,
            lead=printer.lead,
            lan_uid=printer.lan_uid,
            printer_name=printer.printer_name,
            ip=printer.ip,
            is_online=next_state,
            changed_at=changed_at,
        )
    )


def _apply_printer_enabled_state(session: Any, printer: Printer, enabled: bool, at: datetime) -> None:
    next_state = bool(enabled)
    if bool(printer.enabled) == next_state:
        return
    printer.enabled = next_state
    printer.enabled_changed_at = at
    session.add(
        PrinterEnableLog(
            printer_id=printer.id,
            lead=printer.lead,
            lan_uid=printer.lan_uid,
            printer_name=printer.printer_name,
            ip=printer.ip,
            enabled=next_state,
            changed_at=at,
        )
    )


def _refresh_stale_offline(session: Any, lead: str = "", lan_uid: str = "", agent_uid: str = "") -> None:
    stale_before = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_STALE_SECONDS)
    stmt = select(Printer).where(Printer.is_online.is_(True), Printer.updated_at < stale_before)
    if lead:
        stmt = stmt.where(Printer.lead == lead)
    if lan_uid:
        stmt = stmt.where(Printer.lan_uid == lan_uid)
    if agent_uid:
        stmt = stmt.where(Printer.agent_uid == agent_uid)
    rows = session.execute(stmt).scalars().all()
    if not rows:
        return
    now = datetime.now(timezone.utc)
    for item in rows:
        _set_printer_online_state(session, item, False, now)


def _parse_date(value: Any) -> date:
    text = _to_text(value)
    if not text:
        return datetime.now(timezone.utc).date()
    try:
        return date.fromisoformat(text)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc).date()


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
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    Base.metadata.create_all(bind=session_factory.kw["bind"])
    with session_factory() as session:
        # Self-heal schema drift for older deployments (PostgreSQL).
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_user VARCHAR(128) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS auth_password VARCHAR(255) NOT NULL DEFAULT \'\';'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT TRUE;'))
        session.execute(text('ALTER TABLE "Printer" ADD COLUMN IF NOT EXISTS online_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();'))
        session.commit()

    lead_key_map = cfg.lead_keys()

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
        return render_template("devices.html", active_tab="devices", page_title="Devices")

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

        lan_uid = _resolve_lan_uid_from_body(body)
        agent_uid = _to_text(body.get("agent_uid")) or "legacy-agent"
        lan_name = _to_text(body.get("lan_name"))
        subnet_cidr = _to_text(body.get("subnet_cidr"))
        gateway_ip = _to_text(body.get("gateway_ip"))
        gateway_mac = _to_text(body.get("gateway_mac"))
        hostname = _to_text(body.get("hostname"))
        local_ip = _to_text(body.get("local_ip"))
        local_mac = _to_text(body.get("local_mac"))

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

    @app.get("/api/counter/heatmap")
    def counter_heatmap() -> Any:
        page = _to_page(request.args.get("page"), 1)
        page_size = min(50, _to_page(request.args.get("page_size"), 15))
        lead = _to_text(request.args.get("lead"))
        day = _parse_date(request.args.get("date"))
        start_local = datetime.combine(day, time.min, tzinfo=UI_TZ)
        end_local = start_local + timedelta(days=1)
        start_dt = start_local.astimezone(timezone.utc)
        end_dt = end_local.astimezone(timezone.utc)

        printers_stmt = select(CounterInfor.ip, CounterInfor.printer_name).where(
            CounterInfor.timestamp >= start_dt, CounterInfor.timestamp < end_dt
        )
        printers_count_stmt = select(func.count(func.distinct(CounterInfor.ip))).where(
            CounterInfor.timestamp >= start_dt, CounterInfor.timestamp < end_dt
        )
        if lead:
            printers_stmt = printers_stmt.where(CounterInfor.lead == lead)
            printers_count_stmt = printers_count_stmt.where(CounterInfor.lead == lead)

        with session_factory() as session:
            total_printers = int(session.scalar(printers_count_stmt) or 0)
            printer_rows = (
                session.execute(printers_stmt.group_by(CounterInfor.ip, CounterInfor.printer_name).order_by(CounterInfor.printer_name.asc()))
                .all()
            )
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            page_printers = printer_rows[start_idx:end_idx]
            ips = [str(r[0]) for r in page_printers]

            rows_payload: list[dict[str, Any]] = []
            if ips:
                points_stmt = select(
                    CounterInfor.ip,
                    CounterInfor.printer_name,
                    CounterInfor.timestamp,
                    CounterInfor.total,
                ).where(CounterInfor.timestamp >= start_dt, CounterInfor.timestamp < end_dt, CounterInfor.ip.in_(ips))
                if lead:
                    points_stmt = points_stmt.where(CounterInfor.lead == lead)
                points_stmt = points_stmt.order_by(CounterInfor.ip.asc(), CounterInfor.timestamp.asc())
                points = session.execute(points_stmt).all()

                grouped: dict[str, dict[str, Any]] = {}
                for ip_val, printer_name, ts, total in points:
                    ip_key = str(ip_val or "")
                    if ip_key not in grouped:
                        grouped[ip_key] = {
                            "ip": ip_key,
                            "printer_name": str(printer_name or ip_key),
                            "minutes": [0] * 1440,
                            "first_total": total,
                            "last_total": total,
                            "samples": 0,
                        }
                    row = grouped[ip_key]
                    if isinstance(ts, datetime):
                        local_ts = ts.astimezone(UI_TZ)
                        delta = local_ts - start_local
                        minute_idx = int(delta.total_seconds() // 60)
                        if 0 <= minute_idx < 1440:
                            row["minutes"][minute_idx] = 1
                    row["samples"] += 1
                    row["last_total"] = total

                by_ip = {str(r[0]): str(r[1] or r[0]) for r in page_printers}
                for ip_key in ips:
                    if ip_key in grouped:
                        rows_payload.append(grouped[ip_key])
                    else:
                        rows_payload.append(
                            {
                                "ip": ip_key,
                                "printer_name": by_ip.get(ip_key, ip_key),
                                "minutes": [0] * 1440,
                                "first_total": None,
                                "last_total": None,
                                "samples": 0,
                            }
                        )

        return jsonify(
            {
                "date": day.isoformat(),
                "page": page,
                "page_size": page_size,
                "total": total_printers,
                "total_pages": max(1, (total_printers + page_size - 1) // page_size),
                "rows": rows_payload,
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
                )
            if printer_row is not None:
                _set_printer_online_state(session=session, printer=printer_row, is_online=True, changed_at=timestamp)
            device_enabled = True if printer_row is None else bool(printer_row.enabled)
            if not device_enabled:
                skipped_disabled = 1

            if counter_data and device_enabled:
                normalized_counter = _normalize_counter_payload(counter_data)
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
                    select(CounterBaseline).where(CounterBaseline.lead == lead, CounterBaseline.lan_uid == lan_uid, CounterBaseline.ip == ip)
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
                    select(CounterInfor.timestamp, CounterInfor.raw_payload)
                    .where(CounterInfor.lead == lead, CounterInfor.lan_uid == lan_uid, CounterInfor.ip == ip)
                    .order_by(CounterInfor.timestamp.desc(), CounterInfor.id.desc())
                    .limit(1)
                ).first()
                latest_counter_ts = latest_counter_row[0] if latest_counter_row else None
                latest_counter_payload = latest_counter_row[1] if latest_counter_row else None
                if (
                    isinstance(latest_counter_payload, dict)
                    and latest_counter_payload == delta_counter
                    and _is_same_utc_minute(latest_counter_ts, timestamp)
                ):
                    skipped_counter = 1
                else:
                    row = CounterInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
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
                        )
                    session.add(row)
                    session.flush()
                    if row.begin_record_id is None:
                        row.begin_record_id = row.id
                    inserted_counter = 1

            if status_data and device_enabled:
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
                    select(StatusInfor.timestamp, StatusInfor.raw_payload)
                    .where(StatusInfor.lead == lead, StatusInfor.lan_uid == lan_uid, StatusInfor.ip == ip)
                    .order_by(StatusInfor.timestamp.desc(), StatusInfor.id.desc())
                    .limit(1)
                ).first()
                latest_status_ts = latest_status_row[0] if latest_status_row else None
                latest_status_payload = latest_status_row[1] if latest_status_row else None
                if (
                    isinstance(latest_status_payload, dict)
                    and latest_status_payload == status_data
                    and _is_same_utc_minute(latest_status_ts, timestamp)
                ):
                    skipped_status = 1
                else:
                    row = StatusInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
                            begin_record_id=begin_record_id_for_status,
                            system_status=_to_text(status_data.get("system_status")),
                            printer_status=_to_text(status_data.get("printer_status")),
                            printer_alerts=_to_text(status_data.get("printer_alerts")),
                            copier_status=_to_text(status_data.get("copier_status")),
                            copier_alerts=_to_text(status_data.get("copier_alerts")),
                            scanner_status=_to_text(status_data.get("scanner_status")),
                            scanner_alerts=_to_text(status_data.get("scanner_alerts")),
                            toner_black=_to_text(status_data.get("toner_black")),
                            tray_1_status=_to_text(status_data.get("tray_1_status")),
                            tray_2_status=_to_text(status_data.get("tray_2_status")),
                            tray_3_status=_to_text(status_data.get("tray_3_status")),
                            bypass_tray_status=_to_text(status_data.get("bypass_tray_status")),
                            other_info=_to_text(status_data.get("other_info")),
                            raw_payload=status_data,
                        )
                    session.add(row)
                    session.flush()
                    if row.begin_record_id is None:
                        row.begin_record_id = row.id
                    inserted_status = 1
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
            }
        )

    return app


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    config = ServerConfig()
    app = create_app()
    LOGGER.info("server start host=%s port=%s debug=%s", config.host, config.port, config.debug)
    app.run(host=config.host, port=config.port, debug=config.debug)
