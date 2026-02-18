from __future__ import annotations

import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, url_for
from sqlalchemy import func, select

from config import ServerConfig
from db import create_session_factory
from models import AgentNode, Base, CounterBaseline, CounterInfor, LanSite, StatusInfor

LOGGER = logging.getLogger(__name__)
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


def _to_page(value: Any, default: int) -> int:
    try:
        return max(1, int(str(value)))
    except Exception:  # noqa: BLE001
        return default


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


def _parse_date(value: Any) -> date:
    text = _to_text(value)
    if not text:
        return datetime.now(timezone.utc).date()
    try:
        return date.fromisoformat(text)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc).date()


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    Base.metadata.create_all(bind=session_factory.kw["bind"])

    lead_key_map = cfg.lead_keys()

    @app.get("/")
    def index() -> Any:
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard() -> Any:
        return render_template("dashboard.html", active_tab="dashboard", page_title="Dashboard")

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

        lan_uid = _to_text(body.get("lan_uid")) or "legacy-lan"
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
        with session_factory() as session:
            counter_count = session.scalar(select(func.count()).select_from(CounterInfor)) or 0
            status_count = session.scalar(select(func.count()).select_from(StatusInfor)) or 0
            lead_count = session.scalar(select(func.count(func.distinct(CounterInfor.lead)))) or 0
            printer_count = session.scalar(select(func.count(func.distinct(CounterInfor.ip)))) or 0
            latest_counter = session.scalar(select(func.max(CounterInfor.timestamp)))
            latest_status = session.scalar(select(func.max(StatusInfor.timestamp)))
        return jsonify(
            {
                "counter_rows": int(counter_count),
                "status_rows": int(status_count),
                "leads": int(lead_count),
                "printers": int(printer_count),
                "latest_counter_at": latest_counter.isoformat() if latest_counter else "",
                "latest_status_at": latest_status.isoformat() if latest_status else "",
            }
        )

    @app.get("/api/counter/timelapse")
    def counter_timelapse() -> Any:
        page = _to_page(request.args.get("page"), 1)
        page_size = min(200, _to_page(request.args.get("page_size"), 100))
        lead = _to_text(request.args.get("lead"))
        ip = _to_text(request.args.get("ip"))

        stmt = select(CounterInfor)
        count_stmt = select(func.count()).select_from(CounterInfor)
        if lead:
            stmt = stmt.where(CounterInfor.lead == lead)
            count_stmt = count_stmt.where(CounterInfor.lead == lead)
        if ip:
            stmt = stmt.where(CounterInfor.ip == ip)
            count_stmt = count_stmt.where(CounterInfor.ip == ip)

        stmt = stmt.order_by(CounterInfor.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
        with session_factory() as session:
            total = int(session.scalar(count_stmt) or 0)
            rows = session.execute(stmt).scalars().all()
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
                "page_size": page_size,
                "total": total,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            }
        )

    @app.get("/api/status/timelapse")
    def status_timelapse() -> Any:
        page = _to_page(request.args.get("page"), 1)
        page_size = min(200, _to_page(request.args.get("page_size"), 100))
        lead = _to_text(request.args.get("lead"))
        ip = _to_text(request.args.get("ip"))

        stmt = select(StatusInfor)
        count_stmt = select(func.count()).select_from(StatusInfor)
        if lead:
            stmt = stmt.where(StatusInfor.lead == lead)
            count_stmt = count_stmt.where(StatusInfor.lead == lead)
        if ip:
            stmt = stmt.where(StatusInfor.ip == ip)
            count_stmt = count_stmt.where(StatusInfor.ip == ip)

        stmt = stmt.order_by(StatusInfor.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
        with session_factory() as session:
            total = int(session.scalar(count_stmt) or 0)
            rows = session.execute(stmt).scalars().all()
        return jsonify(
            {
                "rows": [
                    {
                        "id": r.id,
                        "lead": r.lead,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                        "printer_name": r.printer_name,
                        "ip": r.ip,
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
                    }
                    for r in rows
                ],
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            }
        )

    @app.get("/api/counter/heatmap")
    def counter_heatmap() -> Any:
        page = _to_page(request.args.get("page"), 1)
        page_size = min(50, _to_page(request.args.get("page_size"), 15))
        lead = _to_text(request.args.get("lead"))
        day = _parse_date(request.args.get("date"))
        start_dt = datetime.combine(day, time.min, tzinfo=timezone.utc)
        end_dt = start_dt + timedelta(days=1)

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
                        delta = ts - start_dt
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

    @app.post("/api/polling")
    def ingest_polling() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("polling: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        lead = _to_text(body.get("lead"))
        if not lead:
            LOGGER.warning("polling: missing lead from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Missing lead"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        expected_token = lead_key_map.get(lead)
        if not expected_token or sent_token != expected_token:
            LOGGER.warning("polling: unauthorized lead=%s ip=%s", lead, request.remote_addr)
            return jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401

        printer_name = _to_text(body.get("printer_name"))
        ip = _to_text(body.get("ip"))
        lan_uid = _to_text(body.get("lan_uid")) or "legacy-lan"
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
            if counter_data:
                normalized_counter = _normalize_counter_payload(counter_data)
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
                    session.add(
                        CounterInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
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
                    )
                    inserted_counter = 1

            if status_data:
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
                    session.add(
                        StatusInfor(
                            lead=lead,
                            lan_uid=lan_uid,
                            agent_uid=agent_uid,
                            timestamp=timestamp,
                            printer_name=printer_name or "Unknown Printer",
                            ip=ip,
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
                    )
                    inserted_status = 1
            session.commit()
        LOGGER.info(
            "polling: lead=%s lan=%s agent=%s printer=%s ip=%s inserted(counter=%s,status=%s) skipped(counter=%s,status=%s)",
            lead,
            lan_uid,
            agent_uid,
            printer_name or "-",
            ip or "-",
            inserted_counter,
            inserted_status,
            skipped_counter,
            skipped_status,
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
