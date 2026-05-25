from __future__ import annotations

import logging
from bisect import bisect_right
from datetime import datetime, timezone, timedelta, time
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select, func

from utils import (
    UI_TZ,
    _to_text,
    _to_page,
    _parse_query_datetime,
    _parse_date,
    _to_int,
    _apply_common_filters,
    _apply_baseline,
)
from app_helpers import _serialize_audit_payload_iso
from serializers import _resolve_day_window
from models import (
    CounterInfor,
    StatusInfor,
    CounterBaseline,
    DeviceInforHistory,
    DeviceInfor,
)

LOGGER = logging.getLogger(__name__)


def register_counter_core_routes(app: Flask, session_factory: Any) -> None:

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
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
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
                        **_serialize_audit_payload_iso(r.created_at, r.updated_at),
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
