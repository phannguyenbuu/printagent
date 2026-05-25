from __future__ import annotations

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select

from utils import (
    UI_TZ,
    _to_text,
    _to_int,
    _to_page,
    _parse_query_datetime,
    _parse_timestamp,
    _normalize_mac,
)
from serializers import (
    _refresh_stale_offline,
    _resolve_public_mac,
)
from app_helpers import _serialize_audit_payload_iso
from models import DeviceInforHistory, DeviceInfor

LOGGER = logging.getLogger(__name__)


def register_infor_routes(app: Flask, session_factory: Any) -> None:

    @app.get("/api/infor/list")
    def infor_list() -> Any:
        lead = _to_text(request.args.get("lead"))
        row_id_query = _to_text(request.args.get("id"))
        printer_name_query = _to_text(request.args.get("printer_name") or request.args.get("name"))
        ip_query = _to_text(request.args.get("ip"))
        mac_query = _to_text(request.args.get("mac_id"))
        lan_uid_query = _to_text(request.args.get("lan_uid"))
        counter_min = _to_int(request.args.get("counter_min"))
        counter_max = _to_int(request.args.get("counter_max"))
        printed_paper_min = _to_int(
            request.args.get("printed_paper_min")
            or request.args.get("printer_page_min")
            or request.args.get("printerpage_min")
        )
        printed_paper_max = _to_int(
            request.args.get("printed_paper_max")
            or request.args.get("printer_page_max")
            or request.args.get("printerpage_max")
        )
        cartridge_status_query = _to_text(request.args.get("cartridge_status")).lower()
        updated_from = _parse_query_datetime(request.args.get("updated_from"), end_of_minute=False)
        updated_to = _parse_query_datetime(request.args.get("updated_to"), end_of_minute=True)
        page = _to_page(request.args.get("page"), 1)
        limit = _to_int(request.args.get("limit"))
        if limit is None:
            limit = 50

        def serialize_infor_row(
            row_id: int,
            row_lead: str,
            row_lan_uid: str,
            row_agent_uid: str,
            row_printer_name: str,
            row_ip: str,
            row_mac_id: str,
            row_machine_uid: str,
            row_is_latest: bool,
            counter_data: dict[str, Any],
            status_data: dict[str, Any],
            last_counter_at: datetime | None,
            last_status_at: datetime | None,
            created_at: datetime | None,
            updated_at: datetime | None,
        ) -> dict[str, Any]:
            return {
                "id": int(row_id),
                "lead": row_lead,
                "lan_uid": row_lan_uid,
                "agent_uid": row_agent_uid,
                "printer_name": row_printer_name,
                "ip": row_ip,
                "mac_id": row_mac_id or "unknown",
                "machine_uid": row_machine_uid or "unknown",
                "is_latest": row_is_latest,
                "counter": counter_data,
                "status": status_data,
                "counter_data": counter_data,
                "status_data": status_data,
                "counter_total": _to_int(counter_data.get("total")) or 0,
                "status_system": _to_text(status_data.get("system_status")) or _to_text(status_data.get("printer_status")),
                "last_counter_at": last_counter_at.isoformat() if last_counter_at else "",
                "last_status_at": last_status_at.isoformat() if last_status_at else "",
                **_serialize_audit_payload_iso(created_at, updated_at),
            }

        def row_updated_dt(row: dict[str, Any]) -> datetime | None:
            raw = (
                _to_text(row.get("updated_at"))
                or _to_text(row.get("updateAt"))
                or _to_text(row.get("last_counter_at"))
                or _to_text(row.get("last_status_at"))
                or _to_text(row.get("created_at"))
                or _to_text(row.get("createAt"))
            )
            if not raw:
                return None
            return _parse_timestamp(raw)

        def row_counter_total(row: dict[str, Any]) -> int:
            return _to_int(row.get("counter_total")) or 0

        def row_cartridge_state(row: dict[str, Any]) -> str:
            status_data = row.get("status_data") if isinstance(row.get("status_data"), dict) else {}
            toner_black = _to_text(status_data.get("toner_black")).lower()
            if toner_black in {"ok", "status ok", "ready", "normal"}:
                return "ok"
            if toner_black and any(token in toner_black for token in ["empty", "replace", "low", "end", "near"]):
                return "empty"
            return ""

        def mac_matches(query_value: str, row_value: str) -> bool:
            query_text = _to_text(query_value).upper()
            row_text = _to_text(row_value).upper()
            if not query_text:
                return True
            query_compact = re.sub(r"[^0-9A-F]", "", query_text)
            row_compact = re.sub(r"[^0-9A-F]", "", row_text)
            if query_compact and row_compact:
                return query_compact in row_compact
            return query_text in row_text

        def apply_printed_paper(rows: list[dict[str, Any]]) -> None:
            start_today_utc = datetime.now(UI_TZ).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
            baseline: dict[tuple[str, str], tuple[datetime, int]] = {}
            for row in rows:
                lan_value = _to_text(row.get("lan_uid"))
                mac_value = _normalize_mac(row.get("mac_id"))
                updated_dt = row_updated_dt(row)
                if not lan_value or not mac_value or updated_dt is None or updated_dt < start_today_utc:
                    continue
                key = (lan_value, mac_value)
                total_value = row_counter_total(row)
                current = baseline.get(key)
                if current is None or updated_dt < current[0]:
                    baseline[key] = (updated_dt, total_value)

            for row in rows:
                lan_value = _to_text(row.get("lan_uid"))
                mac_value = _normalize_mac(row.get("mac_id"))
                total_value = row_counter_total(row)
                base_total = total_value
                if lan_value and mac_value:
                    baseline_row = baseline.get((lan_value, mac_value))
                    if baseline_row is not None:
                        base_total = baseline_row[1]
                printed_paper = max(0, total_value - base_total)
                row["printed_paper"] = printed_paper
                row["printer_page"] = printed_paper
                row["cartridge_status"] = row_cartridge_state(row)

        def matches_infor_filters(row: dict[str, Any]) -> bool:
            if row_id_query:
                row_id_text = str(int(row.get("id") or 0))
                if row_id_query.isdigit():
                    if row_id_text != str(int(row_id_query)):
                        return False
                elif row_id_query not in row_id_text:
                    return False
            if printer_name_query and printer_name_query.lower() not in _to_text(row.get("printer_name")).lower():
                return False
            if ip_query and ip_query.lower() not in _to_text(row.get("ip")).lower():
                return False
            if mac_query and not mac_matches(mac_query, _to_text(row.get("mac_id"))):
                return False
            if lan_uid_query and lan_uid_query.lower() not in _to_text(row.get("lan_uid")).lower():
                return False
            total_value = row_counter_total(row)
            if counter_min is not None and total_value < counter_min:
                return False
            if counter_max is not None and total_value > counter_max:
                return False
            printed_value = _to_int(row.get("printed_paper")) or 0
            if printed_paper_min is not None and printed_value < printed_paper_min:
                return False
            if printed_paper_max is not None and printed_value > printed_paper_max:
                return False
            if cartridge_status_query and row_cartridge_state(row) != cartridge_status_query:
                return False
            updated_dt = row_updated_dt(row)
            if updated_from is not None:
                if updated_dt is None or updated_dt < updated_from:
                    return False
            if updated_to is not None:
                if updated_dt is None or updated_dt > updated_to:
                    return False
            return True

        with session_factory() as session:
            _refresh_stale_offline(session=session, lead=lead)
            session.commit()
            
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            
            history_stmt = select(DeviceInforHistory).where(
                DeviceInforHistory.updated_at >= seven_days_ago
            ).order_by(
                DeviceInforHistory.updated_at.desc(), DeviceInforHistory.id.desc()
            )
            if lead:
                history_stmt = history_stmt.where(DeviceInforHistory.lead == lead)

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
                    is_latest = False
                    if resolved_mac:
                        latest_key = (_to_text(h.lead), _to_text(h.lan_uid), resolved_mac)
                        if latest_key not in latest_by_lan_mac:
                            latest_by_lan_mac.add(latest_key)
                            is_latest = True
                    rows.append(
                        serialize_infor_row(
                            row_id=int(h.id),
                            row_lead=h.lead,
                            row_lan_uid=h.lan_uid,
                            row_agent_uid=h.agent_uid,
                            row_printer_name=h.printer_name,
                            row_ip=h.ip,
                            row_mac_id=resolved_mac,
                            row_machine_uid=machine_uid,
                            row_is_latest=is_latest,
                            counter_data=counter_data,
                            status_data=status_data,
                            last_counter_at=h.last_counter_at,
                            last_status_at=h.last_status_at,
                            created_at=h.created_at,
                            updated_at=h.updated_at,
                        )
                    )
            else:
                base_stmt = select(DeviceInfor).where(
                    DeviceInfor.updated_at >= seven_days_ago
                ).order_by(DeviceInfor.updated_at.desc(), DeviceInfor.id.desc())
                if lead:
                    base_stmt = base_stmt.where(DeviceInfor.lead == lead)

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
                        serialize_infor_row(
                            row_id=int(d.id),
                            row_lead=d.lead,
                            row_lan_uid=d.lan_uid,
                            row_agent_uid=d.agent_uid,
                            row_printer_name=d.printer_name,
                            row_ip=d.ip,
                            row_mac_id=resolved_mac,
                            row_machine_uid=_to_text(d.mac_id) or (f"IP:{_to_text(d.ip)}" if _to_text(d.ip) else "unknown"),
                            row_is_latest=bool(resolved_mac),
                            counter_data=counter_data,
                            status_data=status_data,
                            last_counter_at=d.last_counter_at,
                            last_status_at=d.last_status_at,
                            created_at=d.created_at,
                            updated_at=d.updated_at,
                        )
                    )

            apply_printed_paper(rows)
            rows = [row for row in rows if matches_infor_filters(row)]

            total = len(rows)
            if limit > 0:
                start_index = max(0, (page - 1) * limit)
                rows = rows[start_index:start_index + limit]

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
