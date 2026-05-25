from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import select

from utils import (
    _to_text,
    _to_int,
    _parse_timestamp,
    _normalize_mac,
    _write_last_data,
    _normalize_counter_payload,
    _normalize_status_payload,
    _compute_delta_payload,
    _to_text_max,
    _to_json_value,
)
from serializers import (
    _upsert_lan_and_agent,
    _upsert_printer_from_polling,
    _set_printer_online_state,
    _resolve_public_mac,
)
from models import (
    DeviceInfor,
    DeviceInforHistory,
    CounterInfor,
    CounterBaseline,
    StatusInfor,
)
from app_helpers import (
    _request_api_token,
    _validate_polling_auth,
    _resolve_lan_uid_with_session,
    _is_agent_master_and_get_emails,
)

LOGGER = logging.getLogger(__name__)


def register_polling_core_routes(app: Flask, session_factory: Any, lead_key_map: dict[str, str]) -> None:

    @app.post("/api/polling")
    def ingest_polling() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            LOGGER.warning("polling: invalid json body from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        sent_token = _request_api_token()
        ok_auth, lead, auth_error = _validate_polling_auth(body, lead_key_map, sent_token)
        if not ok_auth:
            LOGGER.warning("polling: unauthorized lead=%s ip=%s", lead, request.remote_addr)
            return auth_error

        printer_name = _to_text(body.get("printer_name"))
        ip = _to_text(body.get("ip"))
        with session_factory() as session:
            lan_uid, _ = _resolve_lan_uid_with_session(session, lead, body)
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
                app_version=app_version,
                run_mode=run_mode,
                web_port=web_port,
                ftp_ports=ftp_ports,
                ftp_sites=ftp_sites,
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
                if "address_book_sync" in body:
                    printer_row.address_book_sync = body.get("address_book_sync")
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
            is_master, emails = _is_agent_master_and_get_emails(session, lead, lan_uid, agent_uid)
            session.commit()
        LOGGER.info(
            "polling: lead=%s lan=%s agent=%s printer=%s ip=%s inserted(counter=%s,status=%s) skipped(counter=%s,status=%s,disabled=%s) master=%s",
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
            is_master,
        )

        # Compute script MD5 hashes
        scripts_info = {}
        try:
            import os
            from pathlib import Path
            for name in ["scan_ricoh.py", "ricoh_address_book.py", "ricoh_wizard.py", "ricoh_web_scan.py"]:
                script_path = os.path.join(os.path.dirname(__file__), "static", "releases", name)
                if os.path.exists(script_path):
                    import hashlib
                    h = hashlib.md5(Path(script_path).read_bytes()).hexdigest()
                    scripts_info[name] = h
        except Exception:
            pass

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
                "is_master": is_master,
                "emails": emails,
                "scripts": scripts_info,
            }
        )
