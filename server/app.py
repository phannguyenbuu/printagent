from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from config import ServerConfig
from db import create_session_factory
from models import Base, CounterInfor, StatusInfor


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


def create_app() -> Flask:
    app = Flask(__name__)
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    Base.metadata.create_all(bind=session_factory.kw["bind"])

    lead_key_map = cfg.lead_keys()

    @app.get("/health")
    def health() -> Any:
        return jsonify({"ok": True, "service": "GoPrinx Polling Server"})

    @app.post("/api/polling")
    def ingest_polling() -> Any:
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

        lead = _to_text(body.get("lead"))
        if not lead:
            return jsonify({"ok": False, "error": "Missing lead"}), 400

        sent_token = _to_text(request.headers.get("X-Lead-Token"))
        expected_token = lead_key_map.get(lead)
        if not expected_token or sent_token != expected_token:
            return jsonify({"ok": False, "error": "Unauthorized lead/token"}), 401

        printer_name = _to_text(body.get("printer_name"))
        ip = _to_text(body.get("ip"))
        timestamp = _parse_timestamp(body.get("timestamp"))
        counter_data = body.get("counter_data") if isinstance(body.get("counter_data"), dict) else {}
        status_data = body.get("status_data") if isinstance(body.get("status_data"), dict) else {}

        inserted_counter = 0
        inserted_status = 0
        with session_factory() as session:
            if counter_data:
                session.add(
                    CounterInfor(
                        lead=lead,
                        timestamp=timestamp,
                        printer_name=printer_name or "Unknown Printer",
                        ip=ip,
                        total=_to_int(counter_data.get("total")),
                        copier_bw=_to_int(counter_data.get("copier_bw")),
                        printer_bw=_to_int(counter_data.get("printer_bw")),
                        fax_bw=_to_int(counter_data.get("fax_bw")),
                        send_tx_total_bw=_to_int(counter_data.get("send_tx_total_bw")),
                        send_tx_total_color=_to_int(counter_data.get("send_tx_total_color")),
                        fax_transmission_total=_to_int(counter_data.get("fax_transmission_total")),
                        scanner_send_bw=_to_int(counter_data.get("scanner_send_bw")),
                        scanner_send_color=_to_int(counter_data.get("scanner_send_color")),
                        coverage_copier_bw=_to_int(counter_data.get("coverage_copier_bw")),
                        coverage_printer_bw=_to_int(counter_data.get("coverage_printer_bw")),
                        coverage_fax_bw=_to_int(counter_data.get("coverage_fax_bw")),
                        a3_dlt=_to_int(counter_data.get("a3_dlt")),
                        duplex=_to_int(counter_data.get("duplex")),
                        raw_payload=counter_data,
                    )
                )
                inserted_counter = 1

            if status_data:
                session.add(
                    StatusInfor(
                        lead=lead,
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

        return jsonify(
            {
                "ok": True,
                "lead": lead,
                "printer_name": printer_name,
                "ip": ip,
                "timestamp": timestamp.isoformat(),
                "inserted_counter": inserted_counter,
                "inserted_status": inserted_status,
            }
        )

    return app


if __name__ == "__main__":
    config = ServerConfig()
    app = create_app()
    app.run(host=config.host, port=config.port, debug=config.debug)
