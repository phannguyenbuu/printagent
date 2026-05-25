from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from agent.modules.ricoh.service import RicohService
from agent.modules.toshiba.service import ToshibaService
from agent.services.api_client import Printer

LOGGER = logging.getLogger(__name__)
_LIVE_HISTORY: deque[tuple[str, int, int, int]] = deque(maxlen=7)


def _to_int(value: str | int | None) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return 0


def _resolve_printer(ip: str, devices: list[Printer]) -> Printer | None:
    return next((p for p in devices if p.ip == ip), None)


def _printer_vendor(printer: Printer | None) -> str:
    if printer is None:
        return ""
    return str(printer.printer_type or "").strip().lower()


def _supports_collection_vendor(printer_type: str) -> bool:
    return str(printer_type or "").strip().lower() in {"ricoh", "toshiba"}


def _collector_service_for(
    printer: Printer,
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
) -> RicohService | ToshibaService:
    if toshiba_service is not None and _printer_vendor(printer) == "toshiba":
        return toshiba_service
    return ricoh_service


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _append_history(copier: int, printer: int, scanner: int, active: int, offline: int, total: int) -> None:
    _LIVE_HISTORY.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), copier, printer, scanner))


def _read_history(limit: int = 7) -> tuple[list[str], list[int], list[int], list[int]]:
    rows = list(_LIVE_HISTORY)[-limit:]
    labels = [r[0][5:16] for r in rows]
    copier = [int(r[1]) for r in rows]
    printer = [int(r[2]) for r in rows]
    scanner = [int(r[3]) for r in rows]
    return labels, copier, printer, scanner


def _build_live_overview(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    devices: list[Printer],
) -> dict[str, Any]:
    live_devices = [d for d in devices if d.ip and _supports_collection_vendor(d.printer_type)]
    ricoh_count = sum(1 for device in live_devices if _printer_vendor(device) == "ricoh")
    toshiba_count = sum(1 for device in live_devices if _printer_vendor(device) == "toshiba")
    copier_pages = 0
    print_pages = 0
    scan_pages = 0
    active_count = 0
    alert_count = {"low_toner": 0, "paper_warning": 0, "scanner_notice": 0}
    details: list[dict[str, Any]] = []

    for printer in live_devices:
        vendor = _printer_vendor(printer)
        collector = _collector_service_for(printer, ricoh_service, toshiba_service)
        device_row: dict[str, Any] = {"name": printer.name, "ip": printer.ip, "ok": False}
        try:
            counter_payload = collector.process_counter(printer, should_post=False)
            status_payload = collector.process_status(printer, should_post=False)

            counter = counter_payload.get("counter_data", {})
            status = status_payload.get("status_data", {})

            copier_pages += _to_int(counter.get("copier_bw"))
            print_pages += _to_int(counter.get("printer_bw"))
            scan_pages += _to_int(counter.get("scanner_send_bw")) + _to_int(counter.get("scanner_send_color"))

            system_status = status.get("system_status", "")
            if vendor == "toshiba":
                if system_status in {"Status OK", "Ready"}:
                    active_count += 1
                if status.get("toner_black", "") not in {"", "Status OK", "Ready"}:
                    alert_count["low_toner"] += 1
                paper_values: list[str] = [
                    str(value).lower()
                    for key, value in status.items()
                    if key.endswith("_tray_status") or (key.startswith("tray_") and key.endswith("_status"))
                ]
                status_json = status.get("status_json", {})
                if isinstance(status_json, dict):
                    input_tray = status_json.get("input_tray", {})
                    if isinstance(input_tray, dict):
                        for tray_value in input_tray.values():
                            if isinstance(tray_value, dict):
                                paper_values.append(str(tray_value.get("text", "")).lower())
                                icons = tray_value.get("icons", [])
                                if isinstance(icons, list):
                                    paper_values.extend(str(icon).lower() for icon in icons)
                if any(
                    token in value
                    for value in paper_values
                    for token in ("out of paper", "almost out of paper", "cover open", "empty", "alert")
                ):
                    alert_count["paper_warning"] += 1
                scanner_alerts = status.get("scanner_alerts", [])
                if isinstance(scanner_alerts, list) and scanner_alerts:
                    alert_count["scanner_notice"] += 1
            else:
                if system_status == "OK":
                    active_count += 1
                if status.get("toner_black", "") != "OK":
                    alert_count["low_toner"] += 1
                if any(k.startswith("tray_") and "status" in k for k in status):
                    paper_values = [str(v).lower() for k, v in status.items() if k.startswith("tray_") and k.endswith("_status")]
                    if any("empty" in v or "near" in v or "alert" in v for v in paper_values):
                        alert_count["paper_warning"] += 1
                if "scanner_alerts" in status:
                    alert_count["scanner_notice"] += 1

            device_row["ok"] = True
            device_row["type"] = vendor or "unknown"
            device_row["counter"] = {
                "copier_bw": counter.get("copier_bw", ""),
                "printer_bw": counter.get("printer_bw", ""),
                "scanner_send_bw": counter.get("scanner_send_bw", ""),
                "scanner_send_color": counter.get("scanner_send_color", ""),
            }
            device_row["status"] = status
        except Exception as exc:  # noqa: BLE001
            device_row["error"] = str(exc)
        details.append(device_row)

    total = len(live_devices)
    offline = max(total - active_count, 0)
    _append_history(copier_pages, print_pages, scan_pages, active_count, offline, total)
    labels, copier_hist, print_hist, scan_hist = _read_history(limit=7)

    return {
        "stats": {
            "total_devices": total,
            "ricoh_devices": ricoh_count,
            "toshiba_devices": toshiba_count,
            "active_devices": active_count,
            "offline_devices": offline,
            "copier_pages_total": copier_pages,
            "print_pages_total": print_pages,
            "scan_pages_total": scan_pages,
        },
        "trend": {
            "labels": labels,
            "copier_pages": copier_hist,
            "print_pages": print_hist,
            "scan_pages": scan_hist,
        },
        "alerts": [
            {"title": "Low toner", "count": alert_count["low_toner"]},
            {"title": "Paper tray warning", "count": alert_count["paper_warning"]},
            {"title": "Scanner notice", "count": alert_count["scanner_notice"]},
        ],
        "live_devices": details,
    }


def _counter_worker(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    printer: Printer,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            collector = _collector_service_for(printer, ricoh_service, toshiba_service)
            collector.process_counter(printer, should_post=True)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Counter push failed: ip=%s error=%s", printer.ip, exc)
        stop_event.wait(60)


def _status_worker(
    ricoh_service: RicohService,
    toshiba_service: ToshibaService | None,
    printer: Printer,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            collector = _collector_service_for(printer, ricoh_service, toshiba_service)
            collector.process_status(printer, should_post=True)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Status push failed: ip=%s error=%s", printer.ip, exc)
        stop_event.wait(30)


def _start_job(jobs: dict[str, dict[str, Any]], key: str, target: Any) -> tuple[bool, str]:
    existing = jobs.get(key)
    if existing and existing["thread"].is_alive():
        return True, "Job already running"
    stop_event = threading.Event()
    thread = threading.Thread(target=target, args=(stop_event,), daemon=True)
    jobs[key] = {"thread": thread, "stop": stop_event, "started_at": datetime.now().isoformat(timespec="seconds")}
    thread.start()
    return True, "Started"


def _stop_job(jobs: dict[str, dict[str, Any]], key: str) -> tuple[bool, str]:
    existing = jobs.get(key)
    if not existing:
        return False, "Job not running"
    existing["stop"].set()
    return True, "Stopped"


def _emit_ui_event(_event: str, _payload: dict[str, Any]) -> None:
    return


