from __future__ import annotations

import json
import logging
import socket
import threading
from datetime import datetime, timezone

import requests

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient, Printer


LOGGER = logging.getLogger(__name__)


class PollingBridge:
    def __init__(self, config: AppConfig, api_client: APIClient, ricoh_service: RicohService) -> None:
        self._config = config
        self._api_client = api_client
        self._ricoh_service = ricoh_service
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_started_at = ""
        self._last_cycle_at = ""
        self._last_success_at = ""
        self._last_error = ""
        self._last_cycle_total_printers = 0
        self._last_cycle_ricoh_printers = 0
        self._last_cycle_sent = 0
        self._last_cycle_failed = 0

    def is_configured(self) -> bool:
        return bool(self._config.get_string("polling.url").strip()) and bool(self._config.get_string("polling.lead").strip()) and bool(
            self._config.get_string("polling.token").strip()
        )

    def _config_issues(self) -> list[str]:
        issues: list[str] = []
        if not self._config.get_string("polling.url").strip():
            issues.append("missing polling.url")
        if not self._config.get_string("polling.lead").strip():
            issues.append("missing polling.lead")
        if not self._config.get_string("polling.token").strip():
            issues.append("missing polling.token")
        return issues

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _resolve_local_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:  # noqa: BLE001
            return ""

    def interval_seconds(self) -> int:
        raw = self._config.get_string("polling.interval_seconds", "60").strip()
        try:
            value = int(raw)
            return max(10, value)
        except Exception:  # noqa: BLE001
            return 60

    def start(self) -> tuple[bool, str]:
        if not self._config.get_bool("polling.enabled", True):
            LOGGER.info("Polling bridge disabled by config polling.enabled=false")
            return False, "Polling disabled"
        if not self.is_configured():
            issues = ", ".join(self._config_issues()) or "unknown"
            LOGGER.warning("Polling bridge not configured: %s", issues)
            return False, f"Polling not configured ({issues})"
        if self._thread and self._thread.is_alive():
            LOGGER.info("Polling bridge already running")
            return True, "Polling already running"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="polling-bridge")
        self._thread.start()
        self._last_started_at = self._now_iso()
        LOGGER.info(
            "Polling bridge started: url=%s lead=%s interval=%ss",
            self._config.get_string("polling.url").strip(),
            self._config.get_string("polling.lead").strip(),
            self.interval_seconds(),
        )
        return True, "Polling started"

    def stop(self) -> None:
        self._stop_event.set()
        LOGGER.info("Polling bridge stop requested")

    def status(self) -> dict[str, object]:
        issues = self._config_issues()
        return {
            "configured": self.is_configured(),
            "config_issues": issues,
            "enabled": self._config.get_bool("polling.enabled", True),
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds(),
            "url": self._config.get_string("polling.url"),
            "lead": self._config.get_string("polling.lead"),
            "last_started_at": self._last_started_at,
            "last_cycle_at": self._last_cycle_at,
            "last_success_at": self._last_success_at,
            "last_error": self._last_error,
            "last_cycle_total_printers": self._last_cycle_total_printers,
            "last_cycle_ricoh_printers": self._last_cycle_ricoh_printers,
            "last_cycle_sent": self._last_cycle_sent,
            "last_cycle_failed": self._last_cycle_failed,
        }

    def _load_printers(self) -> list[Printer]:
        try:
            return self._api_client.get_printers()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Polling bridge cannot load printers: %s", exc)
            return []

    def _post_payload(self, payload: dict) -> None:
        url = self._config.get_string("polling.url").strip()
        token = self._config.get_string("polling.token").strip()
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        resp = requests.post(url, json=payload, headers=headers, timeout=25)
        resp.raise_for_status()

    def _worker(self) -> None:
        interval = self.interval_seconds()
        lead = self._config.get_string("polling.lead").strip()
        hostname = socket.gethostname()
        local_ip = self._resolve_local_ip()
        LOGGER.info("Polling worker loop running: hostname=%s local_ip=%s", hostname, local_ip)
        while not self._stop_event.is_set():
            self._last_cycle_at = self._now_iso()
            printers = self._load_printers()
            self._last_cycle_total_printers = len(printers)
            self._last_cycle_ricoh_printers = 0
            self._last_cycle_sent = 0
            self._last_cycle_failed = 0
            for printer in printers:
                if self._stop_event.is_set():
                    break
                if not str(printer.ip or "").strip():
                    continue
                printer_type = str(printer.printer_type or "").strip().lower()
                printer_name = str(printer.name or "").strip().lower()
                # Local devices often come as "windows-local"; accept brand detection by name too.
                if "ricoh" not in printer_type and "ricoh" not in printer_name:
                    continue
                self._last_cycle_ricoh_printers += 1
                try:
                    counter_payload = self._ricoh_service.process_counter(printer, should_post=False)
                    status_payload = self._ricoh_service.process_status(printer, should_post=False)
                    payload = {
                        "lead": lead,
                        "lan_uid": self._config.get_string("polling.lan_uid", "").strip() or "legacy-lan",
                        "agent_uid": self._config.get_string("polling.agent_uid", "").strip() or hostname,
                        "hostname": hostname,
                        "local_ip": local_ip,
                        "printer_name": counter_payload.get("printer_name", printer.name),
                        "ip": counter_payload.get("ip", printer.ip),
                        "timestamp": counter_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "counter_data": counter_payload.get("counter_data", {}),
                        "status_data": status_payload.get("status_data", {}),
                    }
                    LOGGER.info("Polling payload -> %s", json.dumps(payload, ensure_ascii=False))
                    self._post_payload(payload)
                    self._last_cycle_sent += 1
                    self._last_success_at = self._now_iso()
                    self._last_error = ""
                except Exception as exc:  # noqa: BLE001
                    self._last_cycle_failed += 1
                    self._last_error = str(exc)
                    LOGGER.warning("Polling bridge failed for %s (%s): %s", printer.name, printer.ip, exc)
            LOGGER.info(
                "Polling cycle done: total=%s ricoh=%s sent=%s failed=%s",
                self._last_cycle_total_printers,
                self._last_cycle_ricoh_printers,
                self._last_cycle_sent,
                self._last_cycle_failed,
            )
            self._stop_event.wait(interval)
