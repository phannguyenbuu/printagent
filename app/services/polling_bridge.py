from __future__ import annotations

import logging
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

    def is_configured(self) -> bool:
        return bool(self._config.get_string("polling.url").strip()) and bool(self._config.get_string("polling.lead").strip()) and bool(
            self._config.get_string("polling.token").strip()
        )

    def interval_seconds(self) -> int:
        raw = self._config.get_string("polling.interval_seconds", "60").strip()
        try:
            value = int(raw)
            return max(10, value)
        except Exception:  # noqa: BLE001
            return 60

    def start(self) -> tuple[bool, str]:
        if not self._config.get_bool("polling.enabled", True):
            return False, "Polling disabled"
        if not self.is_configured():
            return False, "Polling not configured"
        if self._thread and self._thread.is_alive():
            return True, "Polling already running"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="polling-bridge")
        self._thread.start()
        return True, "Polling started"

    def stop(self) -> None:
        self._stop_event.set()

    def status(self) -> dict[str, object]:
        return {
            "configured": self.is_configured(),
            "enabled": self._config.get_bool("polling.enabled", True),
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds(),
            "url": self._config.get_string("polling.url"),
            "lead": self._config.get_string("polling.lead"),
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
        while not self._stop_event.is_set():
            printers = self._load_printers()
            for printer in printers:
                if self._stop_event.is_set():
                    break
                if not str(printer.ip or "").strip():
                    continue
                if str(printer.printer_type or "").strip().lower() != "ricoh":
                    continue
                try:
                    counter_payload = self._ricoh_service.process_counter(printer, should_post=False)
                    status_payload = self._ricoh_service.process_status(printer, should_post=False)
                    payload = {
                        "lead": lead,
                        "printer_name": counter_payload.get("printer_name", printer.name),
                        "ip": counter_payload.get("ip", printer.ip),
                        "timestamp": counter_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "counter_data": counter_payload.get("counter_data", {}),
                        "status_data": status_payload.get("status_data", {}),
                    }
                    self._post_payload(payload)
                except Exception as exc:  # noqa: BLE001
                    LOGGER.warning("Polling bridge failed for %s (%s): %s", printer.name, printer.ip, exc)
            self._stop_event.wait(interval)
