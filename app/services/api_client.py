from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from app.config import AppConfig


@dataclass(slots=True)
class Printer:
    id: int = 0
    name: str = ""
    ip: str = ""
    user: str = ""
    password: str = ""
    printer_type: str = ""
    status: str = ""


class APIClient:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        if config.user_token:
            self.session.headers.update({"Authorization": f"Bearer {config.user_token}"})

    def post_data(self, data: dict[str, Any], url: str | None = None, headers: dict[str, str] | None = None) -> None:
        target = url or self.config.api_url
        if not target:
            raise ValueError("api_url is not configured")
        merged_headers = dict(headers or {})
        response = self.session.post(target, json=data, headers=merged_headers, timeout=30)
        response.raise_for_status()

    def get_printers(self, url: str | None = None) -> list[Printer]:
        target = url or f"{self.config.api_url}/printers"
        if not self.config.api_url and url is None:
            raise ValueError("api_url is not configured")
        payload: Any
        response = self.session.get(target, timeout=30, headers={"Accept": "application/json"})
        if response.status_code == 404 and url is None:
            # Local web app exposes /api/devices, not /api/printers.
            fallback_target = f"{self.config.api_url}/devices"
            response = self.session.get(fallback_target, timeout=30, headers={"Accept": "application/json"})
        response.raise_for_status()
        payload = response.json()

        if isinstance(payload, dict) and "data" in payload:
            raw_printers = payload.get("data") or []
        elif isinstance(payload, dict) and "devices" in payload:
            raw_printers = payload.get("devices") or []
        elif isinstance(payload, list):
            raw_printers = payload
        else:
            raw_printers = []

        printers: list[Printer] = []
        for item in raw_printers:
            if not isinstance(item, dict):
                continue
            printers.append(
                Printer(
                    id=int(item.get("id", 0) or 0),
                    name=str(item.get("name", "") or ""),
                    ip=str(item.get("ip", "") or ""),
                    user=str(item.get("user", "") or ""),
                    password=str(item.get("password", "") or ""),
                    printer_type=str(item.get("printer_type", item.get("type", "")) or ""),
                    status=str(item.get("status", "") or ""),
                )
            )
        return printers
