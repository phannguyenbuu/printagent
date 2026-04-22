from __future__ import annotations

import logging
import time
from typing import Any

import requests

from agent.modules.toshiba.common import (
    COUNTER_DATA_KEY,
    COUNTER_PAYLOADS,
    DEFAULT_TIMEOUT,
    STATUS_DATA_KEY,
    STATUS_PAYLOAD,
    bootstrap_session,
    compact_snippet,
    find_text,
    normalize_urls,
    parse_device_information_model,
    post_contentwebserver,
    post_contentwebserver_with_fallback,
)
from agent.modules.toshiba.counter import summarize_counter
from agent.modules.toshiba.status import summarize_status
from app.services.api_client import APIClient, Printer


LOGGER = logging.getLogger(__name__)


class ToshibaService:
    def __init__(self, api_client: APIClient, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.api_client = api_client
        self.timeout = int(timeout or DEFAULT_TIMEOUT)

    def _timestamp(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _landing_url(printer: Printer) -> str:
        return f"http://{printer.ip}/?MAIN=TOPACCESS"

    def _build_session(self, printer: Printer) -> tuple[requests.Session, str, str, str]:
        landing_url, origin = normalize_urls(self._landing_url(printer))
        content_url = f"{origin}/contentwebserver"
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (compatible; ToshibaTopAccessAgent/1.0)",
                "Accept": "*/*",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Referer": landing_url,
            }
        )
        session.cookies.set("pageTrack", "MAIN=TOPACCESS")
        bootstrap_session(
            session=session,
            landing_url=landing_url,
            origin=origin,
            timeout=self.timeout,
        )
        csrf_token = str(session.cookies.get("Session") or "").strip()
        if not csrf_token:
            raise RuntimeError("No Toshiba TopAccess Session cookie found after bootstrap")
        return session, landing_url, content_url, csrf_token

    def _fetch_status_root(self, printer: Printer) -> tuple[Any, str, str]:
        session: requests.Session | None = None
        try:
            session, _landing_url, content_url, csrf_token = self._build_session(printer)
            raw_text, meta = post_contentwebserver(
                session=session,
                content_url=content_url,
                payload=STATUS_PAYLOAD,
                csrf_token=csrf_token,
                timeout=self.timeout,
                label="status",
            )
            root = parse_device_information_model(
                raw_text,
                source_label="status",
                response_meta=meta,
            )
            return root, raw_text, str(meta.get("final_url") or content_url)
        finally:
            if session is not None:
                session.close()

    def _fetch_counter_root(self, printer: Printer) -> tuple[Any, str, str]:
        session: requests.Session | None = None
        try:
            session, _landing_url, content_url, csrf_token = self._build_session(printer)
            raw_text, meta = post_contentwebserver_with_fallback(
                session=session,
                content_url=content_url,
                payloads=list(COUNTER_PAYLOADS),
                csrf_token=csrf_token,
                timeout=self.timeout,
                label="counter",
            )
            root = parse_device_information_model(
                raw_text,
                source_label="counter",
                response_meta=meta,
            )
            return root, raw_text, str(meta.get("final_url") or content_url)
        finally:
            if session is not None:
                session.close()

    def process_status(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        root, raw_text, source_url = self._fetch_status_root(printer)
        data = summarize_status(root)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            STATUS_DATA_KEY: data,
            "status_source": source_url,
            "html": raw_text,
            "status_debug": {
                "source": source_url,
                "html_len": len(raw_text or ""),
                "empty": not bool(data),
                "preview": compact_snippet(raw_text, 220),
            },
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_counter(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        root, raw_text, source_url = self._fetch_counter_root(printer)
        data = summarize_counter(root)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            COUNTER_DATA_KEY: data,
            "counter_source": source_url,
            "html": raw_text,
            "counter_debug": {
                "source": source_url,
                "html_len": len(raw_text or ""),
                "empty": not bool(data),
                "preview": compact_snippet(raw_text, 220),
            },
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_device_info(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        root, raw_text, source_url = self._fetch_status_root(printer)
        data = {
            "Model Name": str(find_text(root, ".//MFP/ModelName") or "").strip(),
            "Machine Name": str(find_text(root, ".//MFP/ModelName") or "").strip(),
            "model_name": str(find_text(root, ".//MFP/ModelName") or "").strip(),
            "Host Name": str(find_text(root, ".//Network/Protocols/TCP-IP/hostName") or "").strip(),
            "Device State": str(find_text(root, ".//MFP/DeviceState") or "").strip(),
            "Printer State": str(find_text(root, ".//MFP/Printer/DeviceState") or "").strip(),
            "Main Memory": str(find_text(root, ".//MFP/System/MainMemory") or "").strip(),
            "Page Memory": str(find_text(root, ".//MFP/System/PageMemory") or "").strip(),
            "HDD": str(find_text(root, ".//MFP/System/HDD") or "").strip(),
        }
        data = {key: value for key, value in data.items() if value}
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "device_info": data,
            "device_info_source": source_url,
            "html": raw_text,
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload
