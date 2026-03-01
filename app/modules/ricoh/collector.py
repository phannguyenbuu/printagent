from __future__ import annotations

import csv
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from app.modules.ricoh.base import RicohServiceBase
from app.services.api_client import Printer

LOGGER = logging.getLogger(__name__)

class RicohCollectorMixin(RicohServiceBase):
    @staticmethod
    def _looks_like_counter_content(html: str) -> bool:
        text = RicohServiceBase._strip_html(html or "")
        if not text:
            return False
        markers = [
            "counter",
            "copier",
            "printer",
            "black & white",
            "send/tx total",
        ]
        lowered = text.lower()
        return sum(1 for marker in markers if marker in lowered) >= 2

    @staticmethod
    def _looks_like_status_content(html: str) -> bool:
        text = RicohServiceBase._strip_html(html or "")
        if not text:
            return False
        markers = [
            "system status",
            "toner",
            "tray",
            "paper",
            "status",
        ]
        lowered = text.lower()
        return sum(1 for marker in markers if marker in lowered) >= 2

    @staticmethod
    def _normalize_guest_path(path: str) -> str:
        value = str(path or "").strip()
        if not value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            match = re.search(r"https?://[^/]+(/.*)$", value, re.IGNORECASE)
            if match:
                value = match.group(1)
        if not value.startswith("/"):
            value = f"/{value}"
        return value

    def _discover_guest_paths(self, session: requests.Session, printer: Printer, keyword: str) -> list[str]:
        found: list[str] = []
        main_frame_candidates = [
            "/web/guest/en/websys/webArch/mainFrame.cgi",
            "/web/guest/en/websys/webArch/mainFrame.cgi?name=main",
            "/web/guest/en/manual/mainFrame.cgi",
        ]
        for path in main_frame_candidates:
            try:
                html = self.authenticate_and_get(session, printer, path)
            except Exception:  # noqa: BLE001
                continue
            if not html:
                continue
            for match in re.finditer(
                r"""['"]([^'"]*(?:counter|status)[^'"]*?\.cgi(?:\?[^'"]*)?)['"]""",
                html,
                re.IGNORECASE,
            ):
                raw = match.group(1)
                if keyword.lower() not in raw.lower():
                    continue
                normalized = self._normalize_guest_path(raw)
                if not normalized:
                    continue
                if "/web/guest/" not in normalized.lower():
                    continue
                found.append(normalized)
        # Keep order, remove duplicates.
        unique: list[str] = []
        seen: set[str] = set()
        for path in found:
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique

    def _read_guest_with_fallback(self, printer: Printer, candidate_paths: list[str], keyword: str) -> str:
        last_exc: Exception | None = None
        tried: list[str] = []
        keyword_lower = str(keyword or "").strip().lower()
        try:
            session = self.create_http_client(printer, authenticated=False)
            dynamic_paths = self._discover_guest_paths(session, printer, keyword)
            paths = [*candidate_paths, *dynamic_paths]

            unique_paths: list[str] = []
            seen: set[str] = set()
            for path in paths:
                normalized = self._normalize_guest_path(path)
                if not normalized:
                    continue
                key = normalized.lower()
                if key in seen:
                    continue
                seen.add(key)
                unique_paths.append(normalized)

            for path in unique_paths:
                tried.append(path)
                try:
                    return self.authenticate_and_get(session, printer, path)
                except requests.exceptions.HTTPError as exc:
                    last_exc = exc
                    code = getattr(exc.response, "status_code", None)
                    if code == 404:
                        continue
                    raise
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    continue

            # Legacy Web Image Monitor variants may embed usable guest data
            # directly in mainFrame without explicit counter/status endpoint.
            main_frame_candidates = [
                "/web/guest/en/websys/webArch/mainFrame.cgi",
                "/web/guest/en/websys/webArch/mainFrame.cgi?name=main",
                "/web/guest/en/manual/mainFrame.cgi",
                "/web/guest/en/websys/webArch/topFrame.cgi",
            ]
            for path in main_frame_candidates:
                tried.append(path)
                try:
                    html = self.authenticate_and_get(session, printer, path)
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    continue
                if keyword_lower == "counter" and self._looks_like_counter_content(html):
                    LOGGER.info("Counter fallback used main frame: ip=%s path=%s", printer.ip, path)
                    return html
                if keyword_lower == "status" and self._looks_like_status_content(html):
                    LOGGER.info("Status fallback used main frame: ip=%s path=%s", printer.ip, path)
                    return html

            if last_exc is not None:
                LOGGER.warning(
                    "No guest endpoint matched for %s: ip=%s tried=%s last_error=%s",
                    keyword,
                    printer.ip,
                    tried,
                    last_exc,
                )
                raise last_exc
            LOGGER.warning("No guest endpoint matched for %s: ip=%s tried=%s", keyword, printer.ip, tried)
            raise RuntimeError(f"No valid guest endpoint for {keyword}: tried={tried}")
        finally:
            self._logout_after_collect(printer, source=f"read_{keyword}")

    def read_counter(self, printer: Printer) -> str:
        candidates = [
            "/web/guest/en/manual/counter/readCounter.cgi",
            "/web/guest/en/manual/counter/counter.cgi",
            "/web/guest/en/websys/status/getCounterData.cgi",
            "/web/guest/en/websys/status/counter.cgi",
            "/web/guest/en/websys/webArch/counter.cgi",
            "/web/guest/en/websys/webArch/getCounter.cgi",
        ]
        return self._read_guest_with_fallback(printer, candidates, keyword="counter")

    def read_device_info(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            return self.authenticate_and_get(session, printer, "/web/guest/en/manual/configuration/readDeviceInfo.cgi")
        finally:
            self._logout_after_collect(printer, source="read_device_info")

    def read_status(self, printer: Printer) -> str:
        candidates = [
            "/web/guest/en/manual/status/readStatus.cgi",
            "/web/guest/en/manual/status/status.cgi",
            "/web/guest/en/websys/status/getStatusData.cgi",
            "/web/guest/en/websys/status/status.cgi",
            "/web/guest/en/websys/webArch/status.cgi",
            "/web/guest/en/websys/webArch/deviceStatus.cgi",
        ]
        return self._read_guest_with_fallback(printer, candidates, keyword="status")

    def read_network_interface(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            # Try multiple common paths for Ricoh network interface info
            paths = [
                "/web/guest/en/manual/configuration/network/interface/readNetworkInterface.cgi",
                "/web/guest/en/manual/configuration/network/readNetworkInterface.cgi",
                "/web/guest/en/manual/configuration/readNetworkInterface.cgi",
                "/web/entry/en/manual/configuration/network/interface/readNetworkInterface.cgi"
            ]
            
            last_err = None
            for path in paths:
                try:
                    html = self.authenticate_and_get(session, printer, path)
                    if html and "Network Interface" in html:
                        return html
                except Exception as e:
                    last_err = e
                    continue
            
            if last_err:
                raise last_err
            return ""
        finally:
            self._logout_after_collect(printer, source="read_network_interface")

    def fetch_mac_address_direct(self, ip: str) -> str:
        printer = Printer(name="MAC Discovery", ip=ip, user="", password="", printer_type="ricoh")
        try:
            session = self.create_http_client(printer, authenticated=True)
            html = self.authenticate_and_get(
                session, printer, "/web/guest/en/manual/configuration/network/interface/readNetworkInterface.cgi"
            )
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", html)
            if match:
                return match.group(0).replace("-", ":").upper()
        except Exception:
            pass
        return ""

    def process_device_info(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_device_info(printer)
        data = self.parse_device_info(html)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "device_info": data,
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_status(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_status(printer)
        data = self.parse_status(html)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "status_data": data,
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_counter(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_counter(printer)
        data = self.parse_counter(html)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "counter_data": data,
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    @staticmethod
    def parse_device_info(html: str) -> dict[str, str]:
        results = {}
        clean = re.sub(r'<(?!td|/td|tr|/tr)[^>]*>', '', html, flags=re.IGNORECASE)
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', clean, flags=re.IGNORECASE | re.DOTALL)
        for row in rows:
            tds = re.findall(r'<td[^>]*>(.*?)</td>', row, flags=re.IGNORECASE | re.DOTALL)
            if len(tds) >= 2:
                key = RicohServiceBase._strip_html(tds[0]).rstrip(":")
                val = RicohServiceBase._strip_html(tds[1])
                if key and val:
                    results[key] = val
        return results

    @staticmethod
    def parse_status(html: str) -> dict[str, str]:
        results = {}
        def parse_alerts(section: str, key_prefix: str) -> None:
            match = re.search(f"{section}.*?>(.*?)</td>", html, re.IGNORECASE | re.DOTALL)
            if match:
                content = RicohServiceBase._strip_html(match.group(1))
                if content and content != "---":
                    results[key_prefix] = content

        parse_alerts("System Status", "system_status")
        parse_alerts("Toner Status", "toner_black")
        tray_matches = re.finditer(r"Tray\s+(\d+).*?>(.*?)</td>", html, re.IGNORECASE | re.DOTALL)
        for m in tray_matches:
            results[f"tray_{m.group(1)}_status"] = RicohServiceBase._strip_html(m.group(2))

        if not results:
            plain = RicohServiceBase._strip_html(html)

            system_match = re.search(r"System\s+Status\s*:?\s*([^\r\n]+)", plain, re.IGNORECASE)
            if system_match:
                value = system_match.group(1).strip(" :-")
                if value:
                    results["system_status"] = value

            toner_match = re.search(r"Toner(?:\s+Status)?\s*:?\s*([^\r\n]+)", plain, re.IGNORECASE)
            if toner_match:
                value = toner_match.group(1).strip(" :-")
                if value:
                    results["toner_black"] = value

            for tray_no, tray_value in re.findall(r"Tray\s+(\d+)\s*:?\s*([^\r\n]+)", plain, re.IGNORECASE):
                normalized = str(tray_value).strip(" :-")
                if normalized:
                    results[f"tray_{tray_no}_status"] = normalized
        return results

    @staticmethod
    def parse_counter(html: str) -> dict[str, str]:
        results = {}
        patterns = {
            "copier_bw": r"Copier:.*?B & W\)?.*?>(.*?)</td>",
            "printer_bw": r"Printer:.*?B & W\)?.*?>(.*?)</td>",
            "fax_bw": r"Fax:.*?Total.*?>(.*?)</td>",
            "scanner_send_bw": r"Scanner:.*?B & W\)?.*?>(.*?)</td>",
            "scanner_send_color": r"Scanner:.*?Full Color.*?>(.*?)</td>",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if match:
                val = RicohServiceBase._strip_html(match.group(1)).replace(",", "")
                if val.isdigit():
                    results[key] = val

        # Older Web Image Monitor pages render values as plain text blocks.
        if not results:
            plain = RicohServiceBase._strip_html(html)
            fallback_patterns = {
                "copier_bw": r"Copier\s+Black\s*&\s*White\s*:\s*([0-9,]+)",
                "printer_bw": r"Printer\s+Black\s*&\s*White\s*:\s*([0-9,]+)",
                "fax_bw": r"Fax\s+Black\s*&\s*White\s*:\s*([0-9,]+)",
                "scanner_send_bw": r"Send/TX\s+Total\s+Black\s*&\s*White\s*:\s*([0-9,]+)",
                "scanner_send_color": r"Send/TX\s+Total\s+Color\s*:\s*([0-9,]+)",
            }
            for key, pattern in fallback_patterns.items():
                match = re.search(pattern, plain, re.IGNORECASE)
                if not match:
                    continue
                val = match.group(1).replace(",", "").strip()
                if val.isdigit():
                    results[key] = val
        return results

    def _prepare_csv_row(self, timestamp: str, printer: Printer, status_data: dict[str, str]) -> list[str]:
        return [
            timestamp, printer.name, printer.ip,
            status_data.get("system_status", ""),
            status_data.get("toner_black", ""),
            status_data.get("tray_1_status", ""),
            status_data.get("tray_2_status", ""),
            status_data.get("tray_3_status", ""),
            status_data.get("tray_4_status", ""),
        ]

    def start_counter_logging(self, printer: Printer) -> None:
        csv_path = Path("storage/data/log_counter.csv")
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        if not csv_path.exists():
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp", "printer_name", "ip", "copier_bw", "printer_bw", "total_bw"])

        while not self._stop_event.is_set():
            try:
                payload = self.process_counter(printer, should_post=True)
                data = payload["counter_data"]
                c_bw = int(data.get("copier_bw", 0))
                p_bw = int(data.get("printer_bw", 0))
                with csv_path.open("a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([self._timestamp(), printer.name, printer.ip, c_bw, p_bw, c_bw + p_bw])
            except Exception as exc:
                LOGGER.error("Counter logging error: %s", exc)
            time.sleep(60)

    def start_status_logging(self, printer: Printer, csv_path: str | Path = "storage/data/log_status.csv") -> None:
        path = Path(csv_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open("w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp", "printer_name", "ip", "sys_status", "toner", "t1", "t2", "t3", "t4"])

        while not self._stop_event.is_set():
            try:
                payload = self.process_status(printer, should_post=True)
                row = self._prepare_csv_row(self._timestamp(), printer, payload["status_data"])
                with path.open("a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow(row)
            except Exception as exc:
                LOGGER.error("Status logging error: %s", exc)
            time.sleep(30)
