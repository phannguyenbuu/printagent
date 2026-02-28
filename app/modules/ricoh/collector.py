from __future__ import annotations

import csv
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from app.modules.ricoh.base import RicohServiceBase
from app.services.api_client import Printer

LOGGER = logging.getLogger(__name__)

class RicohCollectorMixin(RicohServiceBase):
    def read_counter(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            return self.authenticate_and_get(session, printer, "/web/guest/en/manual/counter/readCounter.cgi")
        finally:
            self._logout_after_collect(printer, source="read_counter")

    def read_device_info(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            return self.authenticate_and_get(session, printer, "/web/guest/en/manual/configuration/readDeviceInfo.cgi")
        finally:
            self._logout_after_collect(printer, source="read_device_info")

    def read_status(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            return self.authenticate_and_get(session, printer, "/web/guest/en/manual/status/readStatus.cgi")
        finally:
            self._logout_after_collect(printer, source="read_status")

    def read_network_interface(self, printer: Printer) -> str:
        try:
            session = self.create_http_client(printer, authenticated=False)
            return self.authenticate_and_get(
                session, printer, "/web/guest/en/manual/configuration/network/interface/readNetworkInterface.cgi"
            )
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
