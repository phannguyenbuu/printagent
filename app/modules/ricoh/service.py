from __future__ import annotations

import base64
import csv
import logging
import re
import signal
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from app.services.api_client import APIClient, Printer


LOGGER = logging.getLogger(__name__)
ADDRESS_DEBUG_LOG_FILE = Path("storage/data/address_list_debug.log")


@dataclass(slots=True)
class AddressEntry:
    type: str
    registration_no: str
    name: str
    user_code: str
    date_last_used: str
    email_address: str
    folder: str


class RicohService:
    def __init__(self, api_client: APIClient, interval_seconds: int = 60) -> None:
        self.api_client = api_client
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            LOGGER.info("Ricoh service is already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        LOGGER.info("Ricoh service started. Interval: %ss", self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        LOGGER.info("Ricoh service stopped")

    def _run_loop(self) -> None:
        self.process_printers()
        while not self._stop_event.wait(self.interval_seconds):
            self.process_printers()

    def process_printers(self) -> None:
        printers = self.api_client.get_printers()
        for printer in printers:
            if printer.printer_type.lower() != "ricoh":
                continue
            try:
                html = self.read_counter(printer)
                payload = {
                    "printer_name": printer.name,
                    "ip": printer.ip,
                    "html": html,
                    "timestamp": self._timestamp(),
                }
                self.api_client.post_data(payload)
                LOGGER.info("Posted counter data for %s (%s)", printer.name, printer.ip)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Failed processing printer %s (%s): %s", printer.name, printer.ip, exc)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _append_address_debug(message: str) -> None:
        try:
            ADDRESS_DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).isoformat()
            with ADDRESS_DEBUG_LOG_FILE.open("a", encoding="utf-8") as fp:
                fp.write(f"[{ts}] {message}\n")
        except Exception:  # noqa: BLE001
            return

    @staticmethod
    def _http_get(url: str, timeout: int = 10, session: requests.Session | None = None) -> str:
        client = session or requests.Session()
        response = client.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text

    def read_counter(self, printer: Printer) -> str:
        return self._http_get(f"http://{printer.ip}/web/guest/en/websys/status/getUnificationCounter.cgi")

    def read_device_info(self, printer: Printer) -> str:
        return self._http_get(f"http://{printer.ip}/web/guest/en/websys/status/configuration.cgi")

    def read_status(self, printer: Printer) -> str:
        return self._http_get(f"http://{printer.ip}/web/guest/en/websys/webArch/getStatus.cgi")

    def process_device_info(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_device_info(printer)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "html": html,
            "device_info": self.parse_device_info(html),
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_status(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_status(printer)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "html": html,
            "status_data": self.parse_status(html),
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_counter(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html = self.read_counter(printer)
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "html": html,
            "counter_data": self.parse_counter(html),
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    @staticmethod
    def parse_device_info(html: str) -> dict[str, str]:
        patterns = {
            "model_name": r"Model Name</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "machine_id": r"Machine ID</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "mac_address": r"MAC(?:\s+Address)?</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([0-9A-Fa-f:\-]{12,17})</td>",
            "ethernet_address": r"Ethernet(?:\s+Address)?</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([0-9A-Fa-f:\-]{12,17})</td>",
            "hardware_address": r"Hardware(?:\s+Address)?</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([0-9A-Fa-f:\-]{12,17})</td>",
            "total_memory": r"Total Memory</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "document_server_capacity": r"Document Server</td>\s*<td[^>]*>:</td>\s*<td[^>]*>Capacity\s*:\s*([^<]+)</td>",
            "document_server_free_space": r"Free Space\s*:\s*([^<%]+)</td>",
            "system_version": r"System</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "nib_version": r"NIB</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "web_image_monitor_version": r"Web Image Monitor</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "adobe_postscript3_version": r"Adobe PostScript 3</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "adobe_pdf_version": r"Adobe PDF</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "rpcs_version": r"RPCS</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "pcl5e_version": r"PCL 5e Emulation</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
            "pclxl_version": r"PCL XL Emulation</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([^<]+)</td>",
        }
        parsed: dict[str, str] = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, html, re.S)
            if match:
                parsed[key] = match.group(1).strip()
        # Normalize MAC-like fields if available.
        mac_candidates = [parsed.get("mac_address", ""), parsed.get("ethernet_address", ""), parsed.get("hardware_address", "")]
        for value in mac_candidates:
            raw = str(value or "").strip()
            if not raw:
                continue
            cleaned = raw.replace("-", ":").upper()
            if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", cleaned):
                parsed["mac_address"] = cleaned
                break
        return parsed

    @staticmethod
    def parse_status(html: str) -> dict[str, str]:
        data: dict[str, str] = {}

        if re.search(r"<dt[^>]*>System</dt>\s*<dd[^>]*>.*?Status OK", html, re.S):
            data["system_status"] = "OK"
        elif re.search(r"<dt[^>]*>System</dt>\s*<dd[^>]*>.*?Alert", html, re.S):
            data["system_status"] = "Alert"

        def parse_alerts(section: str, key_prefix: str) -> None:
            match = re.search(rf"<dt[^>]*>{section}</dt>.*?<ul>(.*?)</ul>", html, re.S)
            if not match:
                return
            alerts = [a.strip() for a in re.findall(r"<li>([^<]+)</li>", match.group(1))]
            alerts = [a for a in alerts if a]
            if alerts:
                data[f"{key_prefix}_alerts"] = "; ".join(alerts)
            else:
                data[f"{key_prefix}_status"] = "OK"

        parse_alerts("Printer", "printer")
        parse_alerts("Copier", "copier")
        parse_alerts("Scanner", "scanner")

        if re.search(r"<dt[^>]*>Black</dt>\s*<dd[^>]*>.*?Status OK", html, re.S):
            data["toner_black"] = "OK"

        for tray_num, title in re.findall(r"<dt[^>]*>Tray (\d+)</dt>\s*<dd[^>]*>.*?title=['\"]([^'\"]+)['\"]", html, re.S):
            data[f"tray_{tray_num}_status"] = title

        bypass = re.search(r"<dt[^>]*>Bypass Tray</dt>\s*<dd[^>]*>.*?title=['\"]([^'\"]+)['\"]", html, re.S)
        if bypass:
            data["bypass_tray_status"] = bypass.group(1)
        return data

    @staticmethod
    def parse_counter(html: str) -> dict[str, str]:
        patterns = {
            "total": r"Total</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "copier_bw": r"Copier</div>.*?Black &amp; White</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "printer_bw": r"Printer</div>.*?Black &amp; White</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "fax_bw": r"Fax</div>.*?Black &amp; White</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "send_tx_total_bw": r"Send/TX Total</div>.*?Black &amp; White</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "send_tx_total_color": r"Send/TX Total</div>.*?Color</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "fax_transmission_total": r"Fax Transmission</div>.*?Total</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "scanner_send_bw": r"Scanner Send</div>.*?Black &amp; White</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "scanner_send_color": r"Scanner Send</div>.*?Color</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "coverage_copier_bw": r"Copier</td>.*?B &amp; W Coverage</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>\s*<td[^>]*>%</td>",
            "coverage_printer_bw": r"Printer</td>.*?B &amp; W Coverage</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>\s*<td[^>]*>%</td>",
            "coverage_fax_bw": r"Fax</td>.*?B &amp; W Coverage</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>\s*<td[^>]*>%</td>",
            "a3_dlt": r"A3/DLT</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
            "duplex": r"Duplex</td>\s*<td[^>]*>:</td>\s*<td[^>]*>([\d,\s]+)</td>",
        }
        parsed: dict[str, str] = {key: "" for key in patterns}
        for key, pattern in patterns.items():
            match = re.search(pattern, html, re.S)
            if match:
                parsed[key] = re.sub(r"[^\d]", "", match.group(1))
        return parsed

    def _login(self, session: requests.Session, printer: Printer) -> None:
        if not printer.user:
            raise ValueError("username is required for login")
        base_url = f"http://{printer.ip}"
        session.get(urljoin(base_url, "/web/guest/en/websys/webArch/mainFrame.cgi"), timeout=10).raise_for_status()
        login_page = session.get(urljoin(base_url, "/web/guest/en/websys/webArch/login.cgi"), timeout=10)
        login_page.raise_for_status()
        html = login_page.text

        token_match = re.search(r"name=['\"]wimToken['\"]\s+value=['\"]([^'\"]+)['\"]", html)
        wim_token = token_match.group(1) if token_match else "689773994"
        form = {
            "userid": base64.b64encode(printer.user.encode("utf-8")).decode("ascii"),
            "password": base64.b64encode((printer.password or "").encode("utf-8")).decode("ascii"),
            "wimToken": wim_token,
            "open": "",
        }
        resp = session.post(
            urljoin(base_url, "/web/guest/en/websys/webArch/login.cgi"),
            data=form,
            headers={"Referer": urljoin(base_url, "/web/guest/en/websys/webArch/login.cgi")},
            timeout=10,
        )
        resp.raise_for_status()
        if "login.cgi" in resp.text or "Login User Name" in resp.text:
            raise RuntimeError("login failed, still on login form")

    def create_http_client(self, printer: Printer) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": "printer-agent/0.1"})
        if printer.user:
            self._login(session, printer)
        else:
            session.get(f"http://{printer.ip}/web/guest/en/websys/webArch/mainFrame.cgi", timeout=10).raise_for_status()
        return session

    def authenticate_and_get(self, session: requests.Session, printer: Printer, target_url: str) -> str:
        full_url = f"http://{printer.ip}{target_url}"
        response = session.get(full_url, timeout=10)
        response.raise_for_status()
        html = response.text
        if ("authForm.cgi" in html or "login.cgi" in html) and printer.user:
            self._login(session, printer)
            response = session.get(full_url, timeout=10)
            response.raise_for_status()
            html = response.text
        return html

    @staticmethod
    def _extract_wim_token(html: str) -> str:
        match = re.search(r"name=['\"]wimToken['\"]\s+value=['\"]([^'\"]+)['\"]", html)
        if not match:
            raise ValueError("wimToken not found")
        return match.group(1)

    def enable_machine(self, printer: Printer) -> None:
        config_url = "/web/entry/en/websys/config/getUserAuthenticationManager.cgi"
        session = self.create_http_client(printer)
        html = self.authenticate_and_get(session, printer, config_url)
        wim_token = self._extract_wim_token(html)

        form: list[tuple[str, str]] = [
            ("wimToken", wim_token),
            ("accessConf", "MDowOjA6MDoxOjE6MTowOjA6MDowOjA6"),
            ("title", "MENU_USERAUTH"),
            ("userAuthenticationRW", "3"),
            ("userAuthenticationMethod", "UA_USER_CODE"),
            ("printerJob", "UA_ALL"),
            ("userCodeDocumentBox", "false"),
            ("userCodeFax", "false"),
            ("userCodeScaner", "false"),
            ("userCodeMfpBrowser", "false"),
        ]
        for value in ["RADIO_OFF", "UA_USER_CODE", "UA_LOCAL_AUTHENTICATION", "UA_NT_AUTHENTICATION", "UA_LDAP_AUTHENTICATION", "UA_RDH_AUTHENTICATION"]:
            form.append(("userAuthenticationMethodInfo", value))
        for _ in range(5):
            form.extend(
                [
                    ("exclusionHostIpv6Select", "false"),
                    ("exclusionHostIpv6RangeFrom", "::"),
                    ("exclusionHostIpv6RangeTo", "::"),
                    ("exclusionHostIpv6MaskBase", "::"),
                    ("exclusionHostIpv6MaskLen", "128"),
                ]
            )
        form.extend(
            [
                ("userCodeCopy", "false"),
                ("userCodeCopybox", ""),
                ("userCodeCopy", ""),
                ("userCodeCopybox", ""),
                ("userCodeCopy", ""),
                ("userCodeCopybox", ""),
                ("userCodeCopy", ""),
                ("userCodePrinter", "false"),
                ("userCodePrinterbox", ""),
                ("userCodePrinter", ""),
                ("userCodePrinterbox", "true"),
                ("userCodePrinter", "true"),
            ]
        )
        for _ in range(33):
            form.extend([("userCodeSdkAplibox", ""), ("userCodeSdkApli", "")])
        resp = session.post(
            f"http://{printer.ip}/web/entry/en/websys/config/setUserAuthenticationManager.cgi",
            data=form,
            headers={"Referer": f"http://{printer.ip}{config_url}"},
            timeout=10,
        )
        resp.raise_for_status()

    def lock_machine(self, printer: Printer) -> None:
        config_url = "/web/entry/en/websys/config/getUserAuthenticationManager.cgi"
        session = self.create_http_client(printer)
        html = self.authenticate_and_get(session, printer, config_url)
        wim_token = self._extract_wim_token(html)
        form: list[tuple[str, str]] = [
            ("wimToken", wim_token),
            ("accessConf", "MDowOjA6MDoxOjE6MTowOjA6MDowOjA6"),
            ("title", "MENU_USERAUTH"),
            ("userAuthenticationRW", "3"),
            ("userAuthenticationMethod", "UA_USER_CODE"),
            ("userCodeCopy", "true"),
            ("userCodeCopy", ""),
            ("userCodeCopy", ""),
            ("userCodeCopy", ""),
            ("userCodePrinter", "true"),
            ("userCodePrinter", "false"),
            ("userCodePrinter", ""),
            ("userCodeDocumentBox", "true"),
            ("userCodeFax", "true"),
            ("userCodeScaner", "true"),
            ("userCodeMfpBrowser", "true"),
        ]
        resp = session.post(
            f"http://{printer.ip}/web/entry/en/websys/config/setUserAuthenticationManager.cgi",
            data=form,
            headers={"Referer": f"http://{printer.ip}{config_url}"},
            timeout=10,
        )
        resp.raise_for_status()

    def read_address_list_with_client(self, session: requests.Session, printer: Printer) -> str:
        urls = [
            "/web/entry/en/address/adrsList.cgi",
            "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL",
            "/web/entry/en/address/adrsListAll.cgi",
            "/web/entry/en/address/getAddressList.cgi",
        ]
        for target in urls:
            try:
                html = self.authenticate_and_get(session, printer, target)
                html_len = len(html)
                has_address_markers = "Address List" in html or "adrsList" in html
                has_login_markers = "login.cgi" in html or "Login User Name" in html or "authForm.cgi" in html
                self._append_address_debug(
                    "address_list:url_check "
                    f"ip={printer.ip} target={target} html_len={html_len} "
                    f"has_address_markers={has_address_markers} has_login_markers={has_login_markers}"
                )
                LOGGER.info(
                    "Address list URL check: ip=%s target=%s html_len=%s has_address_markers=%s has_login_markers=%s",
                    printer.ip,
                    target,
                    html_len,
                    has_address_markers,
                    has_login_markers,
                )
                if has_address_markers:
                    return html
            except Exception as exc:  # noqa: BLE001
                self._append_address_debug(
                    f"address_list:url_error ip={printer.ip} target={target} error={type(exc).__name__}:{str(exc)}"
                )
                LOGGER.warning("Address list URL error: ip=%s target=%s error=%s", printer.ip, target, exc)
                continue
        return self.authenticate_and_get(session, printer, urls[0])

    def read_address_list(self, printer: Printer) -> str:
        session = self.create_http_client(printer)
        return self.read_address_list_with_client(session, printer)

    @staticmethod
    def _strip_html(input_value: str) -> str:
        text = re.sub(r"<[^>]*>", "", input_value)
        return unescape(text).strip()

    @staticmethod
    def _extract_hidden_inputs(html: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for match in re.finditer(r"<input[^>]*>", html, re.I | re.S):
            tag = match.group(0)
            type_match = re.search(r"type=['\"]([^'\"]+)['\"]", tag, re.I)
            input_type = (type_match.group(1).strip().lower() if type_match else "").strip()
            if input_type and input_type != "hidden":
                continue
            name_match = re.search(r"name=['\"]([^'\"]+)['\"]", tag, re.I)
            if not name_match:
                continue
            key = name_match.group(1).strip()
            if not key:
                continue
            value_match = re.search(r"value=['\"]([^'\"]*)['\"]", tag, re.I | re.S)
            value = value_match.group(1) if value_match else ""
            result[key] = unescape(value)
        return result

    @staticmethod
    def _pick_field_key(keys: list[str], candidates: list[str]) -> str:
        lowered_map = {k.lower(): k for k in keys}
        for cand in candidates:
            hit = lowered_map.get(cand.lower())
            if hit:
                return hit
        return ""

    def create_address_user_wizard(
        self,
        printer: Printer,
        name: str,
        email: str = "",
        folder: str = "",
        user_code: str = "",
        fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self.create_http_client(printer)
        get_url = "/web/entry/en/address/adrsGetUserWizard.cgi"
        set_url = "/web/entry/en/address/adrsSetUserWizard.cgi"
        html = self.authenticate_and_get(session, printer, get_url)

        defaults = self._extract_hidden_inputs(html)
        token = defaults.get("wimToken", "")
        if not token:
            token = self._extract_wim_token(html)
        defaults["wimToken"] = token

        key_list = list(defaults.keys())
        name_key = self._pick_field_key(key_list, ["nameIn", "userNameIn", "displayNameIn", "name"])
        email_key = self._pick_field_key(key_list, ["emailAddressIn", "emailIn", "mailAddressIn", "email"])
        folder_key = self._pick_field_key(key_list, ["folderPathIn", "folderIn", "pathIn", "folder"])
        user_code_key = self._pick_field_key(key_list, ["userCodeIn", "userCode", "codeIn"])

        if name_key:
            defaults[name_key] = str(name or "").strip()
        else:
            defaults["nameIn"] = str(name or "").strip()
        if email:
            defaults[email_key or "emailAddressIn"] = str(email).strip()
        if folder:
            defaults[folder_key or "folderPathIn"] = str(folder).strip()
        if user_code:
            defaults[user_code_key or "userCodeIn"] = str(user_code).strip()

        if fields and isinstance(fields, dict):
            for k, v in fields.items():
                key = str(k or "").strip()
                if not key:
                    continue
                defaults[key] = "" if v is None else str(v)

        defaults.setdefault("open", "")

        resp = session.post(
            f"http://{printer.ip}{set_url}",
            data=defaults,
            headers={"Referer": f"http://{printer.ip}{get_url}"},
            timeout=15,
        )
        resp.raise_for_status()

        verify_raw = ""
        verify_count = 0
        try:
            verify_raw = self.get_address_list_ajax_with_client(session, printer)
            parsed = self.parse_ajax_address_list(verify_raw)
            verify_count = len(parsed)
        except Exception:  # noqa: BLE001
            verify_raw = ""
            verify_count = 0

        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "ok": True,
            "endpoint": set_url,
            "name": str(name or "").strip(),
            "http_status": resp.status_code,
            "response_excerpt": resp.text[:600],
            "verify_count": verify_count,
            "timestamp": self._timestamp(),
        }

    def modify_address_user_wizard(
        self,
        printer: Printer,
        registration_no: str,
        name: str = "",
        email: str = "",
        folder: str = "",
        user_code: str = "",
        fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        reg = str(registration_no or "").strip()
        if not reg:
            raise ValueError("registration_no is required")

        session = self.create_http_client(printer)
        get_url = f"/web/entry/en/address/adrsGetUserWizard.cgi?regiNoIn={reg}"
        set_url = "/web/entry/en/address/adrsSetUserWizard.cgi"
        html = self.authenticate_and_get(session, printer, get_url)

        defaults = self._extract_hidden_inputs(html)
        token = defaults.get("wimToken", "")
        if not token:
            token = self._extract_wim_token(html)
        defaults["wimToken"] = token

        key_list = list(defaults.keys())
        reg_key = self._pick_field_key(key_list, ["regiNoIn", "registrationNoIn", "entryNoIn"])
        mode_key = self._pick_field_key(key_list, ["modeIn", "actionModeIn", "procModeIn"])
        name_key = self._pick_field_key(key_list, ["nameIn", "userNameIn", "displayNameIn", "name"])
        email_key = self._pick_field_key(key_list, ["emailAddressIn", "emailIn", "mailAddressIn", "email"])
        folder_key = self._pick_field_key(key_list, ["folderPathIn", "folderIn", "pathIn", "folder"])
        user_code_key = self._pick_field_key(key_list, ["userCodeIn", "userCode", "codeIn"])

        defaults[reg_key or "regiNoIn"] = reg
        defaults[mode_key or "modeIn"] = defaults.get(mode_key or "modeIn", "MOD")
        if name:
            defaults[name_key or "nameIn"] = str(name).strip()
        if email:
            defaults[email_key or "emailAddressIn"] = str(email).strip()
        if folder:
            defaults[folder_key or "folderPathIn"] = str(folder).strip()
        if user_code:
            defaults[user_code_key or "userCodeIn"] = str(user_code).strip()
        if fields and isinstance(fields, dict):
            for k, v in fields.items():
                key = str(k or "").strip()
                if not key:
                    continue
                defaults[key] = "" if v is None else str(v)

        defaults.setdefault("open", "")

        resp = session.post(
            f"http://{printer.ip}{set_url}",
            data=defaults,
            headers={"Referer": f"http://{printer.ip}{get_url}"},
            timeout=15,
        )
        resp.raise_for_status()

        verify_raw = self.get_address_list_ajax_with_client(session, printer)
        verify_entries = self.parse_ajax_address_list(verify_raw)
        updated = next((e for e in verify_entries if str(e.registration_no or "").strip() == reg), None)
        if updated is None:
            raise RuntimeError(f"Modified entry not found after set: registration_no={reg}")

        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "ok": True,
            "endpoint": set_url,
            "registration_no": reg,
            "name": updated.name,
            "email_address": updated.email_address,
            "folder": updated.folder,
            "user_code": updated.user_code,
            "http_status": resp.status_code,
            "timestamp": self._timestamp(),
        }

    def delete_address_entries(self, printer: Printer, registration_numbers: list[str]) -> dict[str, Any]:
        regs = [str(x or "").strip() for x in registration_numbers if str(x or "").strip()]
        if not regs:
            raise ValueError("registration_numbers is empty")

        session = self.create_http_client(printer)
        list_url = "/web/entry/en/address/adrsList.cgi"
        delete_url = "/web/entry/en/address/adrsDeleteEntries.cgi"
        html = self.authenticate_and_get(session, printer, list_url)
        defaults = self._extract_hidden_inputs(html)
        token = defaults.get("wimToken", "")
        if not token:
            token = self._extract_wim_token(html)
        defaults["wimToken"] = token

        joined = ",".join(regs)
        form: list[tuple[str, str]] = [(k, str(v)) for k, v in defaults.items()]
        # Best-effort compatibility across Ricoh model variants.
        for key in (
            "regiNoListIn",
            "registrationNoListIn",
            "entryNoListIn",
            "selectedRegiNoIn",
            "selectedEntryNoIn",
            "deleteListIn",
            "deleteEntriesIn",
        ):
            form.append((key, joined))
            for reg in regs:
                form.append((key, reg))
        form.append(("open", ""))

        resp = session.post(
            f"http://{printer.ip}{delete_url}",
            data=form,
            headers={"Referer": f"http://{printer.ip}{list_url}"},
            timeout=15,
        )
        resp.raise_for_status()

        verify_raw = self.get_address_list_ajax_with_client(session, printer)
        verify_entries = self.parse_ajax_address_list(verify_raw)
        remain = {str(e.registration_no or "").strip() for e in verify_entries}
        failed = [reg for reg in regs if reg in remain]
        if failed:
            raise RuntimeError(f"Delete not confirmed for registration_no: {', '.join(failed)}")

        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "ok": True,
            "endpoint": delete_url,
            "deleted": regs,
            "deleted_count": len(regs),
            "http_status": resp.status_code,
            "timestamp": self._timestamp(),
        }

    def parse_address_list(self, html: str) -> list[AddressEntry]:
        user_count = re.search(r'<span id="span_numOfUsers">(\d+)</span>', html)
        group_count = re.search(r'<span id="span_numOfGroups">(\d+)</span>', html)
        user_code_count = re.search(r'<span id="span_numOfUserCode">(\d+)</span>', html)
        entries = [
            AddressEntry(
                type="Summary",
                registration_no="-",
                name=f"Users: {user_count.group(1) if user_count else '0'}, Groups: {group_count.group(1) if group_count else '0'}, User Codes: {user_code_count.group(1) if user_code_count else '0'}",
                user_code="-",
                date_last_used="-",
                email_address="-",
                folder="-",
            )
        ]

        tbody_match = re.search(r'<tbody id="ReportListArea_TableBody">(.*?)</tbody>', html, re.S)
        if not tbody_match:
            return entries

        rows = re.findall(r"<tr(?:\s+[^>]*)?>(?:\s*<td[^>]*>.*?</td>\s*){7,}</tr>", tbody_match.group(1), re.S)
        for row in rows:
            if "reportListDummyRow" in row:
                continue
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            if len(cells) < 8:
                continue
            entry = AddressEntry(
                type=self._strip_html(cells[1]),
                registration_no=self._strip_html(cells[2]),
                name=self._strip_html(cells[3]),
                user_code=self._strip_html(cells[4]),
                date_last_used=self._strip_html(cells[5]),
                email_address=self._strip_html(cells[6]),
                folder=self._strip_html(cells[7]),
            )
            if entry.name and entry.name != "-" and entry.registration_no:
                entries.append(entry)
        return entries

    def get_address_list_ajax_with_client(self, session: requests.Session, printer: Printer) -> str:
        return self.authenticate_and_get(
            session, printer, "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1"
        )

    @staticmethod
    def parse_javascript_array_fields(data: str) -> list[str]:
        fields: list[str] = []
        current: list[str] = []
        in_quotes = False
        quote_char = ""
        escaped = False
        for char in data:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\":
                current.append(char)
                escaped = True
                continue
            if char in {"'", '"'}:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                else:
                    current.append(char)
                continue
            if char == "," and not in_quotes:
                fields.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            fields.append("".join(current).strip())
        return fields

    def parse_ajax_address_list(self, data: str) -> list[AddressEntry]:
        entries: list[AddressEntry] = []
        raw = str(data or "").strip()
        if not raw:
            return entries

        # Some Ricoh models wrap array payload in JS callbacks/vars.
        data = raw
        if not (data.startswith("[") and data.endswith("]")):
            first = data.find("[")
            last = data.rfind("]")
            if first < 0 or last <= first:
                return entries
            data = data[first : last + 1]

        # Keep existing parser behavior for entry chunks inside top-level array.
        raw_entries = re.findall(r"\[([^\]]+)\]", data)
        for raw in raw_entries:
            fields = self.parse_javascript_array_fields(raw)
            if len(fields) < 8:
                continue
            last_used = fields[5]
            if "#" in last_used:
                last_used = last_used.split("#", 1)[1]
            type_map = {"1": "User", "2": "Group"}
            entry = AddressEntry(
                type=type_map.get(fields[1], f"Type_{fields[1]}"),
                registration_no=fields[2].strip("'\""),
                name=fields[3].strip("'\""),
                user_code=fields[4].strip("'\""),
                date_last_used=last_used.strip("'\""),
                email_address=fields[6].strip("'\""),
                folder=fields[7].strip("'\""),
            )
            if entry.name or entry.registration_no:
                entries.append(entry)
        return entries

    def process_address_list(self, printer: Printer, trace_id: str = "") -> dict[str, Any]:
        session = self.create_http_client(printer)
        html = self.read_address_list_with_client(session, printer)
        entries = self.parse_address_list(html)
        has_table = '<tbody id="ReportListArea_TableBody">' in html
        has_login_markers = "login.cgi" in html or "Login User Name" in html or "authForm.cgi" in html
        has_address_markers = "Address List" in html or "adrsList" in html
        non_summary_html_entries = max(0, len(entries) - 1)
        self._append_address_debug(
            "address_list:start "
            f"trace_id={trace_id or '-'} ip={printer.ip} name={printer.name} html_len={len(html)} "
            f"entries_html={len(entries)} non_summary_html_entries={non_summary_html_entries} "
            f"has_table={has_table} has_address_markers={has_address_markers} has_login_markers={has_login_markers}"
        )
        LOGGER.info(
            "Address list start: trace_id=%s ip=%s name=%s html_len=%s entries_html=%s non_summary_html_entries=%s has_table=%s has_address_markers=%s has_login_markers=%s",
            trace_id or "-",
            printer.ip,
            printer.name,
            len(html),
            len(entries),
            non_summary_html_entries,
            has_table,
            has_address_markers,
            has_login_markers,
        )
        ajax_raw = ""
        ajax_entries: list[AddressEntry] = []
        ajax_has_login_markers = False
        try:
            ajax_raw = self.get_address_list_ajax_with_client(session, printer)
            ajax_entries = self.parse_ajax_address_list(ajax_raw)
            ajax_has_brackets = "[" in ajax_raw and "]" in ajax_raw
            ajax_has_login_markers = "login.cgi" in ajax_raw or "Login User Name" in ajax_raw or "authForm.cgi" in ajax_raw
            self._append_address_debug(
                "address_list:ajax "
                f"trace_id={trace_id or '-'} ip={printer.ip} ajax_len={len(ajax_raw)} ajax_entries={len(ajax_entries)} "
                f"ajax_has_brackets={ajax_has_brackets} ajax_has_login_markers={ajax_has_login_markers} "
                f"ajax_excerpt={repr(ajax_raw[:300])}"
            )
            LOGGER.info(
                "Address list ajax: trace_id=%s ip=%s ajax_len=%s ajax_entries=%s ajax_has_brackets=%s ajax_has_login_markers=%s",
                trace_id or "-",
                printer.ip,
                len(ajax_raw),
                len(ajax_entries),
                ajax_has_brackets,
                ajax_has_login_markers,
            )
            if ajax_entries and entries:
                entries = [entries[0], *ajax_entries]
        except Exception as exc:  # noqa: BLE001
            self._append_address_debug(
                f"address_list:ajax_error trace_id={trace_id or '-'} ip={printer.ip} error={type(exc).__name__}:{str(exc)}"
            )
            LOGGER.exception("Address list ajax error: trace_id=%s ip=%s", trace_id or "-", printer.ip)
        if max(0, len(entries) - 1) == 0 and (has_login_markers or ajax_has_login_markers):
            reason = "html_login" if has_login_markers else "ajax_login"
            self._append_address_debug(
                f"address_list:auth_required trace_id={trace_id or '-'} ip={printer.ip} reason={reason}"
            )
            LOGGER.warning("Address list auth required: trace_id=%s ip=%s reason=%s", trace_id or "-", printer.ip, reason)
            raise RuntimeError("address list authentication required (login page detected)")
        if max(0, len(entries) - 1) == 0:
            reasons: list[str] = []
            if has_login_markers:
                reasons.append("html_contains_login_markers")
            if not has_table:
                reasons.append("html_missing_report_table")
            if not has_address_markers:
                reasons.append("html_missing_address_markers")
            if ajax_raw and len(ajax_entries) == 0:
                reasons.append("ajax_present_but_no_parsed_entries")
            if not ajax_raw:
                reasons.append("ajax_response_empty")
            if not reasons:
                reasons.append("no_entry_matched_filters")
            reason_text = ",".join(reasons)
            self._append_address_debug(
                f"address_list:no_data trace_id={trace_id or '-'} ip={printer.ip} reasons={reason_text}"
            )
            LOGGER.warning("Address list no data: trace_id=%s ip=%s reasons=%s", trace_id or "-", printer.ip, reason_text)
        self._append_address_debug(
            "address_list:final "
            f"trace_id={trace_id or '-'} ip={printer.ip} total_entries={len(entries)} "
            f"first_entries={repr([asdict(x) for x in entries[:3]])}"
        )
        LOGGER.info("Address list final: trace_id=%s ip=%s total_entries=%s", trace_id or "-", printer.ip, len(entries))
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "html": html,
            "address_list": [asdict(item) for item in entries],
            "debug": {
                "trace_id": trace_id,
                "html_len": len(html),
                "html_entries": len(self.parse_address_list(html)),
                "non_summary_html_entries": non_summary_html_entries,
                "html_has_table": has_table,
                "html_has_address_markers": has_address_markers,
                "html_has_login_markers": has_login_markers,
                "ajax_len": len(ajax_raw),
                "ajax_entries": len(ajax_entries),
                "ajax_excerpt": ajax_raw[:300],
                "debug_log_file": str(ADDRESS_DEBUG_LOG_FILE),
            },
            "timestamp": self._timestamp(),
        }
        return payload

    def start_counter_logging(self, printer: Printer) -> None:
        stop_event = threading.Event()

        def handle_signal(signum: int, _frame: Any) -> None:
            LOGGER.info("Received signal %s. Stopping counter logging.", signum)
            stop_event.set()

        old_int = signal.signal(signal.SIGINT, handle_signal)
        old_term = signal.signal(signal.SIGTERM, handle_signal)
        try:
            while not stop_event.is_set():
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    data = self.parse_counter(self.read_counter(printer))
                    LOGGER.info("[%s] Counter summary: total=%s copier=%s printer=%s scanner=%s", timestamp, data.get("total", ""), data.get("copier_bw", ""), data.get("printer_bw", ""), data.get("scanner_send_bw", ""))
                except Exception as exc:  # noqa: BLE001
                    LOGGER.error("[%s] Counter logging failed: %s", timestamp, exc)
                stop_event.wait(60)
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)

    @staticmethod
    def _prepare_csv_row(timestamp: str, printer: Printer, status_data: dict[str, str]) -> list[str]:
        def get_value(key: str) -> str:
            return status_data.get(key, "")

        other = [
            f"{k}:{v}"
            for k, v in status_data.items()
            if not any(token in k for token in ("system", "printer", "copier", "scanner", "toner", "tray"))
            and v
        ]
        return [
            timestamp,
            printer.name,
            printer.ip,
            get_value("system_status"),
            get_value("printer_status"),
            get_value("printer_alerts"),
            get_value("copier_status"),
            get_value("copier_alerts"),
            get_value("scanner_status"),
            get_value("scanner_alerts"),
            get_value("toner_black"),
            get_value("tray_1_status"),
            get_value("tray_2_status"),
            get_value("tray_3_status"),
            get_value("bypass_tray_status"),
            "; ".join(other),
        ]

    def start_status_logging(self, printer: Printer, csv_path: str | Path = "storage/data/log_status.csv") -> None:
        output = Path(csv_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        write_header = not output.exists()
        with output.open("a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            if write_header:
                writer.writerow(
                    [
                        "timestamp",
                        "printer_name",
                        "printer_ip",
                        "system_status",
                        "printer_status",
                        "printer_alerts",
                        "copier_status",
                        "copier_alerts",
                        "scanner_status",
                        "scanner_alerts",
                        "toner_black",
                        "tray_1_status",
                        "tray_2_status",
                        "tray_3_status",
                        "bypass_tray_status",
                        "other_info",
                    ]
                )

            while True:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    status_data = self.parse_status(self.read_status(printer))
                    writer.writerow(self._prepare_csv_row(timestamp, printer, status_data))
                except Exception as exc:  # noqa: BLE001
                    writer.writerow(
                        [
                            timestamp,
                            printer.name,
                            printer.ip,
                            "ERROR",
                            "ERROR",
                            str(exc),
                            "ERROR",
                            "",
                            "ERROR",
                            "",
                            "ERROR",
                            "ERROR",
                            "ERROR",
                            "ERROR",
                            "ERROR",
                            "",
                        ]
                    )
                file.flush()
                time.sleep(30)
