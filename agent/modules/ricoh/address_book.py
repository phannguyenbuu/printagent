from __future__ import annotations

import logging
import re
import socket
from dataclasses import asdict
from typing import Any

import requests

from app.modules.ricoh.base import RicohServiceBase, AddressEntry, ADDRESS_DEBUG_LOG_FILE
from app.services.api_client import Printer

LOGGER = logging.getLogger(__name__)

class RicohAddressBookMixin(RicohServiceBase):
    def read_address_list_with_client(self, session: requests.Session, printer: Printer) -> str:
        targets = [
            "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL",
            "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL",
        ]
        last = ""
        for target in targets:
            try:
                html = self.authenticate_and_get(session, printer, target)
                if html.strip():
                    last = html
                    if "adrsList" in html or "ReportListArea_TableBody" in html:
                        return html
            except Exception:  # noqa: BLE001
                continue
        return last

    def read_address_list(self, printer: Printer) -> str:
        session = self.create_http_client(printer, authenticated=True)
        return self.read_address_list_with_client(session, printer)

    def delete_address_entries(
        self,
        printer: Printer,
        registration_numbers: list[str],
        entry_ids: list[str] | None = None,
        verify: bool = True,
    ) -> dict[str, Any]:
        regs = [str(x or "").strip() for x in registration_numbers if str(x or "").strip()]
        ids = [str(x or "").strip() for x in (entry_ids or []) if str(x or "").strip()]
        if not regs and not ids:
            raise ValueError("registration_numbers is empty")

        session = self.create_http_client(printer)
        list_url = "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"
        delete_url = "/web/entry/en/address/adrsDeleteEntries.cgi"
        html = self.authenticate_and_get(session, printer, list_url)
        defaults = self._extract_hidden_inputs(html)
        token = defaults.get("wimToken", "")
        if not token:
            token = self._extract_wim_token(html)
        defaults["wimToken"] = token

        form: list[tuple[str, str]] = [(k, str(v)) for k, v in defaults.items()]
        if ids:
            joined = ",".join(ids)
            if joined and not joined.endswith(","):
                joined = f"{joined},"
            form.append(("entryIndex", joined))
            form.append(("entryIndexIn", joined))
        else:
            joined = ",".join(regs)
            for key in (
                "regiNoListIn", "registrationNoListIn", "entryNoListIn",
                "selectedRegiNoIn", "selectedEntryNoIn", "deleteListIn",
                "deleteEntriesIn", "entryIndex", "entryIndexIn"
            ):
                form.append((key, joined))
                for reg in regs:
                    form.append((key, reg))
            form.append(("open", ""))

        multipart = [(k, (None, str(v))) for k, v in form]
        resp = session.post(
            f"http://{printer.ip}{delete_url}",
            files=multipart,
            headers={"Referer": f"http://{printer.ip}{list_url}"},
            timeout=15,
        )
        resp.raise_for_status()

        if verify:
            verify_raw = self.get_address_list_ajax_with_client(session, printer)
            verify_entries = self.parse_ajax_address_list(verify_raw)
            if ids:
                remain = {str(getattr(e, "entry_id", "") or "").strip() for e in verify_entries}
                failed = [reg for reg in ids if reg in remain]
            else:
                remain = {str(e.registration_no or "").strip() for e in verify_entries}
                failed = [reg for reg in regs if reg in remain]
            if failed:
                label = "entry_id" if ids else "registration_no"
                raise RuntimeError(f"Delete not confirmed for {label}: {', '.join(failed)}")

        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "ok": True,
            "endpoint": delete_url,
            "deleted": ids or regs,
            "deleted_count": len(ids or regs),
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
        targets = [
            "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
            "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1",
            "/web/guest/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
            "/web/guest/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1",
        ]
        last = ""
        for target in targets:
            try:
                raw = self.authenticate_and_get(session, printer, target)
                last = raw
                if "[" in raw and "]" in raw and "login.cgi" not in raw:
                    return raw
            except Exception:  # noqa: BLE001
                continue
        return last

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

        data = raw
        if not (data.startswith("[") and data.endswith("]")):
            first = data.find("[")
            last = data.rfind("]")
            if first < 0 or last <= first:
                return entries
            data = data[first : last + 1]

        raw_entries = re.findall(r"\[([^\]]+)\]", data)
        for raw in raw_entries:
            fields = self.parse_javascript_array_fields(raw)
            if len(fields) < 8:
                continue
            last_used = fields[5]
            if "#" in last_used:
                last_used = last_used.split("#", 1)[1]
            type_map = {"1": "User", "2": "Group"}
            raw_entry_id = fields[0].strip().lstrip("[").strip("'\"")
            entry = AddressEntry(
                type=type_map.get(fields[1], f"Type_{fields[1]}"),
                registration_no=fields[2].strip("'\""),
                name=fields[3].strip("'\""),
                user_code=fields[4].strip("'\""),
                date_last_used=last_used.strip("'\""),
                email_address=fields[6].strip("'\""),
                folder=fields[7].strip("'\""),
                entry_id=raw_entry_id,
            )
            if entry.name or entry.registration_no:
                entries.append(entry)
        return entries

    def process_address_list(self, printer: Printer, trace_id: str = "") -> dict[str, Any]:
        session = self.create_http_client(printer, authenticated=True)
        easysecurity_html = ""
        try:
            easysecurity_html = self.authenticate_and_get(
                session, printer, "/web/entry/en/websys/webArch/mainFrame.cgi?open=websys/easySecurity/getEasySecurity.cgi"
            )
            if not str(easysecurity_html or "").strip():
                easysecurity_html = self.authenticate_and_get(
                    session, printer, "/web/entry/en/websys/easySecurity/getEasySecurity.cgi"
                )
        except Exception:  # noqa: BLE001
             pass

        html = self.read_address_list_with_client(session, printer)
        entries = self.parse_address_list(html)
        
        ajax_raw = ""
        ajax_entries: list[AddressEntry] = []
        try:
            ajax_raw = self.get_address_list_ajax_with_client(session, printer)
            ajax_entries = self.parse_ajax_address_list(ajax_raw)
            if ajax_entries:
                entries = [entries[0], *ajax_entries]
        except Exception:  # noqa: BLE001
             pass

        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "address_list": [asdict(item) for item in entries],
            "timestamp": self._timestamp(),
        }

    def setup_scan_destination(self, printer: Printer, username: str, fields: dict[str, Any] | None = None) -> dict[str, Any]:
        safe_username = re.sub(r"[^A-Za-z0-9_-]", "", str(username or "").strip().replace(" ", "_"))[:48] or "scan"
        ftp_name = f"ftp_{safe_username}"[:48]
        ftp_root = f"storage/ftp/{ftp_name}"
        ftp_res = self.share_manager.create_ftp_site(site_name=ftp_name, local_path=ftp_root, port=2121)
        if not ftp_res.get("ok"):
            return ftp_res

        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:  # noqa: BLE001
            local_ip = "127.0.0.1"
        ftp_port = int(ftp_res.get("port") or 2121)
        ftp_url = f"ftp://{local_ip}:{ftp_port}/"

        try:
            merged_fields = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            wizard_res = self.create_address_user_wizard(
                printer=printer,
                name=f"Scan to {username}",
                folder=ftp_url,
                fields=merged_fields,
            )
            return {
                "ok": True,
                "ftp": ftp_res,
                "printer": wizard_res,
                "ftp_url": ftp_url,
            }
        except Exception as e:
            LOGGER.exception("Auto-scan setup failed: %s", e)
            return {
                "ok": False,
                "error": f"FTP created at {ftp_url}, but printer setup failed: {e}",
                "ftp": ftp_res,
            }
