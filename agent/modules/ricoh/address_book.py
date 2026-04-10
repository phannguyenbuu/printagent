from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

import requests

from app.modules.ricoh.base import RicohServiceBase, AddressEntry, ADDRESS_DEBUG_LOG_FILE
from app.services.api_client import Printer
from app.services.runtime import default_ftp_root, no_window_subprocess_kwargs
from app.services.scan_drop import build_drop_folder_metadata

LOGGER = logging.getLogger(__name__)

class RicohAddressBookMixin(RicohServiceBase):
    @staticmethod
    def _sanitize_ftp_site_name(value: str) -> str:
        text = str(value or "").strip().replace(" ", "_")
        text = re.sub(r"[^A-Za-z0-9_-]", "", text)
        return text[:48]

    @staticmethod
    def _normalize_ipv4(value: str) -> str:
        text = str(value or "").strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            return ""
        try:
            parts = [int(part) for part in text.split(".")]
        except Exception:  # noqa: BLE001
            return ""
        if any(part < 0 or part > 255 for part in parts):
            return ""
        if parts[0] in {0, 127}:
            return ""
        if parts[0] == 169 and parts[1] == 254:
            return ""
        if parts == [255, 255, 255, 255]:
            return ""
        return ".".join(str(part) for part in parts)

    @staticmethod
    def _ipv4_scope_score(value: str) -> int:
        text = RicohAddressBookMixin._normalize_ipv4(value)
        if not text:
            return -1
        octets = [int(part) for part in text.split(".")]
        if octets[0] == 10:
            return 300
        if octets[0] == 192 and octets[1] == 168:
            return 400
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return 350
        return 200

    @classmethod
    def _resolve_local_ipv4_candidates(cls) -> list[str]:
        candidates: list[str] = []

        def _push(value: str) -> None:
            text = cls._normalize_ipv4(value)
            if text and text not in candidates:
                candidates.append(text)

        hostname = socket.gethostname()
        try:
            host_info = socket.gethostbyname_ex(hostname)
            for value in host_info[2]:
                _push(str(value or "").strip())
        except Exception:  # noqa: BLE001
            pass

        try:
            for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
                _push(str(info[4][0] or "").strip())
        except Exception:  # noqa: BLE001
            pass

        for probe_ip in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect((probe_ip, 80))
                    _push(sock.getsockname()[0])
            except Exception:  # noqa: BLE001
                continue

        try:
            script = r"""
$ErrorActionPreference='SilentlyContinue'
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '0.0.0.0' } |
  Select-Object IPAddress |
  ConvertTo-Json -Depth 3
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=8,
                check=True,
                **no_window_subprocess_kwargs(),
            )
            payload = json.loads(result.stdout or "[]")
            if isinstance(payload, dict):
                payload = [payload]
            if isinstance(payload, list):
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    _push(str(item.get("IPAddress", "") or "").strip())
        except Exception:  # noqa: BLE001
            pass

        return sorted(candidates, key=cls._ipv4_scope_score, reverse=True)

    @classmethod
    def resolve_ftp_host_ip(cls, printer_ip: str = "") -> dict[str, Any]:
        normalized_printer_ip = cls._normalize_ipv4(printer_ip)
        candidates = cls._resolve_local_ipv4_candidates()
        if normalized_printer_ip:
            subnet_prefix = ".".join(normalized_printer_ip.split(".")[:3])
            same_subnet = [item for item in candidates if ".".join(item.split(".")[:3]) == subnet_prefix]
            if same_subnet:
                return {
                    "ip": same_subnet[0],
                    "strategy": "same-subnet",
                    "candidates": candidates,
                    "warning": "",
                }
            if candidates:
                fallback_ip = candidates[0]
                return {
                    "ip": fallback_ip,
                    "strategy": "fallback-other-local-ip",
                    "candidates": candidates,
                    "warning": (
                        f'No local FTP IP on the same subnet as printer {normalized_printer_ip}. '
                        f'Using {fallback_ip} instead; choose another FTP/agent if the printer cannot reach it.'
                    ),
                }
        if candidates:
            return {
                "ip": candidates[0],
                "strategy": "best-local-ip",
                "candidates": candidates,
                "warning": "",
            }
        return {
            "ip": "127.0.0.1",
            "strategy": "loopback-fallback",
            "candidates": [],
            "warning": "No valid local LAN IP found for FTP; defaulted to 127.0.0.1. Choose another FTP/agent.",
        }

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

    def setup_scan_destination(
        self,
        printer: Printer | None,
        username: str,
        fields: dict[str, Any] | None = None,
        ftp_site_name: str = "",
        ftp_root: str | Path | None = None,
        ftp_port: int = 2121,
        ftp_user: str = "",
        ftp_password: str = "",
    ) -> dict[str, Any]:
        safe_username = re.sub(r"[^A-Za-z0-9_-]", "", str(username or "").strip().replace(" ", "_"))[:48] or "scan"
        ftp_name = self._sanitize_ftp_site_name(ftp_site_name or f"ftp_{safe_username}") or f"ftp_{safe_username}"
        ftp_root_path = Path(ftp_root) if ftp_root is not None else default_ftp_root(ftp_name)
        ftp_res = self.share_manager.create_ftp_site(
            site_name=ftp_name,
            local_path=ftp_root_path,
            port=int(ftp_port or 2121),
            ftp_user=ftp_user,
            ftp_password=ftp_password,
        )
        if not ftp_res.get("ok"):
            return ftp_res
        ftp_root_path = Path(str(ftp_res.get("physical_path", "") or ftp_root_path))
        ftp_user = str(ftp_res.get("ftp_user", "") or "")
        ftp_password = str(ftp_res.get("ftp_password", "") or "")
        scan_dir_added = False
        scan_dirs: list[str] = []
        app_config = getattr(self, "_config", None)
        if app_config is not None and hasattr(app_config, "ensure_scan_dir"):
            try:
                scan_dir_added, scan_dirs = app_config.ensure_scan_dir(ftp_root_path)
            except Exception:  # noqa: BLE001
                scan_dir_added = False
                scan_dirs = []

        ftp_host_info = self.resolve_ftp_host_ip(str(getattr(printer, "ip", "") or ""))
        local_ip = str(ftp_host_info.get("ip", "") or "127.0.0.1")
        ftp_ip_warning = str(ftp_host_info.get("warning", "") or "").strip()
        ftp_port_value = int(ftp_res.get("port") or ftp_port or 2121)
        ftp_url = f"ftp://{local_ip}:{ftp_port_value}/"
        drop_folder = build_drop_folder_metadata(ftp_root_path, base_url=ftp_url)
        ftp_upload_url = str(drop_folder.get("upload_url", "") or ftp_url)

        if printer is None or not str(getattr(printer, "ip", "") or "").strip():
            return {
                "ok": True,
                "ftp": ftp_res,
                "printer": None,
                "printer_setup_ok": False,
                "ftp_url": ftp_url,
                "ftp_upload_url": ftp_upload_url,
                "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
                "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
                "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
                "ftp_host_ip": local_ip,
                "ftp_ip_candidates": list(ftp_host_info.get("candidates", []) or []),
                "ftp_ip_strategy": str(ftp_host_info.get("strategy", "") or ""),
                "warning": ftp_ip_warning,
                "scan_dir_added": scan_dir_added,
                "scan_dirs": scan_dirs,
            }

        try:
            merged_fields = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            if ftp_user:
                merged_fields["folderAuthUserNameIn"] = ftp_user
                merged_fields["folderAuthUserName"] = ftp_user
            if ftp_password:
                merged_fields["folderPasswordIn"] = ftp_password
                merged_fields["wk_folderPasswordIn"] = ftp_password
                merged_fields["folderPasswordConfirmIn"] = ftp_password
                merged_fields["wk_folderPasswordConfirmIn"] = ftp_password
            wizard_res = self.create_address_user_wizard(
                printer=printer,
                name=f"Scan to {username}",
                folder=ftp_upload_url,
                fields=merged_fields,
            )
            return {
                "ok": True,
                "ftp": ftp_res,
                "printer": wizard_res,
                "printer_setup_ok": True,
                "ftp_url": ftp_url,
                "ftp_upload_url": ftp_upload_url,
                "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
                "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
                "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
                "ftp_host_ip": local_ip,
                "ftp_ip_candidates": list(ftp_host_info.get("candidates", []) or []),
                "ftp_ip_strategy": str(ftp_host_info.get("strategy", "") or ""),
                "warning": ftp_ip_warning,
                "scan_dir_added": scan_dir_added,
                "scan_dirs": scan_dirs,
            }
        except Exception as e:
            LOGGER.exception("Auto-scan setup failed: %s", e)
            warning_parts = []
            if ftp_ip_warning:
                warning_parts.append(ftp_ip_warning)
            warning_parts.append(f"FTP created at {ftp_url}, but printer setup failed: {e}")
            return {
                "ok": True,
                "warning": " ".join(warning_parts).strip(),
                "ftp": ftp_res,
                "printer_setup_ok": False,
                "printer_error": str(e),
                "ftp_url": ftp_url,
                "ftp_upload_url": ftp_upload_url,
                "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
                "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
                "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
                "ftp_host_ip": local_ip,
                "ftp_ip_candidates": list(ftp_host_info.get("candidates", []) or []),
                "ftp_ip_strategy": str(ftp_host_info.get("strategy", "") or ""),
                "scan_dir_added": scan_dir_added,
                "scan_dirs": scan_dirs,
            }
