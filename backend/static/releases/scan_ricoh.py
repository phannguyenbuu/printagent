# scan_ricoh.py
from __future__ import annotations

import logging
import json
import re
import socket
import subprocess
import time
import datetime
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import requests
from flask import jsonify, request

from agent.modules.ricoh.base import RicohServiceBase, AddressEntry
from agent.services.runtime import default_ftp_root, no_window_subprocess_kwargs
from agent.services.scan_drop import build_drop_folder_metadata
import agent.modules.ricoh.service
from agent.services.api_client import Printer
from agent.web_discovery import _normalize_ipv4
from agent.web_scan_helpers import create_local_ftp_for_address, resolve_target_printer
from agent.web_scan_support import (
    _detect_scan_protocol_from_html,
    _load_scan_protocol_prefs,
    _normalize_scan_protocol,
    _save_scan_protocol_prefs,
)
from agent.web_collect import _stop_job

LOGGER = logging.getLogger(__name__)

# =========================================================================
# PART 1: RICOH ADDRESS BOOK MIXIN METHODS (from ricoh_address_book.py)
# =========================================================================

def _sanitize_ftp_site_name(value: str) -> str:
    text = str(value or "").strip().replace(" ", "_")
    text = re.sub(r"[^A-Za-z0-9_-]", "", text)
    return text[:48]

def _normalize_ipv4_local(value: str) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return ""
    try:
        parts = [int(part) for part in text.split(".")]
    except Exception:
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

def _ipv4_scope_score(value: str) -> int:
    text = _normalize_ipv4_local(value)
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

def _resolve_local_ipv4_candidates() -> list[str]:
    candidates: list[str] = []
    def _push(value: str) -> None:
        text = _normalize_ipv4_local(value)
        if text and text not in candidates:
            candidates.append(text)

    hostname = socket.gethostname()
    try:
        host_info = socket.gethostbyname_ex(hostname)
        for value in host_info[2]:
            _push(str(value or "").strip())
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            _push(str(info[4][0] or "").strip())
    except Exception:
        pass
    for probe_ip in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((probe_ip, 80))
                _push(sock.getsockname()[0])
        except Exception:
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
                if isinstance(item, dict):
                    _push(str(item.get("IPAddress", "") or "").strip())
    except Exception:
        pass
    return sorted(candidates, key=_ipv4_scope_score, reverse=True)

def resolve_ftp_host_ip(cls, printer_ip: str = "") -> dict[str, Any]:
    normalized_printer_ip = _normalize_ipv4_local(printer_ip)
    candidates = _resolve_local_ipv4_candidates()
    if normalized_printer_ip:
        subnet_prefix = ".".join(normalized_printer_ip.split(".")[:3])
        same_subnet = [item for item in candidates if ".".join(item.split(".")[:3]) == subnet_prefix]
        if same_subnet:
            return {"ip": same_subnet[0], "strategy": "same-subnet", "candidates": candidates, "warning": ""}
        if candidates:
            fallback_ip = candidates[0]
            return {
                "ip": fallback_ip,
                "strategy": "fallback-other-local-ip",
                "candidates": candidates,
                "warning": f'No local FTP IP on the same subnet as printer {normalized_printer_ip}. Using {fallback_ip} instead.'
            }
    if candidates:
        return {"ip": candidates[0], "strategy": "best-local-ip", "candidates": candidates, "warning": ""}
    return {"ip": "127.0.0.1", "strategy": "loopback-fallback", "candidates": [], "warning": "No valid local LAN IP found for FTP."}

def read_address_list_with_client(self, session: requests.Session, printer: Printer) -> str:
    targets = ["/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL", "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL"]
    last = ""
    for target in targets:
        try:
            html = self.authenticate_and_get(session, printer, target)
            if html.strip():
                last = html
                if "adrsList" in html or "ReportListArea_TableBody" in html:
                    return html
        except Exception as exc:
            LOGGER.warning("Error reading address list from %s: %s", target, exc)
    return last

def read_address_list(self, printer: Printer) -> str:
    session = self.create_http_client(printer, authenticated=True)
    try:
        return self.read_address_list_with_client(session, printer)
    finally:
        session.close()

def delete_address_entries(self, printer: Printer, registration_numbers: list[str], entry_ids: list[str] | None = None, verify: bool = True) -> dict[str, Any]:
    regs = [str(x or "").strip() for x in registration_numbers if str(x or "").strip()]
    ids = [str(x or "").strip() for x in (entry_ids or []) if str(x or "").strip()]
    if not regs and not ids:
        raise ValueError("registration_numbers is empty")

    session = self.create_http_client(printer)
    try:
        list_url = "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"
        delete_url = "/web/entry/en/address/adrsDeleteEntries.cgi"
        html = self.authenticate_and_get(session, printer, list_url)
        defaults = self._extract_hidden_inputs(html)
        token = defaults.get("wimToken", "") or self._extract_wim_token(html)
        defaults["wimToken"] = token

        form: list[tuple[str, str]] = [(k, str(v)) for k, v in defaults.items()]
        if ids:
            joined = ",".join(ids) + ","
            form.append(("entryIndex", joined))
            form.append(("entryIndexIn", joined))
        else:
            joined = ",".join(regs)
            for key in ("regiNoListIn", "registrationNoListIn", "entryNoListIn", "selectedRegiNoIn", "selectedEntryNoIn", "deleteListIn", "deleteEntriesIn", "entryIndex", "entryIndexIn"):
                form.append((key, joined))
                for reg in regs:
                    form.append((key, reg))
            form.append(("open", ""))

        multipart = [(k, (None, str(v))) for k, v in form]
        resp = session.post(f"http://{printer.ip}{delete_url}", files=multipart, headers={"Referer": f"http://{printer.ip}{list_url}"}, timeout=15)
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
                raise RuntimeError(f"Delete not confirmed: {', '.join(failed)}")

        return {"printer_name": printer.name, "ip": printer.ip, "ok": True, "endpoint": delete_url, "deleted": ids or regs, "deleted_count": len(ids or regs), "http_status": resp.status_code, "timestamp": self._timestamp()}
    finally:
        session.close()

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

def get_address_list_ajax_with_client(self, session: requests.Session, printer: Printer, wim_token: str = "") -> str:
    html_targets = ["/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL", "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL"]
    adrs_wim_token = wim_token
    if not adrs_wim_token:
        for path in html_targets:
            try:
                html_data = self.authenticate_and_get(session, printer, path)
                if html_data.strip():
                    adrs_wim_token = self._extract_hidden_inputs(html_data).get("wimToken", "") or self._extract_wim_token(html_data)
                    if adrs_wim_token:
                        break
            except Exception:
                pass
    ajax_targets = [
        "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
        "/web/entry/en/address/adrsListLoadEntry.cgi?listCountIn=50&getCountIn=1",
        "/web/guest/en/address/adrsListLoadEntry.cgi?listCountIn=200&getCountIn=1",
    ]
    last_raw = ""
    for base_path in ajax_targets:
        sub_path = f"{base_path}&wimToken={adrs_wim_token}" if adrs_wim_token else base_path
        try:
            raw = self.authenticate_and_get(session, printer, sub_path)
            last_raw = raw
            if "[" in raw and "]" in raw and "login.cgi" not in raw:
                entries = self.parse_ajax_address_list(raw)
                if entries:
                    return raw
        except Exception:
            pass
    return last_raw

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
    if not (raw.startswith("[") and raw.endswith("]")):
        first = raw.find("[")
        last = raw.rfind("]")
        if first < 0 or last <= first:
            return entries
        raw = raw[first : last + 1]
    raw_entries = re.findall(r"\[([^\]]+)\]", raw)
    for entry_raw in raw_entries:
        fields = parse_javascript_array_fields(entry_raw)
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
    start_time = time.time()
    session = self.create_http_client(printer, authenticated=True)
    html = ""
    wim_token = ""
    try:
        html_targets = ["/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL", "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL"]
        for path in html_targets:
            try:
                html_data = self.authenticate_and_get(session, printer, path)
                if html_data.strip():
                    html = html_data
                    wim_token = self._extract_hidden_inputs(html_data).get("wimToken", "") or self._extract_wim_token(html_data)
                    if wim_token:
                        break
            except Exception:
                pass
        entries: list[AddressEntry] = []
        try:
            ajax_raw = self.get_address_list_ajax_with_client(session, printer, wim_token=wim_token)
            if ajax_raw:
                entries = self.parse_ajax_address_list(ajax_raw)
                if entries and html:
                    try:
                        html_entries = self.parse_address_list(html)
                        if html_entries and html_entries[0].type == "Summary":
                            entries = [html_entries[0]] + entries
                    except Exception:
                        pass
        except Exception:
            pass
        if not entries and html:
            try:
                entries = self.parse_address_list(html)
            except Exception:
                pass
        return {"printer_name": printer.name, "ip": printer.ip, "address_list": [asdict(item) for item in entries], "timestamp": self._timestamp()}
    finally:
        session.close()

def setup_scan_destination(self, printer: Printer | None, username: str, fields: dict[str, Any] | None = None, ftp_site_name: str = "", ftp_root: str | Path | None = None, ftp_port: int = 2121, ftp_user: str = "", ftp_password: str = "") -> dict[str, Any]:
    safe_username = re.sub(r"[^A-Za-z0-9_-]", "", str(username or "").strip().replace(" ", "_"))[:48] or "scan"
    ftp_name = _sanitize_ftp_site_name(ftp_site_name or f"ftp_{safe_username}")
    ftp_root_path = Path(ftp_root) if ftp_root is not None else default_ftp_root(ftp_name)
    ftp_res = self.share_manager.create_ftp_site(site_name=ftp_name, local_path=ftp_root_path, port=int(ftp_port or 2121), ftp_user=ftp_user, ftp_password=ftp_password)
    if not ftp_res.get("ok"):
        return ftp_res
    ftp_root_path = Path(str(ftp_res.get("physical_path", "") or ftp_root_path))
    ftp_user = str(ftp_res.get("ftp_user", "") or "")
    ftp_password = str(ftp_res.get("ftp_password", "") or "")
    scan_dir_added = False
    scan_dirs: list[str] = []
    if self._config is not None:
        try:
            scan_dir_added, scan_dirs = self._config.ensure_scan_dir(ftp_root_path)
        except Exception:
            pass

    ftp_host_info = resolve_ftp_host_ip(self, str(getattr(printer, "ip", "") or ""))
    local_ip = str(ftp_host_info.get("ip", "") or "127.0.0.1")
    ftp_port_value = int(ftp_res.get("port") or ftp_port or 2121)
    ftp_url = f"ftp://{local_ip}:{ftp_port_value}/"
    drop_folder = build_drop_folder_metadata(ftp_root_path, base_url=ftp_url)
    ftp_upload_url = str(drop_folder.get("upload_url", "") or ftp_url)

    if printer is None or not str(getattr(printer, "ip", "") or "").strip():
        return {"ok": True, "ftp": ftp_res, "printer": None, "printer_setup_ok": False, "ftp_url": ftp_url, "ftp_upload_url": ftp_upload_url, "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""), "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""), "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""), "ftp_host_ip": local_ip, "ftp_ip_candidates": list(ftp_host_info.get("candidates", [])), "ftp_ip_strategy": str(ftp_host_info.get("strategy", "")), "warning": str(ftp_host_info.get("warning", "")), "scan_dir_added": scan_dir_added, "scan_dirs": scan_dirs}

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
        wizard_res = self.create_address_user_wizard(printer=printer, name=f"Scan to {username}", folder=ftp_upload_url, fields=merged_fields)
        return {"ok": True, "ftp": ftp_res, "printer": wizard_res, "printer_setup_ok": True, "ftp_url": ftp_url, "ftp_upload_url": ftp_upload_url, "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""), "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""), "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""), "ftp_host_ip": local_ip, "ftp_ip_candidates": list(ftp_host_info.get("candidates", [])), "ftp_ip_strategy": str(ftp_host_info.get("strategy", "")), "warning": str(ftp_host_info.get("warning", "")), "scan_dir_added": scan_dir_added, "scan_dirs": scan_dirs}
    except Exception as e:
        LOGGER.exception("Auto-scan setup failed: %s", e)
        return {"ok": True, "warning": f"FTP created, printer setup failed: {e}", "ftp": ftp_res, "printer_setup_ok": False, "printer_error": str(e), "ftp_url": ftp_url, "ftp_upload_url": ftp_upload_url, "ftp_upload_path": str(drop_folder.get("drop_folder_path", "") or ""), "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""), "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""), "ftp_host_ip": local_ip, "ftp_ip_candidates": list(ftp_host_info.get("candidates", [])), "ftp_ip_strategy": str(ftp_host_info.get("strategy", "")), "scan_dir_added": scan_dir_added, "scan_dirs": scan_dirs}


# =========================================================================
# PART 2: RICOH SETUP WIZARD MIXIN METHODS (from ricoh_wizard.py)
# =========================================================================

def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())

def _normalize_registration_no(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if not digits:
        return ""
    return digits[-5:].zfill(5)

def _field_text(fields: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        if key not in fields:
            continue
        value = str(fields.get(key, "") or "").strip()
        if value:
            return value
    return default

def _multipart(items: list[tuple[str, str]]) -> list[tuple[str, tuple[None, str]]]:
    return [(key, (None, str(value))) for key, value in items]

def _post_wizard_step(self, session: requests.Session, printer: Printer, items: list[tuple[str, str]], referer: str = "") -> str:
    url = f"http://{printer.ip}/web/entry/en/address/adrsSetUserWizard.cgi"
    headers = {"Referer": referer or f"http://{printer.ip}/web/entry/en/address/adrsGetUserWizard.cgi"}
    resp = session.post(url, files=_multipart(items), headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.text

def _open_wizard(self, session: requests.Session, printer: Printer) -> str:
    url = f"http://{printer.ip}/web/entry/en/address/adrsGetUserWizard.cgi"
    attempts = [
        ("GET", None),
        ("POST", _multipart([("mode", "ADDUSER"), ("outputSpecifyModeIn", "DEFAULT")])),
    ]
    last_error: Exception | None = None
    for method, payload in attempts:
        try:
            if method == "GET":
                resp = session.get(url, headers={"Referer": f"http://{printer.ip}/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"}, timeout=20)
            else:
                resp = session.post(url, files=payload, headers={"Referer": f"http://{printer.ip}/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"}, timeout=20)
            resp.raise_for_status()
            if resp.text.strip():
                return resp.text
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    return ""

def _fetch_wim_token(self, session: requests.Session, printer: Printer) -> tuple[str, str]:
    candidates: list[tuple[str, str]] = []
    try:
        html = _open_wizard(self, session, printer)
        if html.strip():
            candidates.append(("wizard", html))
    except Exception:
        pass
    try:
        html = self.read_address_list_with_client(session, printer)
        if html.strip():
            candidates.append(("address_list", html))
    except Exception:
        pass
    for source, html in candidates:
        token = self._extract_wim_token(html) or self._extract_hidden_inputs(html).get("wimToken", "")
        if token:
            return token, source
    return "", ""

def _parse_folder_destination(folder: str) -> tuple[str, int, str]:
    raw = str(folder or "").strip()
    if not raw:
        return "", 21, "/"
    parsed = urlparse(raw if "://" in raw else f"ftp://{raw}")
    host = parsed.hostname or parsed.netloc or ""
    port = int(parsed.port or 21)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return host, port, path

def _next_registration_no(self, session: requests.Session, printer: Printer) -> str:
    highest = 0
    try:
        raw = self.get_address_list_ajax_with_client(session, printer)
        entries = self.parse_ajax_address_list(raw)
        for entry in entries:
            try:
                current = int(_normalize_registration_no(entry.registration_no) or "0")
            except Exception:
                current = 0
            highest = max(highest, current)
    except Exception:
        pass
    if highest <= 0:
        try:
            raw = self.read_address_list_with_client(session, printer)
            entries = self.parse_address_list(raw)
            for entry in entries:
                try:
                    current = int(_normalize_registration_no(entry.registration_no) or "0")
                except Exception:
                    current = 0
                highest = max(highest, current)
        except Exception:
            pass
    hint = int(self._address_index_hint_by_ip.get(printer.ip, 0))
    highest = max(highest, hint)
    return f"{highest + 1:05d}"

def _extract_created_registration_no(html: str) -> str:
    patterns = [r'span_entryIndexIn">(\d{1,10})<', r'name="entryIndexIn"\s+value="(\d{1,10})"', r'entryIndexIn[Adjusted]*[">=]\s*(\d{1,10})']
    for pattern in patterns:
        match = re.search(pattern, html, re.I | re.S)
        if match:
            return match.group(1).zfill(5)[-5:]
    return ""

def _verify_address_entry(self, session: requests.Session, printer: Printer, registration_no: str, name: str, folder: str) -> bool:
    candidates = []
    try:
        raw = self.get_address_list_ajax_with_client(session, printer)
        candidates.extend(self.parse_ajax_address_list(raw))
    except Exception:
        pass
    try:
        raw = self.read_address_list_with_client(session, printer)
        candidates.extend(self.parse_address_list(raw))
    except Exception:
        pass
    seen = set()
    norm_name = _clean_text(name).lower()
    norm_folder = _clean_text(folder).lower()
    target_reg = _normalize_registration_no(registration_no)
    
    # Debug logging
    candidate_list = [(c.registration_no, c.name, c.folder) for c in candidates]
    LOGGER.info("[RicohWizard] Verifying address entry: registration_no=%s name=%s folder=%s", registration_no, name, folder)
    LOGGER.info("[RicohWizard] Total candidates read from copier address list: %d. Candidates: %s", len(candidates), candidate_list)
    
    for entry in candidates:
        reg = _normalize_registration_no(entry.registration_no)
        key = (reg, _clean_text(entry.name).lower(), _clean_text(entry.folder).lower())
        if key in seen:
            continue
        seen.add(key)
        if target_reg and reg == target_reg:
            return True
        if norm_name and _clean_text(entry.name).lower() == norm_name:
            if not norm_folder or norm_folder == _clean_text(entry.folder).lower():
                return True
    return False

def create_address_user_wizard(self, printer: Printer, name: str, email: str = "", folder: str = "", user_code: str = "", fields: dict[str, Any] | None = None, desired_registration_no: str | None = None, allow_auto_update: bool = True) -> dict[str, Any]:
    session = self.create_http_client_auth_form_only(printer)
    try:
        wim_token, _ = _fetch_wim_token(self, session, printer)
        if not wim_token:
            raise RuntimeError("Ricoh wizard token not found")
        reg_no = _normalize_registration_no(desired_registration_no or "") or _next_registration_no(self, session, printer)
        entry_disp = _clean_text(_field_text(fields or {}, "entryDisplayNameIn", "entryDisplayName", default=name)) or _clean_text(name)
        tag_val = _field_text(fields or {}, "entryTagInfoIn", default="1")
        base_items = [("mode", "ADDUSER"), ("step", "BASE"), ("wimToken", wim_token), ("entryIndexIn", reg_no), ("entryNameIn", _clean_text(name)), ("entryDisplayNameIn", entry_disp)]
        for _ in range(4):
            base_items.append(("entryTagInfoIn", tag_val))
        if fields and str(fields.get("entryTypeIn", "")).strip():
            base_items.append(("entryTypeIn", str(fields.get("entryTypeIn")).strip()))

        base_html = _post_wizard_step(self, session, printer, base_items)
        wim_token = self._extract_wim_token(base_html) or wim_token

        mail_items = [("mode", "ADDUSER"), ("step", "MAIL"), ("wimToken", wim_token), ("mailAddressIn", _clean_text(email))]
        mail_html = _post_wizard_step(self, session, printer, mail_items)
        wim_token = self._extract_wim_token(mail_html) or wim_token

        srv_name, port, path = _parse_folder_destination(folder)
        auth_user = _field_text(fields or {}, "folderAuthUserNameIn", "folderAuthUserName", default="")
        pwd = _field_text(fields or {}, "folderPasswordIn", "wk_folderPasswordIn", "folderPassword", default="") or _field_text(fields or {}, "wk_folderPasswordConfirmIn", "folderPasswordConfirmIn", "folderPasswordConfirm", default="")
        
        # Dynamically resolve FTP credentials if they are missing
        if not auth_user and not pwd:
            try:
                share_manager = getattr(self, "share_manager", None)
                if share_manager is not None and hasattr(share_manager, "list_ftp_sites"):
                    for site in share_manager.list_ftp_sites():
                        if int(site.get("port", 0) or 0) == port:
                            auth_user = str(site.get("ftp_user", "") or "")
                            pwd = str(site.get("ftp_password", "") or "")
                            LOGGER.info("[RicohWizard] Dynamically resolved FTP credentials for port %d: user=%s", port, auth_user)
                            break
            except Exception as lookup_exc:
                LOGGER.warning("[RicohWizard] Dynamic FTP credentials lookup failed: %s", lookup_exc)

        folder_items = [
            ("mode", "ADDUSER"), ("step", "FOLDER"), ("wimToken", wim_token), ("folderProtocolIn", "FTP_O"), ("folderPortNoIn", str(port)),
            ("folderServerNameIn", srv_name), ("folderPathNameIn", path), ("folderAuthUserNameIn", auth_user),
            ("wk_folderPasswordIn", pwd), ("folderPasswordIn", pwd), ("wk_folderPasswordConfirmIn", pwd), ("folderPasswordConfirmIn", pwd)
        ]
        folder_html = _post_wizard_step(self, session, printer, folder_items)
        wim_token = self._extract_wim_token(folder_html) or wim_token

        confirm_items = [("wimToken", wim_token), ("stepListIn", "BASE"), ("stepListIn", "MAIL"), ("stepListIn", "FOLDER"), ("mode", "ADDUSER"), ("step", "CONFIRM")]
        confirm_html = _post_wizard_step(self, session, printer, confirm_items)
        created_reg = _extract_created_registration_no(confirm_html) or reg_no

        LOGGER.info("[RicohWizard] confirm_html length: %d, extracted registration no: %s (target reg: %s)", len(confirm_html), created_reg, reg_no)
        time.sleep(0.25)
        if not _verify_address_entry(self, session, printer, created_reg, name, folder):
            # Print response snippet to logs to help locate field issues
            LOGGER.warning("[RicohWizard] Verification failed. Confirm HTML snippet: %s", confirm_html[:1500].replace('\r', '').replace('\n', ' '))
            raise RuntimeError(f"Ricoh address entry not verified: registration_no={created_reg} name={name}")

        if created_reg.isdigit():
            self._address_index_hint_by_ip[printer.ip] = max(int(self._address_index_hint_by_ip.get(printer.ip, 0)), int(created_reg))

        return {
            "printer_name": printer.name, "ip": printer.ip, "ok": True, "endpoint": "/web/entry/en/address/adrsSetUserWizard.cgi",
            "created_registration_no": created_reg, "entry_name": _clean_text(name), "entry_display_name": entry_disp,
            "email": _clean_text(email), "folder": folder, "folder_server_name": srv_name, "folder_port": port, "folder_path": path,
            "http_status": 200, "verified": True, "timestamp": self._timestamp()
        }
    finally:
        session.close()

def modify_address_user_wizard(self, printer: Printer, registration_no: str, name: str = "", email: str = "", folder: str = "", user_code: str = "", fields: dict[str, Any] | None = None) -> dict[str, Any]:
    self.delete_address_entries(printer, [registration_no], verify=False)
    return create_address_user_wizard(self, printer, name=name, email=email, folder=folder, user_code=user_code, fields=fields, desired_registration_no=registration_no, allow_auto_update=False)


# =========================================================================
# PART 3: APPLICATION PATCHING TRIGGER
# =========================================================================

# Patch methods onto RicohAddressBookMixin (which is defined in service.py)
mixin_book = agent.modules.ricoh.service.RicohAddressBookMixin
setattr(mixin_book, "_sanitize_ftp_site_name", staticmethod(_sanitize_ftp_site_name))
setattr(mixin_book, "_normalize_ipv4", staticmethod(_normalize_ipv4_local))
setattr(mixin_book, "_ipv4_scope_score", staticmethod(_ipv4_scope_score))
setattr(mixin_book, "_resolve_local_ipv4_candidates", staticmethod(_resolve_local_ipv4_candidates))
setattr(mixin_book, "resolve_ftp_host_ip", classmethod(resolve_ftp_host_ip))
setattr(mixin_book, "read_address_list_with_client", read_address_list_with_client)
setattr(mixin_book, "read_address_list", read_address_list)
setattr(mixin_book, "delete_address_entries", delete_address_entries)
setattr(mixin_book, "parse_address_list", parse_address_list)
setattr(mixin_book, "get_address_list_ajax_with_client", get_address_list_ajax_with_client)
setattr(mixin_book, "parse_ajax_address_list", parse_ajax_address_list)
setattr(mixin_book, "process_address_list", process_address_list)
setattr(mixin_book, "setup_scan_destination", setup_scan_destination)

# Patch methods onto RicohAddressWizardMixin (which is defined in service.py)
mixin_wizard = agent.modules.ricoh.service.RicohAddressWizardMixin
setattr(mixin_wizard, "_clean_text", staticmethod(_clean_text))
setattr(mixin_wizard, "_normalize_registration_no", staticmethod(_normalize_registration_no))
setattr(mixin_wizard, "_field_text", staticmethod(_field_text))
setattr(mixin_wizard, "_multipart", staticmethod(_multipart))
setattr(mixin_wizard, "_post_wizard_step", _post_wizard_step)
setattr(mixin_wizard, "_open_wizard", _open_wizard)
setattr(mixin_wizard, "_fetch_wim_token", _fetch_wim_token)
setattr(mixin_wizard, "_parse_folder_destination", staticmethod(_parse_folder_destination))
setattr(mixin_wizard, "_next_registration_no", _next_registration_no)
setattr(mixin_wizard, "_extract_created_registration_no", staticmethod(_extract_created_registration_no))
setattr(mixin_wizard, "_verify_address_entry", _verify_address_entry)
setattr(mixin_wizard, "create_address_user_wizard", create_address_user_wizard)
setattr(mixin_wizard, "modify_address_user_wizard", modify_address_user_wizard)

LOGGER.info("scan_ricoh.py loaded. address book and wizard mixins successfully patched.")


# =========================================================================
# PART 4: LOCAL WEB ROUTE REGISTRATION (from ricoh_web_scan.py)
# =========================================================================

def register_scan_routes(app):
    config = app.config["APP_CONFIG"]
    api_client = app.config["API_CLIENT"]
    ricoh_service = app.config["RICOH_SERVICE"]

    @app.get("/api/scan/address-list")
    def api_scan_address_list() -> Any:
        ip = str(request.args.get("ip", "")).strip()
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        mode = str(request.args.get("mode", "")).strip().lower()
        trace_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        
        if mode == "adrslistall":
            try:
                effective_user = "admin"
                effective_password = "admin"
                target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
                target.user = effective_user
                target.password = effective_password
                session = ricoh_service.create_http_client_auth_form_only(target)
                html = ricoh_service.authenticate_and_get(session, target, "/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL")
                if ("Address List" not in html and "adrsList" not in html) or "login.cgi" in html:
                    html = ricoh_service.authenticate_and_get(session, target, "/web/guest/en/address/adrsList.cgi?modeIn=LIST_ALL")
                entries = ricoh_service.parse_address_list(html)
                
                wim_token = ricoh_service._extract_hidden_inputs(html).get("wimToken", "") or ricoh_service._extract_wim_token(html)
                ajax_raw = ""
                ajax_entries = []
                try:
                    ajax_raw = ricoh_service.get_address_list_ajax_with_client(session, target, wim_token=wim_token)
                    ajax_entries = ricoh_service.parse_ajax_address_list(ajax_raw)
                    if ajax_entries:
                        summary = entries[0] if entries else None
                        merged_by_reg: dict[str, Any] = {}
                        merged_order: list[str] = []

                        def _score(item: Any) -> int:
                            score = 0
                            for field in ["name", "email_address", "folder", "user_code"]:
                                if str(getattr(item, field, "") or "").strip() not in {"", "-", "---"}:
                                    score += 1
                            return score

                        for source in [entries[1:] if len(entries) > 1 else [], ajax_entries]:
                            for item in source:
                                reg = str(getattr(item, "registration_no", "") or "").strip()
                                name_key = str(getattr(item, "name", "") or "").strip().lower()
                                key = f"reg::{reg}::name::{name_key}" if reg and reg != "-" else f"name::{name_key}"
                                if key not in merged_by_reg:
                                    merged_by_reg[key] = item
                                    merged_order.append(key)
                                else:
                                    if _score(item) >= _score(merged_by_reg[key]):
                                        merged_by_reg[key] = item

                        merged_entries = [merged_by_reg[key] for key in merged_order]
                        entries = ([summary] if summary else []) + merged_entries
                except Exception:
                    pass
                
                if max(0, len(entries) - 1) == 0:
                    try:
                        fallback_payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                        return jsonify({"ok": True, "payload": fallback_payload})
                    except Exception:
                        pass
                
                payload = {
                    "printer_name": target.name,
                    "ip": target.ip,
                    "html": html,
                    "easysecurity_html": "",
                    "address_list": [
                        {
                            "type": item.type,
                            "registration_no": item.registration_no,
                            "name": item.name,
                            "user_code": item.user_code,
                            "date_last_used": item.date_last_used,
                            "email_address": item.email_address,
                            "folder": item.folder,
                            "entry_id": getattr(item, "entry_id", "") or "",
                        }
                        for item in entries
                    ],
                    "debug": {
                        "trace_id": trace_id,
                        "mode": "adrsListAll",
                        "html_len": len(html),
                        "entries": len(entries),
                        "ajax_len": len(ajax_raw),
                        "ajax_entries": len(ajax_entries),
                    },
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
                return jsonify({"ok": True, "payload": payload})
            except Exception as exc:
                LOGGER.exception("Scan address list adrsListAll failed: trace_id=%s ip=%s", trace_id, ip)
                return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            payload = ricoh_service.process_address_list(target, trace_id=trace_id)
            return jsonify({"ok": True, "payload": payload})
        except Exception as exc:
            if "500 server error" in str(exc).lower() and "login.cgi" in str(exc).lower():
                try:
                    target = resolve_target_printer(config, api_client, ip=ip, user="", password="")
                    target.user = ""
                    target.password = ""
                    payload = ricoh_service.process_address_list(target, trace_id=trace_id)
                    return jsonify({"ok": True, "payload": payload})
                except Exception as fallback_exc:
                    return jsonify({"ok": False, "error": str(fallback_exc), "trace_id": trace_id, "primary_error": str(exc)}), 500
            LOGGER.exception("Scan address list failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-create")
    def api_scan_address_create() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-create-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip or not name:
            return jsonify({"ok": False, "error": "Missing ip or name"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            ftp_payload = create_local_ftp_for_address(config, ricoh_service, name, printer_ip=ip)
            if not bool(ftp_payload.get("ok", False)):
                return jsonify({"ok": False, "error": "FTP setup failed before address creation", "trace_id": trace_id, "ftp": ftp_payload}), 500
            folder_final = str(ftp_payload.get("upload_url", "") or ftp_payload.get("ftp_url", "")).strip() or folder
            
            merged_fields = {"entryTypeIn": "1"}
            if isinstance(fields, dict):
                merged_fields.update(fields)
            payload = ricoh_service.create_address_user_wizard(target, name=name, email=email, folder=folder_final, user_code=user_code, fields=merged_fields)
            return jsonify({"ok": True, "payload": payload, "trace_id": trace_id, "protocol": "FTP", "folder_used": folder_final, "ftp": ftp_payload})
        except Exception as exc:
            LOGGER.exception("Scan address create failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-delete")
    def api_scan_address_delete() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-delete-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        confirm = bool(body.get("confirm", False))
        if not ip or (not registration_no and not entry_id):
            return jsonify({"ok": False, "error": "Missing parameters"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            payload = ricoh_service.delete_address_entries(target, [registration_no], entry_ids=[entry_id] if entry_id else None, verify=not confirm)
            return jsonify({"ok": True, "payload": payload, "trace_id": trace_id})
        except Exception as exc:
            LOGGER.exception("Scan address delete failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.post("/api/scan/address-modify")
    def api_scan_address_modify() -> Any:
        body = request.get_json(silent=True) or {}
        trace_id = f"scan-modify-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        ip = str(body.get("ip", "")).strip()
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        registration_no = str(body.get("registration_no", "")).strip()
        entry_id = str(body.get("entry_id", "")).strip()
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip()
        folder = str(body.get("folder", "")).strip()
        user_code = str(body.get("user_code", "")).strip()
        fields = body.get("fields", {})
        if not ip or not registration_no:
            return jsonify({"ok": False, "error": "Missing parameters"}), 400
        try:
            effective_user = user or "admin"
            effective_password = password or "admin"
            target = resolve_target_printer(config, api_client, ip=ip, user=effective_user, password=effective_password)
            target.user = effective_user
            target.password = effective_password
            if entry_id:
                ricoh_service.delete_address_entries(target, [registration_no], entry_ids=[entry_id], verify=False)
            else:
                ricoh_service.delete_address_entries(target, [registration_no], verify=False)
            create_payload = ricoh_service.create_address_user_wizard(target, name=name, email=email, folder=folder, user_code=user_code, fields=fields if isinstance(fields, dict) else None, desired_registration_no=registration_no, allow_auto_update=False)
            return jsonify({"ok": True, "payload": create_payload, "trace_id": trace_id, "recreated": True})
        except Exception as exc:
            LOGGER.exception("Scan address modify failed: trace_id=%s ip=%s", trace_id, ip)
            return jsonify({"ok": False, "error": str(exc), "trace_id": trace_id}), 500

    @app.get("/api/scan/protocol")
    def api_scan_protocol_get() -> Any:
        ip = _normalize_ipv4(str(request.args.get("ip", "")).strip())
        user = str(request.args.get("user", "")).strip()
        password = str(request.args.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        prefs = _load_scan_protocol_prefs()
        saved = _normalize_scan_protocol(prefs.get(ip, ""))
        detected = ""
        try:
            target = resolve_target_printer(config, api_client, ip=ip, user=user, password=password)
            html = ricoh_service.read_device_info(target)
            detected = _normalize_scan_protocol(_detect_scan_protocol_from_html(html))
        except Exception as exc:
            LOGGER.warning("Scan protocol detect failed: ip=%s error=%s", ip, exc)
        protocol = detected or saved or "FTP"
        return jsonify({"ok": True, "ip": ip, "protocol": protocol, "detected": detected, "saved": saved, "options": ["FTP", "SMBv2/3", "SMBv1"]})

    @app.post("/api/scan/protocol")
    def api_scan_protocol_set() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        protocol = _normalize_scan_protocol(str(body.get("protocol", "")).strip())
        if not ip or not protocol:
            return jsonify({"ok": False, "error": "Missing parameters"}), 400
        prefs = _load_scan_protocol_prefs()
        prefs[ip] = protocol
        _save_scan_protocol_prefs(prefs)
        return jsonify({"ok": True, "ip": ip, "protocol": protocol})

    @app.post("/api/scan/isolate-session")
    def api_scan_isolate_session() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        user = str(body.get("user", "")).strip()
        password = str(body.get("password", "")).strip()
        if not ip:
            return jsonify({"ok": False, "error": "Missing ip"}), 400
        bridge = app.config["POLLING_BRIDGE"]
        counter_jobs = app.config["LOG_JOBS"]["counter"]
        status_jobs = app.config["LOG_JOBS"]["status"]
        counter_stopped, counter_msg = _stop_job(counter_jobs, ip)
        status_stopped, status_msg = _stop_job(status_jobs, ip)
        bridge.stop()
        target = resolve_target_printer(config, api_client, ip=ip, user=user, password=password)
        try:
            ricoh_service.reset_web_session(target)
            logout_ok = True
            logout_msg = "session reset requested"
        except Exception as exc:
            logout_ok = False
            logout_msg = str(exc)
        return jsonify({
            "ok": True, "ip": ip, "polling_running": bool(bridge.status().get("running", False)),
            "counter_stop": {"ok": counter_stopped, "message": counter_msg},
            "status_stop": {"ok": status_stopped, "message": status_msg},
            "logout": {"ok": logout_ok, "message": logout_msg}
        })

    @app.post("/api/scan/release-session")
    def api_scan_release_session() -> Any:
        bridge = app.config["POLLING_BRIDGE"]
        status = bridge.status()
        if bool(status.get("running", False)):
            return jsonify({"ok": True, "polling_start_ok": True, "message": "Polling already running", "status": status})
        ok, message = bridge.start()
        return jsonify({"ok": True, "polling_start_ok": ok, "message": message, "status": bridge.status()})

    @app.post("/api/shares/create")
    def api_shares_create() -> Any:
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        if not username:
            return jsonify({"ok": False, "error": "Missing username"}), 400
        res = ricoh_service.share_manager.setup_auto_share(username)
        return jsonify(res)

    @app.post("/api/scan/setup-auto")
    def api_scan_setup_auto() -> Any:
        body = request.get_json(silent=True) or {}
        ip = _normalize_ipv4(str(body.get("ip", "")).strip())
        username = str(body.get("username", "")).strip()
        fields = body.get("fields", {})
        if not ip or not username:
            return jsonify({"ok": False, "error": "Missing ip or username"}), 400
        target = resolve_target_printer(config, api_client, ip=ip)
        res = ricoh_service.setup_scan_destination(target, username, fields=fields)
        return jsonify(res)

    LOGGER.info("scan_ricoh.py registered scan routes on Flask application.")


# =========================================================================
# PART 5: STANDALONE EXECUTION RUNNER (from scan_ricoh.py)
# =========================================================================

if __name__ == "__main__":
    import argparse
    import sys
    
    # Set up basic logging for standalone execution
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Add project root directory to sys.path to allow importing agent modules
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "agent").is_dir():
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
    elif (script_dir.parent / "agent").is_dir():
        if str(script_dir.parent) not in sys.path:
            sys.path.insert(0, str(script_dir.parent))
    elif (script_dir.parent.parent / "agent").is_dir():
        if str(script_dir.parent.parent) not in sys.path:
            sys.path.insert(0, str(script_dir.parent.parent))

    try:
        from agent.config import AppConfig
        from agent.services.api_client import APIClient, Printer
        from agent.modules.ricoh.service import RicohService
    except ImportError as e:
        LOGGER.error("Failed to import agent modules. Make sure you are running from the printagent_v2 project directory.")
        LOGGER.error("Error: %s", e)
        sys.exit(1)

    # Load local configuration (settings database/env)
    try:
        config = AppConfig.load()
        default_lead = config.get_string("polling.lead") or "default"
        default_token = config.get_string("polling.token") or "change-me"
        default_url = config.get_string("polling.url") or "https://agentapi.quanlymay.com"
        default_agent_uid = config.get_string("polling.agent_uid") or "standalone-agent"
        default_lan_uid = config.get_string("polling.lan_uid") or ""
    except Exception as e:
        LOGGER.warning("Could not load AppConfig, using defaults: %s", e)
        default_lead = "default"
        default_token = "change-me"
        default_url = "https://agentapi.quanlymay.com"
        default_agent_uid = "standalone-agent"
        default_lan_uid = ""

    parser = argparse.ArgumentParser(description="Standalone Ricoh address book sync tool")
    parser.add_argument("--ip", required=True, help="IP address of the Ricoh photocopier")
    parser.add_argument("--user", help="Web Admin username on the copier")
    parser.add_argument("--password", help="Web Admin password on the copier")
    parser.add_argument("--post", action="store_true", help="Post results to the central dashboard /lan-sites backend")
    parser.add_argument("--url", default=default_url, help="Backend central server base URL")
    parser.add_argument("--lead", default=default_lead, help="Lead name for database filtering/auth")
    parser.add_argument("--token", default=default_token, help="Authorization API token for backend")
    parser.add_argument("--agent-uid", default=default_agent_uid, help="Agent UID to use in polling request")
    parser.add_argument("--lan-uid", default=default_lan_uid, help="LAN UID to use in polling request")
    parser.add_argument("--lan-name", help="Optional LAN name if creating a new site")

    args = parser.parse_args()

    ip = args.ip
    user = args.user
    password = args.password
    post = args.post
    url = args.url
    lead = args.lead
    token = args.token
    agent_uid = args.agent_uid
    lan_uid = args.lan_uid
    lan_name = args.lan_name

    # Normalize url
    base_url = url.rstrip("/")
    if base_url.endswith("/api"):
        api_url = base_url
        base_url = base_url[:-4]
    else:
        api_url = f"{base_url}/api"

    # Temporary configuration override for backend API calls
    config.set_value("api_url", api_url)
    config.set_value("user_token", token)
    api_client = APIClient(config)

    # 1. Fetch devices list from server to auto-detect credentials if not provided
    printer_name = ""
    mac_address = ""
    if not user or not password or not lan_uid or not mac_address:
        LOGGER.info("Fetching registered devices from backend to auto-detect credentials/metadata for IP %s...", ip)
        try:
            printers = api_client.get_printers()
            matched = next((p for p in printers if p.ip == ip), None)
            if matched:
                LOGGER.info("Found matching device on backend: name=%s", matched.name)
                if not user:
                    user = matched.user
                    LOGGER.info("Auto-detected username: %s", user)
                if not password:
                    password = matched.password
                    LOGGER.info("Auto-detected password: %s", "***" if password else "<empty>")
                if not lan_uid:
                    lan_uid = matched.lan_uid
                    LOGGER.info("Auto-detected LAN UID: %s", lan_uid)
                mac_address = matched.mac_address
                printer_name = matched.name
        except Exception as e:
            LOGGER.warning("Could not retrieve devices list from server: %s", e)

    # Fallbacks for credentials
    if not user:
        user = "admin"
    if password is None:
        password = ""

    # Build the printer object
    printer = Printer(
        id=0,
        name=printer_name or f"Ricoh Copier {ip}",
        ip=ip,
        user=user,
        password=password,
        printer_type="ricoh",
        mac_address=mac_address or ""
    )

    service = RicohService(api_client, config=config)

    # 2. Try to fetch MAC address directly from the copier if still unknown
    if not printer.mac_address:
        LOGGER.info("Probing copier directly to extract MAC address...")
        try:
            resolved_mac = service.fetch_mac_address_direct(ip)
            if resolved_mac:
                printer.mac_address = resolved_mac
                LOGGER.info("Resolved MAC address directly: %s", resolved_mac)
        except Exception as e:
            LOGGER.warning("Could not fetch MAC address directly from device: %s", e)

    # 3. Retrieve address list
    LOGGER.info("Connecting to copier %s and extracting Address Book...", ip)
    try:
        result = service.process_address_list(printer)
        address_list = result.get("address_list") or []
        LOGGER.info("Address book extraction successful!")
    except Exception as e:
        LOGGER.error("Failed to extract address book: %s", e)
        sys.exit(1)

    # Display the results
    print("\n" + "="*90)
    print(f" ADDRESS BOOK Sync Report - {ip} ({printer.name})")
    print(f" MAC Address: {printer.mac_address or 'Unknown'}")
    print("="*90)
    print(f"{'Reg No':<8} | {'Type':<8} | {'Name':<25} | {'Email':<30} | {'User Code':<10}")
    print("-"*90)
    for entry in address_list:
        reg = entry.get("registration_no") or "-"
        etype = entry.get("type") or "-"
        name = entry.get("name") or "-"
        email = entry.get("email_address") or "-"
        ucode = entry.get("user_code") or "-"
        print(f"{reg:<8} | {etype:<8} | {name[:25]:<25} | {email[:30]:<30} | {ucode:<10}")
    print("="*90 + "\n")

    # 4. Post to backend /api/polling if requested
    if post:
        # Resolve network variables if not present for a clean polling registration
        local_ip = "127.0.0.1"
        gateway_ip = ""
        gateway_mac = ""
        subnet_cidr = ""
        try:
            from agent.services.polling_bridge import PollingBridge
            local_ip = PollingBridge._resolve_local_ip() or "127.0.0.1"
            gateway_ip = PollingBridge._resolve_default_gateway() if hasattr(PollingBridge, "_resolve_default_gateway") else ""
            gateway_mac = PollingBridge._resolve_gateway_mac(gateway_ip) if (gateway_ip and hasattr(PollingBridge, "_resolve_gateway_mac")) else ""
            subnet_cidr = PollingBridge._subnet_hint(local_ip)
            
            if not lan_uid:
                if gateway_mac and gateway_ip:
                    lan_uid = PollingBridge._compose_lan_uid(lead, gateway_mac, gateway_ip)
                else:
                    lan_uid = f"{lead}_standalone_lan"
        except Exception as e:
            LOGGER.debug("Network auto-detection failed: %s", e)
            if not lan_uid:
                lan_uid = f"{lead}_standalone_lan"

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "lead": lead,
            "agent_uid": agent_uid,
            "lan_uid": lan_uid,
            "lan_name": lan_name or f"Standalone LAN Site ({lead})",
            "printer_name": printer.name,
            "ip": printer.ip,
            "mac_id": printer.mac_address,
            "mac_address": printer.mac_address,
            "auth_user": printer.user,
            "auth_password": printer.password,
            "address_book_sync": {
                "status": "success",
                "timestamp": timestamp,
                "address_list": address_list
            },
            "timestamp": timestamp,
            "collector_ok": True,
            "skip_data_update": False,
            "local_ip": local_ip,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "subnet_cidr": subnet_cidr,
            "app_version": "standalone",
            "run_mode": "standalone"
        }

        headers = {
            "Content-Type": "application/json",
            "X-Lead-Token": token,
            "X-API-Token": token
        }
        polling_url = f"{base_url}/api/polling"
        LOGGER.info("Posting polling payload to backend: %s ...", polling_url)
        try:
            resp = requests.post(polling_url, json=payload, headers=headers, timeout=25)
            resp.raise_for_status()
            LOGGER.info("Backend post successful! HTTP Status: %d", resp.status_code)
            try:
                LOGGER.info("Response: %s", resp.json())
            except Exception:
                LOGGER.info("Response: %s", resp.text)
        except Exception as e:
            LOGGER.error("Failed to post payload to backend: %s", e)
            sys.exit(1)
