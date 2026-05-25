from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import requests

from agent.modules.ricoh.base import RicohServiceBase
from agent.services.api_client import Printer

LOGGER = logging.getLogger(__name__)


class RicohAddressWizardMixin(RicohServiceBase):
    _WIZARD_GET = "/web/entry/en/address/adrsGetUserWizard.cgi"
    _WIZARD_SET = "/web/entry/en/address/adrsSetUserWizard.cgi"

    @staticmethod
    def _clean_text(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip())

    @staticmethod
    def _normalize_registration_no(value: str) -> str:
        digits = re.sub(r"\D", "", str(value or ""))
        if not digits:
            return ""
        return digits[-5:].zfill(5)

    @staticmethod
    def _field_text(fields: dict[str, Any], *keys: str, default: str = "") -> str:
        for key in keys:
            if key not in fields:
                continue
            value = str(fields.get(key, "") or "").strip()
            if value:
                return value
        return default

    @staticmethod
    def _multipart(items: list[tuple[str, str]]) -> list[tuple[str, tuple[None, str]]]:
        return [(key, (None, str(value))) for key, value in items]

    def _post_wizard_step(
        self,
        session: requests.Session,
        printer: Printer,
        items: list[tuple[str, str]],
        referer: str = "",
    ) -> str:
        url = f"http://{printer.ip}{self._WIZARD_SET}"
        headers = {"Referer": referer or f"http://{printer.ip}{self._WIZARD_GET}"}
        logged_items = [(k, "[FILTERED]" if "Password" in k or "pw" in k.lower() else v) for k, v in items]
        LOGGER.info("[RicohWizard] Posting step to wizard: URL=%s, items=%s", url, logged_items)
        try:
            resp = session.post(url, files=self._multipart(items), headers=headers, timeout=20)
            resp.raise_for_status()
            LOGGER.info("[RicohWizard] Step post success. HTTP Status: %d, response length: %d", resp.status_code, len(resp.text or ""))
            return resp.text
        except Exception as exc:
            LOGGER.error("[RicohWizard] Step post failed for %s: %s", printer.ip, exc)
            raise

    def _open_wizard(self, session: requests.Session, printer: Printer) -> str:
        LOGGER.info("[RicohWizard] Starting _open_wizard for IP: %s", printer.ip)
        url = f"http://{printer.ip}{self._WIZARD_GET}"
        last_error: Exception | None = None
        attempts = [
            ("GET", None),
            (
                "POST",
                self._multipart(
                    [
                        ("mode", "ADDUSER"),
                        ("outputSpecifyModeIn", "DEFAULT"),
                    ]
                ),
            ),
        ]
        for method, payload in attempts:
            LOGGER.info("[RicohWizard] Attempting wizard open with method: %s, URL: %s", method, url)
            try:
                if method == "GET":
                    resp = session.get(
                        url,
                        headers={"Referer": f"http://{printer.ip}/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"},
                        timeout=20,
                    )
                else:
                    resp = session.post(
                        url,
                        files=payload,
                        headers={"Referer": f"http://{printer.ip}/web/entry/en/address/adrsList.cgi?modeIn=LIST_ALL"},
                        timeout=20,
                    )
                resp.raise_for_status()
                text_len = len(resp.text or "")
                LOGGER.info("[RicohWizard] Wizard open response received. Length: %d, HTTP Status: %d", text_len, resp.status_code)
                if resp.text.strip():
                    return resp.text
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("[RicohWizard] Wizard open attempt (%s) failed for %s: %s", method, printer.ip, exc)
                last_error = exc
                continue
        if last_error is not None:
            LOGGER.error("[RicohWizard] All _open_wizard attempts failed for %s", printer.ip)
            raise last_error
        return ""

    def _fetch_wim_token(self, session: requests.Session, printer: Printer) -> tuple[str, str]:
        LOGGER.info("[RicohWizard] Fetching WIM token for IP: %s", printer.ip)
        candidates: list[tuple[str, str]] = []
        try:
            initial_html = self._open_wizard(session, printer)
            if initial_html.strip():
                candidates.append(("wizard", initial_html))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("[RicohWizard] _open_wizard exception in _fetch_wim_token for %s: %s", printer.ip, exc)

        try:
            list_html = self.read_address_list_with_client(session, printer)
            if list_html.strip():
                candidates.append(("address_list", list_html))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("[RicohWizard] read_address_list_with_client fallback exception in _fetch_wim_token for %s: %s", printer.ip, exc)

        LOGGER.info("[RicohWizard] Found %d candidate HTMLs for token extraction", len(candidates))
        for source, html in candidates:
            token = self._extract_wim_token(html) or self._extract_hidden_inputs(html).get("wimToken", "")
            LOGGER.info("[RicohWizard] Extraction from source '%s': token found='%s'", source, bool(token))
            if token:
                return token, source
        LOGGER.warning("[RicohWizard] No token could be extracted from candidates for %s", printer.ip)
        return "", ""

    def _parse_folder_destination(self, folder: str) -> tuple[str, int, str]:
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
                    current = int(self._normalize_registration_no(entry.registration_no) or "0")
                except Exception:  # noqa: BLE001
                    current = 0
                highest = max(highest, current)
        except Exception:  # noqa: BLE001
            pass

        if highest <= 0:
            try:
                raw = self.read_address_list_with_client(session, printer)
                entries = self.parse_address_list(raw)
                for entry in entries:
                    try:
                        current = int(self._normalize_registration_no(entry.registration_no) or "0")
                    except Exception:  # noqa: BLE001
                        current = 0
                    highest = max(highest, current)
            except Exception:  # noqa: BLE001
                pass

        hint = int(self._address_index_hint_by_ip.get(printer.ip, 0) or 0)
        highest = max(highest, hint)
        if highest <= 0:
            highest = 1
        return f"{highest + 1:05d}"

    @staticmethod
    def _extract_created_registration_no(html: str) -> str:
        patterns = [
            r'span_entryIndexIn">(\d{1,10})<',
            r'name="entryIndexIn"\s+value="(\d{1,10})"',
            r'entryIndexIn[">=]\s*(\d{1,10})',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.I | re.S)
            if match:
                return match.group(1).zfill(5)[-5:]
        return ""

    def _verify_address_entry(
        self,
        session: requests.Session,
        printer: Printer,
        registration_no: str,
        name: str,
        folder: str,
    ) -> bool:
        candidates: list[Any] = []
        try:
            raw = self.get_address_list_ajax_with_client(session, printer)
            candidates.extend(self.parse_ajax_address_list(raw))
        except Exception:  # noqa: BLE001
            pass
        try:
            raw = self.read_address_list_with_client(session, printer)
            candidates.extend(self.parse_address_list(raw))
        except Exception:  # noqa: BLE001
            pass

        seen_ids: set[tuple[str, str, str]] = set()
        normalized_name = self._clean_text(name).lower()
        normalized_folder = self._clean_text(folder).lower()
        target_reg = self._normalize_registration_no(registration_no)
        for entry in candidates:
            reg = self._normalize_registration_no(entry.registration_no)
            key = (reg, self._clean_text(entry.name).lower(), self._clean_text(entry.folder).lower())
            if key in seen_ids:
                continue
            seen_ids.add(key)
            if target_reg and reg == target_reg:
                return True
            if normalized_name and self._clean_text(entry.name).lower() == normalized_name:
                if not normalized_folder or normalized_folder == self._clean_text(entry.folder).lower():
                    return True
        return False

    def create_address_user_wizard(
        self,
        printer: Printer,
        name: str,
        email: str = "",
        folder: str = "",
        user_code: str = "",
        fields: dict[str, Any] | None = None,
        desired_registration_no: str | None = None,
        allow_auto_update: bool = True,
    ) -> dict[str, Any]:
        LOGGER.info(
            "[RicohWizard] === START create_address_user_wizard: printer=%s (IP=%s), name=%s, email=%s, folder=%s, desired_registration_no=%s ===",
            printer.name, printer.ip, name, email, folder, desired_registration_no
        )
        session = self.create_http_client_auth_form_only(printer)
        fields = dict(fields or {})

        wim_token, wim_source = self._fetch_wim_token(session, printer)
        if not wim_token:
            LOGGER.error("[RicohWizard] Token not found for IP: %s", printer.ip)
            raise RuntimeError("Ricoh wizard token not found")
        LOGGER.info("[RicohWizard] Ricoh wizard token source: ip=%s source=%s, token=%s...", printer.ip, wim_source or "unknown", wim_token[:8])

        registration_no = self._normalize_registration_no(desired_registration_no or "")
        if not registration_no:
            LOGGER.info("[RicohWizard] Registration no not provided, calculating next registration no...")
            registration_no = self._next_registration_no(session, printer)
        LOGGER.info("[RicohWizard] Using registration number: %s", registration_no)

        entry_display_name = self._clean_text(
            self._field_text(fields, "entryDisplayNameIn", "entryDisplayName", default=name)
        ) or self._clean_text(name)

        tag_value = self._field_text(fields, "entryTagInfoIn", default="1") or "1"
        tag_values = [tag_value] * 4

        base_items: list[tuple[str, str]] = [
            ("mode", "ADDUSER"),
            ("step", "BASE"),
            ("wimToken", wim_token),
            ("entryIndexIn", registration_no),
            ("entryNameIn", self._clean_text(name)),
            ("entryDisplayNameIn", entry_display_name),
        ]
        for value in tag_values[:4]:
            base_items.append(("entryTagInfoIn", value))
        if str(fields.get("entryTypeIn", "") or "").strip():
            base_items.append(("entryTypeIn", str(fields.get("entryTypeIn", "")).strip()))

        LOGGER.info("[RicohWizard] Submitting BASE step...")
        base_html = self._post_wizard_step(session, printer, base_items, referer="")
        wim_token = self._extract_wim_token(base_html) or wim_token

        mail_items: list[tuple[str, str]] = [
            ("mode", "ADDUSER"),
            ("step", "MAIL"),
            ("wimToken", wim_token),
            ("mailAddressIn", self._clean_text(email)),
        ]
        LOGGER.info("[RicohWizard] Submitting MAIL step...")
        mail_html = self._post_wizard_step(session, printer, mail_items)
        wim_token = self._extract_wim_token(mail_html) or wim_token

        folder_server_name, folder_port, folder_path = self._parse_folder_destination(folder)
        folder_auth_user = self._field_text(fields, "folderAuthUserNameIn", "folderAuthUserName", default="")
        folder_password = self._field_text(
            fields,
            "folderPasswordIn",
            "wk_folderPasswordIn",
            "folderPassword",
            default="",
        )
        if not folder_password:
            folder_password = self._field_text(
                fields,
                "wk_folderPasswordConfirmIn",
                "folderPasswordConfirmIn",
                "folderPasswordConfirm",
                default="",
            )

        folder_items: list[tuple[str, str]] = [
            ("mode", "ADDUSER"),
            ("step", "FOLDER"),
            ("wimToken", wim_token),
            ("folderProtocolIn", "FTP_O"),
            ("folderPortNoIn", str(folder_port or 21)),
            ("folderServerNameIn", folder_server_name),
            ("folderPathNameIn", folder_path),
            ("folderAuthUserNameIn", folder_auth_user),
            ("wk_folderPasswordIn", folder_password),
            ("folderPasswordIn", folder_password),
            ("wk_folderPasswordConfirmIn", folder_password),
            ("folderPasswordConfirmIn", folder_password),
        ]
        LOGGER.info("[RicohWizard] Submitting FOLDER step...")
        folder_html = self._post_wizard_step(session, printer, folder_items)
        wim_token = self._extract_wim_token(folder_html) or wim_token

        confirm_items = [
            ("wimToken", wim_token),
            ("stepListIn", "BASE"),
            ("stepListIn", "MAIL"),
            ("stepListIn", "FOLDER"),
            ("mode", "ADDUSER"),
            ("step", "CONFIRM"),
        ]
        LOGGER.info("[RicohWizard] Submitting CONFIRM step...")
        confirm_html = self._post_wizard_step(session, printer, confirm_items)
        created_registration_no = self._extract_created_registration_no(confirm_html) or registration_no
        LOGGER.info("[RicohWizard] CONFIRM step complete. Created registration no: %s", created_registration_no)

        time.sleep(0.25)
        LOGGER.info("[RicohWizard] Verifying created entry on printer...")
        verified = self._verify_address_entry(session, printer, created_registration_no, name, folder)
        if not verified:
            LOGGER.error("[RicohWizard] Verification failed after creation for registration_no=%s, name=%s", created_registration_no, name)
            raise RuntimeError(
                f"Ricoh address entry not verified after create: registration_no={created_registration_no} name={name}"
            )
        LOGGER.info("[RicohWizard] Verification successful for registration_no=%s", created_registration_no)

        if created_registration_no.isdigit():
            self._address_index_hint_by_ip[printer.ip] = max(
                int(self._address_index_hint_by_ip.get(printer.ip, 0) or 0),
                int(created_registration_no),
            )

        LOGGER.info("[RicohWizard] === FINISH create_address_user_wizard: Success ===")
        return {
            "printer_name": printer.name,
            "ip": printer.ip,
            "ok": True,
            "endpoint": self._WIZARD_SET,
            "created_registration_no": created_registration_no,
            "entry_name": self._clean_text(name),
            "entry_display_name": entry_display_name,
            "email": self._clean_text(email),
            "folder": folder,
            "folder_server_name": folder_server_name,
            "folder_port": folder_port,
            "folder_path": folder_path,
            "http_status": 200,
            "verified": True,
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
        self.delete_address_entries(printer, [registration_no], verify=False)
        return self.create_address_user_wizard(
            printer,
            name=name,
            email=email,
            folder=folder,
            user_code=user_code,
            fields=fields,
            desired_registration_no=registration_no,
            allow_auto_update=False,
        )
