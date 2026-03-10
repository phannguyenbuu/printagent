from __future__ import annotations

import logging
import time
from typing import Any

import requests

from app.modules.ricoh.base import RicohServiceBase
from app.services.api_client import Printer

LOGGER = logging.getLogger(__name__)

class RicohControlMixin(RicohServiceBase):
    def _extract_user_authentication_method(self, html: str) -> str:
        """
        Extract current auth mode from different Ricoh page variants.
        Expected values: RADIO_OFF, UA_USER_CODE, UA_BASIC, etc.
        """
        import re
        text = str(html or "")
        if not text:
            return ""

        input_tags = re.findall(
            r'<input\b[^>]*\bname=["\']userAuthenticationMethod["\'][^>]*>',
            text,
            re.IGNORECASE,
        )
        fallback_values: list[str] = []
        hidden_values: list[str] = []
        for tag in input_tags:
            value_match = re.search(r'\bvalue=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not value_match:
                continue
            value = value_match.group(1).strip()
            if not value:
                continue
            fallback_values.append(value)
            if re.search(r'\btype=["\']hidden["\']', tag, re.IGNORECASE):
                hidden_values.append(value)
            if re.search(r'\bchecked(?:=["\']?checked["\']?)?\b', tag, re.IGNORECASE):
                return value

        select_match = re.search(
            r'<select\b[^>]*\bname=["\']userAuthenticationMethod["\'][^>]*>(.*?)</select>',
            text,
            re.IGNORECASE | re.DOTALL,
        )
        if select_match:
            options_html = select_match.group(1)
            selected_option = re.search(
                r'<option\b[^>]*\bvalue=["\']([^"\']+)["\'][^>]*\bselected\b[^>]*>',
                options_html,
                re.IGNORECASE,
            ) or re.search(
                r'<option\b[^>]*\bselected\b[^>]*\bvalue=["\']([^"\']+)["\']',
                options_html,
                re.IGNORECASE,
            )
            if selected_option:
                return selected_option.group(1).strip()

        # Some firmwares expose current mode in a hidden input instead of checked radio.
        if hidden_values:
            return hidden_values[0]

        if len(fallback_values) == 1:
            return fallback_values[0]

        # Script-level fallback: userAuthenticationMethod = "RADIO_OFF"
        script_match = re.search(
            r'userAuthenticationMethod[^;\n]{0,200}(?:=|:)\s*["\']([A-Z0-9_]+)["\']',
            text,
            re.IGNORECASE,
        )
        if script_match:
            candidate = script_match.group(1).strip()
            if candidate:
                return candidate

        return ""

    def read_machine_control_state(self, printer: Printer) -> dict[str, Any]:
        config_url = "/web/entry/en/websys/config/getUserAuthenticationManager.cgi"
        try:
            try:
                session = self.create_http_client(printer)
                html = self.authenticate_and_get(session, printer, config_url)
            except Exception as exc:
                error_text = str(exc).strip() or "Unable to authenticate/read machine state"
                LOGGER.warning("Machine control state fetch failed: ip=%s error=%s", printer.ip, exc)
                return {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": config_url,
                    "status": "error",
                    "state": "error",
                    "auth_ok": False,
                    "error": error_text,
                }

            method = self._extract_user_authentication_method(html)
            if not method:
                lower_html = (html or "").lower()
                if "login.cgi" in lower_html or "authform.cgi" in lower_html:
                    parse_error = "Unable to access authenticated control page"
                elif "privilege" in lower_html or "permission" in lower_html:
                    parse_error = "Authenticated but no privilege to read authentication settings"
                else:
                    parse_error = "Unable to parse user authentication method"
                return {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": config_url,
                    "status": "error",
                    "state": "error",
                    "auth_ok": True,
                    "error": parse_error,
                }
            enabled = method in {"RADIO_OFF", "OFF", "0", "UA_NONE", "UA_OFF", "OFF_MODE"}
            machine_state = "enable" if enabled else "disable"
            return {
                "enabled": enabled,
                "method": method,
                "known": True,
                "source": config_url,
                "status": machine_state,
                "state": machine_state,
                "auth_ok": True,
            }
        finally:
            self._logout_after_collect(printer, source="machine_state")

    def _submit_user_authentication_settings(
        self,
        printer: Printer,
        *,
        method: str,
        copier_bw: bool,
        printer_bw: bool,
        printer_pc_control: bool,
        document_server: bool,
        fax: bool,
        scanner: bool,
        browser: bool,
    ) -> None:
        config_url = "/web/entry/en/websys/config/getUserAuthenticationManager.cgi"
        session = self.create_http_client(printer, authenticated=True)
        html = self.authenticate_and_get(session, printer, config_url)
        wim_token = self._extract_wim_token(html)
        hidden_vars = self._extract_hidden_inputs(html)

        form: list[tuple[str, str]] = []
        for k, v in hidden_vars.items():
            if k not in {"wimToken", "userAuthenticationMethod", "userCodeCopy", "userCodePrinter", "userCodeDocumentBox", "userCodeFax", "userCodeScanner", "userCodeScaner", "userCodeMfpBrowser"}:
                 form.append((k, v))
        
        form.extend([
            ("wimToken", wim_token),
            ("title", "MENU_USERAUTH"),
            ("userAuthenticationRW", "3"),
            ("userAuthenticationMethod", method),
            ("userCodeCopy", "true" if copier_bw else "false"),
            ("userCodeCopy", ""),
            ("userCodeCopy", ""),
            ("userCodeCopy", ""),
            ("userCodePrinter", "true" if printer_bw else "false"),
            ("userCodePrinter", "true" if printer_pc_control else "false"),
            ("userCodePrinter", ""),
            ("userCodeDocumentBox", "true" if document_server else "false"),
            ("userCodeFax", "true" if fax else "false"),
            ("userCodeScanner", "true" if scanner else "false"),
            ("userCodeScaner", "true" if scanner else "false"),
            ("userCodeMfpBrowser", "true" if browser else "false"),
        ])
        
        desired_method = str(method or "").strip().upper()
        LOGGER.info("Submitting machine control: ip=%s method=%s", printer.ip, desired_method)
        
        try:
            resp = session.post(
                f"http://{printer.ip}/web/entry/en/websys/config/setUserAuthenticationManager.cgi",
                data=form,
                headers={"Referer": f"http://{printer.ip}{config_url}"},
                timeout=25,
            )
            resp.raise_for_status()
            if any(marker in resp.text for marker in ["Application Error", "Error has occurred", "not have the privilege"]):
                if "session has expired" in resp.text.lower():
                     LOGGER.info("Session expired during control POST, retrying once...")
                     self._login(session, printer)
                     resp = session.post(
                        f"http://{printer.ip}/web/entry/en/websys/config/setUserAuthenticationManager.cgi",
                        data=form,
                        headers={"Referer": f"http://{printer.ip}{config_url}"},
                        timeout=25,
                     )
                     resp.raise_for_status()
                else:
                    raise RuntimeError(f"Ricoh error: {resp.text[:200].strip()}")
            time.sleep(1.5)
        except requests.exceptions.Timeout:
            LOGGER.warning("Machine control post timeout; verifying state for %s", printer.ip)
            for _ in range(3):
                time.sleep(1.5)
                try:
                    v_html = self.authenticate_and_get(session, printer, config_url)
                    if self._extract_user_authentication_method(v_html) == desired_method:
                        return
                except Exception:
                    continue

    def enable_machine(self, printer: Printer) -> dict[str, Any]:
        try:
            self._submit_user_authentication_settings(
                printer,
                method="RADIO_OFF",
                copier_bw=False, printer_bw=False, printer_pc_control=False,
                document_server=False, fax=False, scanner=False, browser=False
            )
            return {"ok": True, "action": "enable_machine", "ip": printer.ip}
        except Exception as e:
            LOGGER.error("Enable machine failed: %s", e)
            return {"ok": False, "error": str(e), "action": "enable_machine", "ip": printer.ip}

    def lock_machine(self, printer: Printer) -> dict[str, Any]:
        try:
            self._submit_user_authentication_settings(
                printer,
                method="UA_USER_CODE",
                copier_bw=True, printer_bw=True, printer_pc_control=True,
                document_server=True, fax=True, scanner=True, browser=True
            )
            return {"ok": True, "action": "lock_machine", "ip": printer.ip}
        except Exception as e:
            LOGGER.error("Lock machine failed: %s", e)
            return {"ok": False, "error": str(e), "action": "lock_machine", "ip": printer.ip}

    def disable_machine(self, printer: Printer) -> dict[str, Any]:
        return self.lock_machine(printer)
