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
        """RADIO_OFF, UA_BASIC, UA_USER_CODE, etc."""
        import re
        match = re.search(r'name="userAuthenticationMethod"[^>]*?checked[^>]*?value="([^"]+)"', html, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r'value="([^"]+)"[^>]*?checked', html, re.IGNORECASE)
        return match.group(1) if match else ""

    def read_machine_control_state(self, printer: Printer) -> dict[str, Any]:
        try:
            config_url = "/web/entry/en/websys/config/getUserAuthenticationManager.cgi"
            try:
                session = self.create_http_client(printer)
                html = self.authenticate_and_get(session, printer, config_url)
            except Exception as exc:
                LOGGER.warning("Machine control state fetch failed: ip=%s error=%s", printer.ip, exc)
                return {
                    "enabled": False,
                    "method": "",
                    "known": False,
                    "source": config_url,
                    "error": str(exc),
                }

            method = self._extract_user_authentication_method(html)
            enabled = method in {"RADIO_OFF", "OFF", "0", "UA_NONE", "UA_OFF", "OFF_MODE"}
            return {
                "enabled": enabled,
                "method": method,
                "known": bool(method),
                "source": config_url,
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
