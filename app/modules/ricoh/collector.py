from __future__ import annotations

import csv
import json
import logging
import re
import time
from datetime import datetime
from html import unescape
from pathlib import Path
from typing import Any

import requests

from app.modules.ricoh.base import RicohServiceBase
from app.services.api_client import Printer

LOGGER = logging.getLogger(__name__)

class RicohCollectorMixin(RicohServiceBase):
    @staticmethod
    def _guest_get(session: requests.Session, printer: Printer, target_url: str, timeout: int = 10) -> str:
        """
        Direct guest/public fetch. No re-auth/login fallback.
        Use this for counter/status polling to avoid triggering login flow.
        """
        url = target_url
        if not (str(target_url).startswith("http://") or str(target_url).startswith("https://")):
            url = f"http://{printer.ip}{target_url if str(target_url).startswith('/') else '/' + str(target_url)}"
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text

    @staticmethod
    def _resolve_webarch_relative_path(path: str) -> str:
        raw = str(path or "").strip()
        if not raw:
            return ""
        if raw.startswith("http://") or raw.startswith("https://"):
            match = re.search(r"https?://[^/]+(/.*)$", raw, re.IGNORECASE)
            return match.group(1) if match else ""
        if raw.startswith("/"):
            return raw
        # mainFrame/topPage usually contains relative paths like "header.cgi", "topPage.cgi".
        return f"/web/guest/en/websys/webArch/{raw.lstrip('./')}"

    @staticmethod
    def _compact_preview(html: str, limit: int = 220) -> str:
        text = RicohServiceBase._strip_html(html or "")
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) <= limit:
            return text
        return f"{text[:limit]}..."

    @staticmethod
    def _marker_flags(text: str, markers: list[str]) -> dict[str, bool]:
        lowered = str(text or "").lower()
        return {m: (m.lower() in lowered) for m in markers}

    def _read_guest_mainframe_with_source(self, printer: Printer) -> tuple[str, str]:
        paths = [
            "/web/guest/en/websys/webArch/mainFrame.cgi",
            "/web/guest/en/websys/webArch/mainFrame.cgi?name=main",
        ]
        last_exc: Exception | None = None
        session = self.create_http_client(printer, authenticated=False)
        for path in paths:
            try:
                html = self._guest_get(session, printer, path)
                return html, f"http://{printer.ip}{path}"
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Unable to load guest mainFrame.cgi")

    def _read_guest_mainframe(self, printer: Printer) -> str:
        html, _ = self._read_guest_mainframe_with_source(printer)
        return html

    def _read_guest_counter_with_source(self, printer: Printer) -> tuple[str, str]:
        path = "/web/guest/en/websys/status/getUnificationCounter.cgi"
        session = self.create_http_client(printer, authenticated=False)
        html = self._guest_get(session, printer, path)
        return html, f"http://{printer.ip}{path}"

    def _read_guest_status_with_source(self, printer: Printer) -> tuple[str, str]:
        path = "/web/guest/en/websys/webArch/getStatus.cgi"
        session = self.create_http_client(printer, authenticated=False)
        html = self._guest_get(session, printer, path)
        return html, f"http://{printer.ip}{path}"

    @staticmethod
    def _extract_guest_cgi_candidates(text: str) -> list[str]:
        candidates: list[str] = []
        if not text:
            return candidates
        for match in re.finditer(
            r"""['"]([^'"]*?\.cgi(?:\?[^'"]*)?)['"]""",
            text,
            re.IGNORECASE,
        ):
            candidates.append(match.group(1))
        for match in re.finditer(
            r"""(?:href|src)\s*=\s*['"]([^'"]+)['"]""",
            text,
            re.IGNORECASE,
        ):
            candidates.append(match.group(1))
        return candidates

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

    @staticmethod
    def _extract_first_mac(text: str) -> str:
        if not text:
            return ""
        match = re.search(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", text)
        if not match:
            return ""
        return match.group(0).replace("-", ":").upper()

    def _read_interface_public_with_source(self, printer: Printer) -> tuple[str, str]:
        """
        Read network/interface page via public endpoints only (no auth fallback).
        Prioritize new endpoint requested by user, then legacy guest paths.
        """
        paths = [
            "/web/entry/en/websys/netw/getInterface.cgi",
            "/web/guest/en/websys/netw/getInterface.cgi",
            "/web/guest/en/manual/configuration/network/interface/readNetworkInterface.cgi",
            "/web/guest/en/manual/configuration/network/readNetworkInterface.cgi",
            "/web/guest/en/manual/configuration/readNetworkInterface.cgi",
            "/web/entry/en/manual/configuration/network/interface/readNetworkInterface.cgi",
        ]
        last_err: Exception | None = None
        session = self.create_http_client(printer, authenticated=False)
        for path in paths:
            try:
                html = self._guest_get(session, printer, path)
                if html:
                    return html, f"http://{printer.ip}{path}"
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                continue
        if last_err is not None:
            raise last_err
        raise RuntimeError("Unable to load interface page")

    def _discover_guest_paths(self, session: requests.Session, printer: Printer, keyword: str = "") -> list[str]:
        keyword_lower = str(keyword or "").strip().lower()
        prioritized: list[str] = []
        fallback: list[str] = []
        js_sources: list[str] = []
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
            candidates: list[str] = self._extract_guest_cgi_candidates(html)
            for src_match in re.finditer(
                r"""<script[^>]+src=['"]([^'"]+)['"]""",
                html,
                re.IGNORECASE,
            ):
                js_src = self._normalize_guest_path(src_match.group(1))
                if js_src and js_src.lower().endswith(".js") and "/web/guest/" in js_src.lower():
                    js_sources.append(js_src)

            for raw in candidates:
                normalized = self._normalize_guest_path(str(raw or ""))
                if not normalized:
                    continue
                if "/web/guest/" not in normalized.lower():
                    continue
                if ".cgi" not in normalized.lower():
                    continue
                if keyword_lower and keyword_lower in normalized.lower():
                    prioritized.append(normalized)
                else:
                    fallback.append(normalized)

        # Parse referenced JS files for hidden/indirect .cgi endpoints.
        js_seen: set[str] = set()
        for js_src in js_sources:
            key = js_src.lower()
            if key in js_seen:
                continue
            js_seen.add(key)
            try:
                js_text = self.authenticate_and_get(session, printer, js_src)
            except Exception:  # noqa: BLE001
                continue
            for raw in self._extract_guest_cgi_candidates(js_text):
                normalized = self._normalize_guest_path(str(raw or ""))
                if not normalized:
                    continue
                if "/web/guest/" not in normalized.lower():
                    continue
                if ".cgi" not in normalized.lower():
                    continue
                if keyword_lower and keyword_lower in normalized.lower():
                    prioritized.append(normalized)
                else:
                    fallback.append(normalized)
        # Keep order, remove duplicates.
        unique: list[str] = []
        seen: set[str] = set()
        for path in [*prioritized, *fallback]:
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
        last_html = ""
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
                    html = self.authenticate_and_get(session, printer, path)
                    last_html = html or last_html
                    if keyword_lower == "counter":
                        if self._looks_like_counter_content(html):
                            return html
                    elif keyword_lower == "status":
                        if self._looks_like_status_content(html):
                            return html
                    else:
                        return html
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

            # Final fallback: brute-force all discovered guest cgi links from frames.
            for path in self._discover_guest_paths(session, printer, keyword=""):
                if path in tried:
                    continue
                if len(tried) > 60:
                    break
                tried.append(path)
                try:
                    html = self.authenticate_and_get(session, printer, path)
                    last_html = html or last_html
                except requests.exceptions.HTTPError as exc:
                    last_exc = exc
                    if getattr(exc.response, "status_code", None) == 404:
                        continue
                    continue
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    continue
                if keyword_lower == "counter" and self._looks_like_counter_content(html):
                    LOGGER.info("Counter brute-force endpoint matched: ip=%s path=%s", printer.ip, path)
                    return html
                if keyword_lower == "status" and self._looks_like_status_content(html):
                    LOGGER.info("Status brute-force endpoint matched: ip=%s path=%s", printer.ip, path)
                    return html

            if last_html:
                LOGGER.warning(
                    "Using last HTML fallback for %s: ip=%s tried=%s",
                    keyword,
                    printer.ip,
                    tried,
                )
                return last_html

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
        html, _ = self._read_guest_counter_with_source(printer)
        return html

    def read_device_info(self, printer: Printer) -> str:
        session = self.create_http_client(printer, authenticated=False)
        # Public guest endpoint containing Model Name + Machine ID.
        return self._guest_get(session, printer, "/web/guest/en/websys/status/configuration.cgi")

    def read_status(self, printer: Printer) -> str:
        html, _ = self._read_guest_status_with_source(printer)
        return html

    def read_network_interface(self, printer: Printer) -> str:
        html, _ = self._read_interface_public_with_source(printer)
        return html

    def fetch_mac_address_direct(self, ip: str) -> str:
        printer = Printer(name="MAC Discovery", ip=ip, user="", password="", printer_type="ricoh")
        try:
            html, source_url = self._read_interface_public_with_source(printer)
            mac = self._extract_first_mac(html)
            if mac:
                LOGGER.info("MAC direct success: ip=%s source=%s mac=%s", ip, source_url, mac)
                return mac
            LOGGER.warning("MAC direct parse empty: ip=%s source=%s html_len=%s", ip, source_url, len(html or ""))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("MAC direct fetch failed: ip=%s error=%s", ip, exc)
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
        html, source_url = self._read_guest_status_with_source(printer)
        data = self.parse_status(html)
        plain = RicohServiceBase._strip_html(html or "")
        status_markers = self._marker_flags(plain, ["status", "system status", "toner", "tray", "paper"])
        if not data:
            LOGGER.warning(
                "Status parse empty: ip=%s source=%s html_len=%s markers=%s preview=%s",
                printer.ip,
                source_url,
                len(html or ""),
                status_markers,
                self._compact_preview(html),
            )
        else:
            LOGGER.info(
                "Status parse success: ip=%s source=%s keys=%s html_len=%s markers=%s",
                printer.ip,
                source_url,
                sorted(data.keys()),
                len(html or ""),
                status_markers,
            )
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "status_data": data,
            "status_source": source_url,
            "html": html,
            "status_debug": {
                "source": source_url,
                "html_len": len(html or ""),
                "markers": status_markers,
                "empty": not bool(data),
                "preview": self._compact_preview(html),
            },
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    def process_counter(self, printer: Printer, should_post: bool) -> dict[str, Any]:
        html, source_url = self._read_guest_counter_with_source(printer)
        data = self.parse_counter(html)
        plain = RicohServiceBase._strip_html(html or "")
        counter_markers = self._marker_flags(
            plain,
            ["counter", "copier", "printer", "black & white", "send/tx total", "total"],
        )
        if not data:
            LOGGER.warning(
                "Counter parse empty: ip=%s source=%s html_len=%s markers=%s preview=%s",
                printer.ip,
                source_url,
                len(html or ""),
                counter_markers,
                self._compact_preview(html),
            )
        else:
            LOGGER.info(
                "Counter parse success: ip=%s source=%s keys=%s html_len=%s markers=%s",
                printer.ip,
                source_url,
                sorted(data.keys()),
                len(html or ""),
                counter_markers,
            )
        payload = {
            "printer_name": printer.name,
            "ip": printer.ip,
            "counter_data": data,
            "counter_source": source_url,
            "html": html,
            "counter_debug": {
                "source": source_url,
                "html_len": len(html or ""),
                "markers": counter_markers,
                "empty": not bool(data),
                "preview": self._compact_preview(html),
            },
            "timestamp": self._timestamp(),
        }
        if should_post:
            self.api_client.post_data(payload)
        return payload

    @staticmethod
    def parse_device_info(html: str) -> dict[str, str]:
        results: dict[str, str] = {}
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html or "", flags=re.IGNORECASE | re.DOTALL)
        for row in rows:
            tds = re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.IGNORECASE | re.DOTALL)
            cells = [RicohServiceBase._strip_html(cell) for cell in tds]
            cells = [c for c in cells if c and c != ":"]
            if len(cells) < 2:
                continue
            # Typical structure: [bullet-empty, key, ":", value, ...]
            # After cleaning, this becomes [key, value, ...].
            key = cells[0].rstrip(":").strip()
            val = cells[1].strip()
            if not key or not val:
                continue
            results[key] = val

        # Normalize aliases for downstream code.
        model = results.get("Model Name") or results.get("Machine Name") or results.get("Device Name") or ""
        machine_id = results.get("Machine ID") or results.get("MachineId") or results.get("Serial Number") or ""
        if model:
            results["Model Name"] = model
            results["Machine Name"] = model
            results["model_name"] = model
        if machine_id:
            results["Machine ID"] = machine_id
            results["machine_id"] = machine_id
        return results

    @staticmethod
    def parse_status(html: str) -> dict[str, Any]:
        results: dict[str, Any] = {}

        def _clean(text: str) -> str:
            value = unescape(re.sub(r"<[^>]*>", " ", text or ""))
            return re.sub(r"\s+", " ", value).strip()

        def _extract_items_from_dd(dd_html: str) -> list[str]:
            items: list[str] = []
            for li in re.findall(r"<li[^>]*>(.*?)</li>", dd_html or "", re.IGNORECASE | re.DOTALL):
                text = _clean(li)
                if text:
                    items.append(text)
            return items

        def _extract_img_alts(dd_html: str) -> list[str]:
            alts: list[str] = []
            for alt in re.findall(r'alt="([^"]+)"', dd_html or "", re.IGNORECASE):
                text = str(alt or "").strip()
                if text:
                    alts.append(text)
            return alts

        def _first_status_token(text: str) -> str:
            match = re.search(
                r"\b(Status OK|Alert|Warning|Error|Offline|Online|Energy Saver Mode|No Paper)\b",
                text or "",
                re.IGNORECASE,
            )
            return match.group(1) if match else ""

        # Parse all detail rows globally, then classify by dt label.
        dtm_pattern = (
            r'<dt[^>]*class=["\'][^"\']*listboxdtm[^"\']*["\'][^>]*>\s*(.*?)\s*</dt>\s*'
            r'<dd[^>]*>(.*?)</dd>'
        )
        status_rows = re.findall(
            dtm_pattern,
            html or "",
            re.IGNORECASE | re.DOTALL,
        )
        status_json: dict[str, Any] = {}
        toner_json: dict[str, Any] = {}
        input_trays: dict[str, Any] = {}
        output_trays: dict[str, Any] = {}
        for raw_name, dd_html in status_rows:
            name = _clean(raw_name).lower()
            dd_text = _clean(dd_html)
            li_items = _extract_items_from_dd(dd_html)
            token = _first_status_token(dd_text)
            if name in {"system", "printer", "copier", "scanner"}:
                status_json[name] = {
                    "state": token or dd_text,
                    "details": li_items,
                    "text": dd_text,
                }
                continue
            if name == "black":
                alts = _extract_img_alts(dd_html)
                toner_json[name] = {
                    "state": token or dd_text,
                    "icons": alts,
                    "text": dd_text,
                }
                continue
            if name.startswith("tray ") or name == "bypass tray":
                tray_key = re.sub(r"\s+", "_", name.lower())
                alts = _extract_img_alts(dd_html)
                input_trays[tray_key] = {"text": dd_text, "icons": alts}
                if tray_key == "tray_1":
                    results["tray_1_status"] = dd_text
                elif tray_key == "tray_2":
                    results["tray_2_status"] = dd_text
                elif tray_key == "tray_3":
                    results["tray_3_status"] = dd_text
                elif tray_key == "bypass_tray":
                    results["bypass_tray_status"] = dd_text
                continue
            # Remaining tray labels are typically output tray entries.
            if "tray" in name:
                key = re.sub(r"\s+", "_", name.lower())
                alts = _extract_img_alts(dd_html)
                output_trays[key] = {"text": dd_text, "icons": alts}

        if status_json.get("system"):
            results["system_status"] = status_json["system"].get("state", "")
        if status_json.get("printer"):
            results["printer_status"] = status_json["printer"].get("state", "")
            results["printer_alerts"] = status_json["printer"].get("details", [])
        if status_json.get("copier"):
            results["copier_status"] = status_json["copier"].get("state", "")
            results["copier_alerts"] = status_json["copier"].get("details", [])
        if status_json.get("scanner"):
            results["scanner_status"] = status_json["scanner"].get("state", "")
            results["scanner_alerts"] = status_json["scanner"].get("details", [])

        if "black" in toner_json:
            results["toner_black"] = toner_json["black"].get("state", "")

        # Parse alert/messages summary block
        dtl_pattern = (
            r'<dt[^>]*class=["\'][^"\']*listboxdtl[^"\']*["\'][^>]*>\s*(.*?)\s*</dt>\s*'
            r'<dd[^>]*>(.*?)</dd>'
        )
        alert_rows = re.findall(
            dtl_pattern,
            html or "",
            re.IGNORECASE | re.DOTALL,
        )
        alert_json: dict[str, Any] = {"alert": "", "messages": ""}
        for raw_name, dd_html in alert_rows:
            key = re.sub(r"\s+", "_", _clean(raw_name).lower())
            if key in {"alert", "messages"}:
                alert_json[key] = _clean(dd_html)

        # Structured JSON for backend/CRM.
        results["status_json"] = {
            "alert": alert_json,
            "status": status_json,
            "toner": toner_json,
            "input_tray": input_trays,
            "output_tray": output_trays,
        }

        # Fallback text parser for older HTML variants.
        if not any(k in results for k in ["system_status", "toner_black", "tray_1_status", "tray_2_status", "tray_3_status"]):
            plain = _clean(html)
            lowered = plain.lower()

            def _slice_between(start_pat: str, end_pats: list[str]) -> str:
                start = re.search(start_pat, plain, re.IGNORECASE)
                if not start:
                    return ""
                segment = plain[start.end():]
                end_idx = len(segment)
                for ep in end_pats:
                    m = re.search(ep, segment, re.IGNORECASE)
                    if m:
                        end_idx = min(end_idx, m.start())
                return segment[:end_idx].strip(" :-")

            def _compact_status(value: str, max_len: int = 80) -> str:
                v = re.sub(r"\s+", " ", str(value or "")).strip(" :-")
                if not v:
                    return ""
                m = re.search(r"(Status OK|Alert|Warning|Error|Offline|Online|Energy Saver Mode|No Paper)", v, re.IGNORECASE)
                if m:
                    return m.group(1)
                return v[:max_len]

            # Prefer extracting bounded sections to avoid giant concatenated strings.
            if "system" in lowered:
                sys_seg = _slice_between(r"\bSystem\b", [r"\bPrinter\b", r"\bCopier\b", r"\bScanner\b", r"\bToner\b"])
                sys_val = _compact_status(sys_seg)
                if sys_val:
                    results["system_status"] = sys_val

            if "toner" in lowered:
                toner_seg = _slice_between(r"\bBlack\b", [r"\bInput\s+Tray\b", r"\bOutput\s+Tray\b"])
                toner_val = _compact_status(toner_seg)
                if toner_val:
                    results["toner_black"] = toner_val

            for tray_no in ("1", "2", "3"):
                tray_seg = _slice_between(
                    rf"\bTray\s+{tray_no}\b",
                    [rf"\bTray\s+{int(tray_no)+1}\b", r"\bBypass\s+Tray\b", r"\bOutput\s+Tray\b"],
                )
                if tray_seg:
                    tray_val = re.sub(r"\s+", " ", tray_seg).strip(" :-")[:80]
                    if tray_val:
                        results[f"tray_{tray_no}_status"] = tray_val

            bypass_seg = _slice_between(r"\bBypass\s+Tray\b", [r"\bOutput\s+Tray\b"])
            if bypass_seg:
                bypass_val = re.sub(r"\s+", " ", bypass_seg).strip(" :-")[:80]
                if bypass_val:
                    results["bypass_tray_status"] = bypass_val
        return results

    @staticmethod
    def parse_counter(html: str) -> dict[str, str]:
        results = {}
        # Keep spacing between nodes so labels like "Copier" + "Black & White"
        # are not merged into "CopierBlack".
        plain = unescape(re.sub(r"<[^>]*>", " ", html or ""))
        plain = re.sub(r"\s+", " ", plain).strip()

        def _find_number(pattern: str, text: str) -> str:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if not match:
                return ""
            value = str(match.group(1) or "").replace(",", "").strip()
            return value if value.isdigit() else ""

        def _section(text: str, start_marker: str, end_marker: str) -> str:
            start = re.search(start_marker, text, re.IGNORECASE)
            if not start:
                return ""
            remainder = text[start.start():]
            end = re.search(end_marker, remainder, re.IGNORECASE)
            if not end:
                return remainder
            return remainder[:end.start()]

        # Global counters
        total = _find_number(r"\bTotal\s*:\s*([0-9,]+)", plain)
        if total:
            results["total"] = total
        copier_bw = _find_number(r"Copier\s+Black\s*&\s*White\s*:\s*([0-9,]+)", plain)
        if copier_bw:
            results["copier_bw"] = copier_bw
        printer_bw = _find_number(r"Printer\s+Black\s*&\s*White\s*:\s*([0-9,]+)", plain)
        if printer_bw:
            results["printer_bw"] = printer_bw
        fax_bw = _find_number(r"Fax\s+Black\s*&\s*White\s*:\s*([0-9,]+)", plain)
        if fax_bw:
            results["fax_bw"] = fax_bw

        # Send/TX Total block
        send_tx_block = _section(plain, r"Send/TX\s+Total", r"Fax\s+Transmission")
        if send_tx_block:
            send_bw = _find_number(r"Black\s*&\s*White\s*:\s*([0-9,]+)", send_tx_block)
            send_color = _find_number(r"Color\s*:\s*([0-9,]+)", send_tx_block)
            if send_bw:
                results["send_tx_total_bw"] = send_bw
            if send_color:
                results["send_tx_total_color"] = send_color

        fax_tx_total = _find_number(r"Fax\s+Transmission\s+Total\s*:\s*([0-9,]+)", plain)
        if fax_tx_total:
            results["fax_transmission_total"] = fax_tx_total

        # Scanner Send block
        scanner_block = _section(plain, r"Scanner\s+Send", r"Coverage")
        if scanner_block:
            scanner_bw = _find_number(r"Black\s*&\s*White\s*:\s*([0-9,]+)", scanner_block)
            scanner_color = _find_number(r"Color\s*:\s*([0-9,]+)", scanner_block)
            if scanner_bw:
                results["scanner_send_bw"] = scanner_bw
            if scanner_color:
                results["scanner_send_color"] = scanner_color

        # Coverage block
        coverage_block = _section(plain, r"Coverage", r"Other\s+Function\(s\)")
        if coverage_block:
            copier_cov = _find_number(r"Copier\s+B\s*&\s*W\s+Coverage\s*:\s*([0-9,]+)", coverage_block)
            printer_cov = _find_number(r"Printer\s+B\s*&\s*W\s+Coverage\s*:\s*([0-9,]+)", coverage_block)
            fax_cov = _find_number(r"Fax\s+B\s*&\s*W\s+Coverage\s*:\s*([0-9,]+)", coverage_block)
            if copier_cov:
                results["coverage_copier_bw"] = copier_cov
            if printer_cov:
                results["coverage_printer_bw"] = printer_cov
            if fax_cov:
                results["coverage_fax_bw"] = fax_cov

        # Other Function(s)
        a3_dlt = _find_number(r"A3\/DLT\s*:\s*([0-9,]+)", plain)
        duplex = _find_number(r"Duplex\s*:\s*([0-9,]+)", plain)
        if a3_dlt:
            results["a3_dlt"] = a3_dlt
        if duplex:
            results["duplex"] = duplex

        return results

    def _prepare_csv_row(self, timestamp: str, printer: Printer, status_data: dict[str, Any]) -> list[str]:
        def _as_text(value: Any) -> str:
            if isinstance(value, list):
                return "; ".join(str(item) for item in value)
            if isinstance(value, dict):
                return RicohServiceBase._strip_html(json.dumps(value, ensure_ascii=False))
            return str(value or "")
        return [
            timestamp, printer.name, printer.ip,
            _as_text(status_data.get("system_status", "")),
            _as_text(status_data.get("toner_black", "")),
            _as_text(status_data.get("tray_1_status", "")),
            _as_text(status_data.get("tray_2_status", "")),
            _as_text(status_data.get("tray_3_status", "")),
            _as_text(status_data.get("tray_4_status", "")),
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
