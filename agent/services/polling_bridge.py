from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import requests

from agent.config import AppConfig
from agent.modules.ricoh.service import RicohService
from agent.modules.toshiba.service import ToshibaService
from agent.services.api_client import APIClient, Printer
from agent.services.scan_drop import ensure_active_drop_folder
from agent.services.updater import AutoUpdater
from agent.services.runtime import get_machine_agent_uid, no_window_subprocess_kwargs
from agent.utils.scanner import SubnetScanner
from agent.services.ftp_store import normalize_site_name


LOGGER = logging.getLogger(__name__)
DEFAULT_WEB_PORT = 9173
SCAN_UPLOAD_STATE_FILE = Path("storage/data/scan_upload_state.json")
MAX_SCAN_UPLOAD_HISTORY = 5000


class PollingBridge:
    def __init__(
        self,
        config: AppConfig,
        api_client: APIClient,
        ricoh_service: RicohService,
        toshiba_service: ToshibaService | None = None,
        updater: AutoUpdater | None = None,
        run_mode: str = "web",
        web_port: int = DEFAULT_WEB_PORT,
        restart_callback: Callable[[], None] | None = None,
    ) -> None:
        self._config = config
        self._api_client = api_client
        self._ricoh_service = ricoh_service
        self._toshiba_service = toshiba_service
        self._updater = updater
        self._run_mode = str(run_mode or "web").strip() or "web"
        self._web_port = int(web_port or DEFAULT_WEB_PORT)
        self._restart_callback = restart_callback
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_started_at = ""
        self._last_cycle_at = ""
        self._last_success_at = ""
        self._last_error = ""
        self._last_cycle_total_printers = 0
        self._last_cycle_ricoh_printers = 0
        self._last_cycle_sent = 0
        self._last_cycle_failed = 0
        self._last_control_pull_at = ""
        self._last_control_total = 0
        self._last_control_apply_error = ""
        self._last_ftp_control_pull_at = ""
        self._last_ftp_control_total = 0
        self._last_ftp_control_apply_error = ""
        self._applied_controls: dict[str, bool] = {}
        self._applied_ftp_controls: dict[str, bool] = {}
        self._control_retry_after: dict[str, datetime] = {}
        self._resolved_lan_uid = ""
        self._control_thread: threading.Thread | None = None
        self._running_commands: set[int] = set()
        self._running_commands_lock = threading.Lock()
        self._agent_uid = get_machine_agent_uid(self._config.get_string("polling.agent_uid", ""))
        self._scan_last_cycle_at = ""
        self._scan_last_detected_at = ""
        self._scan_last_detected_file = ""
        self._scan_last_detected_size = 0
        self._scan_last_detected_status = ""
        self._scan_last_upload_at = ""
        self._scan_last_upload_file = ""
        self._scan_last_upload_status = ""
        self._scan_last_upload_drive_path = ""
        self._scan_last_error = ""
        self._scan_uploaded_total = 0
        self._scan_failed_total = 0
        self._scan_pending_total = 0
        self._release_last_check_at = ""
        self._release_last_error = ""
        self._scan_counter_last_by_ip: dict[str, int] = {}
        self._scan_file_state: dict[str, dict[str, object]] = {}
        self._scan_uploaded_fingerprints: dict[str, str] = {}
        self._scan_lock = threading.Lock()
        self._trigger_event = threading.Event()
        self._is_master = False
        self._emails = []
        self._last_discovered_printers = []
        self._load_scan_upload_state()

    @staticmethod
    def _printer_type(value: str) -> str:
        return str(value or "").strip().lower()

    def _collector_service_for(self, printer: Printer) -> RicohService | ToshibaService:
        if self._toshiba_service is not None and self._printer_type(printer.printer_type) == "toshiba":
            return self._toshiba_service
        return self._ricoh_service

    @staticmethod
    def _device_info_probe_name(info: dict[str, Any]) -> tuple[str, str]:
        model_name = (
            str(info.get("Model Name", "") or "").strip()
            or str(info.get("Machine Name", "") or "").strip()
            or str(info.get("model_name", "") or "").strip()
            or str(info.get("Host Name", "") or "").strip()
            or str(info.get("host_name", "") or "").strip()
        )
        machine_id = (
            str(info.get("Machine ID", "") or "").strip()
            or str(info.get("machine_id", "") or "").strip()
        )
        return model_name, machine_id

    def _candidate_probe_types(self, preferred_type: str = "") -> list[str]:
        candidates: list[str] = []
        normalized = self._printer_type(preferred_type)
        if normalized in {"ricoh", "toshiba"}:
            candidates.append(normalized)
        if "ricoh" not in candidates:
            candidates.append("ricoh")
        if self._toshiba_service is not None and "toshiba" not in candidates:
            candidates.append("toshiba")
        return candidates

    def _resolve_scanned_mac(
        self,
        ip: str,
        row: dict[str, object],
        neighbor_mac_map: dict[str, str],
        preferred_type: str = "",
    ) -> str:
        mac = self._normalize_mac(str(row.get("mac_id", "") or row.get("mac_address", "") or ""))
        if not mac:
            mac = self._normalize_mac(neighbor_mac_map.get(ip, ""))
        if not mac and self._printer_type(preferred_type) == "ricoh":
            mac = self._normalize_mac(str(self._ricoh_service.fetch_mac_address_direct(ip) or "").strip())
        return mac

    def _probe_discovered_printer(
        self,
        *,
        ip: str,
        mac: str,
        preferred_type: str = "",
    ) -> Printer | None:
        for candidate_type in self._candidate_probe_types(preferred_type):
            collector = (
                self._toshiba_service
                if candidate_type == "toshiba" and self._toshiba_service is not None
                else self._ricoh_service
            )
            temp = Printer(
                name="Discovery",
                ip=ip,
                user="",
                password="",
                printer_type=candidate_type,
                mac_address=mac,
            )
            try:
                info_payload = collector.process_device_info(temp, should_post=False)
                info = info_payload.get("device_info", {}) if isinstance(info_payload, dict) else {}
                model_name, machine_id = self._device_info_probe_name(info if isinstance(info, dict) else {})
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug("Polling %s discovery probe failed: ip=%s error=%s", candidate_type, ip, exc)
                continue
            if not model_name and not machine_id:
                continue
            return Printer(
                id=0,
                name=model_name or machine_id or ip,
                ip=ip,
                user="",
                password="",
                printer_type=candidate_type,
                status="online",
                mac_address=mac,
            )
        return None

    def _fallback_discovery_candidates(
        self,
        active_rows: list[tuple[str, dict[str, object]]],
    ) -> list[tuple[str, dict[str, object]]]:
        preferred = [
            (ip, row)
            for ip, row in active_rows
            if bool(row.get("has_printer_ports")) or self._printer_type(str(row.get("printer_type", "") or "")) in {"ricoh", "toshiba"}
        ]
        return preferred or active_rows

    def _merge_server_printers(self, printers: list[Printer]) -> list[Printer]:
        try:
            server_printers = self._api_client.get_printers()
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Polling printer merge from server failed: %s", exc)
            return printers

        if not server_printers:
            return printers

        ordered: list[Printer] = list(printers)
        by_ip: dict[str, Printer] = {
            str(printer.ip or "").strip(): printer
            for printer in ordered
            if str(printer.ip or "").strip()
        }

        for printer in server_printers:
            ip = str(printer.ip or "").strip()
            if not ip:
                continue
            existing = by_ip.get(ip)
            if existing is None:
                ordered.append(printer)
                by_ip[ip] = printer
                continue
            if printer.id and not existing.id:
                existing.id = printer.id
            if str(printer.name or "").strip() and (
                not str(existing.name or "").strip() or str(existing.name or "").strip() == ip
            ):
                existing.name = printer.name
            if str(printer.user or "").strip():
                existing.user = printer.user
            if str(printer.password or "").strip():
                existing.password = printer.password
            if str(printer.printer_type or "").strip() and (
                self._printer_type(existing.printer_type) in {"", "unknown"}
                or self._printer_type(printer.printer_type) == "toshiba"
            ):
                existing.printer_type = printer.printer_type
            if str(printer.status or "").strip():
                existing.status = printer.status
            if str(printer.mac_address or "").strip() and not str(existing.mac_address or "").strip():
                existing.mac_address = printer.mac_address
        return ordered

    def _agent_runtime_metadata(self) -> dict[str, object]:
        version = ""
        if self._updater is not None:
            version = str(self._updater.status().get("current_version", "") or "")
        local_ip = self._resolve_local_ip()
        gateway_ip = self._resolve_default_gateway()
        gateway_mac = self._resolve_gateway_mac(gateway_ip) if gateway_ip else ""
        ftp_ports: list[str] = []
        ftp_sites: list[dict[str, object]] = []
        try:
            share_manager = getattr(self._ricoh_service, "share_manager", None)
            if share_manager is not None and hasattr(share_manager, "list_ftp_sites"):
                site_rows: list[dict[str, Any]] = []
                ports = []
                for site in share_manager.list_ftp_sites():
                    port = int(site.get("port", 0) or 0)
                    if port > 0:
                        ports.append(port)
                    site_rows.append(
                        {
                            "name": str(site.get("name", "") or ""),
                            "path": str(site.get("path", "") or ""),
                            "port": port,
                            "ftp_url": str(site.get("ftp_url", "") or ""),
                            "ftp_user": str(site.get("ftp_user", "") or ""),
                            "ftp_password": str(site.get("ftp_password", "") or ""),
                            "running": bool(site.get("running", False)),
                            "state": str(site.get("state", "configured") or "configured"),
                            "error": str(site.get("error", "") or ""),
                        }
                    )
                if ports:
                    ftp_ports = [str(port) for port in sorted(set(ports))]
                if site_rows:
                    ftp_sites = sorted(
                        site_rows,
                        key=lambda item: (
                            int(item.get("port", 0) or 0),
                            str(item.get("name", "") or ""),
                        ),
                    )
        except Exception:  # noqa: BLE001
            ftp_ports = []
            ftp_sites = []
        return {
            "app_version": version,
            "run_mode": self._run_mode,
            "web_port": self._web_port,
            "local_ip": local_ip,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "subnet_cidr": self._subnet_hint(local_ip),
            "ftp_ports": ",".join(ftp_ports),
            "ftp_sites": ftp_sites,
        }

    def is_configured(self) -> bool:
        return bool(self._config.get_string("polling.url").strip()) and bool(self._config.get_string("polling.lead").strip()) and bool(
            self._config.get_string("polling.token").strip()
        )

    def _config_issues(self) -> list[str]:
        issues: list[str] = []
        if not self._config.get_string("polling.url").strip():
            issues.append("missing polling.url")
        if not self._config.get_string("polling.lead").strip():
            issues.append("missing polling.lead")
        if not self._config.get_string("polling.token").strip():
            issues.append("missing polling.token")
        return issues

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_valid_lan_ipv4(value: str) -> bool:
        text = str(value or "").strip()
        parts = text.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(part) for part in parts]
        except Exception:  # noqa: BLE001
            return False
        if any(o < 0 or o > 255 for o in octets):
            return False
        if octets[0] == 127 or octets[0] == 0:
            return False
        if octets[0] == 169 and octets[1] == 254:
            return False
        if octets[0] == 100 and 64 <= octets[1] <= 127:
            return False
        return True

    @staticmethod
    def _ipv4_scope_score(value: str) -> int:
        text = str(value or "").strip()
        if not PollingBridge._is_valid_lan_ipv4(text):
            return -1
        octets = [int(part) for part in text.split(".")]
        if octets[0] == 10:
            return 300
        if octets[0] == 192 and octets[1] == 168:
            return 400
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return 350
        return 200

    @staticmethod
    def _resolve_local_ip() -> str:
        candidates: list[str] = []

        def _push(value: str) -> None:
            text = str(value or "").strip()
            if text and text not in candidates:
                candidates.append(text)

        hostname = socket.gethostname()
        try:
            host_info = socket.gethostbyname_ex(hostname)
            for value in host_info[2]:
                _push(value)
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
  Select-Object IPAddress,InterfaceAlias,PrefixOrigin,AddressState |
  ConvertTo-Json -Depth 4
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
                    ip = str(item.get("IPAddress", "") or "").strip()
                    if ip:
                        _push(ip)
        except Exception:  # noqa: BLE001
            pass

        best_ip = ""
        best_score = -1
        for candidate in candidates:
            score = PollingBridge._ipv4_scope_score(candidate)
            if score > best_score:
                best_ip = candidate
                best_score = score
        return best_ip or ""

    @staticmethod
    def _normalize_mac(value: str) -> str:
        text = str(value or "").strip().replace("-", ":").upper()
        if not text:
            return ""
        if not re.fullmatch(r"[0-9A-F:]{17}", text):
            return ""
        parts = text.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            return ""
        if text == "00:00:00:00:00:00":
            return ""
        return text

    @staticmethod
    def _sanitize_lan_token(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = text.replace("-", "_").replace(":", "_").replace(".", "_")
        text = re.sub(r"[^A-Za-z0-9_]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text

    @classmethod
    def _compose_lan_uid(cls, lead: str, gateway_mac: str, gateway_ip: str) -> str:
        lead_token = cls._sanitize_lan_token(lead)
        mac_token = cls._sanitize_lan_token(cls._normalize_mac(gateway_mac))
        ip_token = cls._sanitize_lan_token(cls._normalize_ipv4(gateway_ip))
        if lead_token and mac_token and ip_token:
            return f"{lead_token}_{mac_token}_{ip_token}"
        return ""

    def _load_neighbor_mac_map(self) -> dict[str, str]:
        script = r"""
$ErrorActionPreference='Stop'
Get-NetNeighbor -AddressFamily IPv4 |
  Select-Object IPAddress,LinkLayerAddress,State |
  ConvertTo-Json -Depth 4
"""
        try:
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
                mapping: dict[str, str] = {}
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    ip = str(item.get("IPAddress", "") or "").strip()
                    mac = self._normalize_mac(str(item.get("LinkLayerAddress", "") or ""))
                    if ip and mac:
                        mapping[ip] = mac
                if mapping:
                    return mapping
        except Exception:  # noqa: BLE001
            pass

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=8,
                check=True,
            )
        except Exception:  # noqa: BLE001
            return {}

        mapping: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})\s+\w+", line)
            if not match:
                continue
            ip = match.group(1)
            mac = self._normalize_mac(match.group(2))
            if mac:
                mapping[ip] = mac
        return mapping

    def interval_seconds(self) -> int:
        raw = self._config.get_string("polling.interval_seconds", "1").strip()
        try:
            value = int(raw)
            return max(1, value)
        except Exception:  # noqa: BLE001
            return 1

    def scan_enabled(self) -> bool:
        return self._config.get_bool("polling.scan_enabled", True)

    def scan_interval_seconds(self) -> int:
        return self.interval_seconds()

    def _scan_dirs(self) -> list[str]:
        raw = self._config.get_string("polling.scan_dirs", "").strip()
        if not raw:
            return ["storage/scans/inbox"]
        parts = re.split(r"[,;\n]+", raw)
        cleaned = [str(p).strip() for p in parts if str(p).strip()]
        return cleaned or ["storage/scans/inbox"]

    def _scan_recursive(self) -> bool:
        return self._config.get_bool("polling.scan_recursive", True)

    def start(self) -> tuple[bool, str]:
        if not self._config.get_bool("polling.enabled", False):
            LOGGER.info("Polling bridge disabled by config polling.enabled=false")
            return False, "Polling disabled"
        if not self.is_configured():
            issues = ", ".join(self._config_issues()) or "unknown"
            LOGGER.warning("Polling bridge not configured: %s", issues)
            return False, f"Polling not configured ({issues})"
        if self._thread and self._thread.is_alive():
            LOGGER.info("Polling bridge already running")
            return True, "Polling already running"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="polling-bridge")
        self._thread.start()
        self._control_thread = threading.Thread(target=self._control_loop, daemon=True, name="polling-control")
        self._control_thread.start()
        self._last_started_at = self._now_iso()
        LOGGER.info(
            "Polling bridge started: url=%s lead=%s interval=%ss",
            self._config.get_string("polling.url").strip(),
            self._config.get_string("polling.lead").strip(),
            self.interval_seconds(),
        )
        if self.scan_enabled():
            LOGGER.info("Scan uploads are merged into polling cycle: interval=%ss dirs=%s", self.scan_interval_seconds(), ",".join(self._scan_dirs()))
        return True, "Polling started"

    def stop(self) -> None:
        self._stop_event.set()
        self._trigger_event.set()
        try:
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3)
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._control_thread and self._control_thread.is_alive():
                self._control_thread.join(timeout=3)
        except Exception:  # noqa: BLE001
            pass
        LOGGER.info("Polling bridge stop requested")

    def trigger_once(self) -> tuple[bool, str]:
        if not self._config.get_bool("polling.enabled", False):
            return False, "Polling disabled"
        if not self.is_configured():
            issues = ", ".join(self._config_issues()) or "unknown"
            return False, f"Polling not configured ({issues})"
        if not (self._thread and self._thread.is_alive()):
            ok, message = self.start()
            if not ok:
                return False, message
        self._trigger_event.set()
        LOGGER.info("Polling trigger requested: immediate next cycle")
        return True, "Trigger queued"

    def status(self) -> dict[str, object]:
        issues = self._config_issues()
        return {
            "configured": self.is_configured(),
            "config_issues": issues,
            "enabled": self._config.get_bool("polling.enabled", False),
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds(),
            "url": self._config.get_string("polling.url"),
            "lead": self._config.get_string("polling.lead"),
            "last_started_at": self._last_started_at,
            "last_cycle_at": self._last_cycle_at,
            "last_success_at": self._last_success_at,
            "last_error": self._last_error,
            "last_cycle_total_printers": self._last_cycle_total_printers,
            "last_cycle_ricoh_printers": self._last_cycle_ricoh_printers,
            "last_cycle_sent": self._last_cycle_sent,
            "last_cycle_failed": self._last_cycle_failed,
            "last_control_pull_at": getattr(self, "_last_control_pull_at", ""),
            "last_control_total": getattr(self, "_last_control_total", 0),
            "last_control_apply_error": getattr(self, "_last_control_apply_error", ""),
            "last_ftp_control_pull_at": getattr(self, "_last_ftp_control_pull_at", ""),
            "last_ftp_control_total": getattr(self, "_last_ftp_control_total", 0),
            "last_ftp_control_apply_error": getattr(self, "_last_ftp_control_apply_error", ""),
            "resolved_lan_uid": getattr(self, "_resolved_lan_uid", ""),
            "scan_enabled": self.scan_enabled(),
            "scan_running": bool(self._thread and self._thread.is_alive()) if self.scan_enabled() else False,
            "scan_interval_seconds": self.scan_interval_seconds(),
            "scan_dirs": self._scan_dirs(),
            "scan_last_cycle_at": self._scan_last_cycle_at,
            "scan_last_detected_at": self._scan_last_detected_at,
            "scan_last_detected_file": self._scan_last_detected_file,
            "scan_last_detected_size": self._scan_last_detected_size,
            "scan_last_detected_status": self._scan_last_detected_status,
            "scan_last_upload_at": self._scan_last_upload_at,
            "scan_last_upload_file": self._scan_last_upload_file,
            "scan_last_upload_status": self._scan_last_upload_status,
            "scan_last_upload_drive_path": self._scan_last_upload_drive_path,
            "scan_last_error": self._scan_last_error,
            "scan_uploaded_total": self._scan_uploaded_total,
            "scan_failed_total": self._scan_failed_total,
            "scan_pending_total": self._scan_pending_total,
            "release_last_check_at": self._release_last_check_at,
            "release_last_error": self._release_last_error,
            "release_status": self._updater.status() if self._updater is not None else {},
        }

    def _load_printers(self) -> list[Printer]:
        try:
            scanner = SubnetScanner(max_workers=100)
            scan_rows = scanner.scan_subnet()
            neighbor_mac_map = self._load_neighbor_mac_map()
            printers: list[Printer] = []
            active_rows: list[tuple[str, dict[str, object]]] = []
            seen: set[str] = set()
            for row in scan_rows:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip", "") or "").strip()
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                active_rows.append((ip, row))
                printer_type = self._printer_type(str(row.get("printer_type", "") or ""))
                if printer_type not in {"ricoh", "toshiba"}:
                    continue
                mac = self._resolve_scanned_mac(ip, row, neighbor_mac_map, preferred_type=printer_type)
                discovered = self._probe_discovered_printer(ip=ip, mac=mac, preferred_type=printer_type)
                if discovered is None:
                    discovered = Printer(
                        id=0,
                        name=ip,
                        ip=ip,
                        user="",
                        password="",
                        printer_type=printer_type,
                        status="online",
                        mac_address=mac,
                    )
                printers.append(discovered)
                if not mac:
                    LOGGER.warning(
                        "Polling MAC unresolved for ip=%s type=%s (UI may still resolve from separate scan path)",
                        ip,
                        printer_type,
                    )
            if not printers and active_rows:
                LOGGER.info(
                    "Polling local scan found %s active hosts but no classified printer hits; probing device-info fallback",
                    len(active_rows),
                )
                for ip, row in self._fallback_discovery_candidates(active_rows):
                    preferred_type = self._printer_type(str(row.get("printer_type", "") or ""))
                    mac = self._resolve_scanned_mac(ip, row, neighbor_mac_map, preferred_type=preferred_type)
                    discovered = self._probe_discovered_printer(ip=ip, mac=mac, preferred_type=preferred_type)
                    if discovered is None:
                        continue
                    printers.append(discovered)
                    if not mac:
                        LOGGER.warning(
                            "Polling fallback MAC unresolved for ip=%s type=%s (printer was detected via device info)",
                            ip,
                            discovered.printer_type,
                        )
            if not printers and self._last_discovered_printers:
                printers = list(self._last_discovered_printers)
                LOGGER.info(
                    "Polling bridge using cached printer list: count=%s",
                    len(printers),
                )
            elif not printers:
                try:
                    cached = self._api_client.get_printers()
                    if cached:
                        printers = list(cached)
                        LOGGER.info(
                            "Polling bridge using server printer fallback: count=%s",
                            len(printers),
                        )
                except Exception as exc:  # noqa: BLE001
                    LOGGER.debug("Polling server printer fallback failed: %s", exc)
            printers = self._merge_server_printers(printers)
            ricoh_count = sum(1 for printer in printers if self._printer_type(printer.printer_type) == "ricoh")
            toshiba_count = sum(1 for printer in printers if self._printer_type(printer.printer_type) == "toshiba")
            LOGGER.info(
                "Polling bridge printers source=local_scan count=%s ricoh=%s toshiba=%s",
                len(printers),
                ricoh_count,
                toshiba_count,
            )
            if printers:
                self._last_discovered_printers = list(printers)
            return printers
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Polling bridge local scan failed: %s", exc)
            if self._last_discovered_printers:
                LOGGER.info(
                    "Polling bridge falling back to cached printers after scan error: count=%s",
                    len(self._last_discovered_printers),
                )
                return list(self._last_discovered_printers)
            try:
                cached = self._api_client.get_printers()
                if cached:
                    LOGGER.info(
                        "Polling bridge falling back to server printer list after scan error: count=%s",
                        len(cached),
                    )
                    self._last_discovered_printers = list(cached)
                    return cached
            except Exception as fallback_exc:  # noqa: BLE001
                LOGGER.debug("Polling bridge server printer fallback after scan error failed: %s", fallback_exc)
            return []

    def _post_payload(self, payload: dict) -> dict:
        self._write_last_payload(payload)
        base_url = self._polling_base_url()
        if not base_url:
            raise ValueError("polling.url is not configured")
        url = f"{base_url}/api/polling"
        token = self._config.get_string("polling.token").strip()
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        last_exc: Exception | None = None
        for attempt in range(1, 4):
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=(5, 30))
                resp.raise_for_status()
                try:
                    data = resp.json()
                    return data if isinstance(data, dict) else {"status_code": resp.status_code}
                except Exception:  # noqa: BLE001
                    return {"status_code": resp.status_code}
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < 3:
                    LOGGER.warning("Polling post failed (attempt %s/3): %s", attempt, exc)
                    time.sleep(2)
        if last_exc is not None:
            raise last_exc

    @staticmethod
    def _write_last_payload(payload: dict) -> None:
        LOGGER.debug("Polling payload kept in-memory only; not writing local snapshot")

    def _check_and_update_scripts(self, remote_scripts: dict[str, str]) -> None:
        if not remote_scripts or not isinstance(remote_scripts, dict):
            return
        
        import os
        from pathlib import Path
        temp_dir = os.environ.get("TEMP")
        if temp_dir:
            scripts_dir = Path(temp_dir) / "GoPrinxAgent" / "scripts"
        else:
            import tempfile
            scripts_dir = Path(tempfile.gettempdir()) / "GoPrinxAgent" / "scripts"
            
        try:
            scripts_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
            
        base_url = self._polling_base_url()
        if not base_url:
            return
            
        token = self._config.get_string("polling.token").strip()
        headers = {"X-Lead-Token": token}
        
        updated_any = False
        import hashlib
        
        for name, expected_hash in remote_scripts.items():
            script_path = scripts_dir / name
            current_hash = ""
            if script_path.exists():
                try:
                    current_hash = hashlib.md5(script_path.read_bytes()).hexdigest()
                except Exception:
                    pass
            
            if current_hash != expected_hash:
                LOGGER.info("Script %s needs update (local hash: %s, remote hash: %s)", name, current_hash, expected_hash)
                script_url = f"{base_url}/static/releases/{name}"
                try:
                    resp = requests.get(script_url, headers=headers, timeout=15)
                    if resp.status_code == 200:
                        script_path.write_bytes(resp.content)
                        LOGGER.info("Successfully updated dynamic script: %s", name)
                        updated_any = True
                    else:
                        LOGGER.warning("Failed to download script %s: status %s", name, resp.status_code)
                except Exception as exc:
                    LOGGER.warning("Error downloading script %s: %s", name, exc)
                    
        if updated_any:
            LOGGER.info("Dynamic scripts updated. Re-compiling...")
            try:
                from agent.main import load_dynamic_scripts
                load_dynamic_scripts()
            except Exception as exc:
                LOGGER.warning("Failed to reload dynamic scripts: %s", exc)

    @staticmethod
    def _normalize_ipv4(value: str) -> str:
        text = str(value or "").strip()
        if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", text):
            return ""
        parts = text.split(".")
        if any(int(p) > 255 for p in parts):
            return ""
        return ".".join(str(int(p)) for p in parts)

    @staticmethod
    def _subnet_hint(ipv4: str) -> str:
        ip = PollingBridge._normalize_ipv4(ipv4)
        if not ip:
            return ""
        parts = ip.split(".")
        return ".".join(parts[:3]) + ".0/24"

    @staticmethod
    def _mac_address() -> str:
        node = uuid.getnode()
        raw = f"{node:012x}".upper()
        return ":".join(raw[i : i + 2] for i in range(0, 12, 2))

    def _resolve_lan_from_server(self, printer_macs: list[str]) -> str:
        """
        Ask the server: "anyone on this lead already owns these MAC addresses?"
        Returns lan_uid string if found, empty string otherwise.
        Called during agent startup before computing local fingerprint so that
        all agents on the same LAN automatically share the same lan_uid.
        """
        base_url = self._polling_base_url()
        if not base_url:
            return ""
        lead = self._config.get_string("polling.lead", "").strip()
        token = self._config.get_string("polling.token", "").strip()
        if not lead or not token:
            return ""
        clean = [m for m in (self._normalize_mac(m) for m in printer_macs) if m]
        if not clean:
            return ""
        try:
            url = f"{base_url}/api/agent/resolve-lan"
            payload = {
                "lead": lead,
                "mac_ids": clean,
                "subnet": self._subnet_hint(self._resolve_local_ip()),   # e.g. "192.168.1.0/24"
                "gateway_ip": self._resolve_default_gateway(),           # e.g. "192.168.1.1"
                "gateway_mac": self._resolve_gateway_mac(self._resolve_default_gateway()),
            }
            headers = {"Content-Type": "application/json", "X-Lead-Token": token}
            resp = requests.post(url, json=payload, headers=headers, timeout=(4, 10))
            if resp.status_code == 200:
                data = resp.json()
                server_uid = str(data.get("lan_uid") or "").strip()
                if server_uid:
                    LOGGER.info(
                        "resolve-lan: server matched mac=%s -> lan_uid=%s",
                        data.get("matched_mac"), server_uid,
                    )
                    return server_uid
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("resolve-lan server lookup failed (non-critical): %s", exc)
        return ""

    @staticmethod
    def _resolve_default_gateway() -> str:
        script = r"""
$ErrorActionPreference='SilentlyContinue'
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
  Sort-Object RouteMetric,InterfaceMetric |
  Select-Object -First 1 -ExpandProperty NextHop
if ($r) { $r }
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
                **no_window_subprocess_kwargs(),
            )
            return PollingBridge._normalize_ipv4(result.stdout.strip())
        except Exception:  # noqa: BLE001
            return ""



    @staticmethod
    def _resolve_gateway_mac(gateway_ip: str) -> str:
        ip = PollingBridge._normalize_ipv4(gateway_ip)
        if not ip:
            return ""
        script = rf"""
$ErrorActionPreference='SilentlyContinue'
$ip = '{ip}'
$node = (Get-NetNeighbor -AddressFamily IPv4 | Where-Object {{ $_.IPAddress -eq $ip }} | Select-Object -First 1 -ExpandProperty LinkLayerAddress)
if ($node) {{ $node }}
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
                **no_window_subprocess_kwargs(),
            )
            mac = PollingBridge._normalize_mac(result.stdout.strip())
            if mac:
                return mac
        except Exception:  # noqa: BLE001
            pass
        try:
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
                **no_window_subprocess_kwargs(),
            )
            match = re.search(r"\b([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", result.stdout or "")
            if not match:
                return ""
            return match.group(1).replace("-", ":").upper()
        except Exception:  # noqa: BLE001
            return ""

    def _resolve_lan_info(self, hostname: str, local_ip: str) -> tuple[str, str]:
        """
        Returns (lan_uid, fingerprint_signature)

        Resolution order:
        1. Derive LAN UID from lead + gateway MAC + gateway IP.
        2. Reuse the last successfully derived LAN UID if the current network
           lookup is temporarily unavailable.

        The agent no longer generates legacy temporary LAN identifiers.
        """
        gateway_ip = self._resolve_default_gateway()
        gateway_mac = self._resolve_gateway_mac(gateway_ip) if gateway_ip else ""
        subnet = self._subnet_hint(local_ip)
        local_mac = self._mac_address()
        lead = self._config.get_string("polling.lead", "").strip()

        lan_core_parts = [
            f"lead={lead}",
            f"subnet={subnet}",
            f"gateway_ip={gateway_ip}",
        ]
        if gateway_mac:
            lan_core_parts.append(f"gateway_mac={gateway_mac}")
        if not gateway_ip and not subnet:
            lan_core_parts.append(f"fallback_local_mac={local_mac}")
            lan_core_parts.append(f"fallback_hostname={hostname}")
        signature = "|".join(lan_core_parts)

        composed_uid = self._compose_lan_uid(lead, gateway_mac, gateway_ip)
        if composed_uid:
            self._resolved_lan_uid = composed_uid
            return composed_uid, signature

        if self._resolved_lan_uid:
            return self._resolved_lan_uid, signature

        return "", signature

    def _polling_base_url(self) -> str:
        raw = self._config.get_string("polling.url").strip()
        if not raw:
            return ""
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def _scan_upload_url(self) -> str:
        base = self._polling_base_url()
        if not base:
            return ""
        return f"{base}/api/polling/scan-upload"

    def _check_for_agent_update(self, lead: str, lan_uid: str, agent_uid: str, hostname: str, local_ip: str) -> bool:
        if self._updater is None or not self._updater.should_check():
            return False
        base_url = self._polling_base_url()
        token = self._config.get_string("polling.token").strip()
        if not base_url or not token or not lead:
            return False
        self._release_last_check_at = self._now_iso()
        ok, message, restart_required = self._updater.check_remote_release(
            session=self._api_client.session,
            base_url=base_url,
            token=token,
            lead=lead,
            agent_uid=agent_uid,
            lan_uid=lan_uid,
            hostname=hostname,
            local_ip=local_ip,
        )
        if ok:
            self._release_last_error = ""
            LOGGER.info("Agent release check: %s", message)
        else:
            self._release_last_error = message
            LOGGER.warning("Agent release check failed: %s", message)
        if restart_required:
            if self._restart_callback is not None:
                try:
                    self._restart_callback()
                except Exception as exc:  # noqa: BLE001
                    LOGGER.warning("Restart callback failed: %s", exc)
            self._stop_event.set()
            self._trigger_event.set()
            return True
        return False

    def _register_with_server(
        self,
        lead: str,
        lan_uid: str,
        agent_uid: str,
        hostname: str,
        local_ip: str,
        fingerprint: str,
    ) -> str:
        base_url = self._polling_base_url()
        token = self._config.get_string("polling.token").strip()
        if not base_url or not token or not lead:
            return lan_uid
        reg_url = f"{base_url}/api/agent/register"
        reg_payload = {
            "lead": lead,
            "lan_uid": lan_uid,
            "agent_uid": agent_uid,
            "hostname": hostname,
            "local_ip": local_ip,
            "local_mac": self._mac_address(),
            "gateway_ip": self._resolve_default_gateway(),
            "gateway_mac": self._resolve_gateway_mac(self._resolve_default_gateway()),
            "fingerprint_signature": fingerprint,
        }
        reg_payload.update(self._agent_runtime_metadata())
        reg_headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        reg_resp = requests.post(reg_url, json=reg_payload, headers=reg_headers, timeout=20)
        if reg_resp.ok:
            server_data = reg_resp.json()
            server_lan_uid = str(server_data.get("lan_uid") or "").strip()
            if server_lan_uid and server_lan_uid != lan_uid:
                LOGGER.info("Server reassigned lan_uid: %s -> %s", lan_uid, server_lan_uid)
                lan_uid = server_lan_uid
            self._resolved_lan_uid = lan_uid
            
            self._is_master = bool(server_data.get("is_master", False))
            self._emails = server_data.get("emails") if isinstance(server_data.get("emails"), list) else []
            try:
                self._reconcile_scan_address_ftp(self._is_master, self._emails)
            except Exception as ftp_exc:
                LOGGER.warning("FTP reconciliation failed during registration: %s", ftp_exc)
        return lan_uid

    @staticmethod
    def _is_scan_candidate(path: Path) -> bool:
        name = path.name.lower()
        if name.endswith((".tmp", ".part", ".partial", ".crdownload")):
            return False
        return path.is_file()

    @staticmethod
    def _scan_root_label(root: Path) -> str:
        label = str(root.name or root.drive or "scan-root").strip()
        label = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip(" -_.")
        return label or "scan-root"

    @staticmethod
    def _relative_scan_path(root: Path, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(root.resolve())
        except Exception:
            try:
                relative = path.relative_to(root)
            except Exception:
                relative = Path(path.name)
        return relative.as_posix()

    def _iter_scan_files(self) -> list[tuple[Path, Path]]:
        files: list[tuple[Path, Path]] = []
        recursive = self._scan_recursive()
        for raw in self._scan_dirs():
            try:
                root = Path(raw).expanduser()
                ensure_active_drop_folder(root)
                iterator = root.rglob("*") if recursive else root.glob("*")
                for item in iterator:
                    if self._is_scan_candidate(item):
                        files.append((root, item))
            except Exception:  # noqa: BLE001
                continue
        files.sort(key=lambda item: str(item[1]))
        return files

    @staticmethod
    def _file_fingerprint(path: Path, size: int, mtime_ns: int) -> str:
        return f"{path.resolve()}|{size}|{mtime_ns}"

    def _load_scan_upload_state(self) -> None:
        path = SCAN_UPLOAD_STATE_FILE
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            uploaded = payload.get("uploaded_fingerprints", {}) if isinstance(payload, dict) else {}
            cleaned: dict[str, str] = {}
            if isinstance(uploaded, dict):
                for key, value in uploaded.items():
                    finger = str(key or "").strip()
                    stamp = str(value or "").strip()
                    if finger:
                        cleaned[finger] = stamp
            self._scan_uploaded_fingerprints = cleaned
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to load scan upload state: %s", exc)

    def _save_scan_upload_state(self) -> None:
        try:
            items = sorted(
                self._scan_uploaded_fingerprints.items(),
                key=lambda item: item[1],
            )
            if len(items) > MAX_SCAN_UPLOAD_HISTORY:
                items = items[-MAX_SCAN_UPLOAD_HISTORY:]
            payload = {
                "updated_at": self._now_iso(),
                "uploaded_fingerprints": {key: value for key, value in items},
            }
            SCAN_UPLOAD_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            SCAN_UPLOAD_STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to save scan upload state: %s", exc)

    def _upload_scan_file(
        self,
        root: Path,
        path: Path,
        fingerprint: str,
        lead: str,
        lan_uid: str,
        agent_uid: str,
        hostname: str,
        local_ip: str,
    ) -> None:
        url = self._scan_upload_url()
        token = self._config.get_string("polling.token").strip()
        if not url or not token:
            raise RuntimeError("Scan upload endpoint/token not configured")
        headers = {"X-Lead-Token": token}
        now_iso = datetime.now(timezone.utc).isoformat()
        rel_path = str(path.resolve())
        relative_scan_path = self._relative_scan_path(root, path)
        data = {
            "lead": lead,
            "lan_uid": lan_uid,
            "agent_uid": agent_uid,
            "hostname": hostname,
            "local_ip": local_ip,
            "timestamp": now_iso,
            "source_path": rel_path,
            "source_root": str(root.resolve()),
            "source_root_label": self._scan_root_label(root),
            "source_relative_path": relative_scan_path,
            "fingerprint": fingerprint,
        }
        with path.open("rb") as fp:
            files = {"file": (path.name, fp, "application/octet-stream")}
            resp = self._api_client.session.post(url, data=data, files=files, headers=headers, timeout=(10, 120))
        resp.raise_for_status()
        payload: dict[str, object] = {}
        if "json" in (resp.headers.get("Content-Type", "").lower()):
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:  # noqa: BLE001
                payload = {}
        self._scan_uploaded_fingerprints[fingerprint] = now_iso
        self._scan_uploaded_total += 1
        self._scan_last_upload_at = self._now_iso()
        self._scan_last_error = ""
        self._save_scan_upload_state()
        return payload

    def _get_owned_emails(self, is_master: bool, emails: list[dict]) -> list[dict]:
        import socket
        hostname = socket.gethostname().strip().lower()
        owned = []
        for em in (emails or []):
            etype = str(em.get("email_type") or "common").strip().lower()
            if etype == "private":
                epc = str(em.get("pc_name") or "").strip().lower()
                if epc == hostname:
                    owned.append(em)
            else:  # common
                if is_master:
                    owned.append(em)
        return owned

    def _reconcile_scan_address_ftp(self, is_master: bool, emails: list[dict]) -> None:
        share_manager = getattr(self._ricoh_service, "share_manager", None)
        if share_manager is None:
            LOGGER.warning("share_manager not available in ricoh_service; skipping FTP reconciliation")
            return

        owned_emails = self._get_owned_emails(is_master, emails)
        LOGGER.info("Reconciling FTP scan addresses: is_master=%s, total_emails=%d, owned_count=%d", 
                    is_master, len(emails) if emails else 0, len(owned_emails))

        # 1. Fetch current FTP sites
        try:
            current_sites = share_manager.list_ftp_sites()
        except Exception as exc:
            LOGGER.warning("Failed to list FTP sites: %s", exc)
            current_sites = []

        # 2. Determine target sites
        target_site_names = set()
        target_ports = set()
        
        if owned_emails:
            for em in owned_emails:
                email = str(em.get("email") or "").strip()
                port = int(em.get("email_number") or 0)
                if not email or port <= 0:
                    continue
                site_name = normalize_site_name(f"gox_scan_{email}")
                target_site_names.add(site_name)
                target_ports.add(port)

                # Ensure local directory C:/Scangox/{email} exists
                local_dir = Path("C:/Scangox") / email
                try:
                    if not local_dir.exists():
                        local_dir.mkdir(parents=True, exist_ok=True)
                        LOGGER.info("Created scan address folder: %s", local_dir)
                except Exception as exc:
                    LOGGER.error("Failed to create scan folder %s: %s", local_dir, exc)
                
                # Check if this FTP site is already configured and matches
                existing = next((s for s in current_sites if str(s.get("name")) == site_name), None)
                if existing:
                    existing_port = int(existing.get("port") or 0)
                    existing_path = str(existing.get("path") or "")
                    if existing_port != port or Path(existing_path).resolve() != local_dir.resolve():
                        LOGGER.info("FTP site %s matches but has different configuration (port %s->%s, path %s->%s). Updating.",
                                    site_name, existing_port, port, existing_path, local_dir)
                        try:
                            share_manager.update_ftp_site(
                                site_name,
                                local_path=local_dir,
                                port=port
                            )
                        except Exception as exc:
                            LOGGER.warning("Failed to update FTP site %s: %s", site_name, exc)
                else:
                    LOGGER.info("Creating new FTP site %s on port %d pointing to %s", site_name, port, local_dir)
                    try:
                        share_manager.create_ftp_site(
                            site_name=site_name,
                            local_path=local_dir,
                            port=port
                        )
                    except Exception as exc:
                        LOGGER.warning("Failed to create FTP site %s: %s", site_name, exc)

        # 3. Clean up any FTP sites starting with "gox_scan_" that are no longer owned by this agent
        for site in current_sites:
            name = str(site.get("name") or "")
            if name.startswith("gox_scan_"):
                if name not in target_site_names:
                    LOGGER.info("Deleting obsolete/inactive FTP site: %s", name)
                    try:
                        share_manager.delete_ftp_site(name)
                    except Exception as exc:
                        LOGGER.warning("Failed to delete FTP site %s: %s", name, exc)

    @staticmethod
    def _safe_int(value: object) -> int:
        try:
            return int(str(value or "0").replace(",", "").strip() or "0")
        except Exception:  # noqa: BLE001
            return 0

    def _has_new_scan_counter(self, ip: str, counter_data: dict[str, object]) -> bool:
        ip_key = str(ip or "").strip()
        if not ip_key:
            return False
        scan_bw = self._safe_int(counter_data.get("scanner_send_bw"))
        scan_color = self._safe_int(counter_data.get("scanner_send_color"))
        total_scan = max(0, scan_bw) + max(0, scan_color)
        previous = self._scan_counter_last_by_ip.get(ip_key)
        self._scan_counter_last_by_ip[ip_key] = total_scan
        if previous is None:
            return False
        return total_scan > previous

    def _run_scan_cycle(
        self,
        lead: str,
        lan_uid: str,
        agent_uid: str,
        hostname: str,
        local_ip: str,
        fingerprint: str,
        reason: str = "timer",
    ) -> None:
        if not self._scan_lock.acquire(blocking=False):
            return
        try:
            self._scan_last_cycle_at = self._now_iso()
            files = self._iter_scan_files()
            pending_total = 0
            active_keys: set[str] = set()
            for root, path in files:
                try:
                    stat = path.stat()
                except Exception:  # noqa: BLE001
                    continue
                size = int(stat.st_size or 0)
                mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
                if size <= 0:
                    continue
                key = str(path.resolve())
                active_keys.add(key)
                state = self._scan_file_state.get(key, {"size": -1, "mtime_ns": -1, "stable": 0})
                same = int(state.get("size", -1)) == size and int(state.get("mtime_ns", -1)) == mtime_ns
                previously_seen = int(state.get("size", -1)) >= 0
                stable = int(state.get("stable", 0)) + 1 if same else 0
                state = {"size": size, "mtime_ns": mtime_ns, "stable": stable}
                self._scan_file_state[key] = state
                if not previously_seen:
                    self._scan_last_detected_at = self._now_iso()
                    self._scan_last_detected_file = key
                    self._scan_last_detected_size = size
                    self._scan_last_detected_status = "new"
                    LOGGER.info("Scan file detected: file=%s size=%s reason=%s stage=new", path, size, reason)
                elif not same:
                    self._scan_last_detected_at = self._now_iso()
                    self._scan_last_detected_file = key
                    self._scan_last_detected_size = size
                    self._scan_last_detected_status = "changed"
                    LOGGER.info("Scan file changed: file=%s size=%s reason=%s stage=changed", path, size, reason)
                elif stable == 1:
                    self._scan_last_detected_at = self._now_iso()
                    self._scan_last_detected_file = key
                    self._scan_last_detected_size = size
                    self._scan_last_detected_status = "waiting"
                    LOGGER.info("Scan file pending: file=%s size=%s reason=%s stage=stable-1/2", path, size, reason)
                if stable < 2:
                    pending_total += 1
                    continue
                file_finger = self._file_fingerprint(path=path, size=size, mtime_ns=mtime_ns)
                if file_finger in self._scan_uploaded_fingerprints:
                    continue
                try:
                    self._scan_last_upload_file = key
                    self._scan_last_upload_status = "uploading"
                    self._scan_last_upload_drive_path = ""
                    LOGGER.info("Scan upload start: file=%s size=%s reason=%s", path, size, reason)
                    upload_payload = self._upload_scan_file(root, path, file_finger, lead, lan_uid, agent_uid, hostname, local_ip)
                    drive_sync = upload_payload.get("drive_sync") if isinstance(upload_payload, dict) and isinstance(upload_payload.get("drive_sync"), dict) else {}
                    drive_path = str(drive_sync.get("drive_path", "") or "").strip()
                    self._scan_last_upload_file = key
                    self._scan_last_upload_status = "ok"
                    self._scan_last_upload_drive_path = drive_path
                    LOGGER.info("Scan upload ok: file=%s size=%s reason=%s drive=%s", path, size, reason, drive_path or "-")
                except Exception as exc:  # noqa: BLE001
                    self._scan_failed_total += 1
                    pending_total += 1
                    self._scan_last_upload_file = key
                    self._scan_last_upload_status = "failed"
                    self._scan_last_upload_drive_path = ""
                    self._scan_last_error = str(exc)
                    LOGGER.warning("Scan upload failed: file=%s reason=%s error=%s", path, reason, exc)
            stale_keys = [k for k in self._scan_file_state.keys() if k not in active_keys]
            for key in stale_keys:
                self._scan_file_state.pop(key, None)
            self._scan_pending_total = pending_total
        except Exception as exc:  # noqa: BLE001
            self._scan_last_error = str(exc)
            LOGGER.warning("Scan watcher cycle failed: reason=%s error=%s", reason, exc)
        finally:
            self._scan_lock.release()

    def _pull_device_controls(self, lan_uid: str) -> dict[str, dict[str, object]]:
        base_url = self._polling_base_url()
        if not base_url:
            return {}
        token = self._config.get_string("polling.token").strip()
        lead = self._config.get_string("polling.lead").strip()
        params = {"lead": lead, "lan_uid": lan_uid, "agent_uid": self._agent_uid}
        headers = {"Accept": "application/json", "X-Lead-Token": token}
        url = f"{base_url}/api/polling/controls"
        response = self._api_client.session.get(url, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("rows", []) if isinstance(payload, dict) else []
        mapping: dict[str, dict[str, object]] = {}
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip", "") or "").strip()
                if not ip:
                    continue
                command = row.get("command") if isinstance(row.get("command"), dict) else None
                mapping[ip] = {
                    "enabled": bool(row.get("enabled", True)),
                    "command": command,
                }
        self._last_control_pull_at = self._now_iso()
        self._last_control_total = len(mapping)
        return mapping

    def _push_inventory(self, printers: list[Printer], hostname: str, local_ip: str, lan_uid: str, fingerprint: str = "") -> None:
        base_url = self._polling_base_url()
        if not base_url:
            return
        token = self._config.get_string("polling.token").strip()
        lead = self._config.get_string("polling.lead").strip()
        agent_uid = self._agent_uid or hostname
        devices: list[dict[str, str]] = []
        for printer in printers:
            devices.append(
                {
                    "printer_name": str(printer.name or "").strip(),
                    "ip": str(printer.ip or "").strip(),
                    "mac_address": str(printer.mac_address or "").strip(),
                    "printer_type": str(printer.printer_type or "").strip(),
                    "status": str(printer.status or "").strip(),
                    "user": str(printer.user or "").strip(),
                }
            )
        payload = {
            "lead": lead,
            "lan_uid": lan_uid,
            "agent_uid": agent_uid,
            "hostname": hostname,
            "local_ip": local_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "devices": devices,
            "fingerprint_signature": fingerprint,
        }
        payload.update(self._agent_runtime_metadata())
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        url = f"{base_url}/api/polling/inventory"
        response = self._api_client.session.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

    def _log_control_event(self, printer: Printer, enabled: bool, result: str, detail: str = "") -> None:
        LOGGER.info(
            "Control event: timestamp=%s printer=%s ip=%s enabled=%s action=%s result=%s detail=%s",
            datetime.now(timezone.utc).isoformat(),
            str(printer.name or ""),
            str(printer.ip or ""),
            str(bool(enabled)).lower(),
            "enable" if enabled else "lock",
            result,
            detail,
        )

    def _apply_machine_control(self, printer: Printer, enabled: bool) -> None:
        ip = str(printer.ip or "").strip()
        if not ip:
            return
        retry_after = self._control_retry_after.get(ip)
        if retry_after and retry_after > datetime.now(timezone.utc):
            return
        current = self._applied_controls.get(ip)
        if current is enabled:
            return
        if not str(printer.user or "").strip():
            printer.user = self._config.get_string("test.user", "").strip()
        if not str(printer.password or "").strip():
            printer.password = self._config.get_string("test.password", "").strip()
        action = "enable" if enabled else "lock"
        LOGGER.info("Applying machine control: action=%s name=%s ip=%s", action, printer.name, ip)
        try:
            if enabled:
                self._ricoh_service.enable_machine(printer)
            else:
                self._ricoh_service.lock_machine(printer)
            self._applied_controls[ip] = enabled
            self._control_retry_after.pop(ip, None)
            self._last_control_apply_error = ""
            self._log_control_event(printer, enabled, "ok", "")
        except Exception as exc:  # noqa: BLE001
            cooldown_seconds = 300
            retry_at = datetime.now(timezone.utc) + timedelta(seconds=cooldown_seconds)
            self._control_retry_after[ip] = retry_at
            self._log_control_event(printer, enabled, "error", str(exc))
            LOGGER.warning(
                "Control apply cooldown: name=%s ip=%s retry_after=%s",
                printer.name,
                ip,
                retry_at.isoformat(),
            )
            raise

    def _post_control_result(self, command_id: int, ok: bool, error: str = "", address_book_data: dict[str, Any] | None = None) -> None:
        base_url = self._polling_base_url()
        if not base_url:
            return
        token = self._config.get_string("polling.token").strip()
        lead = self._config.get_string("polling.lead").strip()
        url = f"{base_url}/api/polling/control-result"
        payload = {
            "lead": lead,
            "command_id": int(command_id),
            "ok": bool(ok),
            "error": str(error or ""),
        }
        if address_book_data:
            payload["address_book_data"] = address_book_data
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        response = self._api_client.session.post(url, json=payload, headers=headers, timeout=20)
        response.raise_for_status()
    def _resolve_ftp_target_printer(self, command: FtpControlCommand, site_name: str) -> tuple[Printer, str]:
        fallback = Printer(
            id=0,
            name=command.printer_name or site_name,
            ip=command.printer_ip,
            user=command.printer_auth_user,
            password=command.printer_auth_password,
            printer_type="ricoh",
            status="online",
            mac_address=command.printer_mac_id,
        )
        normalized_mac = self._normalize_mac(command.printer_mac_id)
        if not normalized_mac:
            return fallback, ""
        try:
            printers = self._load_printers()
        except Exception as exc:  # noqa: BLE001
            return (
                fallback,
                f"Could not refresh printer discovery for mac_id {normalized_mac}; using queued printer IP {command.printer_ip or '-'}. Error: {exc}",
            )
        matched = next(
            (
                item
                for item in printers
                if self._normalize_mac(str(item.mac_address or "")) == normalized_mac
            ),
            None,
        )
        if matched is None:
            return (
                fallback,
                f"Printer mac_id {normalized_mac} was not found in current agent discovery; using queued printer IP {command.printer_ip or '-'}.",
            )
        matched.user = command.printer_auth_user or matched.user
        matched.password = command.printer_auth_password or matched.password
        warning = ""
        if command.printer_ip and matched.ip and matched.ip != command.printer_ip:
            warning = f"Printer mac_id {normalized_mac} moved from {command.printer_ip} to {matched.ip}; using current IP."
        if command.printer_name and not matched.name:
            matched.name = command.printer_name
        return matched, warning

    def _apply_ftp_command(self, command: FtpControlCommand) -> None:
        command_id = int(command.id or 0)
        if command_id <= 0:
            return
        action = command.action
        site_name = command.site_name
        new_site_name = command.new_site_name
        local_path = command.local_path
        port = int(command.port or 0) or 2121
        share_manager = getattr(self._ricoh_service, "share_manager", None)
        if share_manager is None:
            raise RuntimeError("FTP share manager not available")
        result_warning_parts: list[str] = []
        if action == "create":
            if not site_name:
                raise RuntimeError("Missing ftp site_name")
            printer, resolve_warning = self._resolve_ftp_target_printer(command, site_name)
            if resolve_warning:
                result_warning_parts.append(resolve_warning)
            display_name = site_name
            local_leaf = str(Path(local_path).name or "").strip() if local_path else ""
            if local_leaf:
                display_name = local_leaf
            setup_fields = {"entryTypeIn": "1"}
            result = self._ricoh_service.setup_scan_destination(
                printer,
                username=display_name,
                fields=setup_fields,
                ftp_site_name=site_name,
                ftp_root=local_path or command.default_local_path,
                ftp_port=port,
                ftp_user=command.ftp_user,
                ftp_password=command.ftp_password,
            )
        elif action == "update":
            result = share_manager.update_ftp_site(
                site_name,
                new_site_name=new_site_name or None,
                local_path=local_path or None,
                port=port or None,
                ftp_user=command.ftp_user or None,
                ftp_password=command.ftp_password or None,
            )
        elif action == "delete":
            result = share_manager.delete_ftp_site(site_name)
        else:
            raise RuntimeError(f"Unsupported ftp action: {action}")
        if not bool(result.get("ok", False)):
            raise RuntimeError(str(result.get("error", "FTP command failed")) or "FTP command failed")
        warning = str(result.get("warning", "") or "").strip()
        if warning:
            result_warning_parts.append(warning)
        warning = " ".join(part for part in result_warning_parts if str(part or "").strip()).strip()
        if warning:
            LOGGER.warning(
                "Polling FTP command warning: command_id=%s site=%s mac_id=%s warning=%s",
                command_id,
                site_name,
                command.printer_mac_id,
                warning,
            )
        self._applied_ftp_controls[site_name or str(command_id)] = True
        self._post_ftp_control_result(command_id=command_id, ok=True, error="", warning=warning)

    def _apply_command(self, printer: Printer, command: dict[str, object]) -> None:
        command_id = int(command.get("id", 0) or 0)
        desired_enabled = bool(command.get("desired_enabled", True))
        command_type = str(command.get("command_type", "enable_disable")).strip().lower()
        if command_id <= 0:
            return
        auth_user = str(command.get("auth_user", "") or "").strip()
        auth_password = str(command.get("auth_password", "") or "").strip()
        if auth_user:
            printer.user = auth_user
        if auth_password:
            printer.password = auth_password

        if command_type == "install_driver":
            try:
                driver_brand = str(command.get("driver_brand", "") or "").strip()
                driver_model = str(command.get("driver_model", "") or "").strip()
                driver_name = str(command.get("driver_name", "") or "").strip()
                driver_url = str(command.get("driver_url", "") or "").strip()
                
                self._handle_install_driver(
                    printer_ip=printer.ip,
                    brand=driver_brand,
                    model=driver_model,
                    driver_name=driver_name,
                    driver_url=driver_url,
                )
                self._post_control_result(command_id=command_id, ok=True, error="")
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("Failed to install driver for printer %s: %s", printer.ip, exc)
                self._post_control_result(command_id=command_id, ok=False, error=str(exc))
            return

        if command_type == "fetch_address_book":
            import socket
            LOGGER.info("[PollingBridge] === START fetch_address_book command: ID=%s, printer=%s (IP=%s) ===", command_id, printer.name, printer.ip)
            try:
                # 1. On-demand sync of emails first
                result_dict = {}
                latest_emails = []
                try:
                    base_url = self._polling_base_url()
                    if base_url:
                        token = self._config.get_string("polling.token").strip()
                        lead = self._config.get_string("polling.lead").strip()
                        lan_uid = printer.lan_uid or getattr(self, "_resolved_lan_uid", "")
                        headers = {"Accept": "application/json", "X-Lead-Token": token}
                        url = f"{base_url}/api/lan-emails"
                        LOGGER.info("[PollingBridge] Fetching latest emails from %s for on-demand reconciliation...", url)
                        resp = self._api_client.session.get(
                            url,
                            params={"lead": lead, "lan_uid": lan_uid, "agent_uid": self._agent_uid},
                            headers=headers,
                            timeout=15
                        )
                        if resp.ok:
                            emails_data = resp.json()
                            latest_emails = emails_data.get("rows", [])
                            self._emails = latest_emails
                            if "is_master" in emails_data:
                                self._is_master = bool(emails_data["is_master"])
                            LOGGER.info("[PollingBridge] Successfully fetched %d latest emails from server for on-demand reconciliation (is_master=%s).", len(latest_emails), self._is_master)
                        else:
                            LOGGER.warning("[PollingBridge] Failed to fetch latest emails from server, status=%s", resp.status_code)
                except Exception as fetch_exc:
                    LOGGER.warning("[PollingBridge] Exception fetching latest emails: %s", fetch_exc)

                emails_list = latest_emails or getattr(self, "_emails", None) or []
                if emails_list:
                    local_ip = self._resolve_local_ip()
                    my_hostname = socket.gethostname().strip().lower()
                    LOGGER.info("[PollingBridge] Processing %d emails for on-demand reconciliation. Hostname: %s, Local IP: %s", len(emails_list), my_hostname, local_ip)
                    for em in emails_list:
                        etype = str(em.get("email_type") or "common").strip().lower()
                        email = str(em.get("email") or "").strip().lower()
                        port = int(em.get("email_number") or 0)
                        if not email or port <= 0:
                            continue
                        if etype == "common":
                            # For on-demand reconciliation via command execution, we bypass the strict self._is_master check to ensure immediate synchronization.
                            result_dict[email] = (local_ip, port)
                        elif etype == "private":
                            pc_name = str(em.get("pc_name") or "").strip().lower()
                            if pc_name == my_hostname:
                                result_dict[email] = (local_ip, port)
                LOGGER.info("[PollingBridge] Emails filtered for on-demand reconciliation: %s", list(result_dict.keys()))
                if result_dict:
                    try:
                        LOGGER.info("[PollingBridge] Calling _reconcile_single_printer_address_book for %s...", printer.ip)
                        reconcile_res = self._reconcile_single_printer_address_book(printer, result_dict)
                        LOGGER.info("[PollingBridge] _reconcile_single_printer_address_book finished: %s", reconcile_res)
                    except Exception as rec_exc:
                        LOGGER.warning("[PollingBridge] On-demand reconciliation failed for printer %s: %s", printer.ip, rec_exc)

                # 2. Fetch the entire address book of the Ricoh machine
                LOGGER.info("[PollingBridge] Calling process_address_list for %s...", printer.ip)
                result = self._ricoh_service.process_address_list(printer)
                LOGGER.info("[PollingBridge] process_address_list returned %d items", len(result.get("address_list", []) if isinstance(result, dict) else []))
                LOGGER.info("[PollingBridge] Posting control result back to server for command ID: %s", command_id)
                self._post_control_result(command_id=command_id, ok=True, error="", address_book_data=result)
                LOGGER.info("[PollingBridge] === FINISH fetch_address_book command: ID=%s Success ===", command_id)
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("[PollingBridge] Failed to fetch address book for printer %s: %s", printer.ip, exc, exc_info=True)
                self._post_control_result(command_id=command_id, ok=False, error=str(exc))
                raise
            return

        try:
            self._apply_machine_control(printer, desired_enabled)
            self._post_control_result(command_id=command_id, ok=True, error="")
        except Exception as exc:  # noqa: BLE001
            self._post_control_result(command_id=command_id, ok=False, error=str(exc))
            raise

    def _handle_install_driver(self, printer_ip: str, brand: str, model: str, driver_name: str, driver_url: str) -> None:
        import urllib.request
        import zipfile
        import tempfile
        import shutil
        import subprocess
        import os
        from pathlib import Path
        import re
        
        LOGGER.info("Starting driver installation printer_ip=%s brand=%s model=%s driver_name=%s driver_url=%s", 
                    printer_ip, brand, model, driver_name, driver_url)
        
        urls = [u.strip() for u in driver_url.split(";") if u.strip()]
        if not urls:
            raise Exception("No driver URLs provided")
            
        temp_dir = Path(tempfile.mkdtemp(prefix="printagent_driver_"))
        try:
            download_path = None
            filename = None
            
            # 1. Try downloading each URL until one succeeds (real file, min 50KB)
            download_success = False
            last_err = None
            for url in urls:
                curr_download_path = None
                try:
                    url_path = url.split("?")[0]
                    curr_filename = os.path.basename(url_path) or "driver_installer"
                    if not curr_filename.lower().endswith((".zip", ".exe")):
                        curr_filename = curr_filename + ".exe"
                    
                    curr_download_path = temp_dir / curr_filename
                    LOGGER.info("Attempting to download driver from %s → %s", url, curr_download_path)
                    
                    resp = requests.get(
                        url,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                        timeout=180,
                        stream=True,
                        allow_redirects=True,
                    )
                    resp.raise_for_status()
                    
                    # Check content type - reject HTML pages (error pages from server)
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "html" in content_type and "octet-stream" not in content_type:
                        LOGGER.warning("URL %s returned HTML content-type, skipping (likely error page)", url)
                        last_err = Exception(f"URL returned HTML, not a binary file: {url}")
                        continue
                    
                    written = 0
                    with open(curr_download_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size=65536):
                            if chunk:
                                f.write(chunk)
                                written += len(chunk)
                    
                    file_size = curr_download_path.stat().st_size
                    if file_size < 50 * 1024:  # < 50 KB → likely an error page
                        LOGGER.warning("Downloaded file too small (%d bytes) from %s, skipping", file_size, url)
                        last_err = Exception(f"File too small ({file_size} bytes), likely not a real driver")
                        continue
                        
                    LOGGER.info("Downloaded successfully from %s — size=%d bytes", url, file_size)
                    download_path = curr_download_path
                    filename = curr_filename
                    download_success = True
                    break
                except Exception as e:
                    LOGGER.warning("Failed to download from %s: %s", url, e)
                    last_err = e
                    if curr_download_path and curr_download_path.exists():
                        try: curr_download_path.unlink()
                        except Exception: pass
            
            if not download_success:
                raise Exception(f"All {len(urls)} download URLs failed. Last error: {last_err}")

                
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)
            
            is_zip = filename.lower().endswith(".zip")
            is_exe = filename.lower().endswith(".exe")
            extracted_successfully = False
            
            if is_zip:
                LOGGER.info("Extracting ZIP file %s", download_path)
                with zipfile.ZipFile(download_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                extracted_successfully = True
            elif is_exe:
                LOGGER.info("Checking if EXE can be unzipped as ZIP SFX...")
                try:
                    with zipfile.ZipFile(download_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    LOGGER.info("Successfully unzipped EXE SFX using zipfile.")
                    extracted_successfully = True
                except Exception as zip_err:
                    LOGGER.info("EXE is not a standard ZIP archive: %s. Proceeding to execute silently.", zip_err)
            
            if not extracted_successfully and is_exe:
                LOGGER.info("Running silent install on EXE %s", download_path)
                silent_switches = [
                    ["/s"], ["/S"], ["/quiet", "/norestart"], ["/qn", "/norestart"], ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
                ]
                success = False
                for flags in silent_switches:
                    try:
                        LOGGER.info("Trying installer with flags: %s", flags)
                        proc = subprocess.run([str(download_path)] + flags, capture_output=True, text=True, timeout=120)
                        if proc.returncode == 0:
                            LOGGER.info("Installer exited successfully with flags %s", flags)
                            success = True
                            break
                    except Exception as exe_exc:
                        LOGGER.warning("Failed running installer with flags %s: %s", flags, exe_exc)
                if not success:
                    LOGGER.info("Silent installation finished. Searching for extracted infs...")
            
            inf_files = list(extract_dir.glob("**/*.inf"))
            LOGGER.info("Found %d INF files in extracted archive", len(inf_files))
            for inf_file in inf_files:
                try:
                    LOGGER.info("Adding driver store package from INF: %s", inf_file)
                    proc = subprocess.run(["pnputil", "/add-driver", str(inf_file), "/install"], capture_output=True, text=True)
                    LOGGER.info("pnputil output: %s", proc.stdout)
                except Exception as pnp_exc:
                    LOGGER.warning("Failed to run pnputil on %s: %s", inf_file, pnp_exc)

            # Parse extracted INF files to find the exact driver name matching our model or driver name
            exact_driver_name = driver_name
            inf_driver_names = []
            for inf_file in inf_files:
                try:
                    content = ""
                    for encoding in ("utf-8", "utf-16", "windows-1252"):
                        try:
                            content = inf_file.read_text(encoding=encoding)
                            break
                        except Exception:
                            continue
                    
                    if not content:
                        continue
                        
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith(";"):
                            continue
                        
                        # Match "Some Printer Name" = INSTALL_SECTION, HWID
                        matches = re.findall(r'"([^"]+)"\s*=\s*\w+', line)
                        for m in matches:
                            if m not in inf_driver_names:
                                inf_driver_names.append(m)
                                
                        # Also look for [Strings] section key=value where value is "Some Printer Name"
                        if "=" in line:
                            parts = line.split("=", 1)
                            val = parts[1].strip()
                            if val.startswith('"') and val.endswith('"'):
                                m = val[1:-1].strip()
                                if m and m not in inf_driver_names:
                                    inf_driver_names.append(m)
                except Exception as inf_err:
                    LOGGER.warning("Failed to parse INF file %s for driver names: %s", inf_file, inf_err)
            
            LOGGER.info("Driver names found in INF files: %s", inf_driver_names)
            best_match = None
            if inf_driver_names:
                for name in inf_driver_names:
                    if name.lower().strip() == driver_name.lower().strip():
                        best_match = name
                        break
                if not best_match:
                    for name in inf_driver_names:
                        if model.lower().strip() in name.lower():
                            best_match = name
                            break
                if not best_match:
                    for name in inf_driver_names:
                        if driver_name.lower().strip() in name.lower() or name.lower() in driver_name.lower().strip():
                            best_match = name
                            break
                if not best_match:
                    best_match = inf_driver_names[0]
            
            if best_match:
                LOGGER.info("Mapped driver name '%s' to exact INF driver name '%s'", driver_name, best_match)
                exact_driver_name = best_match

            ps_script = f"""
            $ErrorActionPreference = 'Stop'
            Write-Output "Adding printer driver '{exact_driver_name}'..."
            try {{
                Add-PrinterDriver -Name "{exact_driver_name}"
            }} catch {{
                Write-Output "Add-PrinterDriver failed. Checking if driver name is slightly different in the driver store or if it is already installed."
                $installed = Get-PrinterDriver | Where-Object {{ $_.Name -like "*{exact_driver_name}*" }}
                if ($installed) {{
                    $exact_driver_name = $installed[0].Name
                    Write-Output "Found installed matching driver: $exact_driver_name"
                }} else {{
                    throw $_
                }}
            }}
            
            $portName = "Port_{printer_ip}"
            Write-Output "Checking printer port $portName..."
            $port = Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue
            if (-not $port) {{
                Write-Output "Creating printer port for {printer_ip}..."
                Add-PrinterPort -Name $portName -PrinterHostAddress "{printer_ip}"
            }}
            
            $printerName = "{model} ({printer_ip})"
            Write-Output "Checking printer $printerName..."
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            if ($printer) {{
                Write-Output "Printer already exists. Updating driver and port..."
                Set-Printer -Name $printerName -DriverName $exact_driver_name -PortName $portName
            }} else {{
                Write-Output "Adding printer $printerName..."
                Add-Printer -Name $printerName -DriverName $exact_driver_name -PortName $portName
            }}
            """
            LOGGER.info("Running PowerShell script to configure printer on Windows...")
            proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script], 
                                  capture_output=True, text=True)
            LOGGER.info("PowerShell Output: %s", proc.stdout)
            if proc.returncode != 0:
                raise Exception(f"PowerShell configuration failed: {proc.stderr}")
                
            LOGGER.info("Driver and Printer successfully installed for %s!", printer_ip)
            
        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as clean_exc:
                LOGGER.warning("Failed to clean up temp dir %s: %s", temp_dir, clean_exc)

    def _reconcile_single_printer_address_book(
        self,
        printer: Printer,
        result_dict: dict[str, tuple[str, int]],
    ) -> dict[str, Any]:
        """
        Synchronize the address book entries of a Ricoh photocopier.
        Ensures all emails in the result_dict exist on the copier, pointing to their mapped agent's IP and FTP port.
        """
        if not result_dict:
            LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] No emails provided to reconcile.")
            return {"status": "none", "message": "No emails configured/owned."}

        LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Starting address book reconciliation for Ricoh copier: %s (IP: %s)", printer.name, printer.ip)
        details = []
        has_error = False
        
        try:
            # Create an authenticated session to read the address book
            LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Creating authenticated HTTP client...")
            session = self._ricoh_service.create_http_client(printer, authenticated=True)
            
            # Read address entries
            try:
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Trying AJAX read address list...")
                ajax_raw = self._ricoh_service.get_address_list_ajax_with_client(session, printer)
                entries = self._ricoh_service.parse_ajax_address_list(ajax_raw)
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] AJAX read success, parsed %d entries", len(entries))
            except Exception as ajax_exc:
                LOGGER.warning("[PollingBridge] [_reconcile_single_printer_address_book] AJAX read failed, trying HTML fallback: %s", ajax_exc)
                html = self._ricoh_service.read_address_list_with_client(session, printer)
                entries = self._ricoh_service.parse_address_list(html)
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] HTML read success, parsed %d entries", len(entries))

            # Close the authenticated session used for reading
            try:
                session.close()
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Authenticated session closed.")
            except Exception as close_exc:
                LOGGER.warning("[PollingBridge] [_reconcile_single_printer_address_book] Failed to close session: %s", close_exc)
                
        except Exception as read_exc:
            LOGGER.error("[PollingBridge] [_reconcile_single_printer_address_book] Failed to read address book from printer %s: %s", printer.ip, read_exc, exc_info=True)
            return {
                "status": "error",
                "error": f"Failed to read address book: {read_exc}",
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }

        # We have the list of current entries. Now compare and sync each email in result_dict!
        for email, (agent_ip, port) in result_dict.items():
            expected_folder = f"ftp://{agent_ip}:{port}/"
            LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Processing email '%s', expected folder: %s", email, expected_folder)
            
            # Find a matching entry by email address (case-insensitive)
            matched_entry = None
            for e in entries:
                e_email = getattr(e, "email_address", "") or ""
                if e_email.strip().lower() == email:
                    matched_entry = e
                    break
            
            if matched_entry is None:
                # Missing entry, let's create it!
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Target email not found in address book, creating scan destination entry for %s on printer %s", email, printer.ip)
                try:
                    # Lookup FTP credentials from share_manager for this port
                    ftp_user = ""
                    ftp_password = ""
                    try:
                        share_manager = getattr(self._ricoh_service, "share_manager", None)
                        if share_manager is not None and hasattr(share_manager, "list_ftp_sites"):
                            for site in share_manager.list_ftp_sites():
                                if int(site.get("port", 0) or 0) == port:
                                    ftp_user = str(site.get("ftp_user", "") or "")
                                    ftp_password = str(site.get("ftp_password", "") or "")
                                    break
                    except Exception as lookup_exc:
                        LOGGER.warning("[PollingBridge] Failed to lookup FTP credentials for port %d: %s", port, lookup_exc)

                    fields = {"entryTypeIn": "1"}
                    if ftp_user:
                        fields["folderAuthUserNameIn"] = ftp_user
                        fields["folderAuthUserName"] = ftp_user
                    if ftp_password:
                        fields["folderPasswordIn"] = ftp_password
                        fields["wk_folderPasswordIn"] = ftp_password
                        fields["folderPasswordConfirmIn"] = ftp_password
                        fields["wk_folderPasswordConfirmIn"] = ftp_password

                    self._ricoh_service.create_address_user_wizard(
                        printer=printer,
                        name=email,
                        email=email,
                        folder=expected_folder,
                        user_code="",
                        fields=fields,
                    )
                    details.append({
                        "email": email,
                        "action": "create",
                        "status": "success",
                        "folder": expected_folder,
                    })
                    LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Successfully created scan destination entry for %s", email)
                except Exception as create_exc:
                    LOGGER.error("[PollingBridge] [_reconcile_single_printer_address_book] Failed to create scan destination for %s on %s: %s", email, printer.ip, create_exc, exc_info=True)
                    details.append({
                        "email": email,
                        "action": "create",
                        "status": "error",
                        "error": str(create_exc),
                    })
                    has_error = True
            else:
                # Entry exists, check if destination needs update
                current_folder = getattr(matched_entry, "folder", "") or ""
                LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Match found: registration_no=%s, current folder=%s", matched_entry.registration_no, current_folder)
                if current_folder.strip().lower() != expected_folder.lower():
                    LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Folders mismatch! Updating existing scan destination for %s on printer %s to %s", email, printer.ip, expected_folder)
                    try:
                        # Lookup FTP credentials from share_manager for this port
                        ftp_user = ""
                        ftp_password = ""
                        try:
                            share_manager = getattr(self._ricoh_service, "share_manager", None)
                            if share_manager is not None and hasattr(share_manager, "list_ftp_sites"):
                                for site in share_manager.list_ftp_sites():
                                    if int(site.get("port", 0) or 0) == port:
                                        ftp_user = str(site.get("ftp_user", "") or "")
                                        ftp_password = str(site.get("ftp_password", "") or "")
                                        break
                        except Exception as lookup_exc:
                            LOGGER.warning("[PollingBridge] Failed to lookup FTP credentials for port %d: %s", port, lookup_exc)

                        fields = {"entryTypeIn": "1"}
                        if ftp_user:
                            fields["folderAuthUserNameIn"] = ftp_user
                            fields["folderAuthUserName"] = ftp_user
                        if ftp_password:
                            fields["folderPasswordIn"] = ftp_password
                            fields["wk_folderPasswordIn"] = ftp_password
                            fields["folderPasswordConfirmIn"] = ftp_password
                            fields["wk_folderPasswordConfirmIn"] = ftp_password

                        self._ricoh_service.modify_address_user_wizard(
                            printer=printer,
                            registration_no=matched_entry.registration_no,
                            name=email,
                            email=email,
                            folder=expected_folder,
                            user_code=getattr(matched_entry, "user_code", "") or "",
                            fields=fields,
                        )
                        details.append({
                            "email": email,
                            "action": "update",
                            "status": "success",
                            "folder": expected_folder,
                        })
                        LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Successfully updated scan destination entry for %s", email)
                    except Exception as update_exc:
                        LOGGER.error("[PollingBridge] [_reconcile_single_printer_address_book] Failed to update scan destination for %s on %s: %s", email, printer.ip, update_exc, exc_info=True)
                        details.append({
                            "email": email,
                            "action": "update",
                            "status": "error",
                            "error": str(update_exc),
                        })
                        has_error = True

                else:
                    # Up to date!
                    LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Scan destination for %s is already up to date (%s)", email, expected_folder)
                    details.append({
                        "email": email,
                        "action": "none",
                        "status": "success",
                        "folder": expected_folder,
                    })

        LOGGER.info("[PollingBridge] [_reconcile_single_printer_address_book] Completed address book reconciliation for Ricoh copier: %s, status: %s", printer.ip, "error" if has_error else "success")
        return {
            "status": "error" if has_error else "success",
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }

    def _control_loop(self) -> None:
        interval = 1.0  # Poll every 1 second for commands
        LOGGER.info("Polling control worker loop started")
        while not self._stop_event.is_set():
            lan_uid = self._resolved_lan_uid
            if not lan_uid:
                time.sleep(0.5)
                continue
            controls: dict[str, dict[str, object]] = {}
            try:
                controls = self._pull_device_controls(lan_uid=lan_uid)
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug("Control loop pull failed: %s", exc)
                controls = {}
            if controls:
                try:
                    printers = list(self._last_discovered_printers)
                except Exception:
                    printers = []
                for ip_key, control_info in controls.items():
                    ip = str(ip_key).strip()
                    if not ip:
                        continue
                    command = control_info.get("command")
                    self._applied_controls[ip] = bool(control_info.get("enabled", True))
                    
                    if isinstance(command, dict):
                        command_id = int(command.get("id", 0) or 0)
                        if command_id > 0:
                            with self._running_commands_lock:
                                if command_id in self._running_commands:
                                    continue
                                self._running_commands.add(command_id)
                        
                        # Find matching printer or create default
                        printer = next((p for p in printers if str(p.ip or "").strip() == ip), None)
                        if printer is None:
                            printer = Printer(
                                id=0,
                                name=ip,
                                ip=ip,
                                user="",
                                password="",
                                printer_type="ricoh",
                                status="online",
                                mac_address="",
                            )
                        
                        # Run command in separate thread to avoid blocking control loop
                        def _run_async_command(p=printer, c=command, cid=command_id):
                            try:
                                self._apply_command(p, c)
                            except Exception as async_exc:
                                LOGGER.warning("Async control apply failed for printer %s: %s", p.ip, async_exc)
                            finally:
                                if cid > 0:
                                    with self._running_commands_lock:
                                        self._running_commands.discard(cid)
                        
                        threading.Thread(target=_run_async_command, daemon=True).start()
                        LOGGER.info("Control loop started async thread to apply command for printer %s", ip)
            time.sleep(interval)
        LOGGER.info("Polling control worker loop stopped")

    def _worker(self) -> None:
        interval = self.interval_seconds()
        lead = self._config.get_string("polling.lead").strip()
        hostname = socket.gethostname()
        local_ip = self._resolve_local_ip()
        lan_uid, fingerprint = self._resolve_lan_info(hostname=hostname, local_ip=local_ip)
        agent_uid = self._agent_uid or hostname
        
        # Initial registration to get/confirm lan_uid from server
        try:
            lan_uid = self._register_with_server(
                lead=lead,
                lan_uid=lan_uid,
                agent_uid=agent_uid,
                hostname=hostname,
                local_ip=local_ip,
                fingerprint=fingerprint,
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Initial agent registration failed: %s", exc)

        LOGGER.info("Polling worker loop running: hostname=%s local_ip=%s lan_uid=%s", hostname, local_ip, lan_uid)
        if self._check_for_agent_update(lead, lan_uid, agent_uid, hostname, local_ip):
            return
        while not self._stop_event.is_set():
            LOGGER.info("Heartbeat: agent running")
            refreshed_lan_uid, refreshed_fingerprint = self._resolve_lan_info(hostname=hostname, local_ip=local_ip)
            if refreshed_lan_uid and refreshed_lan_uid != lan_uid:
                LOGGER.info("LAN identity changed during runtime: %s -> %s", lan_uid, refreshed_lan_uid)
                lan_uid = refreshed_lan_uid
                fingerprint = refreshed_fingerprint or fingerprint
                try:
                    lan_uid = self._register_with_server(
                        lead=lead,
                        lan_uid=lan_uid,
                        agent_uid=agent_uid,
                        hostname=hostname,
                        local_ip=local_ip,
                        fingerprint=fingerprint,
                    )
                except Exception as exc:  # noqa: BLE001
                    LOGGER.warning("Runtime LAN re-registration failed: %s", exc)
            cycle_started_at = self._now_iso()
            self._last_cycle_at = self._now_iso()
            printers = self._load_printers()
            try:
                self._push_inventory(printers, hostname=hostname, local_ip=local_ip, lan_uid=lan_uid, fingerprint=fingerprint)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Polling inventory sync failed: %s", exc)
            # Legacy FTP control command queue (superseded by _reconcile_scan_address_ftp)
            pass
            self._last_cycle_total_printers = len(printers)
            self._last_cycle_ricoh_printers = 0
            self._last_cycle_sent = 0
            self._last_cycle_failed = 0
            runtime_metadata = self._agent_runtime_metadata()
            LOGGER.info(
                "Polling cycle start: ts=%s total_printers=%s interval=%ss",
                cycle_started_at,
                self._last_cycle_total_printers,
                interval,
            )
            from concurrent.futures import ThreadPoolExecutor
            cycle_lock = threading.Lock()

            def _process_single_printer(printer: Printer) -> None:
                if self._stop_event.is_set():
                    return
                ip = str(printer.ip or "").strip()
                if not ip:
                    return
                if not self._applied_controls.get(ip, True):
                    LOGGER.info("Polling skipped (disabled): name=%s ip=%s", printer.name, printer.ip)
                    return
                
                with cycle_lock:
                    self._last_cycle_ricoh_printers += 1
                
                try:
                    collector = self._collector_service_for(printer)
                    LOGGER.info("Polling collect: name=%s ip=%s type=%s", printer.name, printer.ip, printer.printer_type)
                    counter_payload = collector.process_counter(printer, should_post=False)
                    status_payload = collector.process_status(printer, should_post=False)
                    counter_data = counter_payload.get("counter_data", {})
                    payload = {
                        "lead": lead,
                        "lan_uid": lan_uid,
                        "agent_uid": agent_uid,
                        "hostname": hostname,
                        "local_ip": local_ip,
                        "printer_name": counter_payload.get("printer_name", printer.name),
                        "ip": counter_payload.get("ip", printer.ip),
                        "mac_id": printer.mac_address,
                        "mac_address": printer.mac_address,
                        "timestamp": counter_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "counter_data": counter_data,
                        "status_data": status_payload.get("status_data", {}),
                        "collector_ok": True,
                        "fingerprint_signature": fingerprint,
                    }
                    
                    payload.update(runtime_metadata)
                    LOGGER.info("Polling payload -> %s", json.dumps(payload, ensure_ascii=False))
                    ack = self._post_payload(payload)
                    
                    # Check and update dynamic scripts if provided by server
                    remote_scripts = ack.get("scripts")
                    if isinstance(remote_scripts, dict):
                        try:
                            self._check_and_update_scripts(remote_scripts)
                        except Exception as script_exc:
                            LOGGER.warning("Failed to check or update scripts: %s", script_exc)
                    
                    with cycle_lock:
                        self._is_master = bool(ack.get("is_master", False))
                        self._emails = ack.get("emails") if isinstance(ack.get("emails"), list) else []
                        self._last_cycle_sent += 1
                        self._last_success_at = self._now_iso()
                        self._last_error = ""
                    
                    try:
                        self._reconcile_scan_address_ftp(self._is_master, self._emails)
                    except Exception as ftp_exc:
                        LOGGER.warning("FTP reconciliation failed during polling cycle: %s", ftp_exc)
                    
                    LOGGER.info(
                        "Polling ack <- inserted(counter=%s,status=%s) skipped(counter=%s,status=%s)",
                        ack.get("inserted_counter", "?"),
                        ack.get("inserted_status", "?"),
                        ack.get("skipped_counter", "?"),
                        ack.get("skipped_status", "?"),
                    )
                except Exception as exc:  # noqa: BLE001
                    with cycle_lock:
                        self._last_cycle_failed += 1
                        self._last_error = str(exc)
                    LOGGER.warning("Polling bridge failed for %s (%s): %s", printer.name, printer.ip, exc)
                    # Always send heartbeat payload even when collector fails.
                    try:
                        fallback_payload = {
                            "lead": lead,
                            "lan_uid": lan_uid,
                            "agent_uid": agent_uid,
                            "hostname": hostname,
                            "local_ip": local_ip,
                            "printer_name": str(printer.name or "").strip() or "Unknown Printer",
                            "ip": str(printer.ip or "").strip(),
                            "mac_id": str(printer.mac_address or "").strip(),
                            "mac_address": str(printer.mac_address or "").strip(),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "counter_data": {},
                            "status_data": {},
                            "collector_ok": False,
                            "skip_data_update": True,
                            "collector_error": str(exc),
                            "fingerprint_signature": fingerprint,
                        }
                        
                        fallback_payload.update(runtime_metadata)
                        ack = self._post_payload(fallback_payload)
                        
                        # Check and update dynamic scripts if provided by server
                        remote_scripts = ack.get("scripts")
                        if isinstance(remote_scripts, dict):
                            try:
                                self._check_and_update_scripts(remote_scripts)
                            except Exception as script_exc:
                                LOGGER.warning("Failed to check or update scripts in fallback: %s", script_exc)
                        
                        with cycle_lock:
                            self._is_master = bool(ack.get("is_master", False))
                            self._emails = ack.get("emails") if isinstance(ack.get("emails"), list) else []
                            self._last_cycle_sent += 1
                            self._last_success_at = self._now_iso()
                        
                        try:
                            self._reconcile_scan_address_ftp(self._is_master, self._emails)
                        except Exception as ftp_exc:
                            LOGGER.warning("FTP reconciliation failed during polling fallback: %s", ftp_exc)
                        
                        LOGGER.info(
                            "Polling fallback ack <- inserted(counter=%s,status=%s) skipped(counter=%s,status=%s)",
                            ack.get("inserted_counter", "?"),
                            ack.get("inserted_status", "?"),
                            ack.get("skipped_counter", "?"),
                            ack.get("skipped_status", "?"),
                        )
                    except Exception as post_exc:  # noqa: BLE001
                        LOGGER.warning("Polling fallback post failed for %s (%s): %s", printer.name, printer.ip, post_exc)

            # Poll printers in parallel using ThreadPoolExecutor
            if printers:
                with ThreadPoolExecutor(max_workers=min(16, len(printers))) as executor:
                    executor.map(_process_single_printer, printers)
            LOGGER.info(
                "Polling cycle done: total=%s ricoh=%s sent=%s failed=%s",
                self._last_cycle_total_printers,
                self._last_cycle_ricoh_printers,
                self._last_cycle_sent,
                self._last_cycle_failed,
            )
            if self.scan_enabled():
                current_lan_uid = self._resolved_lan_uid or lan_uid
                self._run_scan_cycle(lead, current_lan_uid, agent_uid, hostname, local_ip, fingerprint, reason="polling-cycle")
            if self._check_for_agent_update(lead, lan_uid, agent_uid, hostname, local_ip):
                break
            triggered = self._trigger_event.wait(interval)
            if triggered:
                self._trigger_event.clear()
