from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient, Printer


LOGGER = logging.getLogger(__name__)
CONTROL_LOG_FILE = Path("storage/data/control_actions.csv")
LAN_FINGER_FILE = Path("storage/data/.lan_finger.json")


class PollingBridge:
    def __init__(self, config: AppConfig, api_client: APIClient, ricoh_service: RicohService) -> None:
        self._config = config
        self._api_client = api_client
        self._ricoh_service = ricoh_service
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
        self._applied_controls: dict[str, bool] = {}
        self._resolved_lan_uid = ""

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
    def _resolve_local_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:  # noqa: BLE001
            return ""

    def interval_seconds(self) -> int:
        raw = self._config.get_string("polling.interval_seconds", "15").strip()
        try:
            value = int(raw)
            return max(10, value)
        except Exception:  # noqa: BLE001
            return 15

    def start(self) -> tuple[bool, str]:
        if not self._config.get_bool("polling.enabled", True):
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
        self._last_started_at = self._now_iso()
        LOGGER.info(
            "Polling bridge started: url=%s lead=%s interval=%ss",
            self._config.get_string("polling.url").strip(),
            self._config.get_string("polling.lead").strip(),
            self.interval_seconds(),
        )
        return True, "Polling started"

    def stop(self) -> None:
        self._stop_event.set()
        LOGGER.info("Polling bridge stop requested")

    def status(self) -> dict[str, object]:
        issues = self._config_issues()
        return {
            "configured": self.is_configured(),
            "config_issues": issues,
            "enabled": self._config.get_bool("polling.enabled", True),
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
            "last_control_pull_at": self._last_control_pull_at,
            "last_control_total": self._last_control_total,
            "last_control_apply_error": self._last_control_apply_error,
            "resolved_lan_uid": self._resolved_lan_uid,
        }

    def _load_printers(self) -> list[Printer]:
        try:
            return self._api_client.get_printers()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Polling bridge cannot load printers: %s", exc)
            return []

    def _post_payload(self, payload: dict) -> dict:
        url = self._config.get_string("polling.url").strip()
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
            )
            return PollingBridge._normalize_ipv4(result.stdout.strip())
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _resolve_gateway_mac(gateway_ip: str) -> str:
        ip = PollingBridge._normalize_ipv4(gateway_ip)
        if not ip:
            return ""
        try:
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=6, check=False)
            match = re.search(r"\b([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", result.stdout or "")
            if not match:
                return ""
            return match.group(1).replace("-", ":").upper()
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _best_effort_hide_file(path: Path) -> None:
        if os.name != "nt":
            return
        try:
            subprocess.run(["attrib", "+h", str(path)], capture_output=True, text=True, timeout=5, check=False)
        except Exception:  # noqa: BLE001
            return

    def _resolve_lan_uid(self, hostname: str, local_ip: str) -> str:
        configured = self._config.get_string("polling.lan_uid", "").strip()
        if configured and configured.lower() not in {"lan-default", "default", "lan_default"}:
            self._resolved_lan_uid = configured
            return configured

        gateway_ip = self._resolve_default_gateway()
        gateway_mac = self._resolve_gateway_mac(gateway_ip)
        subnet = self._subnet_hint(local_ip)
        local_mac = self._mac_address()
        lead = self._config.get_string("polling.lead", "").strip()

        lan_core_parts = [
            f"lead={lead}",
            f"subnet={subnet}",
            f"gateway_ip={gateway_ip}",
            f"gateway_mac={gateway_mac}",
        ]
        if not gateway_ip and not gateway_mac and not subnet:
            lan_core_parts.append(f"fallback_local_mac={local_mac}")
            lan_core_parts.append(f"fallback_hostname={hostname}")
        signature = "|".join(lan_core_parts)

        if LAN_FINGER_FILE.exists():
            try:
                payload = json.loads(LAN_FINGER_FILE.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    saved_uid = str(payload.get("lan_uid", "")).strip()
                    saved_signature = str(payload.get("signature", "")).strip()
                    if saved_uid and saved_signature == signature:
                        self._resolved_lan_uid = saved_uid
                        return saved_uid
            except Exception:  # noqa: BLE001
                pass

        digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:16]
        lan_uid = f"lanf-{digest}"
        payload = {
            "lan_uid": lan_uid,
            "signature": signature,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        LAN_FINGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAN_FINGER_FILE.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        self._best_effort_hide_file(LAN_FINGER_FILE)
        self._resolved_lan_uid = lan_uid
        return lan_uid

    def _polling_base_url(self) -> str:
        raw = self._config.get_string("polling.url").strip()
        if not raw:
            return ""
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def _pull_device_controls(self, lan_uid: str) -> dict[str, bool]:
        base_url = self._polling_base_url()
        if not base_url:
            return {}
        token = self._config.get_string("polling.token").strip()
        lead = self._config.get_string("polling.lead").strip()
        agent_uid = self._config.get_string("polling.agent_uid", "").strip()
        params = {"lead": lead, "lan_uid": lan_uid}
        if agent_uid:
            params["agent_uid"] = agent_uid
        headers = {"Accept": "application/json", "X-Lead-Token": token}
        url = f"{base_url}/api/polling/controls"
        response = self._api_client.session.get(url, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("rows", []) if isinstance(payload, dict) else []
        mapping: dict[str, bool] = {}
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip", "") or "").strip()
                if not ip:
                    continue
                mapping[ip] = bool(row.get("enabled", True))
        self._last_control_pull_at = self._now_iso()
        self._last_control_total = len(mapping)
        return mapping

    def _push_inventory(self, printers: list[Printer], hostname: str, local_ip: str, lan_uid: str) -> None:
        base_url = self._polling_base_url()
        if not base_url:
            return
        token = self._config.get_string("polling.token").strip()
        lead = self._config.get_string("polling.lead").strip()
        agent_uid = self._config.get_string("polling.agent_uid", "").strip() or hostname
        devices: list[dict[str, str]] = []
        for printer in printers:
            devices.append(
                {
                    "printer_name": str(printer.name or "").strip(),
                    "ip": str(printer.ip or "").strip(),
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
        }
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        url = f"{base_url}/api/polling/inventory"
        response = self._api_client.session.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

    def _log_control_event(self, printer: Printer, enabled: bool, result: str, detail: str = "") -> None:
        CONTROL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        is_new = not CONTROL_LOG_FILE.exists()
        with CONTROL_LOG_FILE.open("a", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            if is_new:
                writer.writerow(["timestamp_utc", "printer_name", "ip", "enabled", "action", "result", "detail"])
            writer.writerow(
                [
                    datetime.now(timezone.utc).isoformat(),
                    str(printer.name or ""),
                    str(printer.ip or ""),
                    str(bool(enabled)).lower(),
                    "enable" if enabled else "lock",
                    result,
                    detail,
                ]
            )

    def _apply_machine_control(self, printer: Printer, enabled: bool) -> None:
        ip = str(printer.ip or "").strip()
        if not ip:
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
            self._last_control_apply_error = ""
            self._log_control_event(printer, enabled, "ok", "")
        except Exception as exc:  # noqa: BLE001
            self._log_control_event(printer, enabled, "error", str(exc))
            raise

    def _worker(self) -> None:
        interval = self.interval_seconds()
        lead = self._config.get_string("polling.lead").strip()
        hostname = socket.gethostname()
        local_ip = self._resolve_local_ip()
        lan_uid = self._resolve_lan_uid(hostname=hostname, local_ip=local_ip) or "legacy-lan"
        LOGGER.info("Polling worker loop running: hostname=%s local_ip=%s", hostname, local_ip)
        while not self._stop_event.is_set():
            cycle_started_at = self._now_iso()
            self._last_cycle_at = self._now_iso()
            printers = self._load_printers()
            try:
                self._push_inventory(printers, hostname=hostname, local_ip=local_ip, lan_uid=lan_uid)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Polling inventory sync failed: %s", exc)
            controls: dict[str, bool] = {}
            try:
                controls = self._pull_device_controls(lan_uid=lan_uid)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Polling control pull failed: %s", exc)
                controls = {}
            if controls:
                for printer in printers:
                    ip = str(printer.ip or "").strip()
                    if not ip or ip not in controls:
                        continue
                    printer_type = str(printer.printer_type or "").strip().lower()
                    printer_name = str(printer.name or "").strip().lower()
                    if "ricoh" not in printer_type and "ricoh" not in printer_name:
                        continue
                    try:
                        self._apply_machine_control(printer, controls[ip])
                    except Exception as exc:  # noqa: BLE001
                        self._last_control_apply_error = str(exc)
                        LOGGER.warning(
                            "Polling control apply failed: name=%s ip=%s enabled=%s error=%s",
                            printer.name,
                            ip,
                            controls[ip],
                            exc,
                        )
            self._last_cycle_total_printers = len(printers)
            self._last_cycle_ricoh_printers = 0
            self._last_cycle_sent = 0
            self._last_cycle_failed = 0
            LOGGER.info(
                "Polling cycle start: ts=%s total_printers=%s interval=%ss",
                cycle_started_at,
                self._last_cycle_total_printers,
                interval,
            )
            for printer in printers:
                if self._stop_event.is_set():
                    break
                if not str(printer.ip or "").strip():
                    continue
                if controls and not controls.get(str(printer.ip or "").strip(), True):
                    LOGGER.info("Polling skipped (disabled): name=%s ip=%s", printer.name, printer.ip)
                    continue
                printer_type = str(printer.printer_type or "").strip().lower()
                printer_name = str(printer.name or "").strip().lower()
                # Local devices often come as "windows-local"; accept brand detection by name too.
                if "ricoh" not in printer_type and "ricoh" not in printer_name:
                    continue
                self._last_cycle_ricoh_printers += 1
                try:
                    LOGGER.info("Polling collect: name=%s ip=%s type=%s", printer.name, printer.ip, printer.printer_type)
                    counter_payload = self._ricoh_service.process_counter(printer, should_post=False)
                    status_payload = self._ricoh_service.process_status(printer, should_post=False)
                    payload = {
                        "lead": lead,
                        "lan_uid": lan_uid,
                        "agent_uid": self._config.get_string("polling.agent_uid", "").strip() or hostname,
                        "hostname": hostname,
                        "local_ip": local_ip,
                        "printer_name": counter_payload.get("printer_name", printer.name),
                        "ip": counter_payload.get("ip", printer.ip),
                        "timestamp": counter_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "counter_data": counter_payload.get("counter_data", {}),
                        "status_data": status_payload.get("status_data", {}),
                    }
                    LOGGER.info("Polling payload -> %s", json.dumps(payload, ensure_ascii=False))
                    ack = self._post_payload(payload)
                    self._last_cycle_sent += 1
                    self._last_success_at = self._now_iso()
                    self._last_error = ""
                    LOGGER.info(
                        "Polling ack <- inserted(counter=%s,status=%s) skipped(counter=%s,status=%s)",
                        ack.get("inserted_counter", "?"),
                        ack.get("inserted_status", "?"),
                        ack.get("skipped_counter", "?"),
                        ack.get("skipped_status", "?"),
                    )
                except Exception as exc:  # noqa: BLE001
                    self._last_cycle_failed += 1
                    self._last_error = str(exc)
                    LOGGER.warning("Polling bridge failed for %s (%s): %s", printer.name, printer.ip, exc)
            LOGGER.info(
                "Polling cycle done: total=%s ricoh=%s sent=%s failed=%s",
                self._last_cycle_total_printers,
                self._last_cycle_ricoh_printers,
                self._last_cycle_sent,
                self._last_cycle_failed,
            )
            self._stop_event.wait(interval)
