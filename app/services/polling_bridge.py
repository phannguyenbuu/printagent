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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient, Printer


LOGGER = logging.getLogger(__name__)
CONTROL_LOG_FILE = Path("storage/data/control_actions.csv")
LAN_FINGER_FILE = Path("storage/data/.lan_finger.json")
SCAN_UPLOAD_STATE_FILE = Path("storage/data/scan_upload_state.json")


class PollingBridge:
    def __init__(self, config: AppConfig, api_client: APIClient, ricoh_service: RicohService) -> None:
        self._config = config
        self._api_client = api_client
        self._ricoh_service = ricoh_service
        self._thread: threading.Thread | None = None
        self._scan_thread: threading.Thread | None = None
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
        self._control_retry_after: dict[str, datetime] = {}
        self._resolved_lan_uid = ""
        self._scan_last_cycle_at = ""
        self._scan_last_upload_at = ""
        self._scan_last_error = ""
        self._scan_uploaded_total = 0
        self._scan_failed_total = 0
        self._scan_counter_last_by_ip: dict[str, int] = {}
        self._scan_file_state: dict[str, dict[str, int]] = {}
        self._scan_uploaded_fingerprints: dict[str, str] = self._load_scan_upload_state()
        self._scan_lock = threading.Lock()

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

    def scan_enabled(self) -> bool:
        return self._config.get_bool("polling.scan_enabled", True)

    def scan_interval_seconds(self) -> int:
        raw = self._config.get_string("polling.scan_interval_seconds", "1").strip()
        try:
            value = int(raw)
            return max(1, value)
        except Exception:  # noqa: BLE001
            return 1

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
        if self.scan_enabled():
            self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True, name="scan-upload-bridge")
            self._scan_thread.start()
        self._last_started_at = self._now_iso()
        LOGGER.info(
            "Polling bridge started: url=%s lead=%s interval=%ss",
            self._config.get_string("polling.url").strip(),
            self._config.get_string("polling.lead").strip(),
            self.interval_seconds(),
        )
        if self.scan_enabled():
            LOGGER.info("Scan watcher started: interval=%ss dirs=%s", self.scan_interval_seconds(), ",".join(self._scan_dirs()))
        return True, "Polling started"

    def stop(self) -> None:
        self._stop_event.set()
        self._save_scan_upload_state()
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
            "scan_enabled": self.scan_enabled(),
            "scan_running": bool(self._scan_thread and self._scan_thread.is_alive()),
            "scan_interval_seconds": self.scan_interval_seconds(),
            "scan_dirs": self._scan_dirs(),
            "scan_last_cycle_at": self._scan_last_cycle_at,
            "scan_last_upload_at": self._scan_last_upload_at,
            "scan_last_error": self._scan_last_error,
            "scan_uploaded_total": self._scan_uploaded_total,
            "scan_failed_total": self._scan_failed_total,
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

    def _scan_upload_url(self) -> str:
        base = self._polling_base_url()
        if not base:
            return ""
        return f"{base}/api/polling/scan-upload"

    def _load_scan_upload_state(self) -> dict[str, str]:
        if not SCAN_UPLOAD_STATE_FILE.exists():
            return {}
        try:
            payload = json.loads(SCAN_UPLOAD_STATE_FILE.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return {}
            uploaded = payload.get("uploaded")
            if not isinstance(uploaded, dict):
                return {}
            result: dict[str, str] = {}
            for key, value in uploaded.items():
                k = str(key or "").strip()
                v = str(value or "").strip()
                if k and v:
                    result[k] = v
            return result
        except Exception:  # noqa: BLE001
            return {}

    def _save_scan_upload_state(self) -> None:
        try:
            SCAN_UPLOAD_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            trimmed = dict(list(self._scan_uploaded_fingerprints.items())[-5000:])
            payload = {"updated_at": datetime.now(timezone.utc).isoformat(), "uploaded": trimmed}
            SCAN_UPLOAD_STATE_FILE.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            return

    @staticmethod
    def _is_scan_candidate(path: Path) -> bool:
        name = path.name.lower()
        if name.endswith((".tmp", ".part", ".partial", ".crdownload")):
            return False
        return path.is_file()

    def _iter_scan_files(self) -> list[Path]:
        files: list[Path] = []
        recursive = self._scan_recursive()
        for raw in self._scan_dirs():
            try:
                root = Path(raw).expanduser()
                if not root.exists() or not root.is_dir():
                    continue
                iterator = root.rglob("*") if recursive else root.glob("*")
                for item in iterator:
                    if self._is_scan_candidate(item):
                        files.append(item)
            except Exception:  # noqa: BLE001
                continue
        files.sort(key=lambda p: str(p))
        return files

    @staticmethod
    def _file_fingerprint(path: Path, size: int, mtime_ns: int) -> str:
        return f"{path.resolve()}|{size}|{mtime_ns}"

    def _upload_scan_file(
        self,
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
        rel_path = str(path)
        data = {
            "lead": lead,
            "lan_uid": lan_uid,
            "agent_uid": agent_uid,
            "hostname": hostname,
            "local_ip": local_ip,
            "timestamp": now_iso,
            "source_path": rel_path,
            "fingerprint": fingerprint,
        }
        with path.open("rb") as fp:
            files = {"file": (path.name, fp, "application/octet-stream")}
            resp = self._api_client.session.post(url, data=data, files=files, headers=headers, timeout=(10, 120))
        resp.raise_for_status()
        self._scan_uploaded_fingerprints[fingerprint] = now_iso
        self._scan_uploaded_total += 1
        self._scan_last_upload_at = self._now_iso()
        self._scan_last_error = ""
        if self._scan_uploaded_total % 20 == 0:
            self._save_scan_upload_state()

    def _scan_worker(self) -> None:
        interval = self.scan_interval_seconds()
        lead = self._config.get_string("polling.lead").strip()
        hostname = socket.gethostname()
        local_ip = self._resolve_local_ip()
        lan_uid = self._resolve_lan_uid(hostname=hostname, local_ip=local_ip) or "legacy-lan"
        agent_uid = self._config.get_string("polling.agent_uid", "").strip() or hostname
        LOGGER.info(
            "Scan watcher loop running: lead=%s lan_uid=%s agent_uid=%s interval=%ss dirs=%s",
            lead,
            lan_uid,
            agent_uid,
            interval,
            ",".join(self._scan_dirs()),
        )
        while not self._stop_event.is_set():
            self._run_scan_cycle(lead, lan_uid, agent_uid, hostname, local_ip, reason="timer")
            self._stop_event.wait(interval)
        self._save_scan_upload_state()

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
        reason: str = "timer",
    ) -> None:
        if not self._scan_lock.acquire(blocking=False):
            return
        try:
            self._scan_last_cycle_at = self._now_iso()
            files = self._iter_scan_files()
            active_keys: set[str] = set()
            for path in files:
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
                stable = int(state.get("stable", 0)) + 1 if same else 0
                state = {"size": size, "mtime_ns": mtime_ns, "stable": stable}
                self._scan_file_state[key] = state
                if stable < 2:
                    continue
                fingerprint = self._file_fingerprint(path=path, size=size, mtime_ns=mtime_ns)
                if fingerprint in self._scan_uploaded_fingerprints:
                    continue
                try:
                    self._upload_scan_file(path, fingerprint, lead, lan_uid, agent_uid, hostname, local_ip)
                    LOGGER.info("Scan upload ok: file=%s size=%s reason=%s", path, size, reason)
                except Exception as exc:  # noqa: BLE001
                    self._scan_failed_total += 1
                    self._scan_last_error = str(exc)
                    LOGGER.warning("Scan upload failed: file=%s reason=%s error=%s", path, reason, exc)
            stale_keys = [k for k in self._scan_file_state.keys() if k not in active_keys]
            for key in stale_keys:
                self._scan_file_state.pop(key, None)
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

    def _post_control_result(self, command_id: int, ok: bool, error: str = "") -> None:
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
        headers = {"Content-Type": "application/json", "X-Lead-Token": token}
        response = self._api_client.session.post(url, json=payload, headers=headers, timeout=20)
        response.raise_for_status()

    def _apply_command(self, printer: Printer, command: dict[str, object]) -> None:
        command_id = int(command.get("id", 0) or 0)
        desired_enabled = bool(command.get("desired_enabled", True))
        if command_id <= 0:
            return
        auth_user = str(command.get("auth_user", "") or "").strip()
        auth_password = str(command.get("auth_password", "") or "").strip()
        if auth_user:
            printer.user = auth_user
        if auth_password:
            printer.password = auth_password
        try:
            self._apply_machine_control(printer, desired_enabled)
            self._post_control_result(command_id=command_id, ok=True, error="")
        except Exception as exc:  # noqa: BLE001
            self._post_control_result(command_id=command_id, ok=False, error=str(exc))
            raise

    def _worker(self) -> None:
        interval = self.interval_seconds()
        lead = self._config.get_string("polling.lead").strip()
        hostname = socket.gethostname()
        local_ip = self._resolve_local_ip()
        lan_uid = self._resolve_lan_uid(hostname=hostname, local_ip=local_ip) or "legacy-lan"
        agent_uid = self._config.get_string("polling.agent_uid", "").strip() or hostname
        LOGGER.info("Polling worker loop running: hostname=%s local_ip=%s", hostname, local_ip)
        while not self._stop_event.is_set():
            cycle_started_at = self._now_iso()
            self._last_cycle_at = self._now_iso()
            printers = self._load_printers()
            try:
                self._push_inventory(printers, hostname=hostname, local_ip=local_ip, lan_uid=lan_uid)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Polling inventory sync failed: %s", exc)
            controls: dict[str, dict[str, object]] = {}
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
                        command = controls[ip].get("command")
                        if isinstance(command, dict):
                            self._apply_command(printer, command)
                        self._applied_controls[ip] = bool(controls[ip].get("enabled", True))
                    except Exception as exc:  # noqa: BLE001
                        self._last_control_apply_error = str(exc)
                        LOGGER.warning(
                            "Polling control apply failed: name=%s ip=%s enabled=%s error=%s",
                            printer.name,
                            ip,
                            controls[ip].get("enabled", True),
                            exc,
                        )
            self._last_cycle_total_printers = len(printers)
            self._last_cycle_ricoh_printers = 0
            self._last_cycle_sent = 0
            self._last_cycle_failed = 0
            scan_counter_changed = False
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
                if controls and not bool((controls.get(str(printer.ip or "").strip(), {}) or {}).get("enabled", True)):
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
                    counter_data = counter_payload.get("counter_data", {})
                    if isinstance(counter_data, dict) and self._has_new_scan_counter(str(printer.ip or ""), counter_data):
                        scan_counter_changed = True
                    payload = {
                        "lead": lead,
                        "lan_uid": lan_uid,
                        "agent_uid": agent_uid,
                        "hostname": hostname,
                        "local_ip": local_ip,
                        "printer_name": counter_payload.get("printer_name", printer.name),
                        "ip": counter_payload.get("ip", printer.ip),
                        "timestamp": counter_payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "counter_data": counter_data,
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
            if self.scan_enabled() and scan_counter_changed:
                LOGGER.info("Counter detected new scan pages -> trigger immediate scan watcher cycle")
                self._run_scan_cycle(lead, lan_uid, agent_uid, hostname, local_ip, reason="counter-delta")
            self._stop_event.wait(interval)
