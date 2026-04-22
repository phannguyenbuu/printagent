from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import hashlib
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from app.services.runtime import fresh_pyinstaller_env, is_frozen, is_windows


LOGGER = logging.getLogger(__name__)
DEFAULT_APP_VERSION = "1.3.40"
UPDATE_NOTICE_FILE = Path("storage/data/update_notice.json")
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class UpdateState:
    current_version: str
    pending_version: str = ""
    last_check_at: str = ""
    last_available_version: str = ""
    last_download_url: str = ""
    last_source: str = ""
    last_signal_text: str = ""
    last_event_at: str = ""
    last_attempt_at: str = ""
    last_success_at: str = ""
    last_error: str = ""
    last_command: str = ""
    running: bool = False
    last_return_code: int | None = None


class AutoUpdater:
    def __init__(self, project_root: Path, current_args: list[str] | None = None) -> None:
        self.project_root = project_root
        self.current_version = os.getenv("APP_VERSION", DEFAULT_APP_VERSION).strip() or DEFAULT_APP_VERSION
        self.auto_apply = _env_bool("UPDATE_AUTO_APPLY", default=False)
        self.default_command = os.getenv("UPDATE_DEFAULT_COMMAND", "git pull --ff-only").strip()
        prefix_raw = os.getenv("UPDATE_ALLOWED_PREFIX", "git pull --ff-only").strip()
        self.allowed_prefixes = [item.strip() for item in prefix_raw.split(",") if item.strip()]
        self.webhook_token = os.getenv("UPDATE_WEBHOOK_TOKEN", "").strip()
        self.state = UpdateState(current_version=self.current_version)
        self._lock = threading.Lock()
        self._current_args = list(current_args or ["--mode", "service"])
        self._release_check_interval_seconds = max(300, int(os.getenv("UPDATE_CHECK_INTERVAL_SECONDS", "300") or "300"))

    def status(self) -> dict[str, Any]:
        with self._lock:
            payload = asdict(self.state)
        payload.update(
            {
                "auto_apply": self.auto_apply,
                "allowed_prefixes": self.allowed_prefixes,
                "default_command": self.default_command,
                "check_interval_seconds": self._release_check_interval_seconds,
            }
        )
        return payload

    @property
    def check_interval_seconds(self) -> int:
        return self._release_check_interval_seconds

    def _is_allowed(self, command: str) -> bool:
        if not command:
            return False
        if not self.allowed_prefixes:
            return True
        return any(command.startswith(prefix) for prefix in self.allowed_prefixes)

    def _start_command(self, command: str, target_version: str) -> tuple[bool, str]:
        with self._lock:
            if self.state.running:
                return False, "Update already running"
            self.state.running = True
            self.state.last_attempt_at = _utc_now()
            self.state.last_command = command
            self.state.last_error = ""
            self.state.last_return_code = None

        thread = threading.Thread(target=self._run_command, args=(command, target_version), daemon=True, name="auto-updater-thread")
        thread.start()
        return True, "Update started"

    def _run_command(self, command: str, target_version: str) -> None:
        try:
            process = subprocess.run(
                command,
                cwd=str(self.project_root),
                shell=True,
                capture_output=True,
                text=True,
                timeout=900,
            )
            with self._lock:
                self.state.last_return_code = int(process.returncode)
                if process.returncode == 0:
                    self.state.last_success_at = _utc_now()
                    if target_version:
                        self.state.current_version = target_version
                    self.state.pending_version = ""
                    self.state.last_error = ""
                else:
                    err = (process.stderr or process.stdout or "").strip()
                    self.state.last_error = err or f"Update failed with code {process.returncode}"
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.state.last_error = str(exc)
        finally:
            with self._lock:
                self.state.running = False

    @staticmethod
    def _normalize_version(version: str) -> tuple[int, ...]:
        text = str(version or "").strip()
        if not text:
            return tuple()
        text = text.lstrip("vV")
        parts: list[int] = []
        for chunk in text.split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            if not digits:
                parts.append(0)
            else:
                parts.append(int(digits))
        return tuple(parts)

    @classmethod
    def _is_newer_version(cls, candidate: str, current: str) -> bool:
        c1 = cls._normalize_version(candidate)
        c2 = cls._normalize_version(current)
        if not c1:
            return False
        width = max(len(c1), len(c2))
        c1 = c1 + (0,) * (width - len(c1))
        c2 = c2 + (0,) * (width - len(c2))
        return c1 > c2

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _resolve_url(base_url: str, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return urllib.parse.urljoin(base_url.rstrip("/") + "/", text)

    def _current_binary_path(self) -> Path | None:
        if is_frozen():
            return Path(sys.executable).resolve()
        return None

    @staticmethod
    def _vbs_string(value: str) -> str:
        return str(value or "").replace('"', '""')

    @staticmethod
    def _write_update_notice(path: Path, version: str) -> None:
        payload = {
            "version": str(version or "").strip(),
            "updated_at": _utc_now(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")

    def should_check(self) -> bool:
        with self._lock:
            if self.state.running:
                return False
            last_check_at = self.state.last_check_at
        if not last_check_at:
            return True
        try:
            elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(last_check_at)
            return elapsed.total_seconds() >= self._release_check_interval_seconds
        except Exception:
            return True

    def check_remote_release(
        self,
        session: requests.Session,
        base_url: str,
        token: str,
        lead: str,
        agent_uid: str,
        lan_uid: str,
        hostname: str,
        local_ip: str,
    ) -> tuple[bool, str, bool]:
        if not base_url or not token or not lead:
            return False, "Release check not configured", False

        with self._lock:
            self.state.last_check_at = _utc_now()

        current_binary = self._current_binary_path()
        current_sha = ""
        if current_binary is not None and current_binary.exists():
            try:
                current_sha = self._sha256_file(current_binary)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Failed to hash current agent binary: %s", exc)

        headers = {"Accept": "application/json", "X-Lead-Token": token}
        params = {
            "lead": lead,
            "agent_uid": agent_uid,
            "lan_uid": lan_uid,
            "hostname": hostname,
            "local_ip": local_ip,
            "current_version": self.state.current_version,
            "current_sha256": current_sha,
        }
        try:
            response = session.get(f"{base_url}/api/agent/release", params=params, headers=headers, timeout=20)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.state.last_error = str(exc)
            return False, f"Release check failed: {exc}", False

        if not isinstance(payload, dict):
            return False, "Invalid release payload", False
        return self.apply_release_manifest(payload, base_url=base_url)

    def apply_release_manifest(self, payload: dict[str, Any], base_url: str) -> tuple[bool, str, bool]:
        latest_version = str(payload.get("version") or "").strip()
        download_url = self._resolve_url(base_url, str(payload.get("download_url") or payload.get("url") or "").strip())
        expected_sha = str(payload.get("sha256") or "").strip().lower()
        update_available = bool(payload.get("update_available", False))

        with self._lock:
            self.state.last_available_version = latest_version
            self.state.last_download_url = download_url

        current_binary = self._current_binary_path()
        current_sha = ""
        if current_binary is not None and current_binary.exists():
            try:
                current_sha = self._sha256_file(current_binary)
            except Exception:  # noqa: BLE001
                current_sha = ""

        if expected_sha and current_sha and expected_sha == current_sha:
            with self._lock:
                if latest_version:
                    self.state.current_version = latest_version
                self.state.pending_version = ""
                self.state.last_error = ""
            return True, "Already on latest build", False

        if not update_available and latest_version and not self._is_newer_version(latest_version, self.state.current_version):
            return True, "Already on latest version", False
        if not update_available and not latest_version:
            return True, "No release available", False
        if not download_url:
            return False, "Release payload missing download_url", False
        if not is_windows() or not is_frozen():
            return True, "Release available but auto-apply only runs on Windows EXE build", False
        return self._download_and_restart(download_url=download_url, target_version=latest_version, expected_sha256=expected_sha)

    def _download_and_restart(self, download_url: str, target_version: str, expected_sha256: str) -> tuple[bool, str, bool]:
        current_binary = self._current_binary_path()
        if current_binary is None or not current_binary.exists():
            return False, "Current binary path not available", False

        with self._lock:
            if self.state.running:
                return False, "Update already running", False
            self.state.running = True
            self.state.pending_version = target_version
            self.state.last_attempt_at = _utc_now()
            self.state.last_command = download_url
            self.state.last_error = ""
            self.state.last_return_code = None

        release_dir = current_binary.parent
        staged_binary = release_dir / f"{current_binary.stem}.new{current_binary.suffix}"
        backup_binary = release_dir / f"{current_binary.stem}.bak{current_binary.suffix}"
        helper_script = release_dir / "storage" / "data" / "agent_update.vbs"
        notice_file = UPDATE_NOTICE_FILE if UPDATE_NOTICE_FILE.is_absolute() else release_dir / UPDATE_NOTICE_FILE
        helper_script.parent.mkdir(parents=True, exist_ok=True)

        try:
            request_headers = {
                "Cache-Control": "no-cache, no-store, max-age=0",
                "Pragma": "no-cache",
            }
            cache_buster = ""
            if expected_sha256:
                cache_buster = f"v={expected_sha256}"
            if cache_buster:
                joiner = "&" if "?" in download_url else "?"
                download_url = f"{download_url}{joiner}{cache_buster}"
            with requests.get(download_url, stream=True, timeout=(20, 300), headers=request_headers) as response:
                response.raise_for_status()
                with staged_binary.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            handle.write(chunk)

            downloaded_sha = self._sha256_file(staged_binary).lower()
            if expected_sha256 and downloaded_sha != expected_sha256:
                raise RuntimeError(f"Downloaded agent checksum mismatch: expected={expected_sha256} got={downloaded_sha}")

            if backup_binary.exists():
                backup_binary.unlink()

            relaunch_command = subprocess.list2cmdline([str(current_binary), *self._current_args])
            helper_lines = [
                "Option Explicit",
                f"Dim pid : pid = {int(os.getpid())}",
                f'Dim target : target = "{self._vbs_string(str(current_binary))}"',
                f'Dim staged : staged = "{self._vbs_string(str(staged_binary))}"',
                f'Dim backup : backup = "{self._vbs_string(str(backup_binary))}"',
                f'Dim launchCmd : launchCmd = "{self._vbs_string(relaunch_command)}"',
                "Dim fso, sh, wmi, procSet, proc, result, newPid, alive",
                "Set fso = CreateObject(\"Scripting.FileSystemObject\")",
                "Set sh = CreateObject(\"WScript.Shell\")",
                "Set wmi = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")",
                "sh.Environment(\"PROCESS\")(\"PYINSTALLER_RESET_ENVIRONMENT\") = \"1\"",
                "Do",
                "  Set procSet = wmi.ExecQuery(\"Select * from Win32_Process Where ProcessId=\" & pid)",
                "  If procSet.Count = 0 Then Exit Do",
                "  WScript.Sleep 1000",
                "Loop",
                "WScript.Sleep 5000",
                "On Error Resume Next",
                "If fso.FileExists(backup) Then fso.DeleteFile backup, True",
                "If fso.FileExists(target) Then fso.MoveFile target, backup",
                "fso.MoveFile staged, target",
                "On Error GoTo 0",
                "WScript.Sleep 10000",
                "Set proc = wmi.Get(\"Win32_Process\")",
                "result = proc.Create(launchCmd, Null, Null, newPid)",
                "If result = 0 Then",
                "  WScript.Sleep 15000",
                "  alive = False",
                "  Set procSet = wmi.ExecQuery(\"Select * from Win32_Process Where ProcessId=\" & newPid)",
                "  If procSet.Count > 0 Then alive = True",
                "  If Not alive Then",
                "    WScript.Sleep 5000",
                "    result = proc.Create(launchCmd, Null, Null, newPid)",
                "  End If",
                "End If",
                "On Error Resume Next",
                "fso.DeleteFile WScript.ScriptFullName, True",
                "On Error GoTo 0",
            ]
            helper_script.write_text("\r\n".join(helper_lines) + "\r\n", encoding="utf-8")
            helper_cmd = [
                "wscript.exe",
                "//B",
                "//Nologo",
                str(helper_script),
            ]
            notice_version = str(target_version or self.state.last_available_version or "").strip()
            if notice_version:
                try:
                    self._write_update_notice(notice_file, notice_version)
                except Exception as exc:  # noqa: BLE001
                    LOGGER.warning("Failed to write update notice marker: %s", exc)
            subprocess.Popen(
                helper_cmd,
                cwd=str(release_dir),
                close_fds=True,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                env=fresh_pyinstaller_env(),
            )

            with self._lock:
                self.state.last_success_at = _utc_now()
                self.state.last_return_code = 0
                self.state.last_error = ""
                if target_version:
                    self.state.current_version = target_version
                self.state.running = False
            return True, "Update staged; restarting agent", True
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.state.last_error = str(exc)
                self.state.running = False
                self.state.last_return_code = 1
            try:
                if staged_binary.exists():
                    staged_binary.unlink()
            except Exception:
                pass
            try:
                if notice_file.exists():
                    notice_file.unlink()
            except Exception:
                pass
            return False, str(exc), False

    def handle_signal(self, version: str, command_text: str, source: str, raw_text: str = "") -> tuple[bool, str]:
        version = (version or "").strip()
        command_text = (command_text or "").strip()
        source = source.strip() or "unknown"
        now = _utc_now()

        with self._lock:
            self.state.last_source = source
            self.state.last_signal_text = raw_text[:1000]
            self.state.last_event_at = now
            if version:
                self.state.pending_version = version

        if version and version == self.state.current_version:
            return True, "Already on latest version"

        if not self.auto_apply:
            return True, "Update signal received (auto-apply disabled)"

        command = command_text or self.default_command
        if not self._is_allowed(command):
            with self._lock:
                self.state.last_error = f"Command is not allowed: {command}"
            return False, "Command is not allowed by UPDATE_ALLOWED_PREFIX"

        return self._start_command(command, version)

    def handle_text_message(self, message: str, source: str = "ws") -> tuple[bool, str]:
        text = (message or "").strip()
        if not text:
            return False, "Empty update message"

        version = ""
        command = ""
        try:
            parsed = json.loads(text)
            event = str(parsed.get("event", "")).strip().lower()
            payload = parsed.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            if event in {"update", "update_available", "new_version"}:
                version = str(payload.get("version") or parsed.get("version") or "").strip()
                command = str(payload.get("command") or payload.get("text") or parsed.get("command") or "").strip()
                return self.handle_signal(version, command, source=source, raw_text=text)
            return False, f"Ignored non-update event: {event or 'unknown'}"
        except Exception:  # noqa: BLE001
            pass

        # Plain text format support:
        # "UPDATE 1.2.3|git pull --ff-only"
        # or "UPDATE 1.2.3"
        if text.upper().startswith("UPDATE "):
            body = text[7:].strip()
            if "|" in body:
                version, command = body.split("|", 1)
                return self.handle_signal(version.strip(), command.strip(), source=source, raw_text=text)
            return self.handle_signal(body, "", source=source, raw_text=text)

        return False, "Ignored message format"
