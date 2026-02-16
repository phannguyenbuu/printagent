from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)


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
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.current_version = os.getenv("APP_VERSION", "0.1.0").strip() or "0.1.0"
        self.auto_apply = _env_bool("UPDATE_AUTO_APPLY", default=False)
        self.default_command = os.getenv("UPDATE_DEFAULT_COMMAND", "git pull --ff-only").strip()
        prefix_raw = os.getenv("UPDATE_ALLOWED_PREFIX", "git pull --ff-only").strip()
        self.allowed_prefixes = [item.strip() for item in prefix_raw.split(",") if item.strip()]
        self.webhook_token = os.getenv("UPDATE_WEBHOOK_TOKEN", "").strip()
        self.state = UpdateState(current_version=self.current_version)
        self._lock = threading.Lock()

    def status(self) -> dict[str, Any]:
        with self._lock:
            payload = asdict(self.state)
        payload.update(
            {
                "auto_apply": self.auto_apply,
                "allowed_prefixes": self.allowed_prefixes,
                "default_command": self.default_command,
            }
        )
        return payload

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
