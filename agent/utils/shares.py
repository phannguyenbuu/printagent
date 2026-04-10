from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.ftp_store import (
    find_site_by_name,
    find_site_by_port,
    load_config,
    load_state,
    merge_runtime_with_config,
    normalize_port,
    normalize_site_name,
    normalize_ftp_password,
    normalize_ftp_user,
    normalize_path,
    save_config,
    site_spec,
    upsert_site,
    remove_site,
)
from app.services.scan_drop import build_drop_folder_metadata
from app.services.runtime import no_window_subprocess_kwargs, spawn_detached_command, startup_command_for_current_exe, ensure_startup_registration
from app.services.ftp_store import now_iso

LOGGER = logging.getLogger(__name__)


class ShareManager:
    """
    Manages Windows-specific sharing operations like creating SMB shares and
    persisting FTP site definitions for the dedicated FTP worker.
    """

    def __init__(self) -> None:
        self._worker_lock = threading.Lock()

    @staticmethod
    def is_admin() -> bool:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
                ],
                capture_output=True,
                text=True,
                check=True,
                **no_window_subprocess_kwargs(),
            )
            return "True" in result.stdout
        except Exception:
            return False

    def create_smb_share(self, share_name: str, local_path: str | Path, user: str = "Everyone", access: str = "Full") -> dict[str, Any]:
        if not self.is_admin():
            return {"ok": False, "error": "Administrative privileges required to create SMB shares."}

        path = Path(local_path).absolute()
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            LOGGER.info("Created directory: %s", path)

        try:
            subprocess.run(["icacls", str(path), "/grant", f"{user}:(OI)(CI)F"], check=True, capture_output=True, **no_window_subprocess_kwargs())
            cmd = f"New-SmbShare -Name '{share_name}' -Path '{path}' -FullAccess '{user}' -Force"
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, **no_window_subprocess_kwargs())

            if result.returncode != 0:
                if "already exists" in result.stderr:
                    LOGGER.info("SMB share '%s' already exists.", share_name)
                    return {"ok": True, "message": f"SMB share '{share_name}' already exists.", "path": str(path)}
                return {"ok": False, "error": result.stderr.strip()}

            LOGGER.info("Successfully created SMB share '%s' at '%s'", share_name, path)
            return {"ok": True, "share_name": share_name, "path": str(path)}
        except Exception as e:
            LOGGER.exception("Failed to create SMB share: %s", e)
            return {"ok": False, "error": str(e)}

    @staticmethod
    def _worker_app_name() -> str:
        return "GoPrinxAgentFtpWorker"

    @staticmethod
    def _worker_command() -> str:
        return startup_command_for_current_exe("ftp-worker")

    def _ensure_worker_registration(self) -> tuple[bool, str]:
        return ensure_startup_registration(app_name=self._worker_app_name(), command=self._worker_command())

    @staticmethod
    def _is_worker_live(max_age_seconds: int = 45) -> bool:
        state = load_state()
        heartbeat = str(state.get("worker_heartbeat_at", "") or "").strip()
        if not heartbeat:
            return False
        try:
            elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(heartbeat)
            return elapsed.total_seconds() <= max_age_seconds
        except Exception:
            return False

    def _ensure_worker_started(self) -> None:
        if self._is_worker_live():
            return
        with self._worker_lock:
            if self._is_worker_live():
                return
            self._ensure_worker_registration()
            try:
                spawn_detached_command(self._worker_command())
                LOGGER.info("FTP worker launch requested")
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("FTP worker launch failed: %s", exc)

    @staticmethod
    def _live_site_snapshot(site_name: str, fallback: dict[str, Any] | None = None) -> dict[str, Any] | None:
        config = load_config()
        state = load_state()
        merged = merge_runtime_with_config(config, state)
        safe_name = normalize_site_name(site_name)
        for row in merged:
            if normalize_site_name(str(row.get("name", "") or "")) == safe_name:
                return row
        if fallback:
            row = dict(fallback)
            row.setdefault("running", False)
            row.setdefault("state", "configured")
            return row
        return None

    def _wait_for_live_site(self, site_name: str, timeout_seconds: int = 20) -> dict[str, Any] | None:
        deadline = time.time() + max(1, timeout_seconds)
        while time.time() < deadline:
            live = self._live_site_snapshot(site_name)
            if live and bool(live.get("running", False)) and int(live.get("port", 0) or 0) > 0:
                return live
            time.sleep(0.5)
        return self._live_site_snapshot(site_name)

    @staticmethod
    def _firewall_warnings(site_payload: dict[str, Any] | None) -> list[str]:
        if not isinstance(site_payload, dict):
            return []
        firewall = site_payload.get("firewall")
        if not isinstance(firewall, dict):
            return []
        errors = [str(item or "").strip() for item in firewall.get("errors", []) if str(item or "").strip()]
        if not errors:
            return []
        if any("requires elevation" in err.lower() for err in errors):
            return [
                "FTP site started successfully, but Windows Firewall rules were not added because PrintAgent is not running as Administrator."
            ]
        return [f"FTP site started successfully, but firewall setup reported: {err}" for err in errors]

    @classmethod
    def _attach_site_warnings(cls, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        warnings = cls._firewall_warnings(result)
        if warnings:
            result["warnings"] = warnings
            result["message"] = warnings[0]
        return result

    def _site_conflict_message(self, existing: dict[str, Any]) -> dict[str, Any]:
        return self._attach_site_warnings({
            "ok": True,
            "existed": True,
            "site_name": str(existing.get("name", "") or ""),
            "physical_path": str(existing.get("path", "") or ""),
            "port": int(existing.get("port", 0) or 0),
            "ftp_url": str(existing.get("ftp_url", "") or ""),
            "ftp_user": str(existing.get("ftp_user", "") or ""),
            "ftp_password": str(existing.get("ftp_password", "") or ""),
            "running": bool(existing.get("running", False)),
            "firewall": dict(existing.get("firewall") or {}),
        })

    def create_ftp_site(
        self,
        site_name: str,
        local_path: str | Path,
        port: int = 2121,
        ftp_user: str = "",
        ftp_password: str = "",
    ) -> dict[str, Any]:
        try:
            safe_site_name = normalize_site_name(site_name)
            safe_port = normalize_port(port)
            safe_path = normalize_path(local_path, safe_site_name)
            safe_user = normalize_ftp_user(ftp_user, safe_site_name)
            safe_password = normalize_ftp_password(ftp_password)

            LOGGER.info("FTP create requested: site=%s requested_port=%s path=%s", safe_site_name, safe_port, safe_path)

            config = load_config()
            existing_by_name = find_site_by_name(config, safe_site_name)
            existing_by_port = find_site_by_port(config, safe_port)
            if existing_by_port and normalize_site_name(str(existing_by_port.get("name", "") or "")) != safe_site_name:
                conflict_name = str(existing_by_port.get("name", "") or "").strip() or safe_site_name
                conflict_path = str(existing_by_port.get("path", "") or "")
                LOGGER.warning(
                    "FTP create rejected due to port conflict: requested=%s existing=%s port=%s",
                    safe_site_name,
                    conflict_name,
                    safe_port,
                )
                return {
                    "ok": False,
                    "error": f'Port {safe_port} is already assigned to FTP site "{conflict_name}"',
                    "site_name": conflict_name,
                    "physical_path": conflict_path,
                    "port": safe_port,
                }
            existing = existing_by_name or existing_by_port
            if existing:
                if normalize_site_name(str(existing.get("name", "") or "")) != safe_site_name:
                    LOGGER.info(
                        "FTP requested site matches existing port: requested=%s existing=%s port=%s",
                        safe_site_name,
                        existing.get("name", ""),
                        safe_port,
                    )
                desired = site_spec(
                    site_name=str(existing.get("name", "") or safe_site_name),
                    local_path=existing.get("path", safe_path),
                    port=existing.get("port", safe_port),
                    ftp_user=existing.get("ftp_user", safe_user),
                    ftp_password=existing.get("ftp_password", safe_password),
                    enabled=True,
                )
                upsert_site(config, desired)
                self._ensure_worker_started()
                live = self._wait_for_live_site(str(desired.get("name", "") or safe_site_name))
                if live and bool(live.get("running", False)):
                    LOGGER.info(
                        "FTP reuse confirmed: site=%s path=%s port=%s",
                        live.get("name", safe_site_name),
                        live.get("path", ""),
                        live.get("port", 0),
                    )
                    return self._attach_site_warnings({
                        "ok": True,
                        "existed": True,
                        "site_name": str(live.get("name", safe_site_name)),
                        "physical_path": str(live.get("path", safe_path)),
                        "port": int(live.get("port", safe_port) or safe_port),
                        "ftp_url": str(live.get("ftp_url", f"ftp://127.0.0.1:{safe_port}/")),
                        "ftp_user": str(live.get("ftp_user", safe_user)),
                        "ftp_password": str(live.get("ftp_password", safe_password)),
                        "runtime": "windows-worker",
                        "running": True,
                        "firewall": dict(live.get("firewall") or {}),
                    })
                return self._site_conflict_message(existing)

            desired = site_spec(
                site_name=safe_site_name,
                local_path=safe_path,
                port=safe_port,
                ftp_user=safe_user,
                ftp_password=safe_password,
                enabled=True,
            )
            upsert_site(config, desired)
            self._ensure_worker_started()
            live = self._wait_for_live_site(safe_site_name)
            if live and bool(live.get("running", False)):
                LOGGER.info("FTP site started: name=%s path=%s port=%s", safe_site_name, live.get("path", safe_path), live.get("port", safe_port))
                return self._attach_site_warnings({
                    "ok": True,
                    "existed": False,
                    "site_name": safe_site_name,
                    "physical_path": str(live.get("path", safe_path)),
                    "port": int(live.get("port", safe_port) or safe_port),
                    "ftp_url": str(live.get("ftp_url", f"ftp://127.0.0.1:{safe_port}/")),
                    "ftp_user": str(live.get("ftp_user", safe_user)),
                    "ftp_password": str(live.get("ftp_password", safe_password)),
                    "runtime": "windows-worker",
                    "running": True,
                    "firewall": dict(live.get("firewall") or {}),
                })
            LOGGER.warning("FTP site queued but not live yet: site=%s path=%s port=%s", safe_site_name, safe_path, safe_port)
            return self._attach_site_warnings({
                "ok": True,
                "existed": False,
                "site_name": safe_site_name,
                "physical_path": str(safe_path),
                "port": safe_port,
                "ftp_url": f"ftp://127.0.0.1:{safe_port}/",
                "ftp_user": safe_user,
                "ftp_password": safe_password,
                "runtime": "windows-worker",
                "running": False,
                "queued": True,
                "firewall": dict((live or {}).get("firewall") or {}),
            })
        except Exception as e:
            LOGGER.exception("FTP create failed: site_name=%s path=%s", site_name, local_path)
            return {"ok": False, "error": str(e)}

    def list_ftp_sites(self) -> list[dict[str, Any]]:
        config = load_config()
        state = load_state()
        merged = merge_runtime_with_config(config, state)
        return sorted(merged, key=lambda item: (int(item.get("port", 0) or 0), str(item.get("name", "") or "")))

    def get_ftp_site(self, site_name: str) -> dict[str, Any] | None:
        safe_site_name = normalize_site_name(site_name)
        if not safe_site_name:
            return None
        for site in self.list_ftp_sites():
            if normalize_site_name(str(site.get("name", "") or "")) == safe_site_name:
                return site
        return None

    def delete_ftp_site(self, site_name: str) -> dict[str, Any]:
        safe_site_name = normalize_site_name(site_name)
        if not safe_site_name:
            return {"ok": False, "error": "Invalid FTP site name."}
        config = load_config()
        removed = remove_site(config, safe_site_name)
        if not removed:
            return {"ok": False, "error": "FTP site not found."}
        time.sleep(0.5)
        return {
            "ok": True,
            "site_name": safe_site_name,
            "port": int(removed.get("port", 0) or 0),
            "ftp_url": str(removed.get("ftp_url", "") or f"ftp://127.0.0.1:{int(removed.get('port', 0) or 0)}/"),
            "ftp_user": str(removed.get("ftp_user", "") or ""),
            "ftp_password": str(removed.get("ftp_password", "") or ""),
            "runtime": "windows-worker",
        }

    def update_ftp_site(
        self,
        site_name: str,
        *,
        new_site_name: str | None = None,
        local_path: str | Path | None = None,
        port: int | None = None,
        ftp_user: str | None = None,
        ftp_password: str | None = None,
    ) -> dict[str, Any]:
        safe_old_name = normalize_site_name(site_name)
        if not safe_old_name:
            return {"ok": False, "error": "Invalid FTP site name."}
        config = load_config()
        current = find_site_by_name(config, safe_old_name)
        if not current:
            return {"ok": False, "error": "FTP site not found."}

        target_name = normalize_site_name(new_site_name or safe_old_name)
        next_path = normalize_path(local_path if local_path is not None else current.get("path", ""), target_name)
        next_port = normalize_port(port if port is not None else current.get("port", 2121))
        next_user = normalize_ftp_user(ftp_user or current.get("ftp_user", ""), target_name)
        next_password = normalize_ftp_password(ftp_password or current.get("ftp_password", ""))
        if not next_password:
            next_password = str(current.get("ftp_password", "") or "")

        remove_site(config, safe_old_name)
        config = load_config()
        desired = site_spec(
            site_name=target_name,
            local_path=next_path,
            port=next_port,
            ftp_user=next_user,
            ftp_password=next_password,
            enabled=True,
        )
        upsert_site(config, desired)
        self._ensure_worker_started()
        live = self._wait_for_live_site(target_name)
        if live and bool(live.get("running", False)):
            return {
                "ok": True,
                "old_site_name": safe_old_name,
                "site_name": target_name,
                "physical_path": str(live.get("path", next_path)),
                "port": int(live.get("port", next_port) or next_port),
                "ftp_url": str(live.get("ftp_url", f"ftp://127.0.0.1:{next_port}/")),
                "ftp_user": str(live.get("ftp_user", next_user) or next_user),
                "ftp_password": str(live.get("ftp_password", next_password) or next_password),
                "existed": bool(live.get("running", False)),
                "runtime": "windows-worker",
            }
        return {
            "ok": True,
            "old_site_name": safe_old_name,
            "site_name": target_name,
            "physical_path": str(next_path),
            "port": next_port,
            "ftp_url": f"ftp://127.0.0.1:{next_port}/",
            "ftp_user": next_user,
            "ftp_password": next_password,
            "existed": False,
            "runtime": "windows-worker",
            "queued": True,
        }

    def setup_auto_share(self, username: str) -> dict[str, Any]:
        base_dir = Path("storage/scans").absolute()
        user_dir = base_dir / username
        share_name = f"Scan_{username}"
        result = self.create_smb_share(share_name, user_dir, user=username)
        drop_folder = build_drop_folder_metadata(user_dir)
        result.update(
            {
                "upload_path": str(drop_folder.get("drop_folder_path", "") or ""),
                "drop_folder_name": str(drop_folder.get("drop_folder_name", "") or ""),
                "drop_relative_path": str(drop_folder.get("drop_relative_path", "") or ""),
            }
        )
        return result
