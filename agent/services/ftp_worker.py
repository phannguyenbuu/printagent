from __future__ import annotations

import os
import hashlib
import logging
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
except Exception:  # noqa: BLE001
    DummyAuthorizer = None  # type: ignore[assignment]
    FTPHandler = None  # type: ignore[assignment]
    FTPServer = None  # type: ignore[assignment]

from app.services.ftp_store import (
    find_site_by_port,
    load_config,
    normalize_port,
    normalize_site_name,
    save_state,
    site_spec,
    merge_runtime_with_config,
    now_iso,
)
from app.services.runtime import no_window_subprocess_kwargs
from app.utils.firewall import ensure_ftp_firewall_rules

LOGGER = logging.getLogger(__name__)


@dataclass
class _RunningSite:
    name: str
    path: str
    port: int
    ftp_user: str
    ftp_password: str
    ftp_url: str
    server: Any
    thread: threading.Thread
    started_at: str
    spec_hash: str
    error: str = ""
    pid: int = 0
    firewall: dict[str, Any] | None = None


class FtpWorker:
    def __init__(self, poll_seconds: float = 2.0) -> None:
        self._poll_seconds = max(0.5, float(poll_seconds or 2.0))
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._running: dict[str, _RunningSite] = {}
        self._worker_pid = 0
        self._last_heartbeat_at = ""

    @staticmethod
    def _site_hash(spec: dict[str, Any]) -> str:
        payload = "|".join(
            [
                str(spec.get("name", "") or ""),
                str(spec.get("path", "") or ""),
                str(spec.get("port", 0) or 0),
                str(spec.get("ftp_user", "") or ""),
                str(spec.get("ftp_password", "") or ""),
                str(bool(spec.get("enabled", True))),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _port_in_use(port: int) -> bool:
        if port <= 0:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    @staticmethod
    def _force_release_port(port: int) -> bool:
        if port <= 0:
            return False
        script = (
            f"$c = Get-NetTCPConnection -LocalPort {int(port)} -State Listen -ErrorAction SilentlyContinue | "
            f"Select-Object -First 1; "
            f"if ($null -ne $c) {{ Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; exit 0 }} "
            f"else {{ exit 1 }}"
        )
        try:
            result = subprocess.run(
                ["powershell", "-Command", script],
                capture_output=True,
                text=True,
                check=False,
                **no_window_subprocess_kwargs(),
            )
            return result.returncode == 0
        except Exception:
            return False

    def _start_site(self, spec: dict[str, Any]) -> dict[str, Any]:
        if DummyAuthorizer is None or FTPHandler is None or FTPServer is None:
            return {"ok": False, "error": "pyftpdlib is required but could not be imported"}
        try:
            from pyftpdlib.authorizers import DummyAuthorizer as _DummyAuthorizer
            from pyftpdlib.handlers import FTPHandler as _FTPHandler
            from pyftpdlib.servers import FTPServer as _FTPServer
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"pyftpdlib is required: {exc}"}

        safe_name = normalize_site_name(str(spec.get("name", "") or ""))
        safe_path = str(spec.get("path", "") or "")
        safe_port = normalize_port(spec.get("port"), default=2121)
        ftp_user = str(spec.get("ftp_user", "") or "")
        ftp_password = str(spec.get("ftp_password", "") or "")

        path_obj = Path(safe_path).absolute()
        path_obj.mkdir(parents=True, exist_ok=True)

        if self._port_in_use(safe_port):
            LOGGER.info("FTP worker port busy: site=%s port=%s; attempting to release", safe_name, safe_port)
            released = self._force_release_port(safe_port)
            LOGGER.info("FTP worker port release result: site=%s port=%s released=%s", safe_name, safe_port, released)
            time.sleep(0.5)

        if self._port_in_use(safe_port):
            return {"ok": False, "error": f"Port {safe_port} is already in use"}

        firewall_info = ensure_ftp_firewall_rules(control_port=safe_port)
        authorizer = _DummyAuthorizer()
        authorizer.add_user(ftp_user, ftp_password, str(path_obj), perm="elradfmwMT")

        handler = _FTPHandler
        handler.authorizer = authorizer
        handler.banner = f"PrintAgent FTP [{safe_name}] ready."
        handler.passive_ports = range(30000, 30050)
        server = _FTPServer(("0.0.0.0", safe_port), handler)

        def _serve() -> None:
            try:
                server.serve_forever(timeout=0.5, blocking=True, handle_exit=False)
            except Exception as serve_exc:  # noqa: BLE001
                LOGGER.error("FTP worker serve loop stopped: site=%s error=%s", safe_name, serve_exc)

        thread = threading.Thread(target=_serve, daemon=True, name=f"ftp-worker-{safe_name}")
        thread.start()
        time.sleep(0.2)
        if not thread.is_alive():
            return {"ok": False, "error": "FTP worker thread exited unexpectedly"}

        ftp_url = f"ftp://127.0.0.1:{safe_port}/"
        running = _RunningSite(
            name=safe_name,
            path=str(path_obj),
            port=safe_port,
            ftp_user=ftp_user,
            ftp_password=ftp_password,
            ftp_url=ftp_url,
            server=server,
            thread=thread,
            started_at=now_iso(),
            spec_hash=self._site_hash(spec),
            firewall=firewall_info,
        )
        with self._lock:
            self._running[safe_name] = running
        LOGGER.info("FTP worker site started: name=%s path=%s port=%s", safe_name, path_obj, safe_port)
        return {
            "ok": True,
            "name": safe_name,
            "path": str(path_obj),
            "port": safe_port,
            "ftp_url": ftp_url,
            "ftp_user": ftp_user,
            "ftp_password": ftp_password,
            "firewall": firewall_info,
            "running": True,
        }

    def _stop_site(self, site_name: str) -> None:
        with self._lock:
            site = self._running.pop(site_name, None)
        if not site:
            return
        for method_name in ("close_all", "close", "shutdown"):
            method = getattr(site.server, method_name, None)
            if callable(method):
                try:
                    method()
                except Exception:  # noqa: BLE001
                    pass
                break
        try:
            if site.thread and hasattr(site.thread, "join"):
                site.thread.join(timeout=1)
        except Exception:  # noqa: BLE001
            pass

    def _sync_once(self) -> None:
        config = load_config()
        desired_sites = [site for site in config.get("sites", []) if isinstance(site, dict) and bool(site.get("enabled", True))]
        desired_by_name = {normalize_site_name(str(site.get("name", "") or "")): dict(site) for site in desired_sites if normalize_site_name(str(site.get("name", "") or ""))}

        with self._lock:
            running_names = list(self._running.keys())

        for running_name in running_names:
            if running_name not in desired_by_name:
                LOGGER.info("FTP worker stopping removed site: %s", running_name)
                self._stop_site(running_name)

        for safe_name, spec in desired_by_name.items():
            spec = site_spec(
                site_name=safe_name,
                local_path=spec.get("path", ""),
                port=spec.get("port", 2121),
                ftp_user=spec.get("ftp_user", ""),
                ftp_password=spec.get("ftp_password", ""),
                enabled=spec.get("enabled", True),
            )
            expected_hash = self._site_hash(spec)
            current = None
            with self._lock:
                current = self._running.get(safe_name)
            if current and current.thread.is_alive() and current.spec_hash == expected_hash:
                continue
            if current:
                LOGGER.info("FTP worker restarting site: name=%s", safe_name)
                self._stop_site(safe_name)
            existing_by_port = find_site_by_port({"sites": [site for site in desired_by_name.values()]}, spec.get("port", 0))
            if existing_by_port and normalize_site_name(str(existing_by_port.get("name", "") or "")) != safe_name:
                other_name = normalize_site_name(str(existing_by_port.get("name", "") or ""))
                other_running = None
                with self._lock:
                    other_running = self._running.get(other_name)
                if other_running:
                    self._stop_site(other_name)
            start_result = self._start_site(spec)
            if not start_result.get("ok"):
                with self._lock:
                    cur = self._running.get(safe_name)
                    if cur:
                        cur.error = str(start_result.get("error", "") or "")
                LOGGER.warning("FTP worker failed to start site: name=%s error=%s", safe_name, start_result.get("error", ""))

    def _snapshot_state(self) -> dict[str, Any]:
        with self._lock:
            running = list(self._running.values())
        sites: list[dict[str, Any]] = []
        for site in running:
            if not site.thread.is_alive():
                continue
            sites.append(
                {
                    "name": site.name,
                    "path": site.path,
                    "port": site.port,
                    "ftp_url": site.ftp_url,
                    "ftp_user": site.ftp_user,
                    "ftp_password": site.ftp_password,
                    "running": True,
                    "state": "running",
                    "error": site.error,
                    "pid": self._worker_pid,
                    "started_at": site.started_at,
                    "firewall": dict(site.firewall or {}),
                    "warnings": list((site.firewall or {}).get("errors", []) or []),
                    "updated_at": now_iso(),
                }
            )
        config = load_config()
        merged = merge_runtime_with_config(config, {"sites": sites})
        return {
            "worker_pid": self._worker_pid,
            "worker_heartbeat_at": self._last_heartbeat_at,
            "sites": merged,
        }

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            names = list(self._running.keys())
        for name in names:
            self._stop_site(name)

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        self._worker_pid = int(os.getpid())
        LOGGER.info("FTP worker starting: pid=%s", self._worker_pid)
        while not self._stop_event.is_set() and (stop_event is None or not stop_event.is_set()):
            self._last_heartbeat_at = now_iso()
            try:
                self._sync_once()
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("FTP worker sync failed: %s", exc)
            try:
                save_state(self._snapshot_state())
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("FTP worker state save failed: %s", exc)
            if self._stop_event.wait(self._poll_seconds):
                break
            if stop_event is not None and stop_event.wait(0):
                break
        self.stop()
        try:
            save_state(
                {
                    "worker_pid": self._worker_pid,
                    "worker_heartbeat_at": self._last_heartbeat_at,
                    "sites": [],
                }
            )
        except Exception:  # noqa: BLE001
            pass
