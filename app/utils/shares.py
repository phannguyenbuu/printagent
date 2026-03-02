from __future__ import annotations

import logging
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

class ShareManager:
    """
    Manages Windows-specific sharing operations like creating SMB shares and FTP sites.
    Requires administrative privileges for most operations.
    """

    @staticmethod
    def is_admin() -> bool:
        """Checks if the current process has administrative privileges."""
        try:
            # On Windows, check if the current process can access a restricted path
            result = subprocess.run(
                ["powershell", "-Command", "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"],
                capture_output=True,
                text=True,
                check=True
            )
            return "True" in result.stdout
        except Exception:
            return False

    def create_smb_share(self, share_name: str, local_path: str | Path, user: str = "Everyone", access: str = "Full") -> dict[str, Any]:
        """
        Creates a Windows SMB share for the specified path.
        """
        if not self.is_admin():
            return {"ok": False, "error": "Administrative privileges required to create SMB shares."}

        path = Path(local_path).absolute()
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            LOGGER.info("Created directory: %s", path)

        try:
            # Grant folder NTFS permissions (Read/Write for the user)
            # /grant {user}:(OI)(CI)F -> Object Inherit, Container Inherit, Full Control
            subprocess.run(["icacls", str(path), "/grant", f"{user}:(OI)(CI)F"], check=True, capture_output=True)
            
            # Create the SMB share
            # New-SmbShare -Name name -Path path -FullAccess user
            cmd = f"New-SmbShare -Name '{share_name}' -Path '{path}' -FullAccess '{user}' -Force"
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            
            if result.returncode != 0:
                # Check if share already exists
                if "already exists" in result.stderr:
                    LOGGER.info("SMB share '%s' already exists.", share_name)
                    return {"ok": True, "message": f"SMB share '{share_name}' already exists.", "path": str(path)}
                return {"ok": False, "error": result.stderr.strip()}

            LOGGER.info("Successfully created SMB share '%s' at '%s'", share_name, path)
            return {"ok": True, "share_name": share_name, "path": str(path)}
        except Exception as e:
            LOGGER.exception("Failed to create SMB share: %s", e)
            return {"ok": False, "error": str(e)}

    def create_ftp_site(self, site_name: str, local_path: str | Path, port: int = 2121) -> dict[str, Any]:
        """
        Creates an in-process FTP site using pyftpdlib.
        The FTP server lifetime follows the agent process lifetime.
        """
        if not hasattr(self, "_ftp_lock"):
            self._ftp_lock = threading.Lock()
        if not hasattr(self, "_ftp_sites"):
            self._ftp_sites: dict[str, dict[str, Any]] = {}

        path = Path(local_path).absolute()
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)

        try:
            safe_site_name = "".join(ch for ch in str(site_name or "") if ch.isalnum() or ch in {"_", "-"}).strip()
            if not safe_site_name:
                return {"ok": False, "error": "Invalid FTP site name."}
            safe_site_name = safe_site_name[:48]
            try:
                from pyftpdlib.authorizers import DummyAuthorizer
                from pyftpdlib.handlers import FTPHandler
                from pyftpdlib.servers import FTPServer
            except Exception as exc:
                return {"ok": False, "error": f"pyftpdlib is required: {exc}"}

            preferred_port = int(port) if int(port) > 0 else 2121

            def _port_in_use(check_port: int) -> bool:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.2)
                    return sock.connect_ex(("127.0.0.1", check_port)) == 0

            def _find_free_port(start_port: int) -> int:
                for p in range(start_port, start_port + 300):
                    if not _port_in_use(p):
                        return p
                return start_port

            with self._ftp_lock:
                existing = self._ftp_sites.get(safe_site_name)
                if existing:
                    return {
                        "ok": True,
                        "existed": True,
                        "site_name": safe_site_name,
                        "physical_path": str(path),
                        "port": int(existing.get("port", 0) or 0),
                        "ftp_url": str(existing.get("ftp_url", "")),
                    }

                use_port = _find_free_port(preferred_port)
                authorizer = DummyAuthorizer()
                authorizer.add_anonymous(str(path), perm="elradfmwMT")

                handler = FTPHandler
                handler.authorizer = authorizer
                handler.banner = f"PrintAgent FTP [{safe_site_name}] ready."
                server = FTPServer(("0.0.0.0", use_port), handler)

                def _serve() -> None:
                    try:
                        server.serve_forever(timeout=0.5, blocking=True, handle_exit=False)
                    except Exception as serve_exc:  # noqa: BLE001
                        LOGGER.error("FTP serve loop stopped: site=%s error=%s", safe_site_name, serve_exc)

                thread = threading.Thread(target=_serve, daemon=True, name=f"ftp-{safe_site_name}")
                thread.start()
                time.sleep(0.15)
                if not thread.is_alive():
                    return {"ok": False, "error": "FTP thread exited unexpectedly."}

                ftp_url = f"ftp://127.0.0.1:{use_port}/"
                self._ftp_sites[safe_site_name] = {
                    "name": safe_site_name,
                    "path": str(path),
                    "port": use_port,
                    "ftp_url": ftp_url,
                    "server": server,
                    "thread": thread,
                }
                LOGGER.info("FTP site started: name=%s path=%s port=%s", safe_site_name, path, use_port)
                return {
                    "ok": True,
                    "existed": False,
                    "site_name": safe_site_name,
                    "physical_path": str(path),
                    "port": use_port,
                    "ftp_url": ftp_url,
                    "runtime": "agent-process",
                }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def setup_auto_share(self, username: str) -> dict[str, Any]:
        """
        Standardized setup for a user: creates folder and SMB share.
        """
        base_dir = Path("storage/scans").absolute()
        user_dir = base_dir / username
        share_name = f"Scan_{username}"
        
        return self.create_smb_share(share_name, user_dir, user=username)
