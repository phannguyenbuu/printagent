from __future__ import annotations

import logging
import subprocess
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

    def create_ftp_site(self, site_name: str, local_path: str | Path, port: int = 21) -> dict[str, Any]:
        """
        Attempts to create an FTP site in IIS.
        Note: Requires IIS and Web-Ftp-Server feature enabled.
        """
        if not self.is_admin():
            return {"ok": False, "error": "Administrative privileges required to configure IIS FTP."}

        path = Path(local_path).absolute()
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)

        try:
            safe_site_name = "".join(ch for ch in str(site_name or "") if ch.isalnum() or ch in {"_", "-"}).strip()
            if not safe_site_name:
                return {"ok": False, "error": "Invalid FTP site name."}
            safe_site_name = safe_site_name[:48]

            script = f"""
$ErrorActionPreference='Stop'
Import-Module WebAdministration
$siteName = "{safe_site_name}"
$physicalPath = "{str(path)}"
$preferredPort = {int(port)}
$existing = Get-Website -Name $siteName -ErrorAction SilentlyContinue
if ($existing) {{
  $bindings = @($existing.bindings.Collection | ForEach-Object {{ $_.bindingInformation }})
  [PSCustomObject]@{{
    ok = $true
    existed = $true
    site_name = $siteName
    physical_path = $physicalPath
    bindings = $bindings
  }} | ConvertTo-Json -Depth 5
  exit 0
}}

function Find-FreePort([int]$start) {{
  for ($p = $start; $p -le ($start + 200); $p++) {{
    $busy = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if (-not $busy) {{ return $p }}
  }}
  return $start
}}

$usePort = Find-FreePort -start $preferredPort
if (-not (Test-Path -LiteralPath $physicalPath)) {{
  New-Item -ItemType Directory -Path $physicalPath -Force | Out-Null
}}
New-WebFtpSite -Name $siteName -Port $usePort -PhysicalPath $physicalPath -Force | Out-Null
Set-ItemProperty "IIS:\\Sites\\$siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
Set-ItemProperty "IIS:\\Sites\\$siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $false

[PSCustomObject]@{{
  ok = $true
  existed = $false
  site_name = $siteName
  physical_path = $physicalPath
  port = $usePort
}} | ConvertTo-Json -Depth 5
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=45,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "").strip()
                return {"ok": False, "error": err or "Failed to create FTP site."}
            raw = (result.stdout or "").strip()
            payload: dict[str, Any] = {}
            try:
                import json
                parsed = json.loads(raw) if raw else {}
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                payload = {"raw": raw}
            return {"ok": True, **payload}
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
