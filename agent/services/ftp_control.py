from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.runtime import default_ftp_root

DEFAULT_FTP_PORT = 2121
DEFAULT_FTP_ROOT = default_ftp_root()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except Exception:
        return default


@dataclass(slots=True, frozen=True)
class FtpControlCommand:
    id: int
    action: str
    site_name: str
    new_site_name: str
    local_path: str
    port: int
    ftp_user: str
    ftp_password: str
    printer_mac_id: str
    printer_ip: str
    printer_name: str
    printer_auth_user: str
    printer_auth_password: str

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> FtpControlCommand | None:
        command_id = _int(row.get("id"), 0)
        if command_id <= 0:
            return None
        return cls(
            id=command_id,
            action=_text(row.get("action")).lower() or "create",
            site_name=_text(row.get("site_name")),
            new_site_name=_text(row.get("new_site_name")),
            local_path=_text(row.get("local_path")),
            port=_int(row.get("port"), DEFAULT_FTP_PORT) or DEFAULT_FTP_PORT,
            ftp_user=_text(row.get("ftp_user")),
            ftp_password=_text(row.get("ftp_password")),
            printer_mac_id=_text(row.get("printer_mac_id")),
            printer_ip=_text(row.get("printer_ip")),
            printer_name=_text(row.get("printer_name")),
            printer_auth_user=_text(row.get("printer_auth_user")),
            printer_auth_password=_text(row.get("printer_auth_password")),
        )

    @property
    def target_site_name(self) -> str:
        return self.new_site_name or self.site_name

    @property
    def default_local_path(self) -> Path:
        site_name = self.target_site_name or self.site_name or "site"
        return DEFAULT_FTP_ROOT / site_name


def parse_ftp_control_rows(rows: Any) -> list[FtpControlCommand]:
    if not isinstance(rows, list):
        return []
    commands: list[FtpControlCommand] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        command = FtpControlCommand.from_row(row)
        if command is not None:
            commands.append(command)
    return commands
