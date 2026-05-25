from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent.config import AppConfig

_SCAN_PROTOCOL_PREFS: dict[str, str] = {}


def _load_scan_protocol_prefs() -> dict[str, str]:
    return dict(_SCAN_PROTOCOL_PREFS)


def _save_scan_protocol_prefs(prefs: dict[str, str]) -> None:
    _SCAN_PROTOCOL_PREFS.clear()
    for k, v in (prefs or {}).items():
        ip = _normalize_ipv4(str(k or "").strip())
        protocol = str(v or "").strip()
        if ip and protocol:
            _SCAN_PROTOCOL_PREFS[ip] = protocol


def _normalize_scan_protocol(value: str) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    if text in {"SMBV1", "SMB1", "SMBV1.0"}:
        return "SMBv1"
    if text in {"SMBV2/3", "SMBV2", "SMB2", "SMBV3", "SMB3"}:
        return "SMBv2/3"
    if text == "FTP":
        return "FTP"
    return ""


def _sanitize_ftp_name(value: str) -> str:
    text = str(value or "").strip().replace(" ", "_")
    text = re.sub(r"[^A-Za-z0-9_-]", "", text)
    return text[:48]


def _register_scan_root(config: AppConfig, scan_root: str | Path) -> dict[str, Any]:
    added, scan_dirs = config.ensure_scan_dir(scan_root)
    return {
        "scan_dir_added": added,
        "scan_dirs": scan_dirs,
    }


def _detect_scan_protocol_from_html(html: str) -> str:
    text = str(html or "").lower()
    has_smbv1 = any(token in text for token in ["smbv1", "smb v1", "smb1", "nt1"])
    has_smbv23 = any(token in text for token in ["smbv2", "smb v2", "smb2", "smbv3", "smb v3", "smb3", "cifs"])
    has_ftp = "ftp" in text
    if has_smbv23:
        return "SMBv2/3"
    if has_smbv1:
        return "SMBv1"
    if has_ftp:
        return "FTP"
    return ""


