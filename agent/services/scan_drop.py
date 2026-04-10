from __future__ import annotations

import posixpath
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


DROP_FOLDER_NAME_RE = re.compile(r"^\d{8}_\d{6}_\d{6}(?:_\d{2})?$")
DROP_FOLDER_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S_%f"


def is_drop_folder_name(value: str) -> bool:
    return bool(DROP_FOLDER_NAME_RE.fullmatch(str(value or "").strip()))


def list_drop_folders(scan_root: str | Path) -> list[Path]:
    root = Path(scan_root).expanduser()
    if not root.exists() or not root.is_dir():
        return []
    rows = [child for child in root.iterdir() if child.is_dir() and is_drop_folder_name(child.name)]
    rows.sort(key=lambda item: item.name)
    return rows


def _directory_has_files(path: Path) -> bool:
    try:
        for item in path.rglob("*"):
            if item.is_file():
                return True
    except Exception:
        return False
    return False


def create_drop_folder(scan_root: str | Path, created_at: datetime | None = None) -> Path:
    root = Path(scan_root).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    stamp = (created_at or datetime.now()).strftime(DROP_FOLDER_TIMESTAMP_FORMAT)
    candidate = root / stamp
    index = 1
    while candidate.exists():
        candidate = root / f"{stamp}_{index:02d}"
        index += 1
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def ensure_active_drop_folder(scan_root: str | Path) -> Path:
    root = Path(scan_root).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    existing = list_drop_folders(root)
    if not existing:
        return create_drop_folder(root)
    latest = existing[-1]
    if _directory_has_files(latest):
        return create_drop_folder(root)
    return latest


def append_relative_path_to_url(base_url: str, relative_path: str) -> str:
    base = str(base_url or "").strip()
    rel = str(relative_path or "").strip().replace("\\", "/").strip("/")
    if not base or not rel:
        return base
    parsed = urlsplit(base)
    base_path = parsed.path or "/"
    if not base_path.endswith("/"):
        base_path = f"{base_path}/"
    joined = posixpath.join(base_path, rel)
    if not joined.endswith("/"):
        joined = f"{joined}/"
    return urlunsplit((parsed.scheme, parsed.netloc, joined, parsed.query, parsed.fragment))


def build_drop_folder_metadata(scan_root: str | Path, *, base_url: str = "") -> dict[str, Any]:
    root = Path(scan_root).expanduser()
    drop_dir = ensure_active_drop_folder(root)
    root_resolved = root.resolve()
    drop_resolved = drop_dir.resolve()
    relative_path = drop_resolved.relative_to(root_resolved).as_posix()
    payload: dict[str, Any] = {
        "scan_root": str(root_resolved),
        "drop_folder_name": drop_dir.name,
        "drop_folder_path": str(drop_resolved),
        "drop_relative_path": relative_path,
    }
    upload_url = append_relative_path_to_url(base_url, relative_path)
    if upload_url:
        payload["upload_url"] = upload_url
    return payload
