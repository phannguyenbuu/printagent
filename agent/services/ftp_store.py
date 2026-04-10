from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.runtime import default_ftp_root

BASE_DIR = Path("storage") / "ftp_service"
CONFIG_FILE = BASE_DIR / "sites.json"
STATE_FILE = BASE_DIR / "runtime.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_base_dir() -> Path:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    return BASE_DIR


def _read_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return default
        return json.loads(raw)
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    ensure_base_dir()
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_config() -> dict[str, Any]:
    data = _read_json(CONFIG_FILE, {})
    if not isinstance(data, dict):
        data = {}
    sites = data.get("sites", [])
    if not isinstance(sites, list):
        sites = []
    return {
        "version": int(data.get("version", 1) or 1),
        "updated_at": str(data.get("updated_at", "") or ""),
        "sites": [site for site in sites if isinstance(site, dict)],
    }


def save_config(sites: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "version": 1,
        "updated_at": now_iso(),
        "sites": [site for site in sites if isinstance(site, dict)],
    }
    _write_json(CONFIG_FILE, payload)
    return payload


def load_state() -> dict[str, Any]:
    data = _read_json(STATE_FILE, {})
    if not isinstance(data, dict):
        data = {}
    sites = data.get("sites", [])
    if not isinstance(sites, list):
        sites = []
    return {
        "version": int(data.get("version", 1) or 1),
        "updated_at": str(data.get("updated_at", "") or ""),
        "worker_pid": int(data.get("worker_pid", 0) or 0),
        "worker_heartbeat_at": str(data.get("worker_heartbeat_at", "") or ""),
        "sites": [site for site in sites if isinstance(site, dict)],
    }


def save_state(state: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "version": 1,
        "updated_at": now_iso(),
        "worker_pid": int(state.get("worker_pid", 0) or 0),
        "worker_heartbeat_at": str(state.get("worker_heartbeat_at", "") or ""),
        "sites": [site for site in state.get("sites", []) if isinstance(site, dict)],
    }
    _write_json(STATE_FILE, payload)
    return payload


def normalize_site_name(value: str, default: str = "ftp_site") -> str:
    text = str(value or "").strip().replace(" ", "_")
    text = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-"})
    text = text[:48]
    return text or default


def normalize_ftp_user(value: str, site_name: str) -> str:
    text = str(value or "").strip().replace(" ", "_")
    text = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-"})
    text = text[:64]
    return text or f"ftp_{site_name}"


def normalize_ftp_password(value: str) -> str:
    return str(value or "").strip()


def normalize_port(value: int | str | None, default: int = 2121) -> int:
    try:
        port = int(value or 0)
    except Exception:
        port = 0
    if port <= 0 or port > 65535:
        return default
    return port


def normalize_path(value: str | Path | None, site_name: str) -> Path:
    if value is None:
        return default_ftp_root(site_name)
    path = Path(value).expanduser()
    if not str(path).strip():
        return default_ftp_root(site_name)
    return path


def site_spec(
    *,
    site_name: str,
    local_path: str | Path | None,
    port: int | str | None,
    ftp_user: str = "",
    ftp_password: str = "",
    enabled: bool = True,
) -> dict[str, Any]:
    safe_name = normalize_site_name(site_name)
    safe_port = normalize_port(port)
    safe_path = normalize_path(local_path, safe_name)
    safe_user = normalize_ftp_user(ftp_user, safe_name)
    safe_password = normalize_ftp_password(ftp_password)
    return {
        "name": safe_name,
        "path": str(safe_path),
        "port": int(safe_port),
        "ftp_user": safe_user,
        "ftp_password": safe_password,
        "enabled": bool(enabled),
    }


def upsert_site(config: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    sites = [site for site in config.get("sites", []) if isinstance(site, dict)]
    safe_name = normalize_site_name(str(spec.get("name", "") or ""))
    safe_port = normalize_port(spec.get("port"))
    merged = dict(spec)
    merged["name"] = safe_name
    merged["port"] = int(safe_port)
    merged["path"] = str(normalize_path(merged.get("path", ""), safe_name))
    merged["ftp_user"] = normalize_ftp_user(str(merged.get("ftp_user", "") or ""), safe_name)
    merged["ftp_password"] = normalize_ftp_password(str(merged.get("ftp_password", "") or ""))
    merged["enabled"] = bool(merged.get("enabled", True))

    replaced = False
    for idx, site in enumerate(sites):
        if normalize_site_name(str(site.get("name", "") or "")) == safe_name:
            sites[idx] = merged
            replaced = True
            break
    if not replaced:
        sites.append(merged)
    config = {
        "version": 1,
        "updated_at": now_iso(),
        "sites": sites,
    }
    _write_json(CONFIG_FILE, config)
    return merged


def remove_site(config: dict[str, Any], site_name: str) -> dict[str, Any] | None:
    safe_name = normalize_site_name(site_name)
    sites = [site for site in config.get("sites", []) if isinstance(site, dict)]
    removed: dict[str, Any] | None = None
    kept: list[dict[str, Any]] = []
    for site in sites:
        current_name = normalize_site_name(str(site.get("name", "") or ""))
        if current_name == safe_name:
            removed = dict(site)
            continue
        kept.append(site)
    _write_json(
        CONFIG_FILE,
        {
            "version": 1,
            "updated_at": now_iso(),
            "sites": kept,
        },
    )
    return removed


def find_site_by_name(config: dict[str, Any], site_name: str) -> dict[str, Any] | None:
    safe_name = normalize_site_name(site_name)
    for site in config.get("sites", []):
        if not isinstance(site, dict):
            continue
        if normalize_site_name(str(site.get("name", "") or "")) == safe_name:
            return dict(site)
    return None


def find_site_by_port(config: dict[str, Any], port: int | str) -> dict[str, Any] | None:
    safe_port = normalize_port(port, default=0)
    if safe_port <= 0:
        return None
    for site in config.get("sites", []):
        if not isinstance(site, dict):
            continue
        if normalize_port(site.get("port"), default=0) == safe_port:
            return dict(site)
    return None


def merge_runtime_with_config(config: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    runtime_sites = state.get("sites", [])
    runtime_by_name: dict[str, dict[str, Any]] = {}
    runtime_by_port: dict[int, dict[str, Any]] = {}
    for site in runtime_sites:
        if not isinstance(site, dict):
            continue
        safe_name = normalize_site_name(str(site.get("name", "") or ""))
        safe_port = normalize_port(site.get("port"), default=0)
        if safe_name:
            runtime_by_name[safe_name] = dict(site)
        if safe_port > 0:
            runtime_by_port[safe_port] = dict(site)

    merged: list[dict[str, Any]] = []
    for site in config.get("sites", []):
        if not isinstance(site, dict):
            continue
        safe_name = normalize_site_name(str(site.get("name", "") or ""))
        safe_port = normalize_port(site.get("port"), default=0)
        live = runtime_by_name.get(safe_name) or runtime_by_port.get(safe_port) or {}
        merged.append(
            {
                "name": safe_name,
                "path": str(site.get("path", "") or ""),
                "port": safe_port,
                "ftp_url": str(live.get("ftp_url") or site.get("ftp_url") or ""),
                "ftp_user": str(site.get("ftp_user", "") or live.get("ftp_user", "") or ""),
                "ftp_password": str(site.get("ftp_password", "") or live.get("ftp_password", "") or ""),
                "running": bool(live.get("running", False)),
                "state": str(live.get("state", "configured") or "configured"),
                "error": str(live.get("error", "") or ""),
                "pid": int(live.get("pid", 0) or 0),
                "firewall": dict(live.get("firewall") or {}),
                "warnings": list(live.get("warnings") or []),
                "updated_at": str(site.get("updated_at", "") or config.get("updated_at", "") or ""),
            }
        )
    merged.sort(key=lambda item: (int(item.get("port", 0) or 0), str(item.get("name", "") or "")))
    return merged
