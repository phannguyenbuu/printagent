from __future__ import annotations

from agent.config import AppConfig
from agent.services.runtime import get_machine_agent_uid
from agent.services.updater import AutoUpdater


def _env_snapshot(config: AppConfig, updater: AutoUpdater) -> dict[str, str]:
    return {
        "APP_VERSION": str(updater.status().get("current_version", "") or ""),
        "API_URL": config.api_url,
        "USER_TOKEN": config.user_token,
        "UPDATE_AUTO_APPLY": str(updater.auto_apply).lower(),
        "UPDATE_DEFAULT_COMMAND": updater.default_command,
        "WEBHOOK_MODE": config.get_string("webhook.mode", "listen") or "listen",
        "WEBHOOK_LISTEN_PATH": config.get_string("webhook.listen_path", "/api/update/receive-text") or "/api/update/receive-text",
        "TEST_IP": config.get_string("test.ip"),
        "TEST_USER": config.get_string("test.user"),
        "POLLING_ENABLED": str(config.get_bool("polling.enabled", False)).lower(),
        "POLLING_URL": config.get_string("polling.url"),
        "POLLING_LEAD": config.get_string("polling.lead"),
        "POLLING_TOKEN": config.get_string("polling.token"),
        "POLLING_INTERVAL_SECONDS": config.get_string("polling.interval_seconds", "1"),
        "POLLING_LAN_UID": config.get_string("polling.lan_uid"),
        "POLLING_AGENT_UID": get_machine_agent_uid(config.get_string("polling.agent_uid")),
        "POLLING_SCAN_ENABLED": str(config.get_bool("polling.scan_enabled", True)).lower(),
        "POLLING_SCAN_INTERVAL_SECONDS": config.get_string("polling.scan_interval_seconds", "1"),
        "POLLING_SCAN_DIRS": config.get_string("polling.scan_dirs", "storage/scans/inbox"),
        "POLLING_SCAN_RECURSIVE": str(config.get_bool("polling.scan_recursive", True)).lower(),
    }


def _merge_env_overrides(snapshot: dict[str, str], overrides: dict[str, str]) -> dict[str, str]:
    merged = dict(snapshot)
    for key, value in (overrides or {}).items():
        if key in merged and str(value or "").strip():
            merged[key] = str(value)
    return merged


