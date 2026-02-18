from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import yaml


class AppConfig:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "AppConfig":
        load_dotenv()
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError("Config root must be a mapping")
        cls._apply_env_overrides(raw)
        return cls(raw)

    @staticmethod
    def _set_nested(data: dict[str, Any], key: str, value: Any) -> None:
        parts = key.split(".")
        current: dict[str, Any] = data
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value

    @staticmethod
    def _env_bool(value: str) -> bool:
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def _apply_env_overrides(cls, raw: dict[str, Any]) -> None:
        env_map: list[tuple[str, str, str]] = [
            ("API_URL", "api_url", "str"),
            ("USER_TOKEN", "user_token", "str"),
            ("DATABASE_URL", "database_url", "str"),
            ("WEBHOOK_MODE", "webhook.mode", "str"),
            ("WEBHOOK_LISTEN_PATH", "webhook.listen_path", "str"),
            ("WS_URL", "ws.url", "str"),
            ("WS_TOKEN", "ws.token", "str"),
            ("WS_AUTO_CONNECT", "ws.auto_connect", "bool"),
            ("TEST_IP", "test.ip", "str"),
            ("TEST_USER", "test.user", "str"),
            ("TEST_PASSWORD", "test.password", "str"),
            ("TEST_POST_SERVER", "test.post_server", "bool"),
            ("POLLING_ENABLED", "polling.enabled", "bool"),
            ("POLLING_URL", "polling.url", "str"),
            ("POLLING_LEAD", "polling.lead", "str"),
            ("POLLING_TOKEN", "polling.token", "str"),
            ("POLLING_INTERVAL_SECONDS", "polling.interval_seconds", "str"),
            ("POLLING_LAN_UID", "polling.lan_uid", "str"),
            ("POLLING_AGENT_UID", "polling.agent_uid", "str"),
            ("POLLING_SCAN_ENABLED", "polling.scan_enabled", "bool"),
            ("POLLING_SCAN_INTERVAL_SECONDS", "polling.scan_interval_seconds", "str"),
            ("POLLING_SCAN_DIRS", "polling.scan_dirs", "str"),
            ("POLLING_SCAN_RECURSIVE", "polling.scan_recursive", "bool"),
        ]
        for env_name, key, value_type in env_map:
            env_value = os.getenv(env_name)
            if env_value is None:
                continue
            parsed: Any = env_value
            if value_type == "bool":
                parsed = cls._env_bool(env_value)
            cls._set_nested(raw, key, parsed)

    def _get(self, key: str, default: Any = None) -> Any:
        current: Any = self._data
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    def get_string(self, key: str, default: str = "") -> str:
        value = self._get(key, default)
        if value is None:
            return default
        return str(value)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self._get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @property
    def api_url(self) -> str:
        return self.get_string("api_url", "").rstrip("/")

    @property
    def user_token(self) -> str:
        return self.get_string("user_token", "")

    @property
    def database_url(self) -> str:
        return self.get_string("database_url", "sqlite:///storage/data/agent_config.db")
