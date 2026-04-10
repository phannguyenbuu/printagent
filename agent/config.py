from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any


class AppConfig:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @classmethod
    def load(cls) -> "AppConfig":
        raw = cls._default_data()
        cls._apply_db_overrides(raw)
        cls._apply_env_overrides(raw)
        return cls(raw)

    @staticmethod
    def _default_data() -> dict[str, Any]:
        return {
            "database_url": "sqlite:///storage/data/agent_config.db",
            "api_url": "https://agentapi.quanlymay.com/api",
            "user_token": "",
            "webhook": {
                "mode": "listen",
                "listen_path": "/api/update/receive-text",
            },
            "test": {
                "ip": "",
                "user": "",
                "password": "",
                "post_server": False,
            },
            "polling": {
                "enabled": True,
                "url": "https://agentapi.quanlymay.com",
                "lead": "default",
                "token": "change-me",
                "interval_seconds": "300",
                "lan_uid": "",
                "agent_uid": "",
                "scan_enabled": True,
                "scan_interval_seconds": "300",
                "scan_dirs": "storage/scans/inbox",
                "scan_recursive": True,
            },
        }

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
    def _get_nested(data: dict[str, Any], key: str, default: Any = None) -> Any:
        current: Any = data
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    @staticmethod
    def _env_bool(value: str) -> bool:
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _database_url(raw: dict[str, Any] | None = None) -> str:
        env_value = os.getenv("DATABASE_URL")
        if env_value:
            return str(env_value).strip()
        if isinstance(raw, dict):
            value = raw.get("database_url")
            if value is not None:
                return str(value).strip()
        return "sqlite:///storage/data/agent_config.db"

    @classmethod
    def _settings_db_path(cls, raw: dict[str, Any] | None = None) -> Path | None:
        database_url = cls._database_url(raw)
        if not database_url:
            return None
        if database_url.startswith("sqlite:///"):
            return Path(database_url.replace("sqlite:///", "", 1))
        if database_url.startswith("sqlite://"):
            return Path(database_url.replace("sqlite://", "", 1))
        return None

    @classmethod
    def _apply_db_overrides(cls, raw: dict[str, Any]) -> None:
        db_path = cls._settings_db_path(raw)
        if db_path is None or not db_path.exists():
            return
        try:
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        except Exception:
            return
        for key, value in rows:
            safe_key = str(key or "").strip()
            if not safe_key:
                continue
            parsed: Any = value
            default_value = cls._get_nested(raw, safe_key, None)
            if isinstance(default_value, bool):
                parsed = cls._env_bool(str(value or ""))
            cls._set_nested(raw, safe_key, parsed)

    @classmethod
    def _apply_env_overrides(cls, raw: dict[str, Any]) -> None:
        env_map: list[tuple[str, str, str]] = [
            ("DATABASE_URL", "database_url", "str"),
            ("API_URL", "api_url", "str"),
            ("USER_TOKEN", "user_token", "str"),
            ("WEBHOOK_MODE", "webhook.mode", "str"),
            ("WEBHOOK_LISTEN_PATH", "webhook.listen_path", "str"),
            ("TEST_IP", "test.ip", "str"),
            ("TEST_USER", "test.user", "str"),
            ("TEST_PASSWORD", "test.password", "str"),
            ("TEST_POST_SERVER", "test.post_server", "bool"),
            ("POLLING_ENABLED", "polling.enabled", "bool"),
            ("POLLING_URL", "polling.url", "str"),
            ("POLLING_LEAD", "polling.lead", "str"),
            ("POLLING_TOKEN", "polling.token", "str"),
            ("POLLING_INTERVAL_SECONDS", "polling.interval_seconds", "str"),
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
        return self._get_nested(self._data, key, default)

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

    def _persist_value(self, key: str, value: Any) -> None:
        db_path = self._settings_db_path(self._data)
        if db_path is None:
            return
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key VARCHAR(128) PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO app_settings(key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (str(key), str(value)),
                )
                conn.commit()
        except Exception:
            return

    def set_value(self, key: str, value: Any) -> None:
        self._set_nested(self._data, key, value)
        self._persist_value(key, value)

    @staticmethod
    def _normalize_scan_dir(path: str | Path) -> str:
        try:
            return str(Path(path).expanduser().resolve())
        except Exception:
            return str(Path(path).expanduser())

    def ensure_scan_dir(self, path: str | Path) -> tuple[bool, list[str]]:
        target = self._normalize_scan_dir(path)
        current_raw = self.get_string("polling.scan_dirs", "storage/scans/inbox")
        current_items = [str(item).strip() for item in str(current_raw or "").replace("\n", ";").replace(",", ";").split(";")]
        seen: set[str] = set()
        ordered: list[str] = []
        for item in current_items:
            if not item:
                continue
            normalized = self._normalize_scan_dir(item)
            key = normalized.lower() if os.name == "nt" else normalized
            if key in seen:
                continue
            seen.add(key)
            ordered.append(normalized)
        target_key = target.lower() if os.name == "nt" else target
        added = target_key not in seen
        if added:
            ordered.append(target)
            self.set_value("polling.scan_dirs", ";".join(ordered))
        return added, ordered

    @property
    def api_url(self) -> str:
        return self.get_string("api_url", "").rstrip("/")

    @property
    def user_token(self) -> str:
        return self.get_string("user_token", "")
