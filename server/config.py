from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    # Keep startup simple: auto-read .env from common locations.
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parents[1] / ".env",
    ]
    seen: set[str] = set()
    for env_path in candidates:
        key = str(env_path)
        if key in seen:
            continue
        seen.add(key)
        if env_path.exists():
            load_dotenv(env_path, override=False)


class ServerConfig:
    def __init__(self) -> None:
        _load_env()
        self.host = os.getenv("SERVER_HOST", "0.0.0.0")
        self.port = int(os.getenv("SERVER_PORT", "8005"))
        self.debug = os.getenv("SERVER_DEBUG", "true").strip().lower() in {"1", "true", "yes", "y"}
        self.database_url = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx",
        )
        # Format: "leadA:tokenA,leadB:tokenB"
        self.lead_keys_raw = os.getenv("LEAD_KEYS", "default:change-me")

    def lead_keys(self) -> dict[str, str]:
        pairs = [part.strip() for part in self.lead_keys_raw.split(",") if part.strip()]
        result: dict[str, str] = {}
        for pair in pairs:
            if ":" not in pair:
                continue
            lead, token = pair.split(":", 1)
            lead_name = lead.strip()
            lead_token = token.strip()
            if lead_name and lead_token:
                result[lead_name] = lead_token
        return result
