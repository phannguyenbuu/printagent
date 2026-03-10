from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import request
from werkzeug.utils import secure_filename

LOGGER = logging.getLogger(__name__)
UI_TZ = timezone(timedelta(hours=7))
MAC_PATTERN = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
LAST_DATA_FILE = Path("storage/data/last_data.json")

COUNTER_KEYS = [
    "total",
    "copier_bw",
    "printer_bw",
    "fax_bw",
    "send_tx_total_bw",
    "send_tx_total_color",
    "fax_transmission_total",
    "scanner_send_bw",
    "scanner_send_color",
    "coverage_copier_bw",
    "coverage_printer_bw",
    "coverage_fax_bw",
    "a3_dlt",
    "duplex",
]

def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except Exception:  # noqa: BLE001
        return None


def _to_text(value: Any) -> str:
    return str(value or "").strip()


def _to_text_max(value: Any, max_len: int) -> str:
    text = _to_text(value)
    if max_len <= 0:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len]


def _to_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, bool, int, float)):
        return value
    text = _to_text(value)
    return text if text else None


def _normalize_status_payload(payload: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in payload.items():
        k = _to_text(key)
        if not k:
            continue
        out[k] = _to_text(value)
    return out


def _normalize_mac(value: Any) -> str:
    text = _to_text(value).replace("-", ":").upper()
    if not text:
        return ""
    if MAC_PATTERN.fullmatch(text):
        return text
    return ""


def _safe_path_token(value: str) -> str:
    text = _to_text(value)
    if not text:
        return "unknown"
    cleaned = secure_filename(text)
    return cleaned or "unknown"


def _normalize_ipv4(value: str) -> str:
    text = _to_text(value)
    parts = text.split(".")
    if len(parts) != 4:
        return ""
    try:
        nums = [int(p) for p in parts]
    except Exception:  # noqa: BLE001
        return ""
    if any(n < 0 or n > 255 for n in nums):
        return ""
    return ".".join(str(n) for n in nums)


def _parse_timestamp(value: Any) -> datetime:
    text = _to_text(value)
    if not text:
        return datetime.now(timezone.utc)
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc)


def _write_last_data(payload: dict[str, Any]) -> None:
    try:
        LAST_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        LAST_DATA_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("last_data write failed: %s", exc)


def _parse_query_datetime(value: Any, end_of_minute: bool = False) -> datetime | None:
    text = _to_text(value)
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except Exception:  # noqa: BLE001
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UI_TZ)
    if end_of_minute and len(text) <= 16:
        dt = dt.replace(second=59, microsecond=999999)
    return dt.astimezone(timezone.utc)


def _resolve_lan_info_from_body(body: dict[str, Any]) -> tuple[str, str]:
    """
    Returns (lan_uid, fingerprint_signature)
    """
    raw_lan_uid = _to_text(body.get("lan_uid"))
    fingerprint = _to_text(body.get("fingerprint_signature") or body.get("fingerprint"))

    lead = _to_text(body.get("lead"))
    local_ip = _normalize_ipv4(_to_text(body.get("local_ip")))
    gateway_ip = _normalize_ipv4(_to_text(body.get("gateway_ip")))
    gateway_mac = _to_text(body.get("gateway_mac")).replace("-", ":").upper()
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24" if local_ip else ""

    # Signature is the physical identifier
    signature = "|".join(
        [
            f"lead={lead}",
            f"subnet={subnet}",
            f"gateway_ip={gateway_ip}",
            f"gateway_mac={gateway_mac}",
        ]
    )
    
    if not fingerprint:
        fingerprint = signature

    if raw_lan_uid and raw_lan_uid.lower() not in {"lan-default", "legacy-lan", "default", "lan_default"}:
        return raw_lan_uid, fingerprint

    # Default fallback lan_uid generation if not provided
    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:16]
    generated_uid = f"lanf-{digest}"
    return generated_uid, fingerprint


def _resolve_lan_uid_from_body(body: dict[str, Any]) -> str:
    uid, _ = _resolve_lan_info_from_body(body)
    return uid


def _to_page(value: Any, default: int) -> int:
    try:
        return max(1, int(str(value)))
    except Exception:  # noqa: BLE001
        return default


def _time_scope_start(scope: str) -> datetime | None:
    now = datetime.now(timezone.utc)
    key = (scope or "").strip().lower()
    if key in {"hour", "1h"}:
        return now - timedelta(hours=1)
    if key in {"day", "1d"}:
        return now - timedelta(days=1)
    if key in {"7d", "7days", "week"}:
        return now - timedelta(days=7)
    if key in {"month", "1m"}:
        return now - timedelta(days=30)
    if key in {"3months", "3m"}:
        return now - timedelta(days=90)
    if key in {"6months", "6m"}:
        return now - timedelta(days=180)
    if key in {"year", "1y"}:
        return now - timedelta(days=365)
    if key in {"all", ""}:
        return None
    return None


def _is_same_utc_minute(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return False
    l = left.astimezone(timezone.utc).replace(second=0, microsecond=0)
    r = right.astimezone(timezone.utc).replace(second=0, microsecond=0)
    return l == r


def _normalize_counter_payload(counter_data: dict[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in COUNTER_KEYS:
        value = _to_int(counter_data.get(key))
        if value is not None:
            result[key] = value
    return result


def _compute_delta_payload(current: dict[str, int], baseline: dict[str, int]) -> tuple[dict[str, int], bool]:
    delta: dict[str, int] = {}
    has_reset = False
    for key in COUNTER_KEYS:
        cur = current.get(key)
        base = baseline.get(key)
        if cur is None:
            continue
        if base is None:
            delta[key] = cur
            continue
        diff = cur - base
        if diff < 0:
            has_reset = True
            delta[key] = 0
            continue
        delta[key] = diff
    return delta, has_reset


def _apply_baseline(delta_value: int | None, baseline_payload: dict[str, Any], key: str) -> int | None:
    if delta_value is None:
        return None
    base = _to_int(baseline_payload.get(key))
    if base is None:
        base = 0
    return base + delta_value
