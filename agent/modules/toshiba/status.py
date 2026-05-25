from __future__ import annotations

import re
from typing import Any
import xml.etree.ElementTree as ET

from agent.modules.toshiba.common import find_text, first_non_empty


def summarize_status(root: ET.Element) -> dict[str, Any]:
    return build_status_data(root)


def build_status_data(root: ET.Element) -> dict[str, Any]:
    copier_state = normalize_state(find_text(root, ".//MFP/DeviceState"))
    printer_state = normalize_state(find_text(root, ".//MFP/Printer/DeviceState")) or copier_state
    scanner_state = copier_state

    copier_alerts = build_alerts_from_state_and_details(
        copier_state,
        extract_detail_alerts(root, ".//MFP/ErrorState/Details"),
    )
    printer_alerts = build_alerts_from_state_and_details(
        printer_state,
        extract_detail_alerts(root, ".//MFP/Printer/ErrorState/Details"),
    )
    scanner_alerts = build_alerts_from_state_and_details(scanner_state, [])

    system_alerts = extract_detail_alerts(root, ".//MFP/ErrorState/Details")
    system_status = "Status OK" if not system_alerts else system_alerts[0]
    toner_black = get_black_toner_status(root)
    input_trays = extract_input_trays(root)
    tray_aliases = build_tray_aliases(input_trays)

    return {
        "copier_alerts": copier_alerts,
        "copier_status": copier_state,
        "printer_alerts": printer_alerts,
        "printer_status": printer_state,
        "scanner_alerts": scanner_alerts,
        "scanner_status": scanner_state,
        "status_json": {
            "alert": {
                "alert": first_non_empty(
                    *copier_alerts,
                    *printer_alerts,
                    *scanner_alerts,
                    "",
                )
                or "",
                "messages": " | ".join(
                    dedupe_preserve_order(copier_alerts + printer_alerts + scanner_alerts)
                ),
            },
            "input_tray": input_trays,
            "output_tray": {},
            "status": {
                "copier": build_status_entry(copier_state, copier_alerts),
                "printer": build_status_entry(printer_state, printer_alerts),
                "scanner": build_status_entry(scanner_state, scanner_alerts),
                "system": build_status_entry(system_status, system_alerts),
            },
            "toner": {
                "black": {
                    "icons": [] if toner_black == "Status OK" else [toner_black],
                    "state": toner_black,
                    "text": toner_black,
                }
            },
        },
        "system_status": system_status,
        "toner_black": toner_black,
        **tray_aliases,
    }


def build_status_entry(state: str, details: list[str]) -> dict[str, Any]:
    text_parts = [state, *(detail for detail in details if detail != state)]
    return {
        "details": details,
        "state": state,
        "text": " ".join(text_parts).strip(),
    }


def extract_detail_alerts(root: ET.Element, xpath: str) -> list[str]:
    alerts = [
        humanize_alert_name(name)
        for node in root.findall(xpath)
        if (name := find_child_text(node, "Name"))
    ]
    return dedupe_preserve_order(alerts)


def build_alerts_from_state_and_details(state: str, details: list[str]) -> list[str]:
    if details:
        return details
    if state and state not in {"Ready", "Status OK", "None"}:
        return [state]
    return []


def normalize_state(value: str | None) -> str:
    if not value:
        return "Status OK"
    raw = value.strip()
    normalized = {
        "Ready": "Ready",
        "Waiting": "Ready",
        "Running": "Ready",
        "Stop": "Ready",
        "Initializing": "Ready",
        "WarmingUp": "Warming Up",
        "LowPowerMode": "Energy Saver Mode",
        "SleepMode": "Energy Saver Mode",
        "EnergySaverMode": "Energy Saver Mode",
        "None": "Status OK",
        "Normal": "Status OK",
    }.get(raw)
    return normalized or humanize_alert_name(raw)


def humanize_alert_name(name: str) -> str:
    if not name:
        return ""
    text = name.replace("_", " ").replace("-", " ")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"\s+", " ", text).strip()
    return re.sub(r"\s+", " ", text.replace("Toner", "Toner ")).strip()


def dedupe_preserve_order(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def find_child_text(node: ET.Element, child_name: str) -> str | None:
    child = node.find(child_name)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def get_black_toner_status(root: ET.Element) -> str:
    for alert in extract_detail_alerts(root, ".//MFP/Printer/ErrorState/Details"):
        if "Black Toner" in alert or "K Toner" in alert:
            return alert
    remaining = first_non_empty(
        find_text(root, ".//MFP/Printer/Toner/K/RemainingQuantityDetails"),
        find_text(root, ".//MFP/Printer/Toner/K/TenStepRemainingQuantityDetails"),
        find_text(root, ".//MFP/Printer/Toner/K/ThreeStepRemainingQuantityDetails"),
        find_text(root, ".//MFP/Printer/Toner/K/RemainingQuantity"),
    )
    return "Black Toner Empty" if remaining and remaining.strip() == "0%" else "Status OK"


def extract_input_trays(root: ET.Element) -> dict[str, Any]:
    paper_feeder = root.find(".//MFP/Printer/PaperFeeder")
    if paper_feeder is None:
        return {}

    trays: dict[str, Any] = {}
    for child in list(paper_feeder):
        for tray_key, tray_node in iter_tray_nodes(child):
            if first_non_empty(find_child_text(tray_node, "Installation"), "") == "NotInstalled":
                continue
            trays[tray_key] = {
                "icons": tray_icons(tray_node),
                "text": tray_text(tray_node),
            }
    return trays


def iter_tray_nodes(node: ET.Element) -> list[tuple[str, ET.Element]]:
    if node.tag != "LCF":
        return [(to_snake_label(node.tag), node)]

    trays: list[tuple[str, ET.Element]] = []
    for child_name, tray_key in (("LCFTray", "lcf_tray"), ("LeftTray", "lcf_left_tray")):
        child = node.find(child_name)
        if child is not None:
            trays.append((tray_key, child))
    return trays


def tray_icons(node: ET.Element) -> list[str]:
    cover = normalize_state(find_child_text(node, "Cover"))
    remaining = find_child_text(node, "RemainingQuantity")

    if cover not in {"Status OK", "Ready", "Close"} and cover:
        return ["Cover Open"]
    if find_child_text(node, "IsPaper") == "NotAvailable" or remaining == "0%":
        return ["Out of Paper"]
    if remaining and remaining.endswith("%"):
        try:
            if int(remaining[:-1]) <= 25:
                return ["Almost Out of Paper"]
        except ValueError:
            pass
    return ["Status OK"]


def tray_text(node: ET.Element) -> str:
    parts = [
        value
        for value in (
            find_child_text(node, "PaperSize"),
            find_text(node, ".//MediaType/PaperType"),
        )
        if value
    ]
    attribute = find_child_text(node, "Attribute")
    if attribute and attribute != "Normal":
        parts.append(attribute)
    if not parts and (remaining := find_child_text(node, "RemainingQuantity")):
        parts.append(remaining)
    return " ".join(parts).strip()


def to_snake_label(name: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()


def build_tray_aliases(input_trays: dict[str, Any]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    normalized_map = {
        re.sub(r"[^a-z0-9]+", "", str(key).lower()): value
        for key, value in input_trays.items()
    }

    for target_key, source_keys in (
        ("tray_1_status", ("tray1", "tray_1", "drawer1", "drawer_1", "cassette1", "cassette_1")),
        ("tray_2_status", ("tray2", "tray_2", "drawer2", "drawer_2", "cassette2", "cassette_2")),
        ("tray_3_status", ("tray3", "tray_3", "drawer3", "drawer_3", "cassette3", "cassette_3")),
        ("bypass_tray_status", ("bypass", "bypasstray", "manualfeed", "manual_feed")),
    ):
        for source_key in source_keys:
            matched = normalized_map.get(re.sub(r"[^a-z0-9]+", "", source_key.lower()))
            if matched:
                aliases[target_key] = tray_alias_text(matched)
                break
    return aliases


def tray_alias_text(value: Any) -> str:
    if not isinstance(value, dict):
        return str(value or "").strip()
    text = str(value.get("text") or "").strip()
    if text:
        return text
    icons = value.get("icons")
    if isinstance(icons, list):
        cleaned = [str(item or "").strip() for item in icons if str(item or "").strip()]
        return " | ".join(cleaned)
    return ""
