from __future__ import annotations

from typing import Any
import xml.etree.ElementTree as ET

from agent.modules.toshiba.common import flatten_xml
from agent.modules.toshiba.counter_specs import (
    SCAN_COLOR_COUNTER_SPECS,
    SHEET_COUNTER_SPECS,
    TOTAL_COLOR_COUNTER_SPECS,
)


def summarize_counter(root: ET.Element) -> dict[str, Any]:
    counter_root = root.find(".//DeviceService/DeviceCounters")
    device_counters = flatten_xml(counter_root) if counter_root is not None else {}
    return build_counter_data(device_counters)


def get_counter_value(
    device_counters: dict[str, str],
    *candidates: str,
    token_groups: list[tuple[str, ...]] | None = None,
    leaf_tokens: tuple[str, ...] = ("totalcount", "count", "pagecount"),
) -> tuple[int, bool]:
    for candidate in candidates:
        if candidate and candidate in device_counters:
            return get_counter_int(device_counters, candidate), True

    normalized_candidates = [
        candidate.strip("/") for candidate in candidates if candidate and candidate.strip("/")
    ]
    sorted_paths = sorted(device_counters, key=len)

    for candidate in normalized_candidates:
        suffix = f"/{candidate}"
        for path in sorted_paths:
            if path.endswith(suffix):
                return get_counter_int(device_counters, path), True

    if token_groups:
        best_path: str | None = None
        best_score: tuple[int, int] | None = None
        for path in sorted_paths:
            segments = [segment.lower() for segment in path.split("/")]
            leaf = segments[-1] if segments else ""
            if leaf_tokens and not any(token in leaf for token in leaf_tokens):
                continue
            if not all(
                any(any(alias in segment for alias in group) for segment in segments)
                for group in token_groups
            ):
                continue
            score = (
                sum(
                    1
                    for group in token_groups
                    for alias in group
                    if any(alias in segment for segment in segments)
                ),
                -len(path),
            )
            if best_score is None or score > best_score:
                best_path = path
                best_score = score
        if best_path is not None:
            return get_counter_int(device_counters, best_path), True

    return 0, False


def build_color_counter_row(
    *,
    device_counters: dict[str, str],
    full_color_candidates: list[str],
    twin_mono_candidates: list[str],
    black_candidates: list[str],
    total_candidates: list[str],
    total_token_groups: list[tuple[str, ...]] | None = None,
) -> dict[str, int]:
    full_color, full_color_found = get_counter_value(device_counters, *full_color_candidates)
    twin_mono_color, twin_found = get_counter_value(device_counters, *twin_mono_candidates)
    black, black_found = get_counter_value(device_counters, *black_candidates)
    total, total_found = get_counter_value(
        device_counters,
        *total_candidates,
        token_groups=total_token_groups,
    )

    if not black_found and total_found and (full_color_found or twin_found):
        black = max(total - full_color - twin_mono_color, 0)
    if not total_found:
        total = full_color + twin_mono_color + black

    return {
        "full_color": full_color,
        "twin_mono_color": twin_mono_color,
        "black": black,
        "total": total,
    }


def build_sheet_counter_row(
    *,
    device_counters: dict[str, str],
    small_candidates: list[str],
    large_candidates: list[str],
    total_candidates: list[str],
    small_token_groups: list[tuple[str, ...]] | None = None,
    large_token_groups: list[tuple[str, ...]] | None = None,
    total_token_groups: list[tuple[str, ...]] | None = None,
) -> dict[str, int]:
    small, small_found = get_counter_value(
        device_counters,
        *small_candidates,
        token_groups=[*(small_token_groups or []), ("small",)],
        leaf_tokens=("smallcount", "smallpagecount"),
    )
    large, large_found = get_counter_value(
        device_counters,
        *large_candidates,
        token_groups=[*(large_token_groups or []), ("large",)],
        leaf_tokens=("largecount", "largepagecount"),
    )
    total, total_found = get_counter_value(
        device_counters,
        *total_candidates,
        token_groups=[*(total_token_groups or []), ("total",)],
        leaf_tokens=("pagecount", "totalcount"),
    )

    if not total_found:
        total = small + large
    if not large_found and total_found and small_found:
        large = max(total - small, 0)
    if not small_found and total_found and large_found:
        small = max(total - large, 0)

    return {
        "small": small,
        "large": large,
        "total": total,
    }


def sum_color_counter_rows(*rows: dict[str, int]) -> dict[str, int]:
    return {
        "full_color": sum(row.get("full_color", 0) for row in rows),
        "twin_mono_color": sum(row.get("twin_mono_color", 0) for row in rows),
        "black": sum(row.get("black", 0) for row in rows),
        "total": sum(row.get("total", 0) for row in rows),
    }


def sum_sheet_counter_rows(*rows: dict[str, int]) -> dict[str, int]:
    return {
        "small": sum(row.get("small", 0) for row in rows),
        "large": sum(row.get("large", 0) for row in rows),
        "total": sum(row.get("total", 0) for row in rows),
    }


def stringify_counter_tree(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: stringify_counter_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [stringify_counter_tree(item) for item in value]
    if isinstance(value, int):
        return str(value)
    return value


def build_counter_data(device_counters: dict[str, str]) -> dict[str, Any]:
    total_counter = build_color_counter_group(
        device_counters,
        TOTAL_COLOR_COUNTER_SPECS,
        fallback_keys=("copy", "fax", "printer", "list"),
    )
    scan_counter = build_color_counter_group(
        device_counters,
        SCAN_COLOR_COUNTER_SPECS,
        fallback_keys=("copy", "fax", "network"),
    )
    sheet_counter = build_sheet_counter_group(device_counters)

    copier_bw, _ = get_counter_value(
        device_counters,
        "DeviceCounters/Printer/CopyCounter/Black/TotalCount",
        "Printer/CopyCounter/Black/TotalCount",
        "DeviceCounters/ACS/CopyMono/TotalCount",
    )
    printer_bw, _ = get_counter_value(
        device_counters,
        "DeviceCounters/Printer/PrintCounter/Black/TotalCount",
        "Printer/PrintCounter/Black/TotalCount",
        "DeviceCounters/ACS/PrinterMono/TotalCount",
    )
    scanner_send_bw, _ = get_counter_value(
        device_counters,
        "DeviceCounters/Scanner/NetScanCounter/Black/TotalCount",
        "Scanner/NetScanCounter/Black/TotalCount",
    )
    scanner_send_color, _ = get_counter_value(
        device_counters,
        "DeviceCounters/Scanner/NetScanCounter/FullColor/TotalCount",
        "Scanner/NetScanCounter/FullColor/TotalCount",
    )
    fax_tx_bw, _ = get_counter_value(
        device_counters,
        "DeviceCounters/Facsimile/Transmission/TotalCount",
        "Facsimile/Transmission/TotalCount",
    )

    copy_k_prints = get_counter_int(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Copy/printCount",
    )
    copy_k_average = get_counter_float(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Copy/averagePixel",
    )
    printer_k_prints = get_counter_int(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Printer/printCount",
    )
    printer_k_average = get_counter_float(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Printer/averagePixel",
    )
    fax_k_prints = get_counter_int(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Fax/printCount",
    )
    fax_k_average = get_counter_float(
        device_counters,
        "DeviceCounters/Pixel/Service/Black/K/Fax/averagePixel",
    )

    ocr_total, _ = get_counter_value(
        device_counters,
        "DeviceCounters/OCR/OCRCounter/TotalCount",
        "OCR/OCRCounter/TotalCount",
        token_groups=[("ocr",), ("total",)],
    )

    counter_data: dict[str, Any] = {
        "copier_bw": copier_bw,
        "copier_total": total_counter["copy"]["total"],
        "coverage_copier_bw": round(copy_k_prints * copy_k_average),
        "coverage_printer_bw": round(printer_k_prints * printer_k_average),
        "coverage_fax_bw": round(fax_k_prints * fax_k_average),
        "printer_bw": printer_bw,
        "printer_total": total_counter["printer"]["total"],
        "fax_bw": total_counter["fax"]["black"],
        "fax_transmission_total": fax_tx_bw,
        "list_total": total_counter["list"]["total"],
        "scanner_send_bw": scanner_send_bw,
        "scanner_send_color": scanner_send_color,
        "send_tx_total_bw": scanner_send_bw + fax_tx_bw,
        "send_tx_total_color": scanner_send_color,
        "total_bw": copier_bw + printer_bw,
        "total": total_counter["total"]["total"],
        "grand_total": total_counter["total"]["total"],
        "total_counter": total_counter,
        "scan_counter": scan_counter,
        "sheet_counter": sheet_counter,
        "ocr_counter": {"total": ocr_total},
        "feed_counter": {
            "upper_drawer": get_counter_value(
                device_counters,
                "DeviceCounters/FeedCount/UpperDrawer",
                "FeedCount/UpperDrawer",
            )[0],
            "lower_drawer": get_counter_value(
                device_counters,
                "DeviceCounters/FeedCount/LowerDrawer",
                "FeedCount/LowerDrawer",
            )[0],
            "bypass": get_counter_value(
                device_counters,
                "DeviceCounters/FeedCount/Bypass",
                "FeedCount/Bypass",
            )[0],
            "lcf": get_counter_value(
                device_counters,
                "DeviceCounters/FeedCount/LCF",
                "FeedCount/LCF",
            )[0],
        },
    }
    return stringify_counter_tree(counter_data)


def build_color_counter_group(
    device_counters: dict[str, str],
    specs: dict[str, dict[str, Any]],
    *,
    fallback_keys: tuple[str, ...],
) -> dict[str, dict[str, int]]:
    rows = {
        name: build_color_counter_row(device_counters=device_counters, **spec)
        for name, spec in specs.items()
    }
    if rows["total"]["total"] == 0:
        rows["total"] = sum_color_counter_rows(*(rows[key] for key in fallback_keys))
    return rows


def build_sheet_counter_group(device_counters: dict[str, str]) -> dict[str, dict[str, int]]:
    rows = {
        name: build_sheet_counter_row(device_counters=device_counters, **spec)
        for name, spec in SHEET_COUNTER_SPECS.items()
    }
    if rows["total"]["total"] == 0:
        rows["total"] = sum_sheet_counter_rows(
            rows["copy"],
            rows["fax"],
            rows["printer"],
            rows["list"],
        )
    return rows


def get_counter_int(device_counters: dict[str, str], path: str) -> int:
    value = device_counters.get(path)
    if not value:
        return 0
    try:
        return int(float(value))
    except ValueError:
        return 0


def get_counter_float(device_counters: dict[str, str], path: str) -> float:
    value = device_counters.get(path)
    if not value:
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0
