from __future__ import annotations

from typing import Any


COLOR_TWIN_SUFFIXES = ("TwinColor/TotalCount", "TwinMonoColor/TotalCount")
SHEET_COUNTER_TOKEN = ("sheetcount", "sheetcounter")


def expand_counter_paths(prefixes: tuple[str, ...], suffixes: tuple[str, ...]) -> list[str]:
    return [f"{prefix}/{suffix}" for prefix in prefixes for suffix in suffixes]


def build_printer_color_spec(
    counter_name: str,
    *,
    token_groups: list[tuple[str, ...]],
    full_color_extra: tuple[str, ...] = (),
    black_extra: tuple[str, ...] = (),
    total_extra: tuple[str, ...] = (),
) -> dict[str, Any]:
    prefixes = (f"DeviceCounters/Printer/{counter_name}", f"Printer/{counter_name}")
    return {
        "full_color_candidates": expand_counter_paths(prefixes, ("FullColor/TotalCount",))
        + list(full_color_extra),
        "twin_mono_candidates": expand_counter_paths(prefixes, COLOR_TWIN_SUFFIXES),
        "black_candidates": expand_counter_paths(prefixes, ("Black/TotalCount",))
        + list(black_extra),
        "total_candidates": expand_counter_paths(prefixes, ("Total/TotalCount",))
        + list(total_extra),
        "total_token_groups": token_groups,
    }


def build_scanner_color_spec(
    device_names: tuple[str, ...],
    scanner_names: tuple[str, ...],
    *,
    token_groups: list[tuple[str, ...]],
) -> dict[str, Any]:
    prefixes = tuple(f"DeviceCounters/Scanner/{name}" for name in device_names) + tuple(
        f"Scanner/{name}" for name in scanner_names
    )
    return {
        "full_color_candidates": expand_counter_paths(prefixes, ("FullColor/TotalCount",)),
        "twin_mono_candidates": expand_counter_paths(prefixes, COLOR_TWIN_SUFFIXES),
        "black_candidates": expand_counter_paths(prefixes, ("Black/TotalCount",)),
        "total_candidates": expand_counter_paths(prefixes, ("Total/TotalCount",)),
        "total_token_groups": token_groups,
    }


def build_sheet_spec(
    primary_name: str,
    counter_name: str,
    *,
    token_groups: list[tuple[str, ...]],
) -> dict[str, Any]:
    sheetcount_prefixes = (
        f"DeviceCounters/Printer/{counter_name}/Total/SheetCount",
        f"Printer/{counter_name}/Total/SheetCount",
    )
    combined_sheetcount_prefixes = (
        f"DeviceCounters/Printer/{counter_name}/Total/CombinedSheetCount",
        f"Printer/{counter_name}/Total/CombinedSheetCount",
    )
    primary_prefixes = (
        f"DeviceCounters/SheetCounter/{primary_name}",
        f"DeviceCounters/Printer/SheetCounter/{primary_name}",
        f"Printer/SheetCounter/{primary_name}",
    )
    counter_prefixes = (
        f"DeviceCounters/SheetCounter/{counter_name}",
        f"DeviceCounters/Printer/SheetCounter/{counter_name}",
        f"Printer/SheetCounter/{counter_name}",
    )
    pagecount_prefixes = primary_prefixes + counter_prefixes
    return {
        "small_candidates": expand_counter_paths(sheetcount_prefixes, ("smallCount",))
        + expand_counter_paths(primary_prefixes + counter_prefixes, ("Small/TotalCount",))
        + expand_counter_paths(pagecount_prefixes, ("smallPageCount",)),
        "large_candidates": expand_counter_paths(sheetcount_prefixes, ("largeCount",))
        + expand_counter_paths(primary_prefixes + counter_prefixes, ("Large/TotalCount",))
        + expand_counter_paths(pagecount_prefixes, ("largePageCount",)),
        "total_candidates": expand_counter_paths(
            sheetcount_prefixes + combined_sheetcount_prefixes,
            ("TotalCount",),
        )
        + expand_counter_paths(primary_prefixes, ("TotalCount",))
        + expand_counter_paths(counter_prefixes, ("TotalCount", "Total/TotalCount"))
        + expand_counter_paths(pagecount_prefixes, ("pageCount",)),
        "small_token_groups": list(token_groups),
        "large_token_groups": list(token_groups),
        "total_token_groups": list(token_groups),
    }


TOTAL_COLOR_COUNTER_SPECS = {
    "copy": build_printer_color_spec(
        "CopyCounter",
        token_groups=[("copy",), ("total",)],
        full_color_extra=("DeviceCounters/ACS/CopyColor/TotalCount",),
        black_extra=("DeviceCounters/ACS/CopyMono/TotalCount",),
    ),
    "fax": build_printer_color_spec(
        "FaxCounter",
        token_groups=[("fax",), ("total",)],
        black_extra=("DeviceCounters/Facsimile/Reception/TotalCount",),
    ),
    "printer": build_printer_color_spec(
        "PrintCounter",
        token_groups=[("print", "printer"), ("total",)],
        full_color_extra=("DeviceCounters/ACS/PrinterColor/TotalCount",),
        black_extra=("DeviceCounters/ACS/PrinterMono/TotalCount",),
    ),
    "list": build_printer_color_spec(
        "ListCounter",
        token_groups=[("list",), ("total",)],
    ),
    "total": {
        "full_color_candidates": [
            "DeviceCounters/Printer/TotalCounter/FullColor/TotalCount",
            "DeviceCounters/Printer/Total/fullColorPageCount",
            "Printer/TotalCounter/FullColor/TotalCount",
        ],
        "twin_mono_candidates": [
            "DeviceCounters/Printer/TotalCounter/TwinColor/TotalCount",
            "DeviceCounters/Printer/TotalCounter/TwinMonoColor/TotalCount",
            "DeviceCounters/Printer/Total/twinColorPageCount",
            "Printer/TotalCounter/TwinColor/TotalCount",
            "Printer/TotalCounter/TwinMonoColor/TotalCount",
        ],
        "black_candidates": [
            "DeviceCounters/Printer/TotalCounter/Black/TotalCount",
            "DeviceCounters/Printer/Total/blackPageCount",
            "Printer/TotalCounter/Black/TotalCount",
        ],
        "total_candidates": [
            "DeviceCounters/Printer/TotalCounter/Total/TotalCount",
            "DeviceCounters/Total/TotalCount",
            "Printer/TotalCounter/Total/TotalCount",
        ],
        "total_token_groups": [("total",), ("printer",)],
    },
}


SCAN_COLOR_COUNTER_SPECS = {
    "copy": build_scanner_color_spec(
        ("CopyCounter", "LocalScanCounter"),
        ("CopyCounter", "LocalScanCounter"),
        token_groups=[("scan",), ("copy",), ("total",)],
    ),
    "fax": build_scanner_color_spec(
        ("FaxCounter", "FaxScanCounter"),
        ("FaxCounter",),
        token_groups=[("scan",), ("fax",), ("total",)],
    ),
    "network": build_scanner_color_spec(
        ("NetScanCounter", "NetworkScanCounter"),
        ("NetScanCounter",),
        token_groups=[("scan", "scanner"), ("net", "network"), ("total",)],
    ),
    "total": build_scanner_color_spec(
        ("TotalCounter",),
        ("TotalCounter",),
        token_groups=[("scan", "scanner"), ("total",)],
    ),
}


SHEET_COUNTER_SPECS = {
    "copy": build_sheet_spec(
        "Copy",
        "CopyCounter",
        token_groups=[("copy",), SHEET_COUNTER_TOKEN],
    ),
    "fax": build_sheet_spec(
        "Fax",
        "FaxCounter",
        token_groups=[("fax",), SHEET_COUNTER_TOKEN],
    ),
    "printer": build_sheet_spec(
        "Printer",
        "PrintCounter",
        token_groups=[("print", "printer"), SHEET_COUNTER_TOKEN],
    ),
    "list": build_sheet_spec(
        "List",
        "ListCounter",
        token_groups=[("list",), SHEET_COUNTER_TOKEN],
    ),
    "total": build_sheet_spec(
        "Total",
        "TotalCounter",
        token_groups=[("total",), SHEET_COUNTER_TOKEN],
    ),
}
