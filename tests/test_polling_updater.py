from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import agent.services.polling_bridge as polling_bridge_module
import agent.services.updater as updater_module
from agent.services.polling_bridge import PollingBridge
from agent.services.updater import AutoUpdater


class _DummyConfig:
    def get_string(self, _key: str, default: str = "") -> str:
        return default

    def get_bool(self, _key: str, default: bool = False) -> bool:
        return default


class _DummyAPIClient:
    def __init__(self, printers: list[object] | None = None) -> None:
        self._printers = list(printers or [])

    def get_printers(self) -> list[object]:
        return list(self._printers)


class _DummyRicohService:
    def fetch_mac_address_direct(self, ip: str) -> str:
        if ip == "192.168.1.10":
            return "00:26:73:AA:BB:CC"
        return ""

    def process_device_info(self, printer, should_post: bool = False):  # noqa: ANN001
        if printer.ip == "192.168.1.10":
            return {"device_info": {"Model Name": "Ricoh IM C300"}}
        raise RuntimeError(f"Not a Ricoh target: {printer.ip}")


class _DummyToshibaService:
    def process_device_info(self, printer, should_post: bool = False):  # noqa: ANN001
        if printer.ip == "192.168.1.20":
            return {"device_info": {"Model Name": "Toshiba e-STUDIO2525AC"}}
        raise RuntimeError(f"Not a Toshiba target: {printer.ip}")


def _build_bridge(*, server_printers: list[object] | None = None) -> PollingBridge:
    return PollingBridge(
        _DummyConfig(),
        _DummyAPIClient(server_printers),
        _DummyRicohService(),
        toshiba_service=_DummyToshibaService(),
        updater=None,
        run_mode="service",
        web_port=0,
    )


def test_load_printers_includes_detected_ricoh_and_toshiba(monkeypatch) -> None:
    bridge = _build_bridge()
    monkeypatch.setattr(
        polling_bridge_module.SubnetScanner,
        "scan_subnet",
        lambda self: [
            {"ip": "192.168.1.10", "printer_type": "ricoh", "has_printer_ports": True},
            {"ip": "192.168.1.20", "printer_type": "toshiba", "has_printer_ports": True},
        ],
    )
    monkeypatch.setattr(bridge, "_load_neighbor_mac_map", lambda: {})

    printers = bridge._load_printers()

    by_ip = {printer.ip: printer for printer in printers}
    assert by_ip["192.168.1.10"].printer_type == "ricoh"
    assert by_ip["192.168.1.10"].name == "Ricoh IM C300"
    assert by_ip["192.168.1.20"].printer_type == "toshiba"
    assert by_ip["192.168.1.20"].name == "Toshiba e-STUDIO2525AC"


def test_load_printers_fallback_can_discover_toshiba(monkeypatch) -> None:
    bridge = _build_bridge()
    monkeypatch.setattr(
        polling_bridge_module.SubnetScanner,
        "scan_subnet",
        lambda self: [
            {"ip": "192.168.1.20", "printer_type": "", "has_printer_ports": True},
        ],
    )
    monkeypatch.setattr(bridge, "_load_neighbor_mac_map", lambda: {})

    printers = bridge._load_printers()

    assert len(printers) == 1
    assert printers[0].ip == "192.168.1.20"
    assert printers[0].printer_type == "toshiba"
    assert printers[0].name == "Toshiba e-STUDIO2525AC"


def test_apply_release_manifest_same_sha_skips_update(monkeypatch) -> None:
    binary_path = Path(__file__).resolve()
    expected_sha = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    updater = AutoUpdater(project_root=ROOT_DIR)
    monkeypatch.setattr(updater, "_current_binary_path", lambda: binary_path)

    ok, message, restart_required = updater.apply_release_manifest(
        {
            "version": "1.3.40",
            "download_url": "/static/releases/printagent.exe",
            "sha256": expected_sha,
            "update_available": True,
        },
        base_url="https://agentapi.quanlymay.com",
    )

    assert ok is True
    assert restart_required is False
    assert message == "Already on latest build"
    assert updater.status()["current_version"] == "1.3.40"


def test_apply_release_manifest_triggers_download_for_newer_release(monkeypatch) -> None:
    binary_path = Path(__file__).resolve()
    updater = AutoUpdater(project_root=ROOT_DIR)
    monkeypatch.setattr(updater, "_current_binary_path", lambda: binary_path)
    monkeypatch.setattr(updater_module, "is_windows", lambda: True)
    monkeypatch.setattr(updater_module, "is_frozen", lambda: True)

    captured: dict[str, str] = {}

    def _fake_download_and_restart(download_url: str, target_version: str, expected_sha256: str):
        captured["download_url"] = download_url
        captured["target_version"] = target_version
        captured["expected_sha256"] = expected_sha256
        return True, "Update staged; restarting agent", True

    monkeypatch.setattr(updater, "_download_and_restart", _fake_download_and_restart)

    ok, message, restart_required = updater.apply_release_manifest(
        {
            "version": "1.3.40",
            "download_url": "/static/releases/printagent.exe",
            "sha256": "deadbeef",
            "update_available": True,
        },
        base_url="https://agentapi.quanlymay.com",
    )

    assert ok is True
    assert restart_required is True
    assert message == "Update staged; restarting agent"
    assert captured == {
        "download_url": "https://agentapi.quanlymay.com/static/releases/printagent.exe",
        "target_version": "1.3.40",
        "expected_sha256": "deadbeef",
    }
