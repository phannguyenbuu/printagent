from __future__ import annotations

from pathlib import Path

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "printerdeamon" / "quanlymay" / "storage" / "html"


def _service() -> RicohService:
    config = AppConfig({"api_url": "http://localhost:8080/api"})
    client = APIClient(config)
    return RicohService(client)


def test_parse_counter_fixture() -> None:
    html = (FIXTURE_DIR / "counter.html").read_text(encoding="utf-8", errors="ignore")
    data = _service().parse_counter(html)
    assert data["total"] == "3608283"
    assert "copier_bw" in data
    assert "printer_bw" in data
    assert "scanner_send_bw" in data


def test_parse_status_fixture() -> None:
    html = (FIXTURE_DIR / "status.html").read_text(encoding="utf-8", errors="ignore")
    data = _service().parse_status(html)
    assert "system_status" in data
    assert "scanner_status" in data or "scanner_alerts" in data
    assert "bypass_tray_status" in data


def test_parse_device_info_fixture() -> None:
    html = (FIXTURE_DIR / "info.html").read_text(encoding="utf-8", errors="ignore")
    data = _service().parse_device_info(html)
    assert "model_name" in data
    assert "machine_id" in data


def test_parse_address_list_fixture() -> None:
    html = (FIXTURE_DIR / "adrsList.html").read_text(encoding="utf-8", errors="ignore")
    entries = _service().parse_address_list(html)
    assert entries
    assert entries[0].type == "Summary"
