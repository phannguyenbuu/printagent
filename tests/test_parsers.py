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


def test_parse_counter_color_sections() -> None:
    html = """
    <html><body>
      <div>Total : 442,929</div>
      <div>Copier</div>
      <div>Black &amp; White : 137,251</div>
      <div>Full Color : 11,460</div>
      <div>Single Color : 0</div>
      <div>Two-color : 0</div>
      <div>Printer</div>
      <div>Black &amp; White : 169,463</div>
      <div>Full Color : 117,306</div>
      <div>Single Color : 2</div>
      <div>Two-color : 1,101</div>
      <div>Fax</div>
      <div>Black &amp; White : 6,346</div>
      <div>Send/TX Total</div>
      <div>Black &amp; White : 140,103</div>
      <div>Color : 7,329</div>
      <div>Fax Transmission</div>
      <div>Total : 6,839</div>
      <div>Scanner Send</div>
      <div>Black &amp; White : 133,264</div>
      <div>Color : 7,329</div>
      <div>Coverage</div>
      <div>Copier</div>
      <div>B &amp; W Coverage : 631,049 %</div>
      <div>Single Color Coverage : 0 %</div>
      <div>Two-color Coverage : 0 %</div>
      <div>Full Color Coverage : 124,993 %</div>
      <div>Printer</div>
      <div>B &amp; W Coverage : 708,070 %</div>
      <div>Single Color Coverage : 0 %</div>
      <div>Two-color Coverage : 7,608 %</div>
      <div>Full Color Coverage : 1,037,326 %</div>
      <div>Fax</div>
      <div>B &amp; W Coverage : 22,712 %</div>
      <div>Other Function(s)</div>
      <div>A3/DLT : 12,377</div>
      <div>Duplex : 34,922</div>
    </body></html>
    """
    data = _service().parse_counter(html)
    assert data["total"] == "442929"
    assert data["copier_full_color"] == "11460"
    assert data["printer_single_color"] == "2"
    assert data["printer_two_color"] == "1101"
    assert data["send_tx_total_color"] == "7329"
    assert data["scanner_send_color"] == "7329"
    assert data["coverage_copier_full_color"] == "124993"
    assert data["coverage_printer_two_color"] == "7608"
    assert data["coverage_fax_bw"] == "22712"
    assert data["a3_dlt"] == "12377"
    assert data["duplex"] == "34922"


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
