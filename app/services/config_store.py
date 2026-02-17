from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base, Computer, ComputerPrinterLink, NetworkConfig, PrinterDevice


@dataclass
class DashboardConfigPayload:
    network: dict[str, Any]
    computers: list[dict[str, Any]]
    printers: list[dict[str, Any]]
    links: list[dict[str, int]]


class ConfigStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory
        self.engine = session_factory.kw.get("bind")

    def create_tables(self) -> None:
        if self.engine is None:
            raise RuntimeError("Database engine is not initialized")
        Base.metadata.create_all(self.engine)
        with self.session_factory() as session:
            row = session.get(NetworkConfig, 1)
            if row is None:
                session.add(NetworkConfig(id=1))
                session.commit()

    def get_dashboard_payload(self) -> DashboardConfigPayload:
        with self.session_factory() as session:
            network = session.get(NetworkConfig, 1)
            if network is None:
                network = NetworkConfig(id=1)
                session.add(network)
                session.commit()

            computers = session.execute(select(Computer).order_by(Computer.name.asc())).scalars().all()
            printers = session.execute(select(PrinterDevice).order_by(PrinterDevice.name.asc())).scalars().all()
            links = session.execute(select(ComputerPrinterLink)).scalars().all()

            return DashboardConfigPayload(
                network={
                    "subnet_mask": network.subnet_mask,
                    "gateway": network.gateway,
                    "dns_primary": network.dns_primary,
                    "dns_secondary": network.dns_secondary,
                    "snmp_community": network.snmp_community,
                    "snmp_port": network.snmp_port,
                    "timeout_seconds": network.timeout_seconds,
                },
                computers=[
                    {
                        "id": row.id,
                        "name": row.name,
                        "ip": row.ip,
                        "department": row.department,
                    }
                    for row in computers
                ],
                printers=[
                    {
                        "id": row.id,
                        "name": row.name,
                        "ip": row.ip,
                        "model": row.model,
                        "location": row.location,
                        "protocol": row.protocol,
                    }
                    for row in printers
                ],
                links=[{"computer_id": row.computer_id, "printer_id": row.printer_id} for row in links],
            )

    def save_network(self, payload: dict[str, Any]) -> None:
        with self.session_factory() as session:
            row = session.get(NetworkConfig, 1)
            if row is None:
                row = NetworkConfig(id=1)
                session.add(row)
            row.subnet_mask = str(payload.get("subnet_mask", "")).strip()
            row.gateway = str(payload.get("gateway", "")).strip()
            row.dns_primary = str(payload.get("dns_primary", "")).strip()
            row.dns_secondary = str(payload.get("dns_secondary", "")).strip()
            row.snmp_community = str(payload.get("snmp_community", "")).strip() or "public"
            row.snmp_port = _to_int(payload.get("snmp_port"), default=161)
            row.timeout_seconds = _to_int(payload.get("timeout_seconds"), default=10)
            session.commit()

    def add_computer(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.session_factory() as session:
            row = Computer(
                name=str(payload.get("name", "")).strip() or "Computer",
                ip=str(payload.get("ip", "")).strip(),
                department=str(payload.get("department", "")).strip(),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return {"id": row.id, "name": row.name, "ip": row.ip, "department": row.department}

    def remove_computer(self, computer_id: int) -> bool:
        with self.session_factory() as session:
            row = session.get(Computer, computer_id)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def add_printer(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.session_factory() as session:
            row = PrinterDevice(
                name=str(payload.get("name", "")).strip() or "Printer",
                ip=str(payload.get("ip", "")).strip(),
                model=str(payload.get("model", "")).strip(),
                location=str(payload.get("location", "")).strip(),
                protocol=str(payload.get("protocol", "")).strip() or "TCP/IP",
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return {
                "id": row.id,
                "name": row.name,
                "ip": row.ip,
                "model": row.model,
                "location": row.location,
                "protocol": row.protocol,
            }

    def remove_printer(self, printer_id: int) -> bool:
        with self.session_factory() as session:
            row = session.get(PrinterDevice, printer_id)
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def replace_links(self, links: list[dict[str, Any]]) -> int:
        valid_links: list[tuple[int, int]] = []
        for row in links:
            computer_id = _to_int(row.get("computer_id"), default=0)
            printer_id = _to_int(row.get("printer_id"), default=0)
            if computer_id <= 0 or printer_id <= 0:
                continue
            valid_links.append((computer_id, printer_id))

        with self.session_factory() as session:
            session.execute(delete(ComputerPrinterLink))
            for computer_id, printer_id in sorted(set(valid_links)):
                session.add(ComputerPrinterLink(computer_id=computer_id, printer_id=printer_id))
            session.commit()
        return len(set(valid_links))


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:  # noqa: BLE001
        return default
