from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ComputerPrinterLink(Base):
    __tablename__ = "computer_printer_links"

    computer_id: Mapped[int] = mapped_column(ForeignKey("computers.id", ondelete="CASCADE"), primary_key=True)
    printer_id: Mapped[int] = mapped_column(ForeignKey("printers.id", ondelete="CASCADE"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("computer_id", "printer_id", name="uq_computer_printer_link"),)


class NetworkConfig(Base):
    __tablename__ = "network_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    subnet_mask: Mapped[str] = mapped_column(String(64), default="255.255.255.0")
    gateway: Mapped[str] = mapped_column(String(64), default="")
    dns_primary: Mapped[str] = mapped_column(String(64), default="")
    dns_secondary: Mapped[str] = mapped_column(String(64), default="")
    snmp_community: Mapped[str] = mapped_column(String(64), default="public")
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Computer(Base):
    __tablename__ = "computers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    department: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    printers: Mapped[list["PrinterDevice"]] = relationship(
        "PrinterDevice",
        secondary="computer_printer_links",
        back_populates="computers",
    )


class PrinterDevice(Base):
    __tablename__ = "printers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    location: Mapped[str] = mapped_column(String(128), default="")
    protocol: Mapped[str] = mapped_column(String(32), default="TCP/IP")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    computers: Mapped[list[Computer]] = relationship(
        "Computer",
        secondary="computer_printer_links",
        back_populates="printers",
    )


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
