from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CounterInfor(Base):
    __tablename__ = "CounterInfor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-lan")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    printer_name: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64), index=True)
    begin_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    total: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    copier_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    printer_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    fax_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    send_tx_total_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    send_tx_total_color: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    fax_transmission_total: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    scanner_send_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    scanner_send_color: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    coverage_copier_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    coverage_printer_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    coverage_fax_bw: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    a3_dlt: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    duplex: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    raw_payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class CounterBaseline(Base):
    __tablename__ = "CounterBaseline"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-lan")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    baseline_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utc_now)
    raw_payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class StatusInfor(Base):
    __tablename__ = "StatusInfor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-lan")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    printer_name: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64), index=True)
    begin_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    system_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    printer_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    printer_alerts: Mapped[str | None] = mapped_column(Text, nullable=True)
    copier_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    copier_alerts: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scanner_alerts: Mapped[str | None] = mapped_column(Text, nullable=True)
    toner_black: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tray_1_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tray_2_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tray_3_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bypass_tray_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    other_info: Mapped[str | None] = mapped_column(Text, nullable=True)

    raw_payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class LanSite(Base):
    __tablename__ = "LanSite"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    lan_name: Mapped[str] = mapped_column(String(255), default="")
    subnet_cidr: Mapped[str] = mapped_column(String(64), default="")
    gateway_ip: Mapped[str] = mapped_column(String(64), default="")
    gateway_mac: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class AgentNode(Base):
    __tablename__ = "AgentNode"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    local_mac: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class Printer(Base):
    __tablename__ = "Printer"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    enabled_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    online_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class PrinterEnableLog(Base):
    __tablename__ = "PrinterEnableLog"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    printer_id: Mapped[int] = mapped_column(Integer, index=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class PrinterOnlineLog(Base):
    __tablename__ = "PrinterOnlineLog"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    printer_id: Mapped[int] = mapped_column(Integer, index=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
