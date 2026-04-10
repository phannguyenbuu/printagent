from __future__ import annotations

from enum import Enum
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Lead(Base):
    __tablename__ = "Lead"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class CounterInfor(Base):
    __tablename__ = "CounterInfor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-lan")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    printer_name: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64), index=True)
    mac_id: Mapped[str] = mapped_column(String(64), default="", index=True)
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
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


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
    mac_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    begin_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    system_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    printer_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    printer_alerts: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    copier_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    copier_alerts: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    scanner_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    scanner_alerts: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    toner_black: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    tray_1_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    tray_2_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    tray_3_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    bypass_tray_status: Mapped[object | None] = mapped_column(JSONB, nullable=True)
    other_info: Mapped[object | None] = mapped_column(JSONB, nullable=True)

    raw_payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class LanSite(Base):
    __tablename__ = "LanSite"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    lan_name: Mapped[str] = mapped_column(String(255), default="")
    subnet_cidr: Mapped[str] = mapped_column(String(64), default="")
    gateway_ip: Mapped[str] = mapped_column(String(64), default="")
    gateway_mac: Mapped[str] = mapped_column(String(64), default="")
    fingerprint_signature: Mapped[str | None] = mapped_column(Text, index=True, nullable=True)
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
    app_version: Mapped[str] = mapped_column(String(64), default="")
    run_mode: Mapped[str] = mapped_column(String(32), default="web")
    web_port: Mapped[int] = mapped_column(Integer, default=9173)
    ftp_ports: Mapped[str] = mapped_column(Text, default="")
    ftp_sites: Mapped[list] = mapped_column(JSONB, default=list)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    online_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class AgentPresenceLog(Base):
    __tablename__ = "AgentPresenceLog"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    local_mac: Mapped[str] = mapped_column(String(64), default="")
    app_version: Mapped[str] = mapped_column(String(64), default="")
    run_mode: Mapped[str] = mapped_column(String(32), default="web")
    web_port: Mapped[int] = mapped_column(Integer, default=9173)
    ftp_ports: Mapped[str] = mapped_column(Text, default="")
    ftp_sites: Mapped[list] = mapped_column(JSONB, default=list)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class Printer(Base):
    __tablename__ = "Printer"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    auth_user: Mapped[str] = mapped_column(String(128), default="")
    auth_password: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    enabled_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    online_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    mac_address: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class DeviceInfor(Base):
    __tablename__ = "DeviceInfor"
    __table_args__ = (
        UniqueConstraint("lead", "lan_uid", "mac_id", name="uq_deviceinfor_lead_lan_mac"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    mac_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    counter_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    status_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_counter_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class DeviceInforHistory(Base):
    __tablename__ = "DeviceInforHistory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    machine_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    mac_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    counter_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    status_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_counter_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class PrinterControlCommand(Base):
    __tablename__ = "PrinterControlCommand"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    printer_id: Mapped[int] = mapped_column(Integer, index=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), index=True)
    desired_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    auth_user: Mapped[str] = mapped_column(String(128), default="")
    auth_password: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class FtpControlCommand(Base):
    __tablename__ = "FtpControlCommand"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    action: Mapped[str] = mapped_column(String(32), default="create", index=True)
    site_name: Mapped[str] = mapped_column(String(128), default="", index=True)
    new_site_name: Mapped[str] = mapped_column(String(128), default="")
    local_path: Mapped[str] = mapped_column(Text, default="")
    port: Mapped[int] = mapped_column(Integer, default=2121, index=True)
    ftp_user: Mapped[str] = mapped_column(String(128), default="")
    ftp_password: Mapped[str] = mapped_column(String(255), default="")
    printer_mac_id: Mapped[str] = mapped_column(String(64), default="")
    printer_ip: Mapped[str] = mapped_column(String(64), default="")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    printer_auth_user: Mapped[str] = mapped_column(String(128), default="")
    printer_auth_password: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class UserRole(str, Enum):
    WORKER = "worker"
    LEADER = "leader"
    ADMIN = "admin"
    ACCOUNT = "account"
    CUSTOMER = "customer"


class UserType(str, Enum):
    TECH = "tech"
    SUPPORT = "support"


class TaskStatus(str, Enum):
    BACKLOG = "backlog"
    SELECTED = "selected"
    IN_PROGRESS = "in-progress"
    REVIEW = "review"
    DONE = "done"
    BLOCKED = "blocked"


class TaskPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeatureName(str, Enum):
    ADDRESS_BOOK = "address_book"
    LOCK_HISTORY = "lock_history"


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    PENDING = "pending"
    NOTIFIED = "notified"
    RESOLVED = "resolved"


class UserAccount(Base):
    __tablename__ = "UserAccount"
    __table_args__ = (UniqueConstraint("lead", "username", name="uq_useraccount_lead_username"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    password: Mapped[str] = mapped_column(String(128), default="")
    full_name: Mapped[str] = mapped_column(String(255), default="")
    email: Mapped[str] = mapped_column(String(255), default="", index=True)
    phone_number: Mapped[str] = mapped_column(String(64), default="")
    user_type: Mapped[str] = mapped_column(String(32), default=UserType.SUPPORT.value, index=True)
    role: Mapped[str] = mapped_column(String(32), default=UserType.SUPPORT.value, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    workspaces: Mapped[list["Workspace"]] = relationship(
        "Workspace",
        secondary="UserWorkspace",
        back_populates="users",
    )


class NetworkInfo(Base):
    __tablename__ = "NetworkInfo"
    __table_args__ = (UniqueConstraint("lead", "network_id", name="uq_networkinfo_lead_network"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    network_id: Mapped[str] = mapped_column(String(128), index=True)
    network_name: Mapped[str] = mapped_column(String(255), default="")
    office_name: Mapped[str] = mapped_column(String(255), default="")
    real_address: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class DeviceFeatureFlag(Base):
    __tablename__ = "DeviceFeatureFlag"
    __table_args__ = (UniqueConstraint("lead", "mac_id", "feature_name", name="uq_devicefeature_lead_mac_feature"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    mac_id: Mapped[str] = mapped_column(String(64), index=True)
    feature_name: Mapped[str] = mapped_column(String(64), default=FeatureName.ADDRESS_BOOK.value, index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    meta_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class DeviceLockHistory(Base):
    __tablename__ = "DeviceLockHistory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    mac_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    action: Mapped[str] = mapped_column(String(32), default="lock", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="system")
    meta_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class MachineAlert(Base):
    __tablename__ = "MachineAlert"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    mac_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    alert_type: Mapped[str] = mapped_column(String(64), default="counter")
    severity: Mapped[str] = mapped_column(String(16), default=AlertSeverity.WARNING.value, index=True)
    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.PENDING.value, index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(String(64), default="system")
    notify_role: Mapped[str] = mapped_column(String(32), default=UserRole.LEADER.value, index=True)
    meta_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class Task(Base):
    __tablename__ = "Task"
    __table_args__ = (UniqueConstraint("lead", "task_key", name="uq_task_lead_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    network_id: Mapped[str] = mapped_column(String(128), index=True, default="")
    task_key: Mapped[str] = mapped_column(String(64), default="")
    mac_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    machine_name: Mapped[str] = mapped_column(String(255), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default=TaskStatus.BACKLOG.value, index=True)
    priority: Mapped[str] = mapped_column(String(16), default=TaskPriority.MEDIUM.value, index=True)
    reporter_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("UserAccount.id"), nullable=True, index=True)
    assignee_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("UserAccount.id"), nullable=True, index=True)
    customer_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("UserAccount.id"), nullable=True, index=True)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    status_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    status_reason: Mapped[str] = mapped_column(Text, default="")
    reporter: Mapped[UserAccount | None] = relationship("UserAccount", foreign_keys=[reporter_id], backref="reported_tasks")
    assignee: Mapped[UserAccount | None] = relationship("UserAccount", foreign_keys=[assignee_id], backref="assigned_tasks")
    customer: Mapped[UserAccount | None] = relationship("UserAccount", foreign_keys=[customer_id], backref="customer_tasks")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class Workspace(Base):
    __tablename__ = "Workspace"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    logo: Mapped[str | None] = mapped_column(String(64), nullable=True)
    color: Mapped[str | None] = mapped_column(String(32), nullable=True)
    address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    users: Mapped[list["UserAccount"]] = relationship(
        "UserAccount",
        secondary="UserWorkspace",
        back_populates="workspaces",
    )
    locations: Mapped[list["Location"]] = relationship(
        "Location",
        back_populates="workspace",
    )


class UserWorkspace(Base):
    __tablename__ = "UserWorkspace"
    __table_args__ = (
        UniqueConstraint("user_id", "workspace_id", name="uq_userworkspace_user_workspace"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("UserAccount.id"), index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("Workspace.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)


class Location(Base):
    __tablename__ = "Location"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    room: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    machine_count: Mapped[int] = mapped_column(Integer, default=0)
    workspace_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("Workspace.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    workspace: Mapped[Workspace | None] = relationship(
        "Workspace",
        back_populates="locations",
    )


class RepairRequest(Base):
    __tablename__ = "RepairRequest"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    machine_name: Mapped[str] = mapped_column(String(255))
    location_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("Location.id"), nullable=True)
    workspace_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("Workspace.id"), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(String(32), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="new")
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attachments: Mapped[list] = mapped_column(JSONB, default=list)
    progress_notes: Mapped[list] = mapped_column(JSONB, default=list)
    completion_report: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    labor_cost: Mapped[int | None] = mapped_column(Integer, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Material(Base):
    __tablename__ = "Material"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repair_request_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("RepairRequest.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    unit_price: Mapped[int] = mapped_column(Integer, default=0)
    total_price: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
