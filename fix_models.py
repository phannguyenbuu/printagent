import os

content = '''
class FtpControlCommand(Base):
    __tablename__ = "FtpControlCommand"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lead: Mapped[str] = mapped_column(String(64), index=True)
    lan_uid: Mapped[str] = mapped_column(String(128), index=True, default="")
    agent_uid: Mapped[str] = mapped_column(String(128), index=True, default="legacy-agent")
    action: Mapped[str] = mapped_column(String(64), default="")
    site_name: Mapped[str] = mapped_column(String(255), default="")
    new_site_name: Mapped[str] = mapped_column(String(255), default="")
    local_path: Mapped[str] = mapped_column(Text, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    ftp_user: Mapped[str] = mapped_column(String(128), default="")
    ftp_password: Mapped[str] = mapped_column(String(255), default="")
    printer_mac_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    printer_ip: Mapped[str] = mapped_column(String(64), default="")
    printer_name: Mapped[str] = mapped_column(String(255), default="")
    printer_auth_user: Mapped[str] = mapped_column(String(128), default="")
    printer_auth_password: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(64), default="pending", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
'''

with open('backend/models.py', 'a', encoding='utf-8') as f:
    f.write(content)
