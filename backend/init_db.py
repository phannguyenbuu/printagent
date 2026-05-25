from __future__ import annotations

from config import ServerConfig
from db import create_session_factory
from models import Base
from sqlalchemy import text


def main() -> None:
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    bind = session_factory.kw["bind"]
    Base.metadata.create_all(bind=bind)
    
    with bind.connect() as conn:
        conn.execute(text('ALTER TABLE "LanEmail" ADD COLUMN IF NOT EXISTS email_type VARCHAR(32) DEFAULT \'common\''))
        conn.execute(text('ALTER TABLE "LanEmail" ADD COLUMN IF NOT EXISTS pc_name VARCHAR(255) DEFAULT \'\''))
        conn.commit()
        
    print("Database initialized:", cfg.database_url)


if __name__ == "__main__":
    main()
