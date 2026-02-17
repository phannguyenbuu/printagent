from __future__ import annotations

from config import ServerConfig
from db import create_session_factory
from models import Base


def main() -> None:
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    Base.metadata.create_all(bind=session_factory.kw["bind"])
    print("Database initialized:", cfg.database_url)


if __name__ == "__main__":
    main()
