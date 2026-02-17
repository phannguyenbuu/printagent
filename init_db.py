from __future__ import annotations

# Root entrypoint for DB initialization.
# Supports both layouts:
# 1) server/init_db.py (package layout)
# 2) init_db.py + local modules (flat layout)

try:
    from server.init_db import main  # type: ignore
except Exception:
    # Flat layout fallback
    from config import ServerConfig  # type: ignore
    from db import create_session_factory  # type: ignore
    from models import Base  # type: ignore

    def main() -> None:
        cfg = ServerConfig()
        session_factory = create_session_factory(cfg)
        Base.metadata.create_all(bind=session_factory.kw["bind"])
        print("Database initialized:", cfg.database_url)


if __name__ == "__main__":
    main()
