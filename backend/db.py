from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config import ServerConfig


def create_session_factory(config: ServerConfig) -> sessionmaker[Session]:
    engine = create_engine(config.database_url, pool_pre_ping=True, future=True)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
