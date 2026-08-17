"""Database connection and session management."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

load_dotenv()

logger = logging.getLogger("basilisk.backend.database")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./basilisk.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables(max_retries: int = 3) -> None:
    for attempt in range(max_retries):
        try:
            from models import Base
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created/verified.")
            return
        except Exception as exc:
            logger.warning("DB connect attempt %d/%d failed: %s", attempt + 1, max_retries, exc)
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logger.error("Could not create tables after %d attempts.", max_retries)
                raise


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
