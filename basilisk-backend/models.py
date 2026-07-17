"""SQLAlchemy ORM models — User, Scan, Finding."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    api_key = Column(String(255), unique=True, index=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_url = Column(String(2048), nullable=False)
    pages_scanned = Column(Integer, default=0)
    forms_found = Column(Integer, default=0)
    vulnerable = Column(Boolean, default=False)
    mode = Column(String(32), default="static")
    status = Column(String(32), default="complete")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability = Column(String(512), nullable=False)
    severity = Column(String(32), nullable=False)
    description = Column(String(2048), nullable=False)
    target = Column(String(2048), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
