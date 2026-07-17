"""Pydantic schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class FindingSchema(BaseModel):
    vulnerability: str
    severity: str
    description: str
    target: str


class FindingResponseSchema(FindingSchema):
    id: int
    scan_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanReportSchema(BaseModel):
    """Shape of the report the CLI sends when uploading."""
    target: str
    pages_scanned: int = 0
    forms_found: int = 0
    vulnerable: bool = False
    findings: list[FindingSchema] = []
    mode: str = "static"


class ScanResponseSchema(BaseModel):
    """Shape returned to the dashboard when querying scans."""
    id: int
    user_id: int
    target_url: str
    pages_scanned: int
    forms_found: int
    vulnerable: bool
    mode: str
    status: str
    created_at: datetime
    findings: list[FindingResponseSchema] = []

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class UserSchema(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Auth — Device Code Flow
# ---------------------------------------------------------------------------

class DeviceCodeSchema(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int


class TokenPollSchema(BaseModel):
    device_code: str


class TokenResponseSchema(BaseModel):
    api_key: str = ""
    username: str = ""
    status: int  # 200 = ready, 202 = still waiting


class VerifyDeviceSchema(BaseModel):
    user_code: str
    username: str
    email: str


class VerifyResponseSchema(BaseModel):
    verified: bool
    api_key: str
    username: str
