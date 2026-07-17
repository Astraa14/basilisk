"""Device code flow authentication logic."""

from __future__ import annotations

import os
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta

FRONTEND_URL = os.getenv("BASILISK_FRONTEND_URL", "http://localhost:3000")
EXP_MINUTES = 10


# ---------------------------------------------------------------------------
# In-memory device code store
# ---------------------------------------------------------------------------

@dataclass
class DeviceCodeEntry:
    user_code: str
    expires_at: datetime
    verified: bool = False
    user_id: int | None = None
    api_key: str | None = None
    username: str = ""


_store: dict[str, DeviceCodeEntry] = {}   # device_code  → entry
_uc_map: dict[str, str] = {}              # user_code    → device_code


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_api_key() -> str:
    """Return a new 'bsk_' prefixed API key."""
    return "bsk_" + secrets.token_urlsafe(24)


def _make_user_code() -> str:
    """Generate a readable 6-char code like 'ABC-DEF'."""
    chars = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(chars) for _ in range(3))
    part2 = "".join(secrets.choice(chars) for _ in range(3))
    return f"{part1}-{part2}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_device_code() -> dict:
    """
    Create a new device code entry.
    Returns dict with device_code, user_code, verification_uri, expires_in.
    """
    device_code = secrets.token_urlsafe(32)
    user_code = _make_user_code()
    entry = DeviceCodeEntry(
        user_code=user_code,
        expires_at=datetime.utcnow() + timedelta(minutes=EXP_MINUTES),
    )
    _store[device_code] = entry
    _uc_map[user_code] = device_code
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{FRONTEND_URL}/auth?code={user_code}",
        "expires_in": EXP_MINUTES * 60,
    }


def verify_device_code(user_code: str, user_id: int, api_key: str, username: str = "") -> bool:
    """
    Mark a device code as verified and link it to a user + api_key.
    Called by the frontend /api/auth/verify endpoint.
    Returns True on success, False if code not found or expired.
    """
    dc = _uc_map.get(user_code)
    if not dc:
        return False
    entry = _store.get(dc)
    if not entry or datetime.utcnow() > entry.expires_at:
        return False
    entry.verified = True
    entry.user_id = user_id
    entry.api_key = api_key
    entry.username = username
    return True


def get_verified_token(device_code: str) -> dict | None:
    """
    Check if device_code has been verified.
    Returns {api_key, username} on success and removes the entry.
    Returns None if not yet verified or expired.
    """
    entry = _store.get(device_code)
    if not entry:
        return None
    if datetime.utcnow() > entry.expires_at:
        _uc_map.pop(entry.user_code, None)
        _store.pop(device_code, None)
        return None
    if not entry.verified:
        return None
    # One-time use — clean up
    result = {"api_key": entry.api_key, "username": entry.username}
    _uc_map.pop(entry.user_code, None)
    del _store[device_code]
    return result


def get_user_by_api_key(api_key: str, db):
    """Query the database for a user with the given API key."""
    from models import User
    return db.query(User).filter(User.api_key == api_key).first()


def cleanup_expired_codes() -> None:
    """Remove all expired device code entries from the in-memory store."""
    now = datetime.utcnow()
    expired = [dc for dc, e in _store.items() if now > e.expires_at]
    for dc in expired:
        entry = _store.pop(dc, None)
        if entry:
            _uc_map.pop(entry.user_code, None)
