"""Device code flow authentication — DB-backed for Render reliability."""

from __future__ import annotations

import os
import secrets
import string
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

FRONTEND_URL = os.getenv("BASILISK_FRONTEND_URL", "https://basilisk-livid.vercel.app")
EXP_MINUTES = 10


def generate_api_key() -> str:
    """Return a new 'bsk_' prefixed API key."""
    return "bsk_" + secrets.token_urlsafe(24)


def _make_user_code() -> str:
    """Generate a readable 6-char code like 'ABC-DEF'."""
    chars = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(chars) for _ in range(3))
    part2 = "".join(secrets.choice(chars) for _ in range(3))
    return f"{part1}-{part2}"


def generate_device_code(db: Session) -> dict:
    """
    Create a new device code entry in the database.
    Returns dict with device_code, user_code, verification_uri, expires_in.
    """
    from models import DeviceCode

    cleanup_expired_codes(db)

    device_code = secrets.token_urlsafe(32)
    user_code = _make_user_code()
    # Avoid rare collisions on user_code
    while db.query(DeviceCode).filter(DeviceCode.user_code == user_code).first():
        user_code = _make_user_code()

    entry = DeviceCode(
        device_code=device_code,
        user_code=user_code,
        expires_at=datetime.utcnow() + timedelta(minutes=EXP_MINUTES),
        verified=False,
        username="",
    )
    db.add(entry)
    db.commit()

    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{FRONTEND_URL}/auth?code={user_code}",
        "expires_in": EXP_MINUTES * 60,
    }


def verify_device_code(
    db: Session,
    user_code: str,
    user_id: int,
    api_key: str,
    username: str = "",
) -> bool:
    """
    Mark a device code as verified and link it to a user + api_key.
    Returns True on success, False if code not found or expired.
    """
    from models import DeviceCode

    entry = (
        db.query(DeviceCode)
        .filter(DeviceCode.user_code == user_code)
        .first()
    )
    if not entry or datetime.utcnow() > entry.expires_at:
        return False

    entry.verified = True
    entry.user_id = user_id
    entry.api_key = api_key
    entry.username = username
    db.commit()
    return True


def get_verified_token(db: Session, device_code: str) -> dict | None:
    """
    Check if device_code has been verified.
    Returns {api_key, username} on success and removes the entry.
    Returns None if not yet verified.
    Raises KeyError if device_code is unknown/expired (caller maps to 400).
    """
    from models import DeviceCode

    entry = (
        db.query(DeviceCode)
        .filter(DeviceCode.device_code == device_code)
        .first()
    )
    if not entry:
        raise KeyError("device_code_not_found")
    if datetime.utcnow() > entry.expires_at:
        db.delete(entry)
        db.commit()
        raise KeyError("device_code_expired")
    if not entry.verified:
        return None

    result = {"api_key": entry.api_key or "", "username": entry.username or ""}
    db.delete(entry)
    db.commit()
    return result


def device_code_exists(db: Session, device_code: str) -> bool:
    from models import DeviceCode

    entry = (
        db.query(DeviceCode)
        .filter(DeviceCode.device_code == device_code)
        .first()
    )
    if not entry:
        return False
    if datetime.utcnow() > entry.expires_at:
        db.delete(entry)
        db.commit()
        return False
    return True


def get_user_by_api_key(api_key: str, db: Session):
    """Query the database for a user with the given API key."""
    from models import User

    return db.query(User).filter(User.api_key == api_key).first()


def cleanup_expired_codes(db: Session) -> None:
    """Remove all expired device code entries."""
    from models import DeviceCode

    now = datetime.utcnow()
    db.query(DeviceCode).filter(DeviceCode.expires_at < now).delete()
    db.commit()
