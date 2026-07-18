"""Tests for Basilisk backend auth module."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base
from auth import (
    generate_api_key, generate_device_code, verify_device_code,
    get_verified_token, get_user_by_api_key, cleanup_expired_codes,
)
from database import get_db


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


class TestAuth:
    def test_generate_api_key(self):
        key = generate_api_key()
        assert key.startswith("bsk_")
        assert len(key) > 10

    def test_generate_device_code(self, db_session):
        result = generate_device_code(db_session)
        assert "device_code" in result
        assert "user_code" in result
        assert "verification_uri" in result
        assert result["expires_in"] == 600

    def test_verify_device_code(self, db_session):
        code = generate_device_code(db_session)
        api_key = generate_api_key()

        # Create a user first
        from models import User
        user = User(username="testuser", email="test@example.com", api_key=api_key)
        db_session.add(user)
        db_session.commit()

        success = verify_device_code(db_session, code["user_code"], user.id, api_key, "testuser")
        assert success is True

    def test_verify_expired_code_returns_false(self, db_session):
        from models import DeviceCode
        from datetime import datetime, timedelta

        # Manually insert an expired code
        expired = DeviceCode(
            device_code="expired_dev",
            user_code="EXP-123",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            verified=False,
        )
        db_session.add(expired)
        db_session.commit()

        success = verify_device_code(db_session, "EXP-123", 1, "bsk_test", "user")
        assert success is False

    def test_get_verified_token(self, db_session):
        code = generate_device_code(db_session)
        api_key = generate_api_key()

        from models import User
        user = User(username="u", email="u@e.com", api_key=api_key)
        db_session.add(user)
        db_session.commit()

        verify_device_code(db_session, code["user_code"], user.id, api_key, "u")
        result = get_verified_token(db_session, code["device_code"])
        assert result is not None
        assert result["api_key"] == api_key

    def test_get_verified_token_not_verified_returns_none(self, db_session):
        code = generate_device_code(db_session)
        result = get_verified_token(db_session, code["device_code"])
        assert result is None

    def test_get_verified_token_unknown_raises(self, db_session):
        with pytest.raises(KeyError):
            get_verified_token(db_session, "unknown_code")

    def test_cleanup_expired_codes(self, db_session):
        from models import DeviceCode
        from datetime import datetime, timedelta

        db_session.add(DeviceCode(
            device_code="old_dev", user_code="OLD-123",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        ))
        db_session.commit()

        cleanup_expired_codes(db_session)
        assert db_session.query(DeviceCode).filter(DeviceCode.user_code == "OLD-123").count() == 0
