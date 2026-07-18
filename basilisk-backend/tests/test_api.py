"""Tests for Basilisk backend API."""

import pytest
from database import get_db, create_tables
from models import Base
from main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    create_tables()
    from database import SessionLocal
    session = SessionLocal()
    def override_get_db():
        try:
            yield session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"


class TestDeviceCodeFlow:
    def test_request_device_code(self, client):
        resp = client.post("/api/auth/device-code")
        assert resp.status_code == 200
        data = resp.json()
        assert "device_code" in data
        assert "user_code" in data
        assert "verification_uri" in data
        assert data["expires_in"] > 0

    def test_verify_and_poll_token(self, client):
        code_resp = client.post("/api/auth/device-code")
        code_data = code_resp.json()
        user_code = code_data["user_code"]
        device_code = code_data["device_code"]

        verify_resp = client.post("/api/auth/verify", json={
            "user_code": user_code,
            "username": "testuser",
            "email": "test@example.com",
        })
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["verified"] is True
        assert verify_data["api_key"].startswith("bsk_")

        poll_resp = client.post("/api/auth/token", json={"device_code": device_code})
        assert poll_resp.status_code == 200
        poll_data = poll_resp.json()
        assert poll_data["status"] == 200
        assert poll_data["api_key"].startswith("bsk_")

    def test_poll_not_verified_returns_202(self, client):
        code_resp = client.post("/api/auth/device-code")
        code_data = code_resp.json()

        poll_resp = client.post("/api/auth/token", json={"device_code": code_data["device_code"]})
        assert poll_resp.status_code == 202


class TestScanUpload:
    def _auth_and_get_key(self, client):
        code_resp = client.post("/api/auth/device-code")
        cd = code_resp.json()
        client.post("/api/auth/verify", json={
            "user_code": cd["user_code"], "username": "u", "email": "u@e.com",
        })
        poll = client.post("/api/auth/token", json={"device_code": cd["device_code"]})
        return poll.json()["api_key"]

    def test_upload_scan(self, client):
        api_key = self._auth_and_get_key(client)
        report = {
            "target": "http://example.com",
            "pages_scanned": 10,
            "forms_found": 2,
            "vulnerable": True,
            "mode": "static",
            "findings": [
                {
                    "vulnerability": "XSS",
                    "severity": "High",
                    "description": "Reflected XSS in search",
                    "target": "http://example.com/search",
                    "attack_type": "xss",
                    "payload": "<script>alert(1)</script>",
                }
            ],
            "exploits_found": [
                {"payload": "' OR 1=1 --", "status_code": 200, "reason": "Auth bypass"}
            ],
        }
        resp = client.post("/api/scans/upload", json=report, headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "created"

    def test_upload_without_auth_returns_401(self, client):
        resp = client.post("/api/scans/upload", json={"target": "t"})
        assert resp.status_code == 401

    def test_list_scans(self, client):
        api_key = self._auth_and_get_key(client)
        resp = client.get("/api/scans", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert "total" in data
        assert "page" in data

    def test_list_scans_pagination(self, client):
        api_key = self._auth_and_get_key(client)
        resp = client.get("/api/scans?page=1&per_page=5", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 200

    def test_get_scan_detail(self, client):
        api_key = self._auth_and_get_key(client)
        report = {"target": "http://t.com", "pages_scanned": 1, "findings": []}
        upload = client.post("/api/scans/upload", json=report, headers={"Authorization": f"Bearer {api_key}"})
        scan_id = upload.json()["scan_id"]

        resp = client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_url"] == "http://t.com"
        assert data["id"] == scan_id

    def test_get_nonexistent_scan_returns_404(self, client):
        api_key = self._auth_and_get_key(client)
        resp = client.get("/api/scans/99999", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 404

    def test_delete_scan(self, client):
        api_key = self._auth_and_get_key(client)
        report = {"target": "http://t.com", "pages_scanned": 1, "findings": []}
        upload = client.post("/api/scans/upload", json=report, headers={"Authorization": f"Bearer {api_key}"})
        scan_id = upload.json()["scan_id"]

        resp = client.delete(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 204

        get_resp = client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {api_key}"})
        assert get_resp.status_code == 404

    def test_delete_nonexistent_scan_returns_404(self, client):
        api_key = self._auth_and_get_key(client)
        resp = client.delete("/api/scans/99999", headers={"Authorization": f"Bearer {api_key}"})
        assert resp.status_code == 404
