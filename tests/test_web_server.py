"""
Tests for Basilisk Ephemeral Dashboard Server.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import pytest
from basilisk.web_server import EphemeralDashboardServer, generate_passcode


def test_generate_passcode_format():
    code = generate_passcode()
    assert code.startswith("BSK-")
    assert len(code) == 10  # 'BSK-' (4) + 2 letters + 4 digits (6)


def test_ephemeral_server_lifecycle():
    server = EphemeralDashboardServer(target_url="https://example.com")
    server.start()
    try:
        # 1. Fetch Root HTML
        req = urllib.request.Request(server.url)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            content = resp.read().decode("utf-8")
            assert "BASILISK" in content
            assert "Ephemeral Session" in content

        # 2. Login with incorrect passcode
        login_url = f"{server.url}/api/login"
        bad_data = json.dumps({"code": "WRONG"}).encode("utf-8")
        bad_req = urllib.request.Request(login_url, data=bad_data, headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req)
        assert exc_info.value.code == 401

        # 3. Login with correct passcode
        good_data = json.dumps({"code": server.passcode}).encode("utf-8")
        good_req = urllib.request.Request(login_url, data=good_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(good_req) as resp:
            assert resp.status == 200
            res_data = json.loads(resp.read().decode("utf-8"))
            assert res_data["success"] is True
            token = res_data["token"]

        # 4. Access protected session API with cookie
        session_url = f"{server.url}/api/session"
        sess_req = urllib.request.Request(session_url, headers={"Cookie": f"bsk_token={token}"})
        with urllib.request.urlopen(sess_req) as resp:
            assert resp.status == 200
            sess_data = json.loads(resp.read().decode("utf-8"))
            assert sess_data["target_url"] == "https://example.com"

        # 5. Access session API via autologin code parameter
        code_req = urllib.request.Request(f"{server.url}/api/session?code={server.passcode}")
        with urllib.request.urlopen(code_req) as resp:
            assert resp.status == 200

    finally:
        server.stop()

    # 6. Verify server is stopped and unreachable
    with pytest.raises((urllib.error.URLError, ConnectionRefusedError, OSError)):
        urllib.request.urlopen(server.url, timeout=1)
