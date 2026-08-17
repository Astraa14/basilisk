"""Tests for the SSH bastion tunnel."""

import pytest

from basilisk.tunnel import SshTunnel, TunnelError, open_bastion_tunnel


class TestSshTunnel:
    def test_ssh_missing_raises(self, monkeypatch):
        monkeypatch.setattr("basilisk.tunnel.SshTunnel.ssh_available", staticmethod(lambda: False))
        tunnel = SshTunnel("user@bastion.example.com")
        with pytest.raises(TunnelError):
            tunnel.start()

    def test_bad_target_rejected(self, monkeypatch):
        monkeypatch.setattr("basilisk.tunnel.SshTunnel.ssh_available", staticmethod(lambda: True))
        tunnel = SshTunnel("not-a-host-target")
        with pytest.raises(TunnelError):
            tunnel.start()

    def test_proxy_url_empty_before_start(self):
        tunnel = SshTunnel("user@bastion.example.com")
        assert tunnel.proxy_url == ""

    def test_open_bastion_tunnel_returns_none_on_failure(self, monkeypatch):
        monkeypatch.setattr("basilisk.tunnel.SshTunnel.ssh_available", staticmethod(lambda: False))
        assert open_bastion_tunnel("user@host") is None