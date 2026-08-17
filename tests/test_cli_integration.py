"""
Integration tests for the Basilisk CLI scanner.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from basilisk.cli import app
from tests import LocalServer

runner = CliRunner()


def _minimal_report(url: str = "http://127.0.0.1", vulnerable: bool = False) -> dict:
    return {
        "target": url,
        "pages_scanned": 1,
        "forms_found": 0,
        "findings": [],
        "vulnerable": vulnerable,
        "mode": "static",
        "scan_duration": 0.1,
        "exploits_found": [],
    }


def _mock_scanner(report: dict | None = None, *, raise_exc: Exception | None = None):
    mock_instance = MagicMock()
    if raise_exc:
        mock_instance.scan.side_effect = raise_exc
    else:
        mock_instance.scan.return_value = report or _minimal_report()
    mock_instance.close.return_value = None
    return patch("basilisk.cli.Basilisk", return_value=mock_instance)


class TestCLIStartup:
    def test_help_exits_cleanly(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "basilisk" in result.output.lower() or "scan" in result.output.lower()

    def test_scan_help_exits_cleanly(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--no-llm" in result.output
        assert "--output" in result.output

    def test_login_help_exits_cleanly(self):
        result = runner.invoke(app, ["login", "--help"])
        assert result.exit_code == 0

    def test_auth_help_exits_cleanly(self):
        result = runner.invoke(app, ["auth", "--help"])
        assert result.exit_code == 0

    def test_logout_help_exits_cleanly(self):
        result = runner.invoke(app, ["logout", "--help"])
        assert result.exit_code == 0


class TestScanCommand:
    def test_scan_runs_and_exits_0_when_clean(self):
        with _mock_scanner(_minimal_report(vulnerable=False)):
            result = runner.invoke(app, ["scan", "http://127.0.0.1"])
        assert result.exit_code == 0

    def test_scan_exits_1_when_vulnerable(self):
        report = _minimal_report(vulnerable=True)
        report["findings"] = [
            {
                "vulnerability": "SQLi",
                "severity": "High",
                "description": "SQL injection detected",
                "target": "http://127.0.0.1",
            }
        ]
        with _mock_scanner(report):
            result = runner.invoke(app, ["scan", "http://127.0.0.1"])
        assert result.exit_code == 1

    def test_scan_no_llm_flag(self):
        with _mock_scanner():
            result = runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm"])
        assert result.exit_code == 0


class TestOutputFormats:
    def test_json_stdout_output(self):
        with _mock_scanner():
            result = runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "target" in data

    def test_json_file_output(self, tmp_path):
        out = tmp_path / "result.json"
        with _mock_scanner():
            result = runner.invoke(
                app, ["scan", "http://127.0.0.1", "--no-llm", "--output", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()

    def test_html_file_output(self, tmp_path):
        out = tmp_path / "report.html"
        with _mock_scanner():
            result = runner.invoke(
                app, ["scan", "http://127.0.0.1", "--no-llm", "--output", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()


class TestLocalHTTPIntegration:
    def test_scan_against_local_server_no_llm(self):
        with LocalServer() as srv:
            result = runner.invoke(
                app,
                [
                    "scan",
                    srv.base_url,
                    "--no-llm",
                    "--timeout", "5",
                    "--max-pages", "1",
                    "--no-protocol-scan",
                    "--json",
                ],
            )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert data["target"] == srv.base_url


class TestPackageImports:
    def test_basilisk_core_importable(self):
        from basilisk.core import Basilisk  # noqa: F401

    def test_basilisk_cli_importable(self):
        from basilisk.cli import app  # noqa: F401

    def test_basilisk_reporter_has_functions(self):
        from basilisk.reporter import save_json, save_html, send_report_to_backend  # noqa: F401
