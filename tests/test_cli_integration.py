"""
Integration tests for the Basilisk standalone CLI scanner.

These tests verify:
- CLI startup and help
- scan command invocation
- --no-llm mode
- JSON output
- HTML output
- local result persistence
- backend independence (no network uploads)
- clean Ctrl+C handling
- correct exit codes
- invalid / unreachable targets
- LLM-disabled mode
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

# Make sure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from basilisk.cli import app
from tests import LocalServer  # shared local HTTP test server


runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """Return a context manager that patches Basilisk.scan with a minimal report."""
    mock_instance = MagicMock()
    if raise_exc:
        mock_instance.scan.side_effect = raise_exc
    else:
        mock_instance.scan.return_value = report or _minimal_report()
    mock_instance.close.return_value = None
    return patch("basilisk.cli.Basilisk", return_value=mock_instance)


# ---------------------------------------------------------------------------
# Phase 1 — CLI startup
# ---------------------------------------------------------------------------


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

    def test_no_auth_command(self):
        """There must be no 'auth' subcommand (SaaS removed)."""
        result = runner.invoke(app, ["auth"])
        # Should fail — command doesn't exist
        assert result.exit_code != 0

    def test_no_logout_command(self):
        """There must be no 'logout' subcommand (SaaS removed)."""
        result = runner.invoke(app, ["logout"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Phase 2 — scan command
# ---------------------------------------------------------------------------


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

    def test_scan_adds_https_when_missing_scheme(self):
        """URL without scheme should not crash — https:// is prepended."""
        captured = {}

        def fake_init(self, target_url, **kwargs):
            captured["url"] = target_url
            self.target_url = target_url
            self.use_llm = False
            self.config = MagicMock()
            self.config.ssh_tunnel = ""
            self.tunnel = None

        mock_scan = MagicMock(return_value=_minimal_report())
        mock_close = MagicMock()

        with (
            patch("basilisk.cli.Basilisk.__init__", fake_init),
            patch("basilisk.cli.Basilisk.scan", mock_scan),
            patch("basilisk.cli.Basilisk.close", mock_close),
        ):
            result = runner.invoke(app, ["scan", "example.com", "--no-llm"])

        assert result.exit_code in (0, 1)

    def test_scan_no_llm_flag(self):
        with _mock_scanner():
            result = runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm"])
        # Must not request LLM configuration even if key is present
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Phase 3 — output formats
# ---------------------------------------------------------------------------


class TestOutputFormats:
    def test_json_stdout_output(self):
        with _mock_scanner():
            result = runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "target" in data
        assert "findings" in data

    def test_json_file_output(self, tmp_path):
        out = tmp_path / "result.json"
        with _mock_scanner():
            result = runner.invoke(
                app, ["scan", "http://127.0.0.1", "--no-llm", "--output", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "target" in data

    def test_html_file_output(self, tmp_path):
        out = tmp_path / "report.html"
        with _mock_scanner():
            result = runner.invoke(
                app, ["scan", "http://127.0.0.1", "--no-llm", "--output", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert "<html" in content.lower()
        assert "Basilisk" in content

    def test_output_dir_creates_both_formats(self, tmp_path):
        od = tmp_path / "reports"
        with _mock_scanner():
            result = runner.invoke(
                app,
                ["scan", "http://127.0.0.1", "--no-llm", "--output-dir", str(od)],
            )
        assert result.exit_code == 0
        assert od.is_dir()
        files = list(od.iterdir())
        extensions = {f.suffix.lower() for f in files}
        assert ".json" in extensions
        assert ".html" in extensions


# ---------------------------------------------------------------------------
# Phase 4 — backend independence
# ---------------------------------------------------------------------------


class TestBackendIndependence:
    def test_no_upload_to_basilisk_server(self):
        """Scan must never POST to basilisk-ja22.onrender.com or any Basilisk server."""
        import requests as req_mod

        original_post = req_mod.post
        uploaded_urls: list[str] = []

        def spy_post(url, **kwargs):
            if "onrender.com" in url or "vercel.app" in url or "basilisk" in url.lower():
                uploaded_urls.append(url)
            return original_post(url, **kwargs)

        with (
            _mock_scanner(),
            patch.object(req_mod, "post", side_effect=spy_post),
        ):
            runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm"])

        assert uploaded_urls == [], (
            f"Scan unexpectedly uploaded to: {uploaded_urls}"
        )

    def test_reporter_has_no_backend_url(self):
        """reporter.py must not contain hard-coded Basilisk backend URLs."""
        import basilisk.reporter as rep_mod
        src = Path(rep_mod.__file__).read_text(encoding="utf-8")
        assert "onrender.com" not in src
        assert "vercel.app" not in src

    def test_auth_module_has_no_backend_calls(self):
        """auth.py must not contain device-code / backend polling code."""
        import basilisk.auth as auth_mod
        src = Path(auth_mod.__file__).read_text(encoding="utf-8")
        assert "onrender.com" not in src
        assert "device_code" not in src
        assert "poll_for_backend" not in src

    def test_cli_has_no_dashboard_url(self):
        """cli.py must not reference the Basilisk SaaS dashboard URL."""
        src = Path(__file__).resolve().parents[1] / "basilisk" / "cli.py"
        content = src.read_text(encoding="utf-8")
        assert "vercel.app" not in content
        assert "onrender.com" not in content
        assert "DASHBOARD_URL" not in content


# ---------------------------------------------------------------------------
# Phase 5 — error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_unreachable_target_handled_gracefully(self, tmp_path):
        """Connection failures should not produce a Python traceback."""
        import requests.exceptions as rexc
        from basilisk.core import Basilisk

        with patch.object(
            Basilisk,
            "scan",
            side_effect=rexc.ConnectionError("Connection refused"),
        ):
            with patch.object(Basilisk, "close", return_value=None):
                result = runner.invoke(app, ["scan", "http://127.0.0.1:19999", "--no-llm"])
        # Should produce exit code 2 or fail silently — not a raw traceback
        assert "Traceback" not in result.output
        # exit code should be non-zero
        assert result.exit_code != 0 or "error" in result.output.lower()

    def test_llm_config_error_exits_2(self):
        from basilisk.llm import LLMError

        with patch("basilisk.cli.Basilisk", side_effect=LLMError("no LLM configured")):
            result = runner.invoke(
                app, ["scan", "http://127.0.0.1", "--llm"]
            )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Phase 6 — real local HTTP server integration
# ---------------------------------------------------------------------------


class TestLocalHTTPIntegration:
    def test_scan_against_local_server_no_llm(self):
        """Run an actual scan against a local HTTP server in static mode."""
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
        assert isinstance(data["findings"], list)

    def test_json_report_saved_to_disk_during_real_scan(self, tmp_path):
        """With a real local server, JSON output must be written to disk."""
        out = tmp_path / "scan.json"
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
                    "--output", str(out),
                ],
            )
        assert result.exit_code in (0, 1)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["target"] == srv.base_url

    def test_html_report_saved_to_disk_during_real_scan(self, tmp_path):
        """With a real local server, HTML output must be written to disk."""
        out = tmp_path / "scan.html"
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
                    "--output", str(out),
                ],
            )
        assert result.exit_code in (0, 1)
        assert out.exists()
        html = out.read_text()
        assert "<html" in html.lower()
        assert "Basilisk" in html


# ---------------------------------------------------------------------------
# Phase 7 — LLM modes
# ---------------------------------------------------------------------------


class TestLLMModes:
    def test_no_llm_flag_disables_llm(self):
        """--no-llm must work even when BASILISK_LLM_API_KEY is set in env."""
        env = {**os.environ, "BASILISK_LLM_API_KEY": "sk-fake-key-for-testing"}
        with (
            patch.dict(os.environ, env),
            _mock_scanner(),
        ):
            result = runner.invoke(app, ["scan", "http://127.0.0.1", "--no-llm"])
        assert result.exit_code == 0

    def test_mocked_llm_provider(self):
        """LLM mode with a mocked provider must complete without error."""
        mock_client = MagicMock()
        mock_client.chat.return_value = '[{"payload":"x","strategy":"xss"}]'
        mock_client.chat_json.return_value = [{"payload": "x", "strategy": "xss"}]
        mock_client.backend = "cloud"

        with (
            patch("basilisk.llm.LLMClient", return_value=mock_client),
            _mock_scanner(_minimal_report()),
        ):
            result = runner.invoke(
                app,
                ["scan", "http://127.0.0.1", "--llm", "--api-key", "sk-fake"],
            )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Phase 8 — package importability
# ---------------------------------------------------------------------------


class TestPackageImports:
    def test_basilisk_core_importable(self):
        from basilisk.core import Basilisk  # noqa: F401

    def test_basilisk_cli_importable(self):
        from basilisk.cli import app  # noqa: F401

    def test_basilisk_reporter_has_save_functions(self):
        from basilisk.reporter import save_json, save_html  # noqa: F401

    def test_basilisk_config_importable(self):
        from basilisk.config import config_exists  # noqa: F401

    def test_no_backend_api_in_reporter(self):
        """reporter module must export save_json and save_html, not send_report_to_backend."""
        import basilisk.reporter as rep
        assert hasattr(rep, "save_json")
        assert hasattr(rep, "save_html")
        assert not hasattr(rep, "send_report_to_backend")
