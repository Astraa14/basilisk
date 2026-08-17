"""
Basilisk report helpers for local files and optional SaaS sync.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
import requests

logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BASILISK_BACKEND_URL", "https://basilisk-ja22.onrender.com")


def save_json(report: dict, path: Path) -> None:
    """Write scan report to a JSON file."""
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def send_report_to_backend(report: dict, api_key: str | None = None) -> str | None:
    """Upload completed scan report to the backend (for Vercel dashboard view)."""
    if not api_key:
        from basilisk.config import load_backend_api_key
        api_key = load_backend_api_key()

    if not api_key:
        return None

    url = f"{BACKEND_URL}/api/scans/upload"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    try:
        response = requests.post(url, json=report, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("scan_id")
        else:
            logger.warning("Upload failed with status %s: %s", response.status_code, response.text)
            return None
    except Exception as exc:
        logger.warning("Upload to SaaS backend failed: %s", exc)
        return None


def save_html(report: dict, path: Path) -> None:
    """Write scan report to a self-contained HTML file."""
    findings = report.get("findings", [])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "Info"), 9))

    rows = ""
    for f in ranked:
        sev = f.get("severity", "Info")
        color = {
            "Critical": "#dc2626",
            "High": "#ef4444",
            "Medium": "#eab308",
            "Low": "#06b6d4",
            "Info": "#6b7280",
        }.get(sev, "#6b7280")
        vuln = f.get("vulnerability", "")
        target = f.get("target", "")
        desc = f.get("description", "")
        payload = f.get("payload", "")
        payload_row = (
            f'<tr><td colspan="4" style="padding:.25rem 1rem .5rem;color:#94a3b8;font-size:.8rem">'
            f'Payload: <code>{payload[:200]}</code></td></tr>'
            if payload
            else ""
        )
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{sev}</span></td>
          <td>{vuln}</td>
          <td style="word-break:break-all">{target}</td>
          <td>{desc}</td>
        </tr>{payload_row}"""

    now = datetime.now(timezone.utc).isoformat()
    high_count = sum(1 for f in findings if f.get("severity") in ("High", "Critical"))
    status_color = "#dc2626" if high_count else "#22c55e"
    status_text = f"{high_count} high/critical finding(s)" if high_count else "No high-severity issues"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Basilisk Scan Report — {report.get('target', '')}</title>
<style>
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; line-height:1.5 }}
  h1 {{ color:#22c55e; margin-bottom:.25rem }}
  .subtitle {{ color:#64748b; margin:0 0 1.5rem }}
  .meta {{ background:#1e293b; border:1px solid #334155; border-radius:.5rem;
           padding:1rem 1.5rem; margin:1rem 0; display:grid;
           grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:.5rem }}
  .meta-item {{ display:flex; flex-direction:column }}
  .meta-label {{ font-size:.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:.05em }}
  .meta-value {{ font-weight:600; color:#e2e8f0 }}
  .status-badge {{ display:inline-block; padding:.25rem .75rem; border-radius:999px;
                   background:{status_color}22; color:{status_color};
                   border:1px solid {status_color}55; font-weight:600; font-size:.875rem }}
  table {{ width:100%; border-collapse:collapse; margin-top:1.5rem }}
  th {{ padding:.5rem 1rem; text-align:left; border-bottom:2px solid #334155;
        color:#94a3b8; font-size:.75rem; text-transform:uppercase; letter-spacing:.05em }}
  td {{ padding:.75rem 1rem; text-align:left; border-bottom:1px solid #1e293b; font-size:.875rem }}
  tr:hover td {{ background:#1e293b55 }}
  .empty {{ text-align:center; padding:3rem; color:#64748b }}
  footer {{ margin-top:2rem; color:#475569; font-size:.75rem; border-top:1px solid #1e293b; padding-top:1rem }}
  code {{ background:#1e293b; padding:.1rem .3rem; border-radius:.2rem; font-size:.8rem }}
</style>
</head>
<body>
<h1>&#x1F40D; Basilisk Scan Report</h1>
<p class="subtitle">Vulnerability scanner report — {report.get('target','')}</p>
<div class="meta">
  <div class="meta-item"><span class="meta-label">Target</span>
    <span class="meta-value">{report.get('target','')}</span></div>
  <div class="meta-item"><span class="meta-label">Mode</span>
    <span class="meta-value">{report.get('mode','static')}</span></div>
  <div class="meta-item"><span class="meta-label">Pages Scanned</span>
    <span class="meta-value">{report.get('pages_scanned',0)}</span></div>
  <div class="meta-item"><span class="meta-label">Forms Found</span>
    <span class="meta-value">{report.get('forms_found',0)}</span></div>
  <div class="meta-item"><span class="meta-label">Findings</span>
    <span class="meta-value">{len(findings)}</span></div>
  <div class="meta-item"><span class="meta-label">Status</span>
    <span class="status-badge">{status_text}</span></div>
</div>
{'<table><thead><tr><th>Severity</th><th>Issue</th><th>Target</th><th>Description</th></tr></thead><tbody>' + rows + '</tbody></table>' if findings else '<div class="empty">&#x2705; No issues flagged.</div>'}
<footer>
  Generated by <strong>Basilisk</strong> on {now}<br>
  Scan only systems you own or have explicit written permission to test.
</footer>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
