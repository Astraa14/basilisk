"""Sends completed scan reports to the Basilisk backend API."""

from __future__ import annotations

import logging

import requests

# Update these constants after production deployment (Task 4.5)
BACKEND_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = f"{BACKEND_URL}/api/scans/upload"

logger = logging.getLogger(__name__)


def send_report_to_backend(report: dict, api_key: str | None) -> str | None:
    """
    POST a scan report dict to the backend.

    Returns the scan_id string on success, or None on any failure.
    Never raises — failures are logged as warnings only.
    """
    if not api_key:
        logger.info("No backend API key. Run 'basilisk auth' to save scans.")
        return None

    try:
        response = requests.post(
            UPLOAD_ENDPOINT,
            json=report,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=15,
        )

        if response.status_code == 401:
            logger.warning(
                "Backend rejected API key (401). Run 'basilisk auth' to re-authenticate."
            )
            return None

        if response.status_code in (200, 201):
            data = response.json()
            scan_id = data.get("scan_id")
            return str(scan_id) if scan_id else None

        logger.warning("Backend returned unexpected status %s.", response.status_code)
        return None

    except requests.exceptions.Timeout:
        logger.warning("Upload timed out — backend may be unreachable.")
        return None
    except requests.exceptions.ConnectionError:
        logger.warning("Could not connect to backend at %s.", BACKEND_URL)
        return None
    except requests.RequestException as exc:
        logger.warning("Upload failed: %s", exc)
        return None
