"""HTTP Target — submit attacks against a live web application."""

from __future__ import annotations

from urllib.parse import urljoin

from basilisk.http import RequestEngine

TEXT_TYPES = {"text", "search", "textarea", "email", "password", "url"}


class WebTarget:
    """Wraps RequestEngine as the HackAgent-style Target role."""

    def __init__(self, requester: RequestEngine | None = None, timeout: float = 5):
        self.requester = requester or RequestEngine(timeout=timeout)

    def get(self, url: str) -> dict | None:
        return self.requester.send("GET", url)

    def submit_form(self, form_details: dict, payload: str) -> dict | None:
        action_url = form_details["action_url"]
        method = form_details["method"].upper()
        data = self.build_form_data(form_details.get("inputs", []), payload)
        if method == "POST":
            return self.requester.send("POST", action_url, data=data)
        return self.requester.send("GET", action_url, params=data)

    def submit_login(self, base_url: str, login_endpoint: str, payload: str) -> dict | None:
        full_url = urljoin(base_url.rstrip("/") + "/", login_endpoint.lstrip("/"))
        data = {"username": payload, "password": "wrong_password"}
        return self.requester.send("POST", full_url, data=data)

    @staticmethod
    def build_form_data(inputs: list[dict], payload: str) -> dict:
        data: dict = {}
        for inp in inputs:
            if inp.get("type") in TEXT_TYPES:
                data[inp["name"]] = payload
            else:
                data[inp["name"]] = inp.get("default_value", "")
        return data
