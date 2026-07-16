"""DOM link and form extraction."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


class DomParser:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.target_domain = urlparse(base_url).netloc

    def extract_links(self, html_content: str) -> list[str]:
        soup = BeautifulSoup(html_content, "html.parser")
        discovered: set[str] = set()
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            absolute = urljoin(self.base_url, href).split("#")[0]
            if urlparse(absolute).netloc == self.target_domain:
                discovered.add(absolute)
        return list(discovered)

    def extract_forms(self, html_content: str) -> list[dict]:
        soup = BeautifulSoup(html_content, "html.parser")
        forms: list[dict] = []
        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            form_url = urljoin(self.base_url, action)
            method = form.get("method", "get").lower()
            details = {"action_url": form_url, "method": method, "inputs": []}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                details["inputs"].append(
                    {
                        "name": name,
                        "type": tag.get("type", "text"),
                        "default_value": tag.get("value", ""),
                    }
                )
            forms.append(details)
        return forms
