"""OpenAI-compatible LLM client for Generator and Judge roles (HackAgent-style)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import requests

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

DEFAULT_CLOUD_BASE = "https://api.openai.com/v1"
DEFAULT_OLLAMA_BASE = "http://localhost:11434/v1"
DEFAULT_CLOUD_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL = "llama3.2"


class LLMError(RuntimeError):
    """Raised when LLM configuration or API calls fail."""


def load_llm_env(dotenv_path: str | Path | None = None) -> None:
    """Load `.env` from cwd without overriding existing env."""
    if load_dotenv is None:
        return
    if dotenv_path:
        load_dotenv(dotenv_path, override=False)
        return
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env, override=False)
    else:
        load_dotenv(override=False)


def ollama_available(timeout: float = 1.5) -> bool:
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False


def resolve_llm_settings(
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> dict[str, str]:
    """
    Resolve backend like HackAgent:
    - Prefer explicit / .env cloud credentials
    - Else fall back to local Ollama (no paid key)
    """
    load_llm_env()
    key = (api_key if api_key is not None else os.getenv("BASILISK_LLM_API_KEY", "")).strip()
    base = (base_url or os.getenv("BASILISK_LLM_BASE_URL", "")).strip().rstrip("/")
    mdl = (model or os.getenv("BASILISK_LLM_MODEL", "")).strip()

    if key and key.lower() != "ollama":
        return {
            "api_key": key,
            "base_url": base or DEFAULT_CLOUD_BASE,
            "model": mdl or DEFAULT_CLOUD_MODEL,
            "backend": "cloud",
        }

    if base and "11434" in base:
        return {
            "api_key": key or "ollama",
            "base_url": base,
            "model": mdl or DEFAULT_OLLAMA_MODEL,
            "backend": "ollama",
        }

    if ollama_available():
        return {
            "api_key": "ollama",
            "base_url": DEFAULT_OLLAMA_BASE,
            "model": mdl or DEFAULT_OLLAMA_MODEL,
            "backend": "ollama",
        }

    if key:  # placeholder "ollama" without server
        return {
            "api_key": key,
            "base_url": base or DEFAULT_OLLAMA_BASE,
            "model": mdl or DEFAULT_OLLAMA_MODEL,
            "backend": "ollama",
        }

    return {"api_key": "", "base_url": "", "model": "", "backend": "none"}


def llm_configured(api_key: str | None = None) -> bool:
    settings = resolve_llm_settings(api_key=api_key)
    return settings["backend"] != "none"


class LLMClient:
    """Chat-completions client used by Generator and Judge roles."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 90,
    ):
        settings = resolve_llm_settings(api_key=api_key, base_url=base_url, model=model)
        self.api_key = settings["api_key"]
        self.base_url = settings["base_url"].rstrip("/")
        self.model = settings["model"]
        self.backend = settings["backend"]
        self.timeout = timeout

    def require_configured(self) -> None:
        if self.backend == "none" or not self.base_url:
            raise LLMError(
                "No LLM backend available. Either:\n"
                "  1) Set BASILISK_LLM_API_KEY in .env (cloud OpenAI-compatible), or\n"
                "  2) Run Ollama locally (http://localhost:11434) like HackAgent's default."
            )

    def chat(self, system: str, user: str, temperature: float = 0.4) -> str:
        self.require_configured()
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key or 'ollama'}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except requests.RequestException as exc:
            raise LLMError(f"LLM request failed ({self.backend}): {exc}") from exc
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected LLM response shape: {exc}") from exc

    def chat_json(self, system: str, user: str, temperature: float = 0.2) -> Any:
        text = self.chat(system, user, temperature=temperature)
        return _parse_json_content(text)


def _parse_json_content(text: str) -> Any:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"[\[{][\s\S]*[\]}]", text)
        if match:
            return json.loads(match.group(0))
        raise LLMError(f"Could not parse LLM JSON: {text[:200]}")
