"""Load bundled and custom payload datasets."""

from __future__ import annotations

import json
from pathlib import Path

DATASETS_DIR = Path(__file__).resolve().parent


def load_json_payloads(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [str(item) for item in data if str(item).strip()]
    if isinstance(data, dict):
        payloads: list[str] = []
        for value in data.values():
            if isinstance(value, list):
                payloads.extend(str(item) for item in value if str(item).strip())
            elif isinstance(value, str) and value.strip():
                payloads.append(value)
        return payloads
    raise ValueError(f"Unsupported dataset format in {path}")


def load_bundled(name: str) -> list[str]:
    path = DATASETS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Bundled dataset not found: {path}")
    return load_json_payloads(path)


def load_custom(path: str | Path) -> list[str]:
    return load_json_payloads(Path(path))
