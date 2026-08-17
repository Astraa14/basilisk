"""User-Agent rotation to avoid bot detection.

Provides: a pool of common browser User-Agent strings, rotation logic,
and the ability to inject rotated User-Agents into HTTP requests.
"""

from __future__ import annotations

import random
from typing import Any, List, Optional

from basilisk.http import RequestEngine

USER_AGENT_POOL: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 "
    "Firefox/121.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:121.0) Gecko/20100101 "
    "Firefox/121.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # Android
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]


def get_random_user_agent() -> str:
    """Return a random User-Agent string from the pool."""
    return random.choice(USER_AGENT_POOL)


def rotate_user_agent(
    engine: RequestEngine,
    pool_size: int | None = None,
) -> None:
    """Rotate the User-Agent on the given engine instance.

    Args:
        engine: The RequestEngine to rotate the User-Agent on.
        pool_size: Number of User-Agents to use from the pool. Defaults to
            the full pool size.
    """
    if pool_size is None:
        pool_size = len(USER_AGENT_POOL)
    pool_size = min(pool_size, len(USER_AGENT_POOL))
    ua = random.sample(USER_AGENT_POOL, pool_size)
    # Set a random User-Agent from the pool
    engine.session.headers.update({"User-Agent": random.choice(ua)})


def set_user_agent_pool(
    new_pool: list[str],
) -> None:
    """Replace the default User-Agent pool with a custom one."""
    global USER_AGENT_POOL
    USER_AGENT_POOL = new_pool