"""Single outbound HTTP policy for every external call.

AGENTS invariant 5: all HTTP calls keep the shared USER_AGENT and a bounded
timeout. This module is the only place that constructs an httpx client;
tests/test_http.py asserts that.
"""

from __future__ import annotations

from typing import Any

import httpx

# Kept verbatim: upstream sources recognise this agent string, so changing it
# is a deliberate decision rather than a refactoring side effect.
USER_AGENT = "security-live-feed-mvp/0.1 (+contact: security-team@example.com)"
HTTP_TIMEOUT = 8.0


def client(
    *,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Return an httpx client carrying the shared user agent and timeout.

    Extra headers are merged over the user agent (e.g. GitHub's Accept
    header), and follow_redirects defaults to True because every caller wants it.
    """
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    kwargs.setdefault("follow_redirects", True)
    return httpx.AsyncClient(
        timeout=HTTP_TIMEOUT if timeout is None else timeout,
        headers=merged,
        **kwargs,
    )