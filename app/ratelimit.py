"""In-process, fixed-window request rate limiting.

Deliberately dependency-free (no ``slowapi``/``starlette-limiter``): the public
read endpoints are a small set and the limiter lives directly on the request
path. Known limitations, documented in the README:

- State is per process, so running N replicas allows up to N x the configured
  rate. A shared store (Redis, etc.) would be needed to coordinate across pods.
- It is a fixed window, not a sliding one: a client can burst up to
  ``max_requests`` at the very end of one window and again at the start of the
  next.
"""

from __future__ import annotations

import threading
import time
from collections import deque

# Keys whose newest hit has aged out are dropped once the map grows past this
# many entries, so a client rotating its key cannot grow memory without bound.
_PRUNE_THRESHOLD = 4096


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """False when the limiter is configured off (``max_requests <= 0``)."""
        return self.max_requests > 0

    def check(self, key: str, now: float | None = None) -> bool:
        """Record a hit for ``key``; return True while it is under the limit."""
        if not self.enabled:
            return True
        timestamp = time.monotonic() if now is None else now
        cutoff = timestamp - self.window_seconds
        with self._lock:
            if len(self._hits) > _PRUNE_THRESHOLD:
                self._prune(cutoff)
            hits = self._hits.get(key)
            if hits is None:
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(timestamp)
            return True

    def _prune(self, cutoff: float) -> None:
        """Drop keys with no hits inside the current window (lock held)."""
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in stale:
            del self._hits[key]
