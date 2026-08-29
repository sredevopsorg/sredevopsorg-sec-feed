"""Tiny pub/sub broker for Server-Sent Events."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class Broker:
    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=16)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self.subscribers.discard(q)

    async def publish(self, event: dict[str, Any]) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the event for slow consumers rather than blocking.
                logger.debug("SSE subscriber queue full; dropping event")
                continue


broker = Broker()
