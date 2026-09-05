"""Feed refresh pipeline/orchestrator (ADR-0004).

Owns the cached feed and the background refresh. The pipeline is a small,
one-way sequence of best-effort steps:

    fetch -> enrich -> persist -> index -> publish -> alert
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import alerts
from . import fetcher
from . import search
from . import store
from .enrich import enrich_items
from .events import broker
from .models import FeedItem
from .osv import enrich_with_osv

logger = logging.getLogger(__name__)

CACHE_TTL = 600  # seconds


@dataclass
class FeedCache:
    items: list[FeedItem] = field(default_factory=list)
    fetched_at: datetime | None = None
    generated_at: datetime | None = None
    errors: list[str] = field(default_factory=list)


CACHE = FeedCache()
CACHE_LOCK = asyncio.Lock()


async def _enrich(items: list[FeedItem]) -> list[FeedItem]:
    """Best-effort enrichment: CISA KEV + FIRST EPSS, then OSV.dev."""
    try:
        items = await enrich_items(items)
    except Exception:
        logger.exception("Unexpected enrichment error; continuing with raw items")
    try:
        items = await enrich_with_osv(items)
    except Exception:
        logger.exception("Unexpected OSV enrichment error; continuing")
    return items


def _persist(items: list[FeedItem]) -> None:
    """Persist items to the store (blocking; run in a worker thread)."""
    store.upsert_items(items)


async def _index(items: list[FeedItem]) -> None:
    """Best-effort OpenSearch indexing: ensure index, index items, reconcile."""
    await search.ensure_index()
    await search.index_items(items)
    await search.maybe_sync_archive()


async def _publish(generated_at: datetime, count: int) -> None:
    await broker.publish(
        {
            "type": "feed_updated",
            "generated_at": generated_at.isoformat(),
            "count": count,
        }
    )


async def _alert() -> None:
    alerted = await alerts.send_urgent_alerts()
    if alerted:
        logger.info("Sent %d urgent alert(s)", len(alerted))


async def refresh_feed() -> list[FeedItem]:
    """Run the full pipeline and rebuild the cached feed."""
    global CACHE
    async with CACHE_LOCK:
        items, errors = await fetcher.fetch_all()
        items = await _enrich(items)

        now = datetime.now(timezone.utc)
        CACHE = FeedCache(items=items, fetched_at=now, generated_at=now, errors=errors)

        # Each downstream step is best-effort: a failure never breaks the feed.
        try:
            await asyncio.to_thread(_persist, items)
        except Exception:
            logger.exception("Failed to persist feed items")

        try:
            await _index(items)
        except Exception:
            logger.exception("Search indexing failed")

        try:
            await _publish(CACHE.generated_at, len(items))
        except Exception:
            logger.exception("Event publishing failed")

        try:
            await _alert()
        except Exception:
            logger.exception("Alerting failed")

        return CACHE.items


async def get_feed(limit: int = 50) -> FeedCache:
    """Return a cached feed. Refresh synchronously if this is the first call."""
    if CACHE.generated_at is None:
        await refresh_feed()
    if CACHE.fetched_at is None or (datetime.now(timezone.utc) - CACHE.fetched_at).total_seconds() > CACHE_TTL:
        # Best-effort background refresh; do not block the response.
        asyncio.create_task(refresh_feed())
    return CACHE
