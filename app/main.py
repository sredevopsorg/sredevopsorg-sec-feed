"""FastAPI entry point for the security live-feed MVP."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import fetcher
from . import search as search_backend
from . import store
from .events import broker
from .sources import SOURCES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialise persistence and make sure there is always something to show,
    # even before the first live refresh finishes.
    await asyncio.to_thread(store.init_db)
    await asyncio.to_thread(store.seed_if_empty)

    # Warm/refresh the live cache in the background.
    asyncio.create_task(fetcher.refresh_feed())
    yield


app = FastAPI(title="Security Intelligence Live Feed", version="0.2.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    try:
        stats = await asyncio.to_thread(store.stats)
    except Exception:
        stats = {}
    return {
        "status": "ok",
        "cache_fetched_at": fetcher.CACHE.fetched_at.isoformat() if fetcher.CACHE.fetched_at else None,
        "db_total": stats.get("total"),
    }


@app.get("/api/feed")
async def api_feed(
    tag: str | None = Query(default=None, description="Filter by a single tag, e.g. kubernetes"),
    severity: str | None = Query(default=None, description="Filter by severity, e.g. critical"),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    # Make sure a refresh is scheduled if the cache is empty or stale.
    await fetcher.get_feed()

    items = await asyncio.to_thread(store.query_feed, tag, severity, limit)
    cache = fetcher.CACHE
    return {
        "generated_at": cache.generated_at.isoformat() if cache.generated_at else None,
        "fetched_at": cache.fetched_at.isoformat() if cache.fetched_at else None,
        "source_errors": cache.errors,
        "count": len(items),
        "items": items,
    }


@app.get("/api/items")
async def api_items(
    tag: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    """Search/filter the persistent archive (all stored items)."""
    items = await asyncio.to_thread(store.query_feed, tag, severity, limit)
    return {"count": len(items), "items": items}


@app.get("/api/stats")
async def api_stats() -> dict:
    return await asyncio.to_thread(store.stats)


@app.get("/api/search")
async def api_search(
    q: str = Query(default="", description="Search query"),
    tag: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Search the feed. Uses OpenSearch when configured, otherwise SQLite."""
    return await search_backend.search(q, tag, severity, limit)


@app.get("/api/events")
async def api_events() -> StreamingResponse:
    """Server-Sent Events stream that pushes feed updates to the browser."""

    async def event_stream():
        queue = broker.subscribe()
        try:
            # Confirm the stream is open immediately.
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            broker.unsubscribe(queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/sources")
async def api_sources() -> dict:
    return {
        "sources": [
            {"id": s.id, "name": s.name, "kind": s.kind, "url": s.url, "tags": sorted(s.tags)}
            for s in SOURCES
        ]
    }


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# Mount static assets (the SPA is a single file today; this keeps room for
# future CSS/JS/images).
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
