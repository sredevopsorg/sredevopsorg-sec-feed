"""FastAPI entry point for the security live-feed API."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from . import pipeline
from . import search as search_backend
from . import store
from .config import settings
from .events import broker
from .ratelimit import RateLimiter
from .sources import SOURCES

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        # Initialise persistence and make sure there is always something to show,
        # even before the first live refresh finishes.
        await asyncio.to_thread(store.init_db)
        await asyncio.to_thread(store.seed_if_empty)

        # Backfill OpenSearch from the archive if configured (best-effort).
        try:
            await search_backend.ensure_index()
            await search_backend.sync_archive()
        except Exception:
            logger.exception("OpenSearch startup sync failed")

        # Warm/refresh the live cache in the background (single-flight).
        pipeline.schedule_refresh()
        yield
    finally:
        # Release pooled database connections on shutdown.
        await asyncio.to_thread(store.close)


app = FastAPI(title="Security Intelligence Live Feed API", version="0.2.0-rc.1", lifespan=lifespan)

# CORS fails closed: with CORS_ORIGINS unset the allow-list is empty, so no
# cross-origin caller is allowed. The bundled frontend is same-origin (nginx
# reverse-proxies /api), so this default is transparent. Set CORS_ORIGINS to a
# comma-separated allow-list only when hosting the frontend on another origin.
if "*" in settings.cors_origins:
    logger.warning(
        "CORS_ORIGINS is set to '*': any origin may call this API. Use an explicit "
        "allow-list in production, or leave CORS_ORIGINS unset to deny cross-origin."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting for the public read endpoints that can be abused cheaply
# (/api/search) or held open (/api/events). See app/ratelimit.py for the
# per-process caveat.
RATE_LIMITER = RateLimiter(settings.rate_limit_per_minute)


def _client_key(request: Request) -> str:
    """Best-effort client identity for rate limiting.

    With the bundled nginx in front, the *last* X-Forwarded-For hop is the
    address nginx accepted the connection from (it appends ``$remote_addr``),
    so a client cannot forge it. Set RATE_LIMIT_TRUST_PROXY=false when this API
    is reachable directly, so the socket peer is used instead.
    """
    if settings.rate_limit_trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
            if hops:
                return hops[-1]
    return request.client.host if request.client else "unknown"


def _rate_limit(request: Request) -> None:
    """FastAPI dependency enforcing the per-client rate limit."""
    if not RATE_LIMITER.check(_client_key(request)):
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(int(RATE_LIMITER.window_seconds))},
        )


@app.get("/health")
async def health() -> dict:
    try:
        stats = await asyncio.to_thread(store.stats)
    except Exception:
        stats = {}
    return {
        "status": "ok",
        "cache_fetched_at": pipeline.CACHE.fetched_at.isoformat() if pipeline.CACHE.fetched_at else None,
        "db_total": stats.get("total"),
    }


@app.get("/api/feed")
async def api_feed(
    tag: str | None = Query(default=None, description="Filter by a single tag, e.g. kubernetes"),
    severity: str | None = Query(default=None, description="Filter by severity, e.g. critical"),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    # Make sure a refresh is scheduled if the cache is empty or stale.
    await pipeline.get_feed()

    items = await asyncio.to_thread(store.query_feed, tag, severity, limit)
    cache = pipeline.CACHE
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


@app.get("/api/search", dependencies=[Depends(_rate_limit)])
async def api_search(
    q: str = Query(default="", description="Search query"),
    tag: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Search the feed. Uses OpenSearch when configured, otherwise SQLite."""
    return await search_backend.search(q, tag, severity, limit)


@app.get("/api/events", dependencies=[Depends(_rate_limit)])
async def api_events() -> StreamingResponse:
    """Server-Sent Events stream that pushes feed updates to the browser."""

    # Subscribe before the response starts so a full broker can be rejected
    # with a real error status instead of an empty stream.
    queue = broker.subscribe()
    if queue is None:
        raise HTTPException(
            status_code=503,
            detail="Too many event subscribers",
            headers={"Retry-After": "30"},
        )

    async def event_stream():
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


@app.get("/api")
async def api_index() -> dict:
    """Service descriptor listing the available endpoints."""
    return {
        "name": app.title,
        "version": app.version,
        "endpoints": [
            "/health",
            "/api/feed",
            "/api/items",
            "/api/stats",
            "/api/search",
            "/api/events",
            "/api/sources",
        ],
    }
