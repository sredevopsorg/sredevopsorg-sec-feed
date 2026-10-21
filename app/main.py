"""FastAPI entry point for the security live-feed API."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from . import VERSION, pipeline
from . import search as search_backend
from . import store
from .config import settings
from .events import broker
from .ratelimit import RateLimiter
from .sources import SOURCES

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

# /api/stats scans the archive; every container probe and dashboard refresh
# must not translate into a full-table aggregate. The cache is refreshed at
# most every 30 s, well below the 10 min feed refresh cadence.
STATS_CACHE_TTL = 30.0
_STATS_CACHE: tuple[float, dict] | None = None


async def _init_store() -> None:
    """Initialise/verify the store, retrying transient connectivity failures.

    A missing or stale schema (``SchemaNotMigrated``) must fail fast: starting
    the API against an unmigrated database would serve 500s until an operator
    notices. A database that is merely unreachable is retried briefly; if it is
    still down we log and start in degraded mode (``/ready`` reports not ready,
    and the pool reconnects when the database returns).
    """
    delay = 1.0
    for attempt in range(1, 6):
        try:
            await asyncio.to_thread(store.init_db)
            return
        except store.SchemaNotMigrated:
            raise
        except Exception:
            if attempt == 5:
                raise
            logger.warning(
                "Database init attempt %d/5 failed; retrying in %.0fs", attempt, delay
            )
            await asyncio.sleep(delay)
            delay *= 2


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await _init_store()
    except store.SchemaNotMigrated:
        raise
    except Exception:
        if not settings.database_url:
            raise
        logger.exception(
            "Database unavailable at startup; starting in degraded mode (readiness will fail)"
        )
    else:
        await asyncio.to_thread(store.seed_if_empty)

        # Backfill OpenSearch from the archive if configured (best-effort).
        try:
            await search_backend.ensure_index()
            await search_backend.sync_archive()
        except Exception:
            logger.exception("OpenSearch startup sync failed")

    # Warm/refresh the live cache in the background (single-flight).
    pipeline.schedule_refresh()
    try:
        yield
    finally:
        # Release pooled database connections on shutdown.
        await asyncio.to_thread(store.close)


app = FastAPI(title="Security Intelligence Live Feed API", version=VERSION, lifespan=lifespan)

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


@app.exception_handler(store.StoreUnavailable)
async def _database_unavailable(request: Request, exc: store.StoreUnavailable) -> JSONResponse:
    """Map a database outage to a retryable 503 instead of a 500 traceback."""
    logger.warning("Database unavailable: %s", exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "database unavailable"},
        headers={"Retry-After": "5"},
    )


@app.get("/health")
async def health() -> dict:
    """Liveness: must not touch the database.

    Container/Kubernetes liveness probes call this frequently; querying the
    archive here was the single most expensive statement in the database. Use
    ``/ready`` for the database check.
    """
    cache = pipeline.CACHE
    age = None
    if cache.fetched_at is not None:
        age = max(0, int((datetime.now(timezone.utc) - cache.fetched_at).total_seconds()))
    return {
        "status": "ok",
        "cache_fetched_at": cache.fetched_at.isoformat() if cache.fetched_at else None,
        "cache_age_seconds": age,
        "pipeline": cache.steps,
    }


@app.get("/ready")
async def ready():
    """Readiness: prove the store answers a cheap query within 2 seconds."""
    try:
        await asyncio.wait_for(asyncio.to_thread(store.ping), timeout=2.0)
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "db": "unavailable"},
            headers={"Retry-After": "5"},
        )
    return {"status": "ready", "db": "ok"}


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
    """Aggregate counts from the archive, cached for ``STATS_CACHE_TTL`` seconds."""
    global _STATS_CACHE
    now = time.monotonic()
    if _STATS_CACHE is not None and now - _STATS_CACHE[0] < STATS_CACHE_TTL:
        return _STATS_CACHE[1]
    data = await asyncio.to_thread(store.stats)
    _STATS_CACHE = (time.monotonic(), data)
    return data


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
            "/ready",
            "/api/feed",
            "/api/items",
            "/api/stats",
            "/api/search",
            "/api/events",
            "/api/sources",
        ],
    }
