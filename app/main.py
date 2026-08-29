"""FastAPI entry point for the security live-feed MVP."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .fetcher import CACHE, get_feed, item_to_dict, refresh_feed
from .sources import SOURCES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    # Warm the cache in the background so the first page load is fast.
    asyncio.create_task(refresh_feed())
    yield


app = FastAPI(title="Security Intelligence Live Feed", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "cache_fetched_at": CACHE.fetched_at.isoformat() if CACHE.fetched_at else None}


@app.get("/api/feed")
async def api_feed(
    tag: str | None = Query(default=None, description="Filter by a single tag, e.g. kubernetes"),
    severity: str | None = Query(default=None, description="Filter by severity, e.g. critical"),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    cache = await get_feed()
    items = [item_to_dict(item) for item in cache.items]
    if tag:
        items = [i for i in items if tag in i["tags"]]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    items = items[:limit]
    return {
        "generated_at": cache.generated_at.isoformat() if cache.generated_at else None,
        "fetched_at": cache.fetched_at.isoformat() if cache.fetched_at else None,
        "source_errors": cache.errors,
        "count": len(items),
        "items": items,
    }


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
