"""Search backend abstraction.

If OPENSEARCH_URL is configured, feed items are indexed into OpenSearch and
`/api/search` queries OpenSearch. Otherwise search falls back to SQLite LIKE
queries so the feature works with zero extra infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

from . import store
from .fetcher import FeedItem

logger = logging.getLogger(__name__)

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL")
INDEX_NAME = os.environ.get("OPENSEARCH_INDEX", "security-feed")

SEARCH_TIMEOUT = 8.0


async def index_items(items: list[FeedItem]) -> None:
    """Best-effort indexing into OpenSearch. No-op when OPENSEARCH_URL is unset."""
    if not OPENSEARCH_URL or not items:
        return
    bulk_lines: list[str] = []
    for item in items:
        bulk_lines.append(f'{{"index": {{"_index": "{INDEX_NAME}", "_id": "{item.id}"}}}}')
        doc = {
            "id": item.id,
            "title": item.title,
            "summary": item.summary,
            "source": item.source,
            "tags": sorted(item.tags),
            "cves": item.cves,
            "severity": item.severity,
            "urgent": item.urgent,
            "published": item.published.isoformat() if item.published else None,
        }
        bulk_lines.append(json_dumps(doc))
    if not bulk_lines:
        return
    payload = "\n".join(bulk_lines) + "\n"
    try:
        async with httpx.AsyncClient(timeout=SEARCH_TIMEOUT) as client:
            resp = await client.post(
                f"{OPENSEARCH_URL.rstrip('/')}/_bulk",
                content=payload,
                headers={"Content-Type": "application/x-ndjson"},
            )
            resp.raise_for_status()
            logger.info("Indexed %d items into OpenSearch", len(items))
    except Exception:
        logger.warning("OpenSearch indexing failed; continuing without it")


async def search(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50) -> dict[str, Any]:
    if OPENSEARCH_URL:
        try:
            return await _search_opensearch(q, tag, severity, limit)
        except Exception as exc:
            logger.warning("OpenSearch search failed, using SQLite fallback: %s", exc)
    items = await asyncio.to_thread(store.search_feed, q, tag, severity, limit)
    return {"backend": "sqlite", "count": len(items), "items": items}


async def _search_opensearch(q: str, tag: str | None, severity: str | None, limit: int) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    if q:
        must.append({"multi_match": {"query": q, "fields": ["title^3", "summary^2", "source", "cves"]}})
    else:
        must.append({"match_all": {}})
    filters: list[dict[str, Any]] = []
    if tag:
        filters.append({"term": {"tags": tag}})
    if severity:
        filters.append({"term": {"severity": severity}})

    body: dict[str, Any] = {
        "size": limit,
        "sort": [{"urgent": {"order": "desc"}}, {"published": {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": filters}},
    }
    async with httpx.AsyncClient(timeout=SEARCH_TIMEOUT) as client:
        resp = await client.post(f"{OPENSEARCH_URL.rstrip('/')}/{INDEX_NAME}/_search", json=body)
        resp.raise_for_status()
        data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    items = [h.get("_source", {}) for h in hits]
    return {"backend": "opensearch", "count": len(items), "items": items}


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, default=str)
