"""Search backend abstraction.

If OPENSEARCH_URL is configured, feed items are indexed into OpenSearch and
`/api/search` queries OpenSearch. Otherwise search falls back to SQL (Postgres
ILIKE or SQLite LIKE) so the feature works with zero extra infrastructure.

When OpenSearch is enabled the index is kept in sync automatically:

- ``ensure_index()`` creates the index with an explicit mapping (idempotent),
  so ``severity``/``tags``/``cves`` are keyword fields, ``urgent``/``kev`` are
  booleans and ``published`` is a date.
- ``index_items()`` incrementally indexes each refresh's items.
- ``sync_archive()`` backfills/reconciles the full archive from the store.

All OpenSearch operations are best-effort: a down or misconfigured OpenSearch
never breaks the feed or the SQL fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import store
from .fetcher import FeedItem, _ensure_aware, _time_ago, item_to_dict

logger = logging.getLogger(__name__)

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL")
INDEX_NAME = os.environ.get("OPENSEARCH_INDEX", "security-feed")

SEARCH_TIMEOUT = 8.0
SYNC_INTERVAL = 30 * 60  # seconds between full archive reconciles
_last_sync_at: float | None = None


def _index_mappings() -> dict[str, Any]:
    """Return the explicit index settings/mappings used for the feed index."""
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "title": {"type": "text"},
                "summary": {"type": "text"},
                "url": {"type": "keyword"},
                "source": {"type": "keyword"},
                "source_url": {"type": "keyword"},
                "published": {"type": "date"},
                "tags": {"type": "keyword"},
                "cves": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "urgent": {"type": "boolean"},
                "kev": {"type": "boolean"},
                "epss_score": {"type": "float"},
                "is_sample": {"type": "boolean"},
                "patch_status": {"type": "keyword"},
                "osv_affected": {"type": "keyword"},
                "osv_fixed": {"type": "keyword"},
                "osv_severity": {"type": "keyword"},
            }
        },
    }


async def ensure_index() -> None:
    """Create the feed index with its mapping if it does not exist yet."""
    if not OPENSEARCH_URL:
        return
    base = OPENSEARCH_URL.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=SEARCH_TIMEOUT) as client:
            exists = await client.head(f"{base}/{INDEX_NAME}")
            if exists.status_code == 200:
                return
            resp = await client.put(f"{base}/{INDEX_NAME}", json=_index_mappings())
            resp.raise_for_status()
            logger.info("Created OpenSearch index %s", INDEX_NAME)
    except Exception:
        logger.warning("Could not create OpenSearch index; continuing without it")


def _doc_from_item(item: FeedItem) -> dict[str, Any]:
    """Build the indexed document for a feed item (API shape minus time_ago)."""
    doc = item_to_dict(item)
    doc.pop("time_ago", None)
    return doc


def _hit_to_item(source: dict[str, Any]) -> dict[str, Any]:
    """Normalize an OpenSearch hit so it matches the /api/feed contract."""
    item = dict(source)
    item.setdefault("tags", [])
    item.setdefault("cves", [])
    item["time_ago"] = ""
    published_raw = item.get("published")
    if isinstance(published_raw, str):
        try:
            published = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
            seconds = max(0, int((datetime.now(timezone.utc) - _ensure_aware(published)).total_seconds()))
            item["time_ago"] = _time_ago(seconds)
        except Exception:
            pass
    return item


async def _bulk(docs: list[dict[str, Any]]) -> int:
    if not docs:
        return 0
    bulk_lines: list[str] = []
    for doc in docs:
        bulk_lines.append(f'{{"index": {{"_index": "{INDEX_NAME}", "_id": "{doc["id"]}"}}}}')
        bulk_lines.append(json_dumps(doc))
    payload = "\n".join(bulk_lines) + "\n"
    async with httpx.AsyncClient(timeout=SEARCH_TIMEOUT) as client:
        resp = await client.post(
            f"{OPENSEARCH_URL.rstrip('/')}/_bulk",
            content=payload,
            headers={"Content-Type": "application/x-ndjson"},
        )
        resp.raise_for_status()
    return len(docs)


async def index_items(items: list[FeedItem]) -> int:
    """Index the current refresh's items, excluding fallback/sample rows."""
    if not OPENSEARCH_URL:
        return 0
    docs = [_doc_from_item(item) for item in items if not item.is_sample]
    try:
        return await _bulk(docs)
    except Exception:
        logger.warning("OpenSearch indexing failed; continuing without it")
        return 0


async def sync_archive(limit: int = 10000) -> int:
    """Backfill/reconcile the index from the persistent archive."""
    if not OPENSEARCH_URL:
        return 0
    try:
        items = await asyncio.to_thread(store.query_feed, None, None, limit)
    except Exception:
        logger.warning("Could not read archive for OpenSearch sync")
        return 0
    docs = [{k: v for k, v in item.items() if k != "time_ago"} for item in items]
    try:
        return await _bulk(docs)
    except Exception:
        logger.warning("OpenSearch archive sync failed; continuing")
        return 0


async def maybe_sync_archive(force: bool = False) -> int:
    """Run a full archive sync, throttled to SYNC_INTERVAL unless forced."""
    global _last_sync_at
    if not OPENSEARCH_URL:
        return 0
    now = time.time()
    if not force and _last_sync_at is not None and (now - _last_sync_at) < SYNC_INTERVAL:
        return 0
    count = await sync_archive()
    if count:
        _last_sync_at = now
    return count


async def search(q: str, tag: str | None = None, severity: str | None = None, limit: int = 50) -> dict[str, Any]:
    if OPENSEARCH_URL:
        try:
            return await _search_opensearch(q, tag, severity, limit)
        except Exception as exc:
            logger.warning("OpenSearch search failed, using SQL fallback: %s", exc)
    items = await asyncio.to_thread(store.search_feed, q, tag, severity, limit)
    return {"backend": "sql", "count": len(items), "items": items}


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
    items = [_hit_to_item(h.get("_source", {})) for h in hits]
    return {"backend": "opensearch", "count": len(items), "items": items}


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, default=str)
