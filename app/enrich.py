"""Optional enrichment: CISA KEV and FIRST EPSS.

Both enrichments are best-effort. Failures are logged and ignored so the feed
keeps working even when these services are unreachable.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import httpx

from .fetcher import FeedItem

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

_kev_cache: dict[str, dict] | None = None
_kev_fetched_at: float | None = None
KEV_TTL = 24 * 60 * 60  # seconds
EPSS_BATCH = 100


async def _fetch_kev() -> dict[str, dict]:
    global _kev_cache, _kev_fetched_at
    now = time.time()
    if _kev_cache is not None and _kev_fetched_at and (now - _kev_fetched_at) < KEV_TTL:
        return _kev_cache
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    _kev_cache = {v.get("cveID", "").upper(): v for v in vulns if v.get("cveID")}
    _kev_fetched_at = now
    logger.info("KEV cache refreshed with %d entries", len(_kev_cache))
    return _kev_cache


async def _fetch_epss(cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    cves = sorted(set(cves))[:EPSS_BATCH]
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        resp = await client.get(EPSS_URL, params={"cve": ",".join(cves)})
        resp.raise_for_status()
        data = resp.json()
    out: dict[str, float] = {}
    for row in data.get("data", []):
        cve = (row.get("cve") or "").upper()
        epss = row.get("epss")
        if cve and isinstance(epss, (int, float)):
            out[cve] = float(epss)
    return out


async def enrich_items(items: list[FeedItem]) -> list[FeedItem]:
    """Add KEV and EPSS context to items, mutating and returning them."""
    cves = sorted({cve for item in items for cve in item.cves})
    if not cves:
        return items

    kev: dict[str, dict] = {}
    epss: dict[str, float] = {}
    try:
        kev = await _fetch_kev()
    except Exception as exc:
        logger.warning("KEV enrichment unavailable: %s", exc)
    try:
        epss = await _fetch_epss(cves)
    except Exception as exc:
        logger.warning("EPSS enrichment unavailable: %s", exc)

    for item in items:
        item.kev = any(cve in kev for cve in item.cves)
        item.epss_score = max((epss.get(cve, 0.0) for cve in item.cves), default=None)
        if item.kev:
            item.tags.add("exploit")
            item.tags.add("kev")
            if item.severity in ("critical", "high"):
                item.urgent = True
        if item.epss_score is not None and item.epss_score >= 0.5 and item.severity in ("critical", "high"):
            item.urgent = True
    return items
