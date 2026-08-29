"""OSV.dev enrichment.

Best-effort: for every CVE in the feed (up to a per-run cap) we fetch the
OSV.dev record and extract affected packages, fixed versions, and severity.
Failures are logged and ignored so the feed never breaks.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .fetcher import FeedItem, _ensure_aware

logger = logging.getLogger(__name__)

OSV_URL = "https://api.osv.dev/v1/vulns/{cve}"
CACHE_TTL = 24 * 60 * 60
MAX_CVES_PER_RUN = 25
MAX_CONCURRENCY = 5

_osv_cache: dict[str, dict[str, Any]] = {}
_osv_cache_time: dict[str, float] = {}


def parse_osv(data: dict[str, Any]) -> dict[str, Any]:
    """Extract the fields we care about from an OSV.dev response."""
    affected_packages: list[str] = []
    fixed_versions: list[str] = []
    for affected in data.get("affected") or []:
        pkg = affected.get("package") or {}
        name = pkg.get("name")
        ecosystem = pkg.get("ecosystem") or "unknown"
        if name:
            affected_packages.append(f"{ecosystem}:{name}")
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed_versions.append(event["fixed"])

    # Keep only version-looking fixed values (e.g. 1.1.12, 6.18.47); OSV
    # often includes commit hashes in the same event list.
    fixed_versions = [v for v in fixed_versions if re.match(r"^v?\d+(\.\d+)+", v)]

    severity = None
    db_specific = data.get("database_specific") or {}
    if isinstance(db_specific, dict):
        severity = db_specific.get("severity")

    return {
        "summary": data.get("summary"),
        "details": data.get("details"),
        "aliases": data.get("aliases") or [],
        "affected_packages": sorted(set(affected_packages))[:5],
        "fixed_versions": sorted(set(fixed_versions))[:5],
        "severity": severity.lower() if isinstance(severity, str) else None,
        "patch_available": bool(fixed_versions),
    }


async def _fetch_one(cve: str, client: httpx.AsyncClient) -> tuple[str, dict[str, Any] | None]:
    now = time.time()
    cached = _osv_cache.get(cve)
    if cached is not None and (now - _osv_cache_time.get(cve, 0)) < CACHE_TTL:
        return cve, cached
    resp = await client.get(OSV_URL.format(cve=cve))
    if resp.status_code == 404:
        _osv_cache[cve] = {}
        _osv_cache_time[cve] = now
        return cve, {}
    resp.raise_for_status()
    parsed = parse_osv(resp.json())
    _osv_cache[cve] = parsed
    _osv_cache_time[cve] = now
    return cve, parsed


async def fetch_osv(cves: list[str], max_cves: int = MAX_CVES_PER_RUN) -> dict[str, dict[str, Any]]:
    # Deduplicate while preserving caller priority (urgent/recent first).
    cves = list(dict.fromkeys(cves))[:max_cves]
    if not cves:
        return {}
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:

        async def guarded(cve: str) -> tuple[str, dict[str, Any] | None]:
            async with sem:
                try:
                    return await _fetch_one(cve, client)
                except Exception as exc:
                    logger.warning("OSV fetch failed for %s: %s", cve, exc)
                    return cve, None

        results = await asyncio.gather(*(guarded(cve) for cve in cves))
    return {cve: data for cve, data in results if data}


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


async def enrich_with_osv(items: list[FeedItem]) -> list[FeedItem]:
    # Fetch OSV for CVEs that matter most first: urgent/high severity and
    # recent items, then the rest. This keeps the cap useful.
    ordered = sorted(
        items,
        key=lambda item: (
            1 if item.urgent else 0,
            SEVERITY_ORDER.get(item.severity, 0),
            _ensure_aware(item.published) if item.published else datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    cves: list[str] = []
    for item in ordered:
        for cve in item.cves:
            if cve not in cves:
                cves.append(cve)
    if not cves:
        return items
    osv = await fetch_osv(cves)
    for item in items:
        for cve in item.cves:
            data = osv.get(cve)
            if not data:
                continue
            if not item.summary and data.get("summary"):
                item.summary = data["summary"]
            item.osv_affected = sorted(set(item.osv_affected) | set(data.get("affected_packages", [])))
            item.osv_fixed = sorted(set(item.osv_fixed) | set(data.get("fixed_versions", [])))
            if item.severity == "unknown" and data.get("severity") in ("critical", "high", "medium", "low"):
                item.osv_severity = data["severity"]
                item.severity = data["severity"]
            if data.get("patch_available"):
                item.tags.add("patch")
    return items
