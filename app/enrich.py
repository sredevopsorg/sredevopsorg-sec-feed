"""Optional enrichment: CISA KEV and FIRST EPSS.

Both enrichments are best-effort. Failures are logged and ignored so the feed
keeps working even when these services are unreachable.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

from . import http_client
from .config import settings
from .fetcher import FeedItem, _hash_item, _infer_tags, _strip_html, _truncate
from .sources import Source

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

_kev_cache: dict[str, dict] | None = None
_kev_fetched_at: float | None = None
KEV_TTL = 24 * 60 * 60  # seconds
# EPSS scores are requested in a single call; CVEs beyond this cap stay
# unscored rather than being chunked into extra requests.
EPSS_MAX_CVES = 100


async def _fetch_kev() -> dict[str, dict]:
    global _kev_cache, _kev_fetched_at
    now = time.time()
    if _kev_cache is not None and _kev_fetched_at and (now - _kev_fetched_at) < KEV_TTL:
        return _kev_cache
    async with http_client.client() as client:
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
    cves = sorted(set(cves))[:EPSS_MAX_CVES]
    async with http_client.client() as client:
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
        # Only report a score we actually received: a CVE EPSS does not know
        # (or an unavailable EPSS response) must stay ``None``, not 0.0.
        known_scores = [epss[cve] for cve in item.cves if cve in epss]
        item.epss_score = max(known_scores) if known_scores else None
        if item.kev:
            item.tags.add("exploit")
            item.tags.add("kev")
            if item.severity in ("critical", "high"):
                item.urgent = True
        if item.epss_score is not None and item.epss_score >= 0.5 and item.severity in ("critical", "high"):
            item.urgent = True
    return items


# ---------------------------------------------------------------------------
# KEV source: recently added known-exploited entries
# ---------------------------------------------------------------------------

_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
_NVD_LINK_RE = re.compile(r"https://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def _kev_reference(entry: dict) -> str:
    """Return the NVD detail URL for a KEV entry.

    KEV notes usually embed an NVD link; fall back to the canonical detail
    page so every item has a stable, actionable URL.
    """
    match = _NVD_LINK_RE.search(str(entry.get("notes") or ""))
    if match:
        return _NVD_DETAIL_URL.format(cve_id=match.group(1).upper())
    return _NVD_DETAIL_URL.format(cve_id=(entry.get("cveID") or "").upper())


def _kev_added_at(entry: dict) -> datetime | None:
    """Parse the catalog's `dateAdded` (YYYY-MM-DD) as a UTC datetime."""
    raw = str(entry.get("dateAdded") or "").strip()
    try:
        return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def fetch_recent_kev(source: Source) -> list[FeedItem]:
    """Publish KEV entries added to CISA's catalog recently as feed items.

    Enrichment only flags CVEs that another source already published; this
    source closes the gap for exploited CVEs no keyword feed mentions. Every
    item is `urgent` and carries the `kev` tag because CISA has confirmed
    exploitation in the wild.
    """
    catalog = await _fetch_kev()
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, settings.kev_source_days))
    recent: list[tuple[datetime, dict]] = []
    for entry in catalog.values():
        added = _kev_added_at(entry)
        if added is not None and added >= cutoff:
            recent.append((added, entry))
    recent.sort(key=lambda pair: pair[0], reverse=True)

    items: list[FeedItem] = []
    for added, entry in recent[: source.max_items]:
        cve_id = (entry.get("cveID") or "").upper()
        if not cve_id:
            continue
        name = (entry.get("vulnerabilityName") or "").strip()
        title = f"{cve_id}: {name}" if name else cve_id
        parts = [entry.get("shortDescription") or ""]
        if entry.get("requiredAction"):
            parts.append(f"Required action: {entry['requiredAction']}")
        summary = _truncate(_strip_html(" ".join(p for p in parts if p)))
        url = _kev_reference(entry)
        cves = [cve_id]
        tags = _infer_tags(f"{title} {summary}", source.tags | {"kev"}, cves)
        items.append(
            FeedItem(
                id=_hash_item(url, title),
                title=title,
                summary=summary,
                url=url,
                source=source.name,
                source_url=source.url,
                published=added,
                tags=tags,
                cves=cves,
                severity="unknown",
                urgent=True,
                kev=True,
            )
        )
    return items
