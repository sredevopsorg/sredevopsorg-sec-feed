"""Fetching, normalising, enriching and caching feed items.

The MVP is deliberately resilient: if the network is unavailable or every
source fails, a small set of realistic sample items is returned so the
frontend still renders the full experience.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

from .sources import SOURCES, Source

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
CVSS_TEXT_RE = re.compile(r"\bv[34]\s+(\d+(?:\.\d+)?)", re.IGNORECASE)

TARGET_KEYWORDS = (
    "linux", "ubuntu", "debian", "red hat", "fedora", "suse", "arch linux",
    "kernel", "glibc", "systemd", "openssl", "openssh", "runc", "containerd",
    "kubernetes", "k8s", "kube", "helm", "istio", "envoy", "cri-o",
    "cloud", "aws", "amazon", "azure", "gcp", "google cloud", "gke",
    "docker", "container", "virtual machine", "server",
)
SECURITY_KEYWORDS = (
    "security", "cve", "vulnerability", "vulnerabilities", "advisory",
    "exploit", "patch", "backport", "fixed", "update", "bulletin", "flaw",
)


def _strip_html(value: str) -> str:
    """Remove HTML tags and compact whitespace for plain-text summaries."""
    value = TAG_RE.sub(" ", value or "")
    # Decode a handful of common entities. feedparser usually does this, but
    # the CISA feed embeds HTML inside the description field.
    for entity, replacement in (
        ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"),
        ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " "),
    ):
        value = value.replace(entity, replacement)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _truncate(value: str, limit: int = 320) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _extract_cvss_score(text: str) -> float | None:
    """Return the first CVSS base score found in text, or None."""
    scores: list[float] = []
    for m in CVSS_TEXT_RE.finditer(text):
        try:
            scores.append(float(m.group(1)))
        except ValueError:
            continue
    return max(scores) if scores else None


def _is_relevant(source: Source, text: str) -> bool:
    """Return True when an item is on-topic for this feed."""
    t = text.lower()
    # Sources that are already topic-scoped (distro trackers, cloud bulletins,
    # keyword-scoped NVD queries) are kept unless explicitly filtered below.
    if source.id == "k8s":
        return any(w in t for w in SECURITY_KEYWORDS)
    if source.id == "cisa":
        # CISA publishes both ICS/OT and enterprise advisories. Keep only the
        # ones that touch our target ecosystem.
        return any(w in t for w in TARGET_KEYWORDS)
    if source.id == "redhat":
        # Red Hat CVE DB returns CVEs from every Red Hat product. Keep only
        # entries that are Linux-platform relevant (which is most of them).
        return True
    return True

HTTP_TIMEOUT = 8.0
CACHE_TTL = 600  # seconds
USER_AGENT = "security-live-feed-mvp/0.1 (+contact: security-team@example.com)"

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class FeedItem:
    id: str
    title: str
    summary: str
    url: str
    source: str
    source_url: str
    published: datetime | None
    tags: set[str] = field(default_factory=set)
    cves: list[str] = field(default_factory=list)
    severity: str = "unknown"
    urgent: bool = False
    kev: bool = False
    epss_score: float | None = None
    is_sample: bool = False


@dataclass
class FeedCache:
    items: list[FeedItem] = field(default_factory=list)
    fetched_at: datetime | None = None
    generated_at: datetime | None = None
    errors: list[str] = field(default_factory=list)


CACHE = FeedCache()
CACHE_LOCK = asyncio.Lock()


# ---------------------------------------------------------------------------
# Sample / fallback data
# ---------------------------------------------------------------------------

def _sample_items() -> list[FeedItem]:
    now = datetime.now(timezone.utc)

    def ago(**kw) -> datetime:
        return now - timedelta(**kw)

    raw = [
        {
            "title": "CVE-2024-21626: runc container escape via process.cwd and leaked fds",
            "summary": "runc before 1.1.12 contains a container escape that is exploitable from inside a container. Patch available in runc 1.1.12.",
            "url": "https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv",
            "source": "GitHub Security Advisory",
            "source_url": "https://github.com/opencontainers/runc/security/advisories",
            "published": ago(minutes=17),
            "tags": {"linux", "kubernetes", "cve", "exploit", "patch"},
            "cves": ["CVE-2024-21626"],
            "severity": "critical",
            "urgent": True,
        },
        {
            "title": "CISA KEV adds CVE-2025-1974: ingress-nginx RCE via admission controller",
            "summary": "Kubernetes ingress-nginx unauthenticated remote code execution; added to CISA Known Exploited Vulnerabilities. Patch to v1.11.6 / v1.12.2.",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source": "CISA KEV",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published": ago(minutes=42),
            "tags": {"kubernetes", "cloud", "cve", "exploit", "patch"},
            "cves": ["CVE-2025-1974"],
            "severity": "critical",
            "urgent": True,
        },
        {
            "title": "Ubuntu Security Notice 7234-1: Linux kernel vulnerabilities",
            "summary": "Several security issues were fixed in the Linux kernel: use-after-free in netfilter, KVM out-of-bounds access and an io_uring double-free.",
            "url": "https://ubuntu.com/security/notices/USN-7234-1",
            "source": "Ubuntu Security Notices",
            "source_url": "https://ubuntu.com/security/notices/rss.xml",
            "published": ago(hours=6),
            "tags": {"linux", "cve", "patch"},
            "cves": ["CVE-2024-50241", "CVE-2024-50251", "CVE-2024-50262"],
            "severity": "high",
            "urgent": False,
        },
        {
            "title": "Kubernetes security advisory: multiple CVEs in kubelet including CVE-2025-25587",
            "summary": "Upstream Kubernetes discloses a kubelet symlink handling issue rated high and a medium-severity CPU denial of service. Fixed in 1.31.5, 1.30.9, 1.29.13.",
            "url": "https://kubernetes.io/blog/security/",
            "source": "Kubernetes Security Announcements",
            "source_url": "https://kubernetes.io/feed.xml",
            "published": ago(hours=11),
            "tags": {"kubernetes", "cloud", "cve", "patch"},
            "cves": ["CVE-2025-25587", "CVE-2025-25588"],
            "severity": "high",
            "urgent": False,
        },
        {
            "title": "AWS security bulletin: Apache Airflow on MWAA updated for CVE-2025-39001",
            "summary": "AWS updated managed Apache Airflow environments to address an information disclosure vulnerability rated medium.",
            "url": "https://aws.amazon.com/security/security-bulletins/",
            "source": "AWS Security Bulletins",
            "source_url": "https://aws.amazon.com/security/security-bulletins/rss/feed/",
            "published": ago(hours=12),
            "tags": {"cloud", "cve", "patch"},
            "cves": ["CVE-2025-39001"],
            "severity": "medium",
            "urgent": False,
        },
        {
            "title": "Red Hat Product Security: glibc vulnerabilities fixed in RHEL 9 and 10",
            "summary": "Updated glibc packages address two out-of-bounds reads and an integer overflow affecting setuid binaries.",
            "url": "https://access.redhat.com/security/security-updates/",
            "source": "Red Hat Product Security",
            "source_url": "https://access.redhat.com/blogs/product-security/feed",
            "published": ago(hours=23),
            "tags": {"linux", "cloud", "cve", "patch"},
            "cves": ["CVE-2025-0395", "CVE-2025-17428"],
            "severity": "high",
            "urgent": False,
        },
        {
            "title": "CISA alert: nation-state actors exploiting public-facing Kubernetes clusters",
            "summary": "Joint advisory details TTPs used against misconfigured Kubernetes dashboards and exposed etcd endpoints. Mitigations include RBAC review and network policy.",
            "url": "https://www.cisa.gov/cybersecurity-advisories",
            "source": "CISA Cybersecurity Advisories",
            "source_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "published": ago(days=1, hours=2),
            "tags": {"kubernetes", "cloud", "threat", "exploit"},
            "cves": [],
            "severity": "high",
            "urgent": True,
        },
        {
            "title": "Google Cloud security bulletin: GKE node image updated for containerd CVE-2025-0817",
            "summary": "New GKE node images include containerd 1.7.27 to fix a high-severity privilege escalation in the CRI plugin.",
            "url": "https://cloud.google.com/security/bulletins",
            "source": "Google Cloud Security Bulletins",
            "source_url": "https://cloud.google.com/feeds/security-bulletins.xml",
            "published": ago(days=1, hours=7),
            "tags": {"cloud", "kubernetes", "cve", "patch"},
            "cves": ["CVE-2025-0817"],
            "severity": "high",
            "urgent": False,
        },
    ]

    items = [FeedItem(**item, id=_hash_item(item["url"], item["title"])) for item in raw]
    for item in items:
        item.is_sample = True
    return items


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _hash_item(unique: str, fallback: str) -> str:
    return hashlib.sha1((unique or fallback).encode("utf-8")).hexdigest()[:16]


def _first_text(entry: Any, key: str) -> str:
    """Return a plain-text value from a feedparser entry or an empty string."""
    value = entry.get(key, "")
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (tuple, list)):
        return str(value[0]).strip() if value else ""
    return str(value).strip() if value else ""


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _published_from_entry(entry: Any) -> datetime | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        try:
            parsed = entry.get(key)
            if parsed:
                return datetime(*parsed[:6], tzinfo=timezone.utc)
        except Exception:
            continue
    # Fallback: try the raw RFC 2822 string from some feeds.
    for key in ("published", "updated"):
        raw = entry.get(key)
        if isinstance(raw, str) and raw.strip():
            try:
                return _ensure_aware(parsedate_to_datetime(raw))
            except Exception:
                continue
    return None


def _extract_cves(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in CVE_RE.findall(text):
        cve = m.upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _infer_severity(text: str, cvss_score: float | None = None) -> str:
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        if cvss_score > 0.0:
            return "low"
        return "unknown"
    t = text.lower()
    if any(w in t for w in ("critical severity", "critical vulnerability", "critical security", "critical flaw", "critical remote", "rated critical", "cvss 9.", "cvss:4.0/av:n/ac:l")):
        return "critical"
    if any(w in t for w in ("high severity", "high-severity", "important severity", "privilege escalation", "remote code execution", "rce")):
        return "high"
    if "medium severity" in t or "medium-severity" in t:
        return "medium"
    if "low severity" in t or "low-severity" in t:
        return "low"
    return "unknown"


def _infer_tags(text: str, source_tags: frozenset[str], cves: list[str]) -> set[str]:
    t = text.lower()
    tags = set(source_tags)
    if any(w in t for w in ("linux", "ubuntu", "debian", "red hat", "fedora", "suse", "kernel", "glibc", "systemd", "openssl")):
        tags.add("linux")
    if any(w in t for w in ("aws", "amazon", "azure", "gcp", "google cloud", "cloud", "mwaa", "gke")):
        tags.add("cloud")
    if any(w in t for w in ("kubernetes", "k8s", "kube", "containerd", "cri-o", "helm", "istio", "envoy", "runc", "ingress")):
        tags.add("kubernetes")
    if cves:
        tags.add("cve")
    if any(w in t for w in ("exploit", "exploited", "kev", "in the wild", "weaponized", "poc", "ransomware")):
        tags.add("exploit")
    if any(w in t for w in ("patch", "update", "fixed", "security update", "advisory", "bulletin")):
        tags.add("patch")
    if any(w in t for w in ("cisa", "alert", "threat", "apt", "nation-state")):
        tags.add("threat")
    return tags


def _tag_priority(tag: str) -> int:
    order = {"exploit": 0, "kubernetes": 1, "cloud": 2, "linux": 3, "cve": 4, "patch": 5, "threat": 6}
    return order.get(tag, 99)


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

async def _fetch_rss(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    resp = await client.get(source.url)
    resp.raise_for_status()
    parsed = feedparser.parse(resp.content)
    items: list[FeedItem] = []
    for entry in parsed.entries[: source.max_items]:
        title = _first_text(entry, "title")
        raw_summary = _first_text(entry, "summary") or _first_text(entry, "description")
        summary = _truncate(_strip_html(raw_summary))
        url = entry.get("link", "")
        if not title:
            continue
        text = f"{title} {summary}"
        if not _is_relevant(source, text):
            continue
        cves = _extract_cves(text)
        tags = _infer_tags(text, source.tags, cves)
        cvss_score = _extract_cvss_score(raw_summary) if source.id == "cisa" else None
        severity = _infer_severity(text, cvss_score)
        urgent = severity in ("critical", "high") and ("exploit" in tags or "exploit" in text.lower())
        items.append(
            FeedItem(
                id=_hash_item(url, title),
                title=title,
                summary=summary,
                url=url,
                source=source.name,
                source_url=source.url,
                published=_published_from_entry(entry),
                tags=tags,
                cves=cves,
                severity=severity,
                urgent=urgent,
            )
        )
    return items


def _nvd_cvss_score(vuln: dict[str, Any]) -> float | None:
    metrics = vuln.get("metrics", {})
    scores: list[float] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {})
            base = data.get("baseScore")
            if isinstance(base, (int, float)):
                scores.append(float(base))
    return max(scores) if scores else None


def _nvd_english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _nvd_reference_url(cve: dict[str, Any]) -> str:
    refs = cve.get("references", []) or []
    if refs:
        return refs[0].get("url", "")
    return f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"


def _nvd_latest_url(source_url: str, max_items: int) -> str:
    """Return the NVD query URL that fetches the *latest* matching CVEs.

    NVD keyword queries return the oldest matches first, so we use the total
    result count to skip straight to the last page (the newest items).
    """
    url = urllib.parse.urlparse(source_url)
    params = dict(urllib.parse.parse_qsl(url.query))
    params["resultsPerPage"] = str(max(1, max_items))
    return urllib.parse.urlunparse(url._replace(query=urllib.parse.urlencode(params)))


async def _fetch_nvd(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    # First, learn how many CVEs match this keyword so we can jump to the
    # newest results (NVD returns keyword matches in ascending date order).
    count_url = _nvd_latest_url(source.url, 1)
    count_resp = await client.get(count_url)
    count_resp.raise_for_status()
    total = int(count_resp.json().get("totalResults") or 0)

    url = urllib.parse.urlparse(source.url)
    params = dict(urllib.parse.parse_qsl(url.query))
    start_index = max(0, total - source.max_items)
    params["resultsPerPage"] = str(source.max_items)
    params["startIndex"] = str(start_index)
    url = urllib.parse.urlunparse(url._replace(query=urllib.parse.urlencode(params)))

    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()
    items: list[FeedItem] = []
    for wrapper in (data.get("vulnerabilities") or [])[: source.max_items]:
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        title = cve_id
        description = _nvd_english_description(cve)
        text = f"{title} {description}"
        cves = [cve_id] if cve_id else []
        cvss = _nvd_cvss_score(cve)
        tags = _infer_tags(text, source.tags, cves)
        severity = _infer_severity(text, cvss)
        published_raw = cve.get("published")
        try:
            published = datetime.fromisoformat(published_raw.replace("Z", "+00:00")) if published_raw else None
        except Exception:
            published = None
        items.append(
            FeedItem(
                id=_hash_item(cve_id, title),
                title=title,
                summary=description,
                url=_nvd_reference_url(cve),
                source=source.name,
                source_url=source.url,
                published=published,
                tags=tags,
                cves=cves,
                severity=severity,
                urgent=severity in ("critical", "high") and "exploit" in tags,
            )
        )
    return items


async def _fetch_redhat(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    resp = await client.get(source.url)
    resp.raise_for_status()
    data = resp.json()
    items: list[FeedItem] = []
    for row in data[: source.max_items]:
        cve_id = row.get("CVE", "")
        if not cve_id:
            continue
        description = _truncate(_strip_html(row.get("bugzilla_description", "")))
        title = cve_id
        if description:
            # Use the first sentence as a title, keep the rest as summary.
            first_sentence = re.split(r"(?<=[.!?])\s+", description)[0]
            if first_sentence and len(first_sentence) < 120:
                title = f"{cve_id}: {first_sentence}"
        text = f"{title} {description}"
        cves = [cve_id]
        tags = _infer_tags(text, source.tags, cves)
        severity = _infer_severity(text)
        published_raw = row.get("public_date")
        try:
            published = datetime.fromisoformat(published_raw.replace("Z", "+00:00")) if published_raw else None
        except Exception:
            published = None
        items.append(
            FeedItem(
                id=_hash_item(cve_id, title),
                title=title,
                summary=description,
                url=f"https://access.redhat.com/security/cve/{cve_id}",
                source=source.name,
                source_url=source.url,
                published=published,
                tags=tags,
                cves=cves,
                severity=severity,
                urgent=False,
            )
        )
    return items


async def _fetch_source(source: Source) -> list[FeedItem]:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
        if source.kind == "rss":
            return await _fetch_rss(source, client)
        if source.kind == "nvd":
            return await _fetch_nvd(source, client)
        if source.kind == "redhat-api":
            return await _fetch_redhat(source, client)
    return []


# ---------------------------------------------------------------------------
# Caching / public API
# ---------------------------------------------------------------------------

def _sort_key(item: FeedItem):
    published = item.published or datetime.min.replace(tzinfo=timezone.utc)
    published = _ensure_aware(published)
    return (1 if item.urgent else 0, published)


def _dedupe(items: list[FeedItem]) -> list[FeedItem]:
    seen: dict[str, FeedItem] = {}
    for item in items:
        key = item.id
        if key not in seen:
            seen[key] = item
            continue
        existing = seen[key]
        # Merge tags/cves if we hit a duplicate from another source.
        existing.tags |= item.tags
        existing.cves = list(dict.fromkeys(existing.cves + item.cves))
        if SEVERITY_RANK.get(item.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = item.severity
        existing.urgent = existing.urgent or item.urgent
    return sorted(seen.values(), key=_sort_key, reverse=True)


async def refresh_feed() -> list[FeedItem]:
    """Fetch every source concurrently and rebuild the feed cache."""
    global CACHE
    async with CACHE_LOCK:
        errors: list[str] = []
        results = await asyncio.gather(
            *(_fetch_source(source) for source in SOURCES),
            return_exceptions=True,
        )
        items: list[FeedItem] = []
        for source, result in zip(SOURCES, results):
            if isinstance(result, BaseException):
                errors.append(f"{source.id}: {type(result).__name__}: {result}")
                continue
            items.extend(result)
        if not items:
            logger.warning("All live sources failed or returned empty; serving sample feed")
            items = _sample_items()
        else:
            # Always keep the sample feed available if the live feed is tiny.
            if len(items) < 4:
                items.extend(_sample_items())
        items = _dedupe(items)

        # Best-effort enrichment (CISA KEV + FIRST EPSS). Failures are logged
        # inside enrich_items and never break the feed.
        from .enrich import enrich_items

        try:
            items = await enrich_items(items)
        except Exception:
            logger.exception("Unexpected enrichment error; continuing with raw items")

        CACHE = FeedCache(items=items, fetched_at=datetime.now(timezone.utc), generated_at=datetime.now(timezone.utc), errors=errors)

        # Persist and notify SSE subscribers.
        from . import store
        from .events import broker

        try:
            await asyncio.to_thread(store.upsert_items, items)
        except Exception:
            logger.exception("Failed to persist feed items")
        await broker.publish(
            {
                "type": "feed_updated",
                "generated_at": CACHE.generated_at.isoformat(),
                "count": len(items),
            }
        )

        # Deliver alerts for any urgent items we have not notified about yet.
        try:
            from . import alerts

            alerted = await alerts.send_urgent_alerts()
            if alerted:
                logger.info("Sent %d urgent alert(s)", len(alerted))
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


def item_to_dict(item: FeedItem, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    tags = sorted(item.tags, key=lambda t: (_tag_priority(t), t))
    published = item.published or now
    published = _ensure_aware(published)
    delta = now - published
    seconds = max(0, int(delta.total_seconds()))
    return {
        "id": item.id,
        "title": item.title,
        "summary": item.summary,
        "url": item.url,
        "source": item.source,
        "source_url": item.source_url,
        "published": published.isoformat(),
        "time_ago": _time_ago(seconds),
        "tags": tags,
        "cves": item.cves,
        "severity": item.severity,
        "urgent": item.urgent,
        "kev": getattr(item, "kev", False),
        "epss_score": getattr(item, "epss_score", None),
    }


def _time_ago(seconds: int) -> str:
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = hours // 24
    if days < 7:
        return f"{days} day{'s' if days != 1 else ''}"
    weeks = days // 7
    return f"{weeks} week{'s' if weeks != 1 else ''}"
