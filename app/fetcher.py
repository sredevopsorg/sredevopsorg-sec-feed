"""Fetching and normalising feed items from upstream sources.

The MVP is deliberately resilient: if the network is unavailable or every
source fails, a small set of realistic sample items is returned so the
frontend still renders the full experience. Orchestration (enrichment,
persistence, indexing, publishing, alerting) lives in ``app/pipeline.py``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

from . import http_client, store
from .config import settings
from .models import (
    FeedItem,
    _ensure_aware,
    _hash_item,
    _sample_items,
    _tag_priority,
    _time_ago,
    item_from_dict,
    item_to_dict,
)
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


# Short tokens that occur inside unrelated words ("source" contains "rce",
# "process" contains "poc", "truncate" contains "runc", "misused" contains
# "suse"). Those must match as whole words; longer phrases keep the cheaper
# substring test.
_AMBIGUOUS_TOKENS = frozenset({"rce", "poc", "apt", "kev", "aws", "runc", "suse", "gke"})
_MENTION_PATTERNS: dict[str, re.Pattern[str]] = {}


def _mentions(text: str, token: str) -> bool:
    """True when *token* appears in *text* as a whole word."""
    pattern = _MENTION_PATTERNS.get(token)
    if pattern is None:
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])")
        _MENTION_PATTERNS[token] = pattern
    return pattern.search(text) is not None


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    """Match phrases as substrings, ambiguous short tokens as whole words."""
    for token in tokens:
        if token in _AMBIGUOUS_TOKENS:
            if _mentions(text, token):
                return True
        elif token in text:
            return True
    return False


def _is_relevant(source: Source, text: str) -> bool:
    """Return True when an item is on-topic for this feed.

    Most sources are already topic-scoped (distro trackers, cloud bulletins,
    official CVE feeds, keyword-scoped NVD queries), so only the broad CISA
    feed needs filtering.
    """
    t = text.lower()
    if source.id == "cisa":
        # CISA publishes both ICS/OT and enterprise advisories. Keep only the
        # ones that touch our target ecosystem.
        return any(w in t for w in TARGET_KEYWORDS)
    return True

# Re-exported for callers that still import them from here; the single
# outbound HTTP policy lives in app/http_client.py.
HTTP_TIMEOUT = http_client.HTTP_TIMEOUT
USER_AGENT = http_client.USER_AGENT

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

# A source that is not due yet. Distinct from a failure: it must not appear in
# source_errors and must never trigger the sample fallback.
SKIPPED = object()


def _load_state(source_id: str) -> dict[str, Any] | None:
    """Read the stored fetch state, degrading to an unconditional fetch."""
    try:
        return store.get_source_state(source_id)
    except Exception:
        logger.warning("Could not read fetch state for %s; fetching unconditionally", source_id)
        return None


def _save_state(
    source: Source,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    payload: list[dict[str, Any]] | None = None,
    ok: bool = True,
    error: str | None = None,
) -> None:
    """Persist a fetch attempt; failures here never break the refresh."""
    try:
        store.set_source_state(
            source.id,
            etag=etag,
            last_modified=last_modified,
            fetched_at=datetime.now(timezone.utc),
            ok=ok,
            error=error,
            payload=payload,
        )
    except Exception:
        logger.warning("Could not persist fetch state for %s", source.id)


def _validator_headers(state: dict[str, Any] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if state:
        if state.get("etag"):
            headers["If-None-Match"] = str(state["etag"])
        if state.get("last_modified"):
            headers["If-Modified-Since"] = str(state["last_modified"])
    return headers


def _stored_items(state: dict[str, Any] | None) -> list[FeedItem] | None:
    """Rebuild items from the stored payload, or None when it is unusable."""
    payload = (state or {}).get("last_payload")
    if not payload:
        return None
    try:
        return [item_from_dict(row) for row in payload]
    except Exception:
        logger.warning("Stored source payload is unusable; refetching without validators")
        return None


def _is_due(source: Source, state: dict[str, Any] | None) -> bool:
    """False while the source is inside its minimum fetch interval."""
    if source.min_interval_seconds <= 0 or not state:
        return True
    raw = state.get("last_fetched_at")
    if not raw:
        return True
    try:
        last = _ensure_aware(datetime.fromisoformat(str(raw)))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() >= source.min_interval_seconds


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _first_text(entry: Any, key: str) -> str:
    """Return a plain-text value from a feedparser entry or an empty string."""
    value = entry.get(key, "")
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (tuple, list)):
        return str(value[0]).strip() if value else ""
    return str(value).strip() if value else ""


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
    if _contains_any(t, ("critical severity", "critical vulnerability", "critical security", "critical flaw", "critical remote", "rated critical", "(critical)", "cvss 9.", "cvss:4.0/av:n/ac:l")):
        return "critical"
    # "important" is the Red Hat / Amazon Linux rating between critical and
    # moderate, so it maps to high.
    if _contains_any(t, ("high severity", "high-severity", "important severity", "(important)", "privilege escalation", "remote code execution", "rce")):
        return "high"
    if _contains_any(t, ("medium severity", "medium-severity", "(moderate)")):
        return "medium"
    if _contains_any(t, ("low severity", "low-severity", "(low)")):
        return "low"
    return "unknown"


def _infer_tags(text: str, source_tags: frozenset[str], cves: list[str]) -> set[str]:
    t = text.lower()
    tags = set(source_tags)
    if _contains_any(t, ("linux", "ubuntu", "debian", "red hat", "fedora", "suse", "kernel", "glibc", "systemd", "openssl")):
        tags.add("linux")
    if _contains_any(t, ("aws", "amazon", "azure", "gcp", "google cloud", "cloud", "mwaa", "gke")):
        tags.add("cloud")
    if _contains_any(t, ("kubernetes", "k8s", "kube", "containerd", "cri-o", "helm", "istio", "envoy", "runc", "ingress")):
        tags.add("kubernetes")
    if cves:
        tags.add("cve")
    if _contains_any(t, ("exploit", "exploited", "kev", "in the wild", "weaponized", "poc", "ransomware")):
        tags.add("exploit")
    if _contains_any(t, ("patch", "update", "fixed", "security update", "advisory", "bulletin")):
        tags.add("patch")
    if _contains_any(t, ("cisa", "alert", "threat", "apt", "nation-state")):
        tags.add("threat")
    return tags


# ---------------------------------------------------------------------------
# Distro patch-status normalization
# ---------------------------------------------------------------------------

PATCH_STATUS_FIXED = "fixed"
PATCH_STATUS_AFFECTED = "affected"
PATCH_STATUS_NOT_AFFECTED = "not-affected"
PATCH_STATUS_DEFERRED = "deferred"
PATCH_STATUS_UNKNOWN = "unknown"


def normalize_patch_status(raw: str | None) -> str:
    """Map a distro-specific patch/fix status string to a canonical value."""
    if not raw:
        return PATCH_STATUS_UNKNOWN
    key = " ".join(str(raw).strip().lower().split())
    if key in ("not affected", "not vulnerable", "unaffected"):
        return PATCH_STATUS_NOT_AFFECTED
    if any(w in key for w in ("will not fix", "won't fix", "no fix", "fix deferred", "deferred", "out of support", "end of life")):
        return PATCH_STATUS_DEFERRED
    if any(w in key for w in ("fixed", "released", "resolved", "patch", "patched", "available", "backport")):
        return PATCH_STATUS_FIXED
    if any(w in key for w in ("affected", "vulnerable", "under investigation")):
        return PATCH_STATUS_AFFECTED
    return PATCH_STATUS_UNKNOWN


def _patch_status_from_text(source: Source, text: str) -> str:
    """Best-effort patch status derived from advisory text.

    Ubuntu/Debian security notices (USN/DSA) and Amazon Linux errata (ALAS)
    announce released fixes by default, so they start at ``fixed`` and are
    only downgraded when the text explicitly says otherwise. Other sources
    stay ``unknown``.
    """
    t = text.lower()
    released_fix_sources = ("ubuntu", "debian", "alas")
    status = PATCH_STATUS_FIXED if source.id in released_fix_sources else PATCH_STATUS_UNKNOWN
    if any(w in t for w in ("not affected", "not vulnerable", "unaffected", "not-affected")):
        return PATCH_STATUS_NOT_AFFECTED
    if any(w in t for w in ("will not fix", "won't fix", "no fix", "fix deferred", "deferred")):
        return PATCH_STATUS_DEFERRED
    return status


def _redhat_patch_status(row: dict[str, Any]) -> str:
    """Derive a canonical patch status from Red Hat CVE security-data fields."""
    if row.get("affected_release"):
        return PATCH_STATUS_FIXED
    states = [
        (p.get("fix_state") or "")
        for p in (row.get("package_state") or [])
        if isinstance(p, dict)
    ]
    if not states:
        return PATCH_STATUS_UNKNOWN
    normalized = [normalize_patch_status(s) for s in states]
    if PATCH_STATUS_AFFECTED in normalized:
        return PATCH_STATUS_AFFECTED
    if PATCH_STATUS_DEFERRED in normalized:
        return PATCH_STATUS_DEFERRED
    if all(s == PATCH_STATUS_NOT_AFFECTED for s in normalized):
        return PATCH_STATUS_NOT_AFFECTED
    return PATCH_STATUS_UNKNOWN


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

async def _fetch_rss(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    state = _load_state(source.id)
    validators = _validator_headers(state)
    resp = await client.get(source.url, headers=validators) if validators else await client.get(source.url)
    if resp.status_code == 304:
        cached = _stored_items(state)
        if cached is not None:
            _save_state(
                source,
                etag=resp.headers.get("etag") or (state or {}).get("etag"),
                last_modified=resp.headers.get("last-modified") or (state or {}).get("last_modified"),
            )
            return cached[: source.max_items]
        # Validators without a usable payload: refetch the body once.
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
        patch_status = _patch_status_from_text(source, text)
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
                patch_status=patch_status,
            )
        )
    _save_state(
        source,
        etag=resp.headers.get("etag"),
        last_modified=resp.headers.get("last-modified"),
        payload=[item_to_dict(item) for item in items[: source.max_items]],
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


def _nvd_window_url(
    source_url: str,
    results_per_page: int,
    days: int,
    start_index: int | None = None,
) -> str:
    """Return an NVD query URL limited to CVEs published in the last `days` days.

    NVD API 2.0 requires both `pubStartDate` and `pubEndDate` (at most 120
    days apart) in ISO-8601 UTC. A bounded window lets one page cover every
    recent match for our keywords (measured: 50 "linux kernel", 13
    "kubernetes", 89 "cloud" in seven days), so a refresh needs a single
    request per NVD source instead of a totalResults probe plus a jump to the
    last page over the whole corpus.
    """
    url = urllib.parse.urlparse(source_url)
    params = dict(urllib.parse.parse_qsl(url.query))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, days))
    params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.999")
    params["resultsPerPage"] = str(max(1, results_per_page))
    if start_index is not None:
        params["startIndex"] = str(max(0, start_index))
    return urllib.parse.urlunparse(url._replace(query=urllib.parse.urlencode(params)))


def _nvd_items(data: dict[str, Any], source: Source) -> list[FeedItem]:
    items: list[FeedItem] = []
    for wrapper in data.get("vulnerabilities") or []:
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


async def _fetch_nvd(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    days = max(1, settings.nvd_window_days)
    # One page large enough to cover a whole week of matches for this keyword.
    page_size = max(100, source.max_items * 10)
    resp = await client.get(_nvd_window_url(source.url, page_size, days))
    resp.raise_for_status()
    data = resp.json()
    total = int(data.get("totalResults") or 0)
    items = _nvd_items(data, source)
    if total > page_size:
        # Rare: the window holds more matches than one page. Jump to the last
        # page so the newest window CVEs are the ones kept (NVD lists matches
        # in ascending publication order).
        resp = await client.get(
            _nvd_window_url(
                source.url, source.max_items, days, start_index=max(0, total - source.max_items)
            )
        )
        resp.raise_for_status()
        items = _nvd_items(resp.json(), source)
    items.sort(
        key=lambda item: item.published or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return items[: source.max_items]


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
        patch_status = _redhat_patch_status(row)
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
                patch_status=patch_status,
            )
        )
    return items


# GitHub Advisory Database: one query per curated package, newest first.
# The advisories API returns MEDIUM on current data and MODERATE on older
# entries, so both map to the canonical "medium".
GHSA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
}


def _github_headers() -> dict[str, str]:
    """GitHub API headers, adding the token when configured (rate limits)."""
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


def _ghsa_published(row: dict[str, Any]) -> datetime | None:
    # The advisories *list* endpoint names the timestamps published_at /
    # updated_at; single-advisory responses use published / updated.
    raw = (
        row.get("published_at")
        or row.get("published")
        or row.get("updated_at")
        or row.get("updated")
    )
    if not raw:
        return None
    try:
        return _ensure_aware(datetime.fromisoformat(str(raw).replace("Z", "+00:00")))
    except Exception:
        return None


async def _fetch_ghsa(source: Source, client: httpx.AsyncClient) -> list[FeedItem]:
    """Fetch GitHub Security Advisories affecting one curated package.

    The GitHub Advisory Database covers the cloud-native ecosystem
    (containerd, runc, Helm, Argo CD, Istio) as GHSA entries with linked
    CVEs. Only the curated package is queried: one request per package.
    """
    state = _load_state(source.id)
    headers = _github_headers()
    headers.update(_validator_headers(state))
    resp = await client.get(source.url, headers=headers)
    if resp.status_code == 304:
        cached = _stored_items(state)
        if cached is not None:
            _save_state(
                source,
                etag=resp.headers.get("etag") or (state or {}).get("etag"),
                last_modified=resp.headers.get("last-modified") or (state or {}).get("last_modified"),
            )
            return cached[: source.max_items]
        resp = await client.get(source.url, headers=_github_headers())
    resp.raise_for_status()
    rows = resp.json()
    if not isinstance(rows, list):
        return []
    items: list[FeedItem] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ghsa_id = (row.get("ghsa_id") or "").strip()
        cve_id = (row.get("cve_id") or "").strip().upper()
        summary = (row.get("summary") or "").strip()
        label = cve_id or ghsa_id
        if not label:
            continue
        description = _truncate(_strip_html(row.get("description") or ""))
        title = f"{label}: {summary}" if summary else label
        text = f"{title} {description}"
        cves = list(dict.fromkeys(([cve_id] if cve_id else []) + _extract_cves(text)))
        severity = GHSA_SEVERITY.get((row.get("severity") or "").upper(), "unknown")
        if severity == "unknown":
            severity = _infer_severity(text)
        tags = _infer_tags(text, source.tags, cves)
        url = row.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
        items.append(
            FeedItem(
                id=_hash_item(url, title),
                title=title,
                summary=description or summary,
                url=url,
                source=source.name,
                source_url=source.url,
                published=_ghsa_published(row),
                tags=tags,
                cves=cves,
                severity=severity,
                urgent=severity in ("critical", "high") and "exploit" in tags,
            )
        )
    items.sort(
        key=lambda item: item.published or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    items = items[: source.max_items]
    _save_state(
        source,
        etag=resp.headers.get("etag"),
        last_modified=resp.headers.get("last-modified"),
        payload=[item_to_dict(item) for item in items],
    )
    return items


# Connect-phase failures to upstream hosts are intermittently transient: the
# same deployment has reached a source and then failed to reach it minutes
# later (a dropped SYN surfaces as ConnectTimeout, a reset as ConnectError).
# One retry turns most of those back into a successful refresh. HTTP error
# *responses* are deliberately never retried: a 4xx/5xx is the source's answer,
# and retrying it would double our request rate against that source
# (invariant 5).
FETCH_ATTEMPTS = 2
FETCH_RETRY_DELAY = 0.75  # seconds, multiplied by the attempt number


def _error_detail(exc: BaseException) -> str:
    """Return the first non-empty message in an exception's cause chain.

    httpx re-raises httpcore's connect failures as its own classes without a
    message, so ``str(exc)`` is empty exactly when the cause matters most: a
    blackholed connection surfaces as a message-less ``ConnectTimeout``. The
    errno or reason, when there is one, lives further down the chain.
    """
    node: BaseException | None = exc
    for _ in range(5):
        if node is None:
            break
        detail = str(node).strip()
        if detail:
            return detail
        node = node.__cause__ or node.__context__
    return ""


def _describe_fetch_error(source: Source, exc: BaseException) -> str:
    """One actionable line describing why a source could not be fetched.

    Keeps the ``<id>: <ExceptionType>: <detail>`` shape the API has always
    reported, but names the unreachable host instead of trailing off after an
    empty colon when the exception carries no usable message of its own.
    """
    kind = type(exc).__name__
    host = urllib.parse.urlsplit(source.url).netloc or source.url
    if isinstance(exc, httpx.TimeoutException):
        # anyio reports a deadline through a cancel scope whose message embeds
        # a memory address ("Cancelled via cancel scope 0x7f75…"), which is
        # noise; the exception type already names the phase that timed out.
        return f"{source.id}: {kind} reaching {host}"
    detail = _error_detail(exc)
    if detail:
        return f"{source.id}: {kind}: {detail}"
    return f"{source.id}: {kind} reaching {host}"


async def _fetch_source_once(source: Source) -> list[FeedItem] | object:
    state = _load_state(source.id)
    if not _is_due(source, state):
        # Not due yet: not an error, and not a reason to serve samples.
        return SKIPPED
    try:
        if source.kind == "ossf-malicious":
            from . import ossf

            items, _ = await ossf.fetch_recent_reports()
            items = items[: source.max_items]
        elif source.kind == "kev":
            from . import enrich

            items = await enrich.fetch_recent_kev(source)
        else:
            async with http_client.client() as client:
                if source.kind == "rss":
                    # Saves its own state (validators + payload).
                    return await _fetch_rss(source, client)
                if source.kind == "ghsa":
                    # Saves its own state (validators + payload).
                    return await _fetch_ghsa(source, client)
                if source.kind == "nvd":
                    items = await _fetch_nvd(source, client)
                elif source.kind == "redhat-api":
                    items = await _fetch_redhat(source, client)
                else:
                    items = []
        _save_state(
            source,
            etag=(state or {}).get("etag"),
            last_modified=(state or {}).get("last_modified"),
        )
        return items
    except Exception as exc:
        _save_state(
            source,
            etag=(state or {}).get("etag"),
            last_modified=(state or {}).get("last_modified"),
            ok=False,
            error=f"{type(exc).__name__}: {exc}"[:500],
        )
        raise


async def _fetch_source(source: Source) -> list[FeedItem] | object:
    """Fetch one source, retrying once when the connection itself fails."""
    last_exc: BaseException | None = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            return await _fetch_source_once(source)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt + 1 < FETCH_ATTEMPTS:
                logger.info("Retrying %s after %s", source.id, type(exc).__name__)
                await asyncio.sleep(FETCH_RETRY_DELAY * (attempt + 1))
    # The loop either returns or leaves an exception to re-raise.
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Deduplication and fetch orchestration
# ---------------------------------------------------------------------------

def _sort_key(item: FeedItem):
    # Publication time is the primary key: urgency stays visible as a badge,
    # but a week of KEV backlog must not pin the top of a "live" feed.
    published = item.published or datetime.min.replace(tzinfo=timezone.utc)
    published = _ensure_aware(published)
    return (published, 1 if item.urgent else 0)


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


async def fetch_all() -> tuple[list[FeedItem], list[str]]:
    """Fetch every source concurrently, normalize, dedupe, and apply the sample
    fallback. Returns ``(items, errors)``.

    Enrichment, persistence, indexing, publishing, and alerting are handled by
    the orchestrator in ``app/pipeline.py`` (ADR-0004).
    """
    errors: list[str] = []
    results = await asyncio.gather(
        *(_fetch_source(source) for source in SOURCES),
        return_exceptions=True,
    )
    items: list[FeedItem] = []
    skipped = 0
    for source, result in zip(SOURCES, results):
        if result is SKIPPED:
            skipped += 1
            continue
        if isinstance(result, BaseException):
            errors.append(_describe_fetch_error(source, result))
            continue
        items.extend(result)
    # A skipped source is healthy, just not due. Serving samples here would
    # write fallback rows over a live archive.
    if not items and skipped == 0:
        logger.warning("All live sources failed or returned empty; serving sample feed")
        items = _sample_items()
    elif items and len(items) < 4 and skipped == 0:
        # Keep the sample feed available only when no source was skipped.
        items.extend(_sample_items())
    return _dedupe(items), errors


