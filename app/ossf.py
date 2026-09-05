"""OpenSSF Malicious Packages source.

This source reads recent OSV reports from the
`ossf/malicious-packages` GitHub repository without cloning the full repo.
It keeps a cursor (last processed commit SHA) in SQLite and only fetches
files touched by newer commits, so the 1 GB+ repository is never cloned.

Rate limits:
- Unauthenticated GitHub API: 60 req/hour. This source uses ~2-6 requests
  per refresh, so it fits comfortably.
- Set GITHUB_TOKEN to raise the limit and avoid IP rate limiting.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from . import store
from .config import settings
from .fetcher import (
    CVE_RE,
    FeedItem,
    _ensure_aware,
    _hash_item,
    _infer_severity,
    _infer_tags,
    _strip_html,
    _truncate,
)

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com/repos/ossf/malicious-packages"
RAW_BASE = "https://raw.githubusercontent.com/ossf/malicious-packages/main"
REPO_URL = "https://github.com/ossf/malicious-packages"
GITHUB_TOKEN = settings.github_token

# Only files whose name looks like a real assigned report ID.
REPORT_ID_RE = re.compile(r"^MAL-\d{4}-\d+$")
REPORT_FILE_RE = re.compile(r"^MAL-\d{4}-\d+\.json$")
PLACEHOLDER_ID_RE = re.compile(r"^MAL-0000-")

# Ecosystems we always include because they are core to Linux/cloud/kubernetes.
CORE_ECOSYSTEMS = {"Go", "git"}

# For other ecosystems, only include packages/details that mention these topics.
TOPIC_KEYWORDS = (
    "linux", "kubernetes", "k8s", "kube", "helm", "istio", "envoy",
    "container", "docker", "cloud", "aws", "azure", "gcp", "google cloud",
    "terraform", "ansible", "openssl", "openssh", "kernel", "systemd",
)

GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "security-live-feed-mvp/0.3",
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=15.0, headers=GITHUB_HEADERS, follow_redirects=True)


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return _ensure_aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except Exception:
        return None


def _is_relevant_ossf(ecosystem: str, package_name: str, text: str) -> bool:
    if ecosystem in CORE_ECOSYSTEMS:
        return True
    haystack = f"{ecosystem} {package_name} {text}".lower()
    return any(k in haystack for k in TOPIC_KEYWORDS)


def _build_item(path: str, data: dict[str, Any]) -> FeedItem | None:
    osv_id = data.get("id") or ""
    if not REPORT_ID_RE.match(osv_id or ""):
        return None
    affected = (data.get("affected") or [{}])[0] or {}
    pkg = affected.get("package") or {}
    ecosystem = pkg.get("ecosystem") or "unknown"
    package_name = pkg.get("name") or ""
    summary = data.get("summary") or f"Malicious code in {package_name} ({ecosystem})"
    details = _truncate(_strip_html(data.get("details") or ""), 320)
    text = f"{summary} {package_name} {ecosystem} {details}"
    if not _is_relevant_ossf(ecosystem, package_name, text):
        return None

    cves = _extract_cves(text)
    tags = _infer_tags(text, frozenset({"malware", "supply-chain"}), cves)
    tags.add("malicious-packages")
    tags.add(ecosystem.lower())

    severity = _infer_severity(text)
    if severity == "unknown":
        severity = "high"

    return FeedItem(
        id=_hash_item(osv_id, path),
        title=summary,
        summary=details or summary,
        url=f"{REPO_URL}/blob/main/{path}",
        source="OpenSSF Malicious Packages",
        source_url=REPO_URL,
        published=_parse_published(data.get("published")),
        tags=tags,
        cves=cves,
        severity=severity,
        urgent=True,
    )


def _extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(CVE_RE.findall(text)))


async def fetch_recent_reports(limit_commits: int = 5) -> tuple[list[FeedItem], str | None]:
    """Fetch recently added/renamed malicious-package reports.

    Returns (items, latest_commit_sha). On first run the cursor is empty and
    only the latest commit is processed to avoid backfilling 236k reports.
    """
    cursor = await _cursor()
    async with _client() as client:
        commits_resp = await client.get(
            f"{GITHUB_API}/commits",
            params={"path": "osv/malicious", "per_page": min(max(limit_commits, 1), 10)},
        )
        commits_resp.raise_for_status()
        commits = commits_resp.json()

    if not commits:
        return [], None

    latest_sha = commits[0]["sha"]
    if cursor is None:
        # First run: start from the newest commit only.
        new_commits = commits[:1]
    else:
        new_commits = []
        for commit in commits:
            if commit["sha"] == cursor:
                break
            new_commits.append(commit)

    items: list[FeedItem] = []
    async with _client() as client:
        for commit in new_commits:
            sha = commit["sha"]
            try:
                detail_resp = await client.get(f"{GITHUB_API}/commits/{sha}")
                detail_resp.raise_for_status()
                files = detail_resp.json().get("files") or []
            except Exception:
                logger.warning("Could not inspect OSSF commit %s", sha)
                continue
            for file in files:
                path = file.get("filename") or ""
                status = file.get("status") or ""
                if not path.startswith("osv/malicious/") or not path.endswith(".json"):
                    continue
                if status not in ("added", "modified", "renamed", "changed"):
                    continue
                basename = path.rsplit("/", 1)[-1]
                if PLACEHOLDER_ID_RE.match(basename) or not REPORT_FILE_RE.match(basename):
                    continue
                try:
                    raw_resp = await client.get(f"{RAW_BASE}/{path}")
                    raw_resp.raise_for_status()
                    data = raw_resp.json()
                except Exception:
                    logger.warning("Could not fetch OSSF report %s", path)
                    continue
                item = _build_item(path, data)
                if item:
                    items.append(item)

    # Persist cursor before returning so progress is not lost on restart.
    if latest_sha:
        await _set_cursor(latest_sha)
    return items, latest_sha


async def _cursor() -> str | None:
    import asyncio

    return await asyncio.to_thread(store.get_source_cursor, "ossf-malicious")


async def _set_cursor(sha: str) -> None:
    import asyncio

    await asyncio.to_thread(store.set_source_cursor, "ossf-malicious", sha)
