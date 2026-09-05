"""Domain model and serialization for feed items.

Holding ``FeedItem`` and its serialization here (rather than in the fetch
module) breaks the ``fetcher <-> store`` import cycle: both the fetch pipeline
and the storage adapters depend one-way on this module (ADR-0004).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


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
    osv_affected: list[str] = field(default_factory=list)
    osv_fixed: list[str] = field(default_factory=list)
    osv_severity: str | None = None
    patch_status: str = "unknown"


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _hash_item(unique: str, fallback: str) -> str:
    return hashlib.sha1((unique or fallback).encode("utf-8")).hexdigest()[:16]


def _tag_priority(tag: str) -> int:
    order = {"exploit": 0, "kubernetes": 1, "cloud": 2, "linux": 3, "cve": 4, "patch": 5, "threat": 6}
    return order.get(tag, 99)


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
        "osv_affected": getattr(item, "osv_affected", []),
        "osv_fixed": getattr(item, "osv_fixed", []),
        "osv_severity": getattr(item, "osv_severity", None),
        "patch_status": getattr(item, "patch_status", "unknown"),
    }


def _sample_items() -> list[FeedItem]:
    """Return a small set of realistic fallback items used when every live
    source fails, so the frontend never renders an empty feed."""
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
            "patch_status": "fixed",
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
            "patch_status": "fixed",
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
