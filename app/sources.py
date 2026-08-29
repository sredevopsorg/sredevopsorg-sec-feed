"""High-value source definitions for the MVP.

Every source is normalised into the same feed-item shape so adding a new
source is just a matter of appending an entry here (or adding a fetcher in
fetcher.py for non-RSS APIs).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    kind: str  # "rss" or "nvd"
    url: str
    tags: frozenset[str] = field(default_factory=frozenset)
    max_items: int = 12


SOURCES: list[Source] = [
    Source(
        id="ubuntu",
        name="Ubuntu Security Notices",
        kind="rss",
        url="https://ubuntu.com/security/notices/rss.xml",
        tags=frozenset({"linux", "patch"}),
        max_items=12,
    ),
    Source(
        id="debian",
        name="Debian Security Advisories",
        kind="rss",
        url="https://www.debian.org/security/dsa",
        tags=frozenset({"linux", "patch"}),
        max_items=12,
    ),
    Source(
        id="redhat",
        name="Red Hat CVE Database",
        kind="redhat-api",
        url="https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=20",
        tags=frozenset({"linux", "cloud"}),
        max_items=20,
    ),
    Source(
        id="k8s",
        name="Kubernetes Blog (security)",
        kind="rss",
        url="https://kubernetes.io/feed.xml",
        tags=frozenset({"kubernetes", "cloud"}),
        max_items=12,
    ),
    Source(
        id="aws",
        name="AWS Security Bulletins",
        kind="rss",
        url="https://aws.amazon.com/security/security-bulletins/rss/feed/",
        tags=frozenset({"cloud"}),
        max_items=12,
    ),
    Source(
        id="cisa",
        name="CISA Cybersecurity Advisories",
        kind="rss",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        tags=frozenset({"threat", "exploit"}),
        max_items=15,
    ),
    Source(
        id="nvd-linux",
        name="NVD CVE — Linux",
        kind="nvd",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=linux%20kernel&resultsPerPage=10",
        tags=frozenset({"linux", "cve"}),
        max_items=10,
    ),
    Source(
        id="nvd-kubernetes",
        name="NVD CVE — Kubernetes",
        kind="nvd",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&resultsPerPage=10",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=10,
    ),
    Source(
        id="nvd-cloud",
        name="NVD CVE — Cloud",
        kind="nvd",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=cloud&resultsPerPage=10",
        tags=frozenset({"cloud", "cve"}),
        max_items=10,
    ),
]
