"""High-value source definitions for the MVP.

Every source is normalised into the same feed-item shape so adding a new
source is just a matter of appending an entry here (or adding a fetcher in
fetcher.py for non-RSS APIs).

Kinds: "rss" (plain feeds, including Atom), "nvd" (NVD API 2.0 window
queries), "redhat-api" (Red Hat security-data JSON), "ghsa" (GitHub Advisory
Database for one curated package), "kev" (CISA KEV catalog additions) and
"ossf-malicious" (OpenSSF Malicious Packages commits).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    kind: str  # one of the kinds described in the module docstring
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
        id="k8s-cve",
        name="Kubernetes Official CVE Feed",
        kind="rss",
        url="https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=12,
    ),
    Source(
        id="gcp",
        name="Google Cloud Security Bulletins",
        kind="rss",
        url="https://cloud.google.com/feeds/google-cloud-security-bulletins.xml",
        tags=frozenset({"cloud"}),
        max_items=12,
    ),
    Source(
        id="alas",
        name="Amazon Linux 2023 Advisories",
        kind="rss",
        url="https://alas.aws.amazon.com/AL2023/alas.rss",
        tags=frozenset({"linux", "cloud", "patch"}),
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
    Source(
        id="kev",
        name="CISA KEV — Newly Exploited",
        kind="kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        tags=frozenset({"exploit", "kev"}),
        max_items=10,
    ),
    # Curated cloud-native projects: one GitHub Advisory Database query each.
    # Each entry costs one GitHub API request per refresh; keep this list short
    # and set GITHUB_TOKEN to raise the unauthenticated 60/hour limit.
    Source(
        id="ghsa-containerd",
        name="GHSA — containerd",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=github.com/containerd/containerd",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    ),
    Source(
        id="ghsa-runc",
        name="GHSA — runc",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=github.com/opencontainers/runc",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    ),
    Source(
        id="ghsa-argo-cd",
        name="GHSA — Argo CD",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=github.com/argoproj/argo-cd",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    ),
    Source(
        id="ghsa-helm",
        name="GHSA — Helm",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=github.com/helm/helm",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    ),
    Source(
        id="ghsa-istio",
        name="GHSA — Istio",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=istio.io/istio",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    ),
    Source(
        id="ossf-malicious",
        name="OpenSSF Malicious Packages",
        kind="ossf-malicious",
        url="https://api.github.com/repos/ossf/malicious-packages",
        tags=frozenset({"malware", "supply-chain"}),
        max_items=10,
    ),
    Source(
        id="zeroday",
        name="ZDI Published Advisories",
        kind="rss",
        url="https://www.zerodayinitiative.com/rss/published/",
        tags=frozenset({"exploit", "zeroday"}),
        max_items=5,
    ),
    Source(
        id="zeroday-upcoming",
        name="ZDI Upcoming Advisories",
        kind="rss",
        url="https://www.zerodayinitiative.com/rss/upcoming/",
        tags=frozenset({"exploit", "zeroday"}),
        max_items=5,
    ),
]
