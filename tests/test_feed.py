import asyncio
from datetime import datetime, timedelta, timezone

import httpx

import app.fetcher as fetcher
from app.fetcher import (
    _dedupe,
    _ensure_aware,
    _extract_cves,
    _infer_severity,
    _infer_tags,
    _is_relevant,
    _patch_status_from_text,
    _redhat_patch_status,
    _sample_items,
    _time_ago,
    FeedItem,
    item_to_dict,
    normalize_patch_status,
)


def test_extract_cves():
    text = "CVE-2024-21626 and cve-2025-1974 are duplicates CVE-2024-21626"
    assert _extract_cves(text) == ["CVE-2024-21626", "CVE-2025-1974"]


def test_infer_severity():
    assert _infer_severity("critical remote code execution") == "critical"
    assert _infer_severity("high severity privilege escalation") == "high"
    assert _infer_severity("medium severity issue") == "medium"
    assert _infer_severity("something") == "unknown"
    assert _infer_severity("some text", cvss_score=9.8) == "critical"
    # Red Hat / Amazon Linux rating words appear in serialized advisory titles.
    assert _infer_severity("ALAS2023-2026-3234 (important): mariadb1011") == "high"
    assert _infer_severity("ALAS2023-2026-9999 (critical): kernel") == "critical"
    assert _infer_severity("ALAS2023-2026-0001 (moderate): openssl") == "medium"
    assert _infer_severity("ALAS2023-2026-0002 (low): vim") == "low"


def test_ambiguous_tokens_need_word_boundaries():
    """Short tokens must not match inside unrelated words."""
    # "source"/"force" contain "rce"; neither is an RCE claim.
    assert _infer_severity("The advisory source was updated") == "unknown"
    assert _infer_severity("This will force a restart") == "unknown"
    # "process" contains "poc"; "misused" contains "suse"; "adapt" contains "apt".
    assert "exploit" not in _infer_tags("process the archive", frozenset(), [])
    assert "linux" not in _infer_tags("a misused flag", frozenset(), [])
    assert "threat" not in _infer_tags("adapt the config", frozenset(), [])
    # The actual words still match.
    assert _infer_severity("an RCE in kubelet") == "high"
    assert "threat" in _infer_tags("APT actor activity", frozenset(), [])


def test_infer_tags():
    tags = _infer_tags("Ubuntu Linux kernel kubernetes AWS exploited patch", frozenset({"source"}), ["CVE-2024-0001"])
    assert "linux" in tags
    assert "kubernetes" in tags
    assert "cloud" in tags
    assert "exploit" in tags
    assert "cve" in tags
    assert "patch" in tags


def test_dedupe_merges_tags_and_keeps_higher_severity():
    items = [
        FeedItem(id="a", title="t", summary="", url="u", source="s1", source_url="u", published=None, tags={"linux"}, cves=[], severity="low"),
        FeedItem(id="a", title="t", summary="", url="u", source="s2", source_url="u", published=None, tags={"cloud"}, cves=["CVE-2024-0001"], severity="high"),
    ]
    result = _dedupe(items)
    assert len(result) == 1
    assert result[0].severity == "high"
    assert "linux" in result[0].tags and "cloud" in result[0].tags
    assert result[0].cves == ["CVE-2024-0001"]


def test_sample_items_are_well_formed():
    items = _sample_items()
    assert len(items) >= 6
    for item in items:
        assert item.title
        assert item.url
        assert item.published is not None
        assert item.title
        assert item.url
        assert item.summary or item.cves


def test_time_ago():
    assert _time_ago(30) == "just now"
    assert _time_ago(60) == "1 minute"
    assert _time_ago(120) == "2 minutes"
    assert _time_ago(3600) == "1 hour"
    assert _time_ago(7200) == "2 hours"


def test_normalize_patch_status():
    assert normalize_patch_status("Fixed") == "fixed"
    assert normalize_patch_status("Affected") == "affected"
    assert normalize_patch_status("Not affected") == "not-affected"
    assert normalize_patch_status("Will not fix") == "deferred"
    assert normalize_patch_status("Fix deferred") == "deferred"
    assert normalize_patch_status("Out of support scope") == "deferred"
    assert normalize_patch_status(None) == "unknown"
    assert normalize_patch_status("") == "unknown"
    assert normalize_patch_status("something else") == "unknown"


def test_redhat_patch_status():
    fixed = {"affected_release": [{"package": "kernel"}]}
    assert _redhat_patch_status(fixed) == "fixed"

    affected = {"package_state": [{"fix_state": "Affected"}, {"fix_state": "Not affected"}]}
    assert _redhat_patch_status(affected) == "affected"

    deferred = {"package_state": [{"fix_state": "Will not fix"}]}
    assert _redhat_patch_status(deferred) == "deferred"

    not_affected = {"package_state": [{"fix_state": "Not affected"}, {"fix_state": "Not affected"}]}
    assert _redhat_patch_status(not_affected) == "not-affected"

    assert _redhat_patch_status({}) == "unknown"


def test_patch_status_from_text():
    from app.sources import Source

    ubuntu = Source(id="ubuntu", name="Ubuntu", kind="rss", url="u", tags=frozenset())
    debian = Source(id="debian", name="Debian", kind="rss", url="u", tags=frozenset())
    k8s = Source(id="k8s", name="K8s", kind="rss", url="u", tags=frozenset())

    # Distro notices default to "fixed" (advisory = released fixes).
    assert _patch_status_from_text(ubuntu, "USN-7234-1: Linux kernel vulnerabilities") == "fixed"
    assert _patch_status_from_text(debian, "DSA-5812-1 openssl security update") == "fixed"
    alas = Source(id="alas", name="ALAS", kind="rss", url="u", tags=frozenset())
    assert _patch_status_from_text(alas, "ALAS2023-2026-3234 (important): mariadb1011") == "fixed"
    # Explicit "not affected" downgrades.
    assert _patch_status_from_text(ubuntu, "CVE-2024-0001 ... Ubuntu is not affected") == "not-affected"
    # Non-distro sources stay unknown.
    assert _patch_status_from_text(k8s, "Kubernetes security advisory") == "unknown"


def test_ensure_aware_converts_offsets_to_utc():
    shifted = datetime(2025, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=-4)))
    normalized = _ensure_aware(shifted)
    assert normalized == datetime(2025, 1, 1, 14, 0, tzinfo=timezone.utc)
    assert normalized.utcoffset() == timedelta(0)


def test_ensure_aware_treats_naive_values_as_utc():
    assert _ensure_aware(datetime(2025, 1, 1, 12, 0)) == datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_item_to_dict_always_publishes_utc():
    item = FeedItem(
        id="tz",
        title="t",
        summary="s",
        url="u",
        source="src",
        source_url="su",
        published=datetime(2025, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=-4))),
    )
    assert item_to_dict(item)["published"] == "2025-01-01T14:00:00+00:00"


def test_item_to_dict_exposes_is_sample():
    """The API contract reports whether a row is fallback/sample data."""
    from app.fetcher import item_to_dict

    live = FeedItem(id="l", title="t", summary="s", url="u", source="src", source_url="su", published=None)
    sample = FeedItem(id="s", title="t", summary="s", url="u", source="src", source_url="su", published=None, is_sample=True)
    assert item_to_dict(live)["is_sample"] is False
    assert item_to_dict(sample)["is_sample"] is True
    assert all(item_to_dict(item)["is_sample"] is True for item in _sample_items())


# ---------------------------------------------------------------------------
# Enrichment (KEV + EPSS)
# ---------------------------------------------------------------------------

def _enrichment_item(cves: list[str]) -> FeedItem:
    return FeedItem(
        id="e",
        title="t",
        summary="s",
        url="u",
        source="src",
        source_url="su",
        published=None,
        cves=cves,
        severity="high",
    )


def _enriched(monkeypatch, item: FeedItem, *, kev=None, epss=None) -> FeedItem:
    from app import enrich as enrich_module

    async def fake_kev():
        return kev or {}

    async def fake_epss(cves):
        return epss or {}

    monkeypatch.setattr(enrich_module, "_fetch_kev", fake_kev)
    monkeypatch.setattr(enrich_module, "_fetch_epss", fake_epss)
    return asyncio.run(enrich_module.enrich_items([item]))[0]


def test_epss_unknown_score_stays_none(monkeypatch):
    # Unavailable EPSS or an unscored CVE means "unknown", never 0.0.
    assert _enriched(monkeypatch, _enrichment_item(["CVE-2024-0001"])).epss_score is None
    other_cve = _enriched(monkeypatch, _enrichment_item(["CVE-2024-0001"]), epss={"CVE-2024-0002": 0.42})
    assert other_cve.epss_score is None


def test_epss_zero_score_is_kept(monkeypatch):
    item = _enriched(monkeypatch, _enrichment_item(["CVE-2024-0001"]), epss={"CVE-2024-0001": 0.0})
    assert item.epss_score == 0.0
    assert item.urgent is False


def test_epss_high_score_marks_urgent(monkeypatch):
    item = _enriched(monkeypatch, _enrichment_item(["CVE-2024-0001"]), epss={"CVE-2024-0001": 0.62})
    assert item.epss_score == 0.62
    assert item.urgent is True


def test_kev_marks_urgent_and_tags(monkeypatch):
    item = _enriched(monkeypatch, _enrichment_item(["CVE-2024-0001"]), kev={"CVE-2024-0001": {}})
    assert item.kev is True
    assert item.urgent is True
    assert {"kev", "exploit"} <= item.tags


def test_epss_request_is_capped_not_chunked(monkeypatch):
    from app import enrich as enrich_module

    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"data": []}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, params=None):
            captured["params"] = params
            return FakeResponse()

    monkeypatch.setattr(enrich_module.http_client, "client", lambda **kwargs: FakeClient())
    over_cap = [f"CVE-2024-{i:04d}" for i in range(enrich_module.EPSS_MAX_CVES + 25)]

    assert asyncio.run(enrich_module._fetch_epss(over_cap)) == {}
    assert captured["params"]["cve"].count(",") == enrich_module.EPSS_MAX_CVES - 1


def test_is_relevant_filters_only_the_broad_sources():
    from app.sources import Source

    cisa = Source(id="cisa", name="CISA", kind="rss", url="u")
    ubuntu = Source(id="ubuntu", name="Ubuntu", kind="rss", url="u")
    gcp = Source(id="gcp", name="GCP", kind="rss", url="u")

    # CISA carries ICS/OT advisories that are off-topic for this feed.
    assert _is_relevant(cisa, "Siemens SIMATIC ICS advisory") is False
    assert _is_relevant(cisa, "Advisory: Kubernetes cluster takeover") is True
    # Topic-scoped sources, including the official Kubernetes CVE feed, are
    # never filtered here.
    assert _is_relevant(ubuntu, "USN-7234-1: Linux kernel vulnerabilities") is True
    assert _is_relevant(gcp, "GCP-2026-068 Cloud VPN vulnerability") is True

# ---------------------------------------------------------------------------
# Source definitions and newer source kinds (NVD window, KEV, GHSA)
# ---------------------------------------------------------------------------

def test_sources_are_well_formed():
    from app.sources import SOURCES

    ids = [source.id for source in SOURCES]
    assert len(ids) == len(set(ids))
    assert {"k8s-cve", "gcp", "alas", "kev", "ghsa-containerd"} <= set(ids)
    assert all(source.url.startswith("https://") for source in SOURCES)
    assert all(source.max_items > 0 for source in SOURCES)
    kinds = {"rss", "nvd", "redhat-api", "ghsa", "kev", "ossf-malicious"}
    assert {source.kind for source in SOURCES} <= kinds


def test_nvd_window_url_uses_a_bounded_date_window():
    from app.fetcher import _nvd_window_url

    url = _nvd_window_url(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&resultsPerPage=10",
        100,
        7,
    )
    assert "keywordSearch=kubernetes" in url
    assert "pubStartDate=" in url
    assert "pubEndDate=" in url
    assert "resultsPerPage=100" in url
    # The window query replaces the totalResults probe, so there is no page
    # jump unless the window overflows a single page.
    assert "startIndex" not in url
    overflow = _nvd_window_url("https://example.test/cves?keywordSearch=a", 10, 7, start_index=5)
    assert "startIndex=5" in overflow


def test_fetch_recent_kev_filters_window_and_flags_urgent(monkeypatch):
    from types import SimpleNamespace

    from app import enrich as enrich_module
    from app.sources import Source

    now = datetime.now(timezone.utc)
    catalog = {
        "CVE-2026-0001": {
            "cveID": "CVE-2026-0001",
            "dateAdded": now.strftime("%Y-%m-%d"),
            "vendorProject": "Acme",
            "product": "kubelet",
            "vulnerabilityName": "Acme kubelet remote code execution",
            "shortDescription": "RCE in kubelet.",
            "requiredAction": "Apply updates.",
            "notes": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        },
        "CVE-2026-0002": {
            "cveID": "CVE-2026-0002",
            "dateAdded": (now - timedelta(days=90)).strftime("%Y-%m-%d"),
            "vulnerabilityName": "Old bug",
        },
        "CVE-2026-0003": {  # malformed dates are skipped, never crash a refresh
            "cveID": "CVE-2026-0003",
            "dateAdded": "not-a-date",
        },
    }

    async def fake_kev():
        return catalog

    monkeypatch.setattr(enrich_module, "_fetch_kev", fake_kev)
    monkeypatch.setattr(enrich_module, "settings", SimpleNamespace(kev_source_days=7))
    source = Source(
        id="kev",
        name="KEV",
        kind="kev",
        url="https://example.test/kev",
        tags=frozenset({"exploit", "kev"}),
        max_items=10,
    )
    items = asyncio.run(enrich_module.fetch_recent_kev(source))

    assert [item.cves for item in items] == [["CVE-2026-0001"]]
    item = items[0]
    assert item.urgent is True and item.kev is True
    assert {"kev", "cve"} <= item.tags
    assert item.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    assert item.published == datetime.strptime(now.strftime("%Y-%m-%d"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    assert "Required action:" in item.summary
    # No CVSS score, but the title says "remote code execution" -> high.
    assert item.severity == "high"


def test_fetch_recent_kev_uses_cvss_from_the_catalog_text(monkeypatch):
    from types import SimpleNamespace

    from app import enrich as enrich_module
    from app.sources import Source

    now = datetime.now(timezone.utc)
    catalog = {
        "CVE-2026-0010": {
            "cveID": "CVE-2026-0010",
            "dateAdded": now.strftime("%Y-%m-%d"),
            "vulnerabilityName": "Acme kubelet flaw",
            "shortDescription": "A flaw in kubelet.",
            "notes": "CVSS v3 9.8: critical; see the vendor advisory.",
        }
    }

    async def fake_kev():
        return catalog

    monkeypatch.setattr(enrich_module, "_fetch_kev", fake_kev)
    monkeypatch.setattr(enrich_module, "settings", SimpleNamespace(kev_source_days=7))
    source = Source(
        id="kev",
        name="KEV",
        kind="kev",
        url="https://example.test/kev",
        tags=frozenset({"exploit", "kev"}),
        max_items=10,
    )
    items = asyncio.run(enrich_module.fetch_recent_kev(source))
    assert items[0].severity == "critical"
    assert items[0].urgent is True


def test_ghsa_uses_linked_cve_severity_and_html_url(monkeypatch):
    from app.fetcher import GHSA_SEVERITY, _fetch_ghsa
    from app.sources import Source

    # Keep the test off the default store (and off the network).
    monkeypatch.setattr(fetcher.store, "get_source_state", lambda sid: None)
    monkeypatch.setattr(fetcher.store, "set_source_state", lambda sid, **kw: None)

    # Current advisories use MEDIUM; older entries use MODERATE.
    assert GHSA_SEVERITY["MEDIUM"] == "medium"
    assert GHSA_SEVERITY["MODERATE"] == "medium"

    row = {
        "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
        "cve_id": "CVE-2026-12345",
        "summary": "runc: container escape via /proc",
        "description": "<p>Container escape in runc.</p>",
        "severity": "HIGH",
        "published_at": "2026-10-01T10:00:00Z",
        "html_url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
    }

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return [row]

    class FakeClient:
        async def get(self, url, headers=None):
            return FakeResponse()

    source = Source(
        id="ghsa-runc",
        name="GHSA — runc",
        kind="ghsa",
        url="https://api.github.com/advisories?affects=github.com/opencontainers/runc",
        tags=frozenset({"kubernetes", "cve"}),
        max_items=5,
    )
    items = asyncio.run(_fetch_ghsa(source, FakeClient()))

    assert len(items) == 1
    item = items[0]
    assert item.title.startswith("CVE-2026-12345:")
    assert item.severity == "high"
    assert item.cves == ["CVE-2026-12345"]
    assert item.url == "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"
    assert {"kubernetes", "cve"} <= item.tags
    assert item.published == datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Conditional fetch (ETag / Last-Modified) and interval skipping
# ---------------------------------------------------------------------------

_RSS_BODY = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>USN-1: linux kernel vulnerability</title><link>https://example.com/1</link>
<description>fixed in the kernel</description></item></channel></rss>"""


class _FakeFetchClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def get(self, url, headers=None):
        self.calls.append(dict(headers or {}))
        return self.responses.pop(0)


def _response(status, url, body=b"", headers=None):
    return httpx.Response(status, content=body, headers=headers or {}, request=httpx.Request("GET", url))


def test_rss_sends_validators_and_reuses_the_payload_on_304(monkeypatch):
    from app.models import FeedItem, item_to_dict
    from app.sources import Source

    item = FeedItem(
        id="cached", title="cached", summary="s", url="https://e/1",
        source="s", source_url="u", published=None,
    )
    state = {"etag": '"v1"', "last_modified": None, "last_payload": [item_to_dict(item)]}
    saved = {}
    monkeypatch.setattr(fetcher.store, "get_source_state", lambda sid: state)
    monkeypatch.setattr(fetcher.store, "set_source_state", lambda sid, **kw: saved.update(kw))
    source = Source(id="ubuntu", name="Ubuntu", kind="rss", url="https://example.com/feed")
    client = _FakeFetchClient([_response(304, source.url, headers={"etag": '"v1"'})])

    items = asyncio.run(fetcher._fetch_rss(source, client))

    assert [i.id for i in items] == ["cached"]
    assert client.calls[0]["If-None-Match"] == '"v1"'
    assert saved["ok"] is True


def test_rss_304_without_a_stored_payload_refetches(monkeypatch):
    from app.sources import Source

    monkeypatch.setattr(fetcher.store, "get_source_state", lambda sid: {"etag": '"v1"', "last_payload": None})
    monkeypatch.setattr(fetcher.store, "set_source_state", lambda sid, **kw: None)
    source = Source(id="ubuntu", name="Ubuntu", kind="rss", url="https://example.com/feed")
    client = _FakeFetchClient([
        _response(304, source.url, headers={"etag": '"v1"'}),
        _response(200, source.url, body=_RSS_BODY, headers={"etag": '"v2"'}),
    ])

    items = asyncio.run(fetcher._fetch_rss(source, client))

    assert items and items[0].title.startswith("USN-1")
    assert client.calls[1] == {}  # retried without validators


def test_fetch_all_does_not_serve_samples_when_sources_are_skipped(monkeypatch):
    from app.sources import Source

    async def skipped(source):
        return fetcher.SKIPPED

    monkeypatch.setattr(fetcher, "_fetch_source", skipped)
    monkeypatch.setattr(
        fetcher, "SOURCES",
        [Source(id="ubuntu", name="Ubuntu", kind="rss", url="https://example.com/feed")],
    )

    items, errors = asyncio.run(fetcher.fetch_all())
    assert items == []
    assert errors == []
