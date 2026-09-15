import asyncio
from datetime import datetime, timedelta, timezone

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

    monkeypatch.setattr(enrich_module.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    over_cap = [f"CVE-2024-{i:04d}" for i in range(enrich_module.EPSS_MAX_CVES + 25)]

    assert asyncio.run(enrich_module._fetch_epss(over_cap)) == {}
    assert captured["params"]["cve"].count(",") == enrich_module.EPSS_MAX_CVES - 1


def test_is_relevant_filters_only_the_broad_sources():
    from app.sources import Source

    k8s = Source(id="k8s", name="K8s", kind="rss", url="u")
    cisa = Source(id="cisa", name="CISA", kind="rss", url="u")
    ubuntu = Source(id="ubuntu", name="Ubuntu", kind="rss", url="u")

    # The Kubernetes blog also carries release notes and tutorials.
    assert _is_relevant(k8s, "Kubernetes v1.32 release notes") is False
    assert _is_relevant(k8s, "CVE-2025-0001: kubelet vulnerability fixed") is True
    # CISA carries ICS/OT advisories that are off-topic for this feed.
    assert _is_relevant(cisa, "Siemens SIMATIC ICS advisory") is False
    assert _is_relevant(cisa, "Advisory: Kubernetes cluster takeover") is True
    # Topic-scoped sources are never filtered here.
    assert _is_relevant(ubuntu, "USN-7234-1: Linux kernel vulnerabilities") is True
