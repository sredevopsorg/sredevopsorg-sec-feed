import pytest

from app.fetcher import (
    CVE_RE,
    _dedupe,
    _extract_cves,
    _infer_severity,
    _infer_tags,
    _sample_items,
    _time_ago,
    FeedItem,
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
