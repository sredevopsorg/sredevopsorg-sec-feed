from datetime import datetime, timezone

from app.fetcher import FeedItem
from app.search import _doc_from_item, _hit_to_item, _index_mappings


def test_index_mappings_types():
    props = _index_mappings()["mappings"]["properties"]
    assert props["severity"]["type"] == "keyword"
    assert props["tags"]["type"] == "keyword"
    assert props["cves"]["type"] == "keyword"
    assert props["urgent"]["type"] == "boolean"
    assert props["published"]["type"] == "date"


def test_doc_from_item_omits_time_ago():
    item = FeedItem(
        id="a",
        title="t",
        summary="s",
        url="u",
        source="src",
        source_url="su",
        published=datetime.now(timezone.utc),
        tags={"linux"},
        cves=["CVE-2024-0001"],
        severity="high",
        urgent=True,
        patch_status="fixed",
    )
    doc = _doc_from_item(item)
    assert "time_ago" not in doc
    assert doc["id"] == "a"
    assert doc["tags"] == ["linux"]
    assert doc["patch_status"] == "fixed"


def test_hit_to_item_adds_time_ago():
    source = {
        "id": "a",
        "title": "t",
        "published": "2025-01-01T12:00:00+00:00",
        "severity": "high",
        "tags": ["linux"],
        "cves": ["CVE-2024-0001"],
    }
    item = _hit_to_item(source)
    assert item["severity"] == "high"
    assert item["tags"] == ["linux"]
    assert "time_ago" in item
    assert item["time_ago"]  # non-empty for a past date
