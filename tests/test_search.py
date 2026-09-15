import asyncio
import json
from datetime import datetime, timezone

import httpx

from app.fetcher import FeedItem
from app.search import _bulk, _doc_from_item, _hit_to_item, _index_mappings, _needs_sample_purge


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
    assert doc["is_sample"] is False  # indexed so sample rows can be filtered/purged
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


def test_needs_sample_purge_only_when_live_rows_exist():
    """Sample documents must not survive once the archive has live rows."""
    assert _needs_sample_purge([]) is False
    assert _needs_sample_purge([{"is_sample": True}, {"is_sample": True}]) is False
    assert _needs_sample_purge([{"is_sample": True}, {"is_sample": False}]) is True


def test_bulk_posts_ndjson_documents(monkeypatch):
    import app.search as search_module

    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, content=None, headers=None):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(search_module, "OPENSEARCH_URL", "http://os:9200")
    monkeypatch.setattr(search_module, "INDEX_NAME", "security-feed")
    # Patch the shared transport entry point, so the test keeps working
    # whether or not the module builds its own httpx client.
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())

    docs = [{"id": "a", "title": "t", "published": datetime.now(timezone.utc), "is_sample": False}]
    assert asyncio.run(_bulk(docs)) == 1

    lines = captured["content"].strip().split("\n")
    assert lines[0] == '{"index": {"_index": "security-feed", "_id": "a"}}'
    assert json.loads(lines[1])["id"] == "a"
    assert captured["headers"] == {"Content-Type": "application/x-ndjson"}
