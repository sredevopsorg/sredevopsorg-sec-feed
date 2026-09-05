import asyncio

from app import fetcher, pipeline
from app.models import FeedItem
from app.sources import Source


def make_item(id: str) -> FeedItem:
    return FeedItem(
        id=id,
        title="title",
        summary="summary",
        url="https://example.com/" + id,
        source="test",
        source_url="https://example.com/feed",
        published=None,
        tags={"linux"},
        cves=["CVE-2024-0001"],
        severity="high",
        urgent=False,
    )


def test_pipeline_exposes_cache_and_public_api():
    assert isinstance(pipeline.CACHE, pipeline.FeedCache)
    assert callable(pipeline.refresh_feed)
    assert callable(pipeline.get_feed)


def test_fetch_all_returns_items_and_errors(monkeypatch):
    async def fake_fetch(source: Source):
        if source.id == "boom":
            raise RuntimeError("network down")
        return [make_item(f"{source.id}-{i}") for i in range(5)]

    monkeypatch.setattr(fetcher, "_fetch_source", fake_fetch)
    monkeypatch.setattr(
        fetcher,
        "SOURCES",
        [
            Source(id="ok", name="OK", kind="rss", url="u"),
            Source(id="boom", name="BOOM", kind="rss", url="u"),
        ],
    )

    items, errors = asyncio.run(fetcher.fetch_all())

    assert any(item.id == "ok-0" for item in items)
    assert not any(item.is_sample for item in items)  # >= 4 live items -> no samples
    assert any("boom" in error for error in errors)


def test_fetch_all_falls_back_to_samples_when_empty(monkeypatch):
    async def fake_fetch(source: Source):
        raise RuntimeError("down")

    monkeypatch.setattr(fetcher, "_fetch_source", fake_fetch)
    monkeypatch.setattr(fetcher, "SOURCES", [Source(id="boom", name="BOOM", kind="rss", url="u")])

    items, errors = asyncio.run(fetcher.fetch_all())

    assert items and all(item.is_sample for item in items)
    assert errors
