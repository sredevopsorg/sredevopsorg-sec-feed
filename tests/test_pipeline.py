import asyncio
import contextlib
import time

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
    assert callable(pipeline.schedule_refresh)
    assert callable(pipeline.refresh_in_flight)


def test_feed_cache_does_not_copy_items():
    """The cache holds refresh metadata; items are read from the store."""
    assert not hasattr(pipeline.FeedCache(), "items")


def _reset_pipeline(monkeypatch):
    monkeypatch.setattr(pipeline, "CACHE", pipeline.FeedCache())
    monkeypatch.setattr(pipeline, "_REFRESH_TASK", None)


def _stub_downstream(monkeypatch):
    """Keep refresh_feed() off the network and off the real store."""

    async def identity(items):
        return items

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(pipeline, "_enrich", identity)
    monkeypatch.setattr(pipeline, "_persist", lambda items: None)
    monkeypatch.setattr(pipeline, "_index", noop)
    monkeypatch.setattr(pipeline, "_publish", noop)
    monkeypatch.setattr(pipeline, "_alert", noop)


def test_get_feed_never_blocks_on_a_refresh(monkeypatch):
    async def slow_fetch_all():
        await asyncio.sleep(5)
        return [], []

    _reset_pipeline(monkeypatch)
    _stub_downstream(monkeypatch)
    monkeypatch.setattr(fetcher, "fetch_all", slow_fetch_all)

    async def scenario():
        started = time.monotonic()
        cache = await pipeline.get_feed()
        elapsed = time.monotonic() - started
        in_flight = pipeline.refresh_in_flight()
        task = pipeline._REFRESH_TASK
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return cache, elapsed, in_flight

    cache, elapsed, in_flight = asyncio.run(scenario())

    assert cache.generated_at is None  # nothing was awaited
    assert elapsed < 0.2
    assert in_flight is True


def test_get_feed_schedules_a_single_refresh(monkeypatch):
    calls = {"n": 0}

    async def counting_fetch_all():
        calls["n"] += 1
        await asyncio.sleep(0.2)
        return [], []

    _reset_pipeline(monkeypatch)
    _stub_downstream(monkeypatch)
    monkeypatch.setattr(fetcher, "fetch_all", counting_fetch_all)

    async def scenario():
        await asyncio.gather(*(pipeline.get_feed() for _ in range(5)))
        await asyncio.sleep(0.05)
        task = pipeline._REFRESH_TASK
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return calls["n"]

    assert asyncio.run(scenario()) == 1


def test_completed_refresh_clears_the_in_flight_handle(monkeypatch):
    calls = {"n": 0}

    async def fast_fetch_all():
        calls["n"] += 1
        return [], []

    _reset_pipeline(monkeypatch)
    _stub_downstream(monkeypatch)
    monkeypatch.setattr(fetcher, "fetch_all", fast_fetch_all)

    async def scenario():
        assert pipeline.schedule_refresh() is True
        await pipeline._REFRESH_TASK
        await asyncio.sleep(0)  # let the done-callback run
        after_first = pipeline.refresh_in_flight()
        assert pipeline.schedule_refresh() is True
        await pipeline._REFRESH_TASK
        return after_first, calls["n"]

    after_first, total = asyncio.run(scenario())
    assert after_first is False
    assert total == 2


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
