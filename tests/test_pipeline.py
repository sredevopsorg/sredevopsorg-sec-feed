import asyncio
import contextlib
import time

import httpx
import pytest

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


# ---------------------------------------------------------------------------
# Source failures: actionable reporting and the transport-error retry
# ---------------------------------------------------------------------------


def test_describe_fetch_error_keeps_the_exception_detail():
    source = Source(id="boom", name="BOOM", kind="rss", url="https://example.com/feed")

    assert fetcher._describe_fetch_error(source, RuntimeError("network down")) == (
        "boom: RuntimeError: network down"
    )


def test_describe_fetch_error_names_the_host_when_the_message_is_empty():
    """A blackholed connection raises ConnectTimeout with an empty message.

    httpx re-raises httpcore's connect failures without a message, which used
    to render as a dangling colon in the UI ("debian: ConnectTimeout: ").
    """
    source = Source(
        id="debian", name="Debian", kind="rss", url="https://www.debian.org/security/dsa"
    )

    assert fetcher._describe_fetch_error(source, httpx.ConnectTimeout("")) == (
        "debian: ConnectTimeout reaching www.debian.org"
    )


def test_describe_fetch_error_falls_back_to_the_cause_chain():
    """When the outer exception is blank, the underlying reason is reported."""
    exc = httpx.ConnectError("")
    exc.__cause__ = OSError("Network is unreachable")
    source = Source(
        id="ossf-malicious",
        name="OpenSSF",
        kind="ossf-malicious",
        url="https://api.github.com/repos/ossf/malicious-packages",
    )

    assert fetcher._describe_fetch_error(source, exc) == (
        "ossf-malicious: ConnectError: Network is unreachable"
    )


def test_describe_fetch_error_hides_cancel_scope_noise():
    """anyio's deadline message embeds a memory address; do not leak it."""
    exc = httpx.ConnectTimeout("")
    exc.__cause__ = TimeoutError(
        "Cancelled via cancel scope 0x7f75352420d0; reason: deadline exceeded"
    )
    source = Source(
        id="debian", name="Debian", kind="rss", url="https://www.debian.org/security/dsa"
    )

    assert fetcher._describe_fetch_error(source, exc) == (
        "debian: ConnectTimeout reaching www.debian.org"
    )


def test_fetch_source_retries_a_transport_failure(monkeypatch):
    """One retry turns an intermittent connect failure into a good refresh."""
    monkeypatch.setattr(fetcher, "FETCH_RETRY_DELAY", 0)
    attempts = {"n": 0}

    async def flaky(source):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("All connection attempts failed")
        return [make_item(f"{source.id}-0")]

    monkeypatch.setattr(fetcher, "_fetch_source_once", flaky)
    source = Source(
        id="debian", name="Debian", kind="rss", url="https://www.debian.org/security/dsa"
    )

    items = asyncio.run(fetcher._fetch_source(source))

    assert attempts["n"] == 2
    assert [item.id for item in items] == ["debian-0"]


def test_fetch_source_does_not_retry_an_http_error_response(monkeypatch):
    """A 4xx/5xx is the source's answer; retrying would double our rate."""
    monkeypatch.setattr(fetcher, "FETCH_RETRY_DELAY", 0)
    attempts = {"n": 0}

    async def forbidden(source):
        attempts["n"] += 1
        request = httpx.Request("GET", source.url)
        response = httpx.Response(403, request=request)
        raise httpx.HTTPStatusError("403 Forbidden", request=request, response=response)

    monkeypatch.setattr(fetcher, "_fetch_source_once", forbidden)
    source = Source(
        id="ossf-malicious",
        name="OpenSSF",
        kind="ossf-malicious",
        url="https://api.github.com/repos/ossf/malicious-packages",
    )

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(fetcher._fetch_source(source))

    assert attempts["n"] == 1


def test_fetch_all_reports_an_empty_transport_failure_with_its_host(monkeypatch):
    """End to end: the message the frontend renders is actionable."""

    async def blackholed(source):
        raise httpx.ConnectTimeout("")

    monkeypatch.setattr(fetcher, "_fetch_source", blackholed)
    monkeypatch.setattr(
        fetcher,
        "SOURCES",
        [
            Source(
                id="debian",
                name="Debian",
                kind="rss",
                url="https://www.debian.org/security/dsa",
            )
        ],
    )

    _, errors = asyncio.run(fetcher.fetch_all())

    assert errors == ["debian: ConnectTimeout reaching www.debian.org"]
