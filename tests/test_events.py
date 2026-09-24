"""SSE broker tests (subscriber cap and fan-out)."""

import asyncio

from app.events import Broker


def test_subscribe_returns_none_at_cap():
    broker = Broker(max_subscribers=1)
    first = broker.subscribe()
    assert first is not None
    assert broker.subscribe() is None
    broker.unsubscribe(first)
    assert broker.subscribe() is not None


def test_zero_disables_the_cap():
    broker = Broker(max_subscribers=0)
    assert broker.subscribe() is not None
    assert broker.subscribe() is not None


def test_publish_fans_out_and_drops_when_full():
    broker = Broker(max_subscribers=10)
    queue = broker.subscribe()
    assert queue is not None
    assert asyncio.run(broker.publish({"type": "feed_updated"})) is None
    assert queue.get_nowait() == {"type": "feed_updated"}

    for _ in range(queue.maxsize):
        asyncio.run(broker.publish({"n": 1}))
    assert queue.full()
    # A full subscriber queue is dropped, never raised.
    asyncio.run(broker.publish({"n": 2}))


def test_unsubscribe_is_idempotent():
    broker = Broker(max_subscribers=10)
    queue = broker.subscribe()
    assert queue is not None
    broker.unsubscribe(queue)
    broker.unsubscribe(queue)
    assert not broker.subscribers
