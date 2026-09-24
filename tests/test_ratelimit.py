"""In-process rate limiter tests (app/ratelimit.py)."""

from app.ratelimit import RateLimiter


def test_allows_up_to_limit_then_denies():
    limiter = RateLimiter(2, window_seconds=60)
    assert limiter.check("a", now=0.0) is True
    assert limiter.check("a", now=1.0) is True
    assert limiter.check("a", now=2.0) is False


def test_window_rolls_over():
    limiter = RateLimiter(1, window_seconds=60)
    assert limiter.check("a", now=0.0) is True
    assert limiter.check("a", now=30.0) is False
    assert limiter.check("a", now=60.0) is True


def test_keys_are_isolated():
    limiter = RateLimiter(1)
    assert limiter.check("a", now=0.0) is True
    assert limiter.check("b", now=0.0) is True
    assert limiter.check("a", now=0.1) is False


def test_zero_disables_limiting():
    limiter = RateLimiter(0)
    assert limiter.enabled is False
    for _ in range(5):
        assert limiter.check("a") is True


def test_stale_keys_are_pruned():
    """Rotating keys must not grow the map without bound."""
    limiter = RateLimiter(1, window_seconds=1)
    for i in range(5000):
        assert limiter.check(f"key-{i}", now=float(i)) is True
    assert len(limiter._hits) < 5000
