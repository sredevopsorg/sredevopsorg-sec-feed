import asyncio

import pytest
from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount

from app import main
from app.config import Settings
from app.events import Broker
from app.main import api_index, app
from app.ratelimit import RateLimiter


def test_api_is_pure_json_api():
    """The backend no longer serves the frontend (no static/FileResponse routes)."""
    assert not any(isinstance(route, Mount) for route in app.routes)
    assert all(getattr(route, "path", None) != "/" for route in app.routes)


def test_cors_middleware_enabled():
    assert any(
        getattr(mw.cls, "__name__", "") == CORSMiddleware.__name__
        for mw in app.user_middleware
    )


def _request(forwarded_for: str | None = None, peer: str = "203.0.113.9") -> Request:
    headers = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "client": (peer, 4321),
        }
    )


def test_public_read_routes_are_rate_limited():
    """Only /api/search and /api/events carry the rate-limit dependency."""
    limited = {
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
        and any(dep.call is main._rate_limit for dep in route.dependant.dependencies)
    }
    assert limited == {"/api/search", "/api/events"}


def test_rate_limit_dependency_raises_429(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMITER", RateLimiter(1, window_seconds=60))
    request = _request()
    main._rate_limit(request)
    with pytest.raises(HTTPException) as excinfo:
        main._rate_limit(request)
    assert excinfo.value.status_code == 429
    assert excinfo.value.headers["Retry-After"] == "60"


def test_client_key_uses_last_forwarded_hop(monkeypatch):
    # Restore the shipped default: trust the proxy-appended last hop.
    monkeypatch.setattr(main, "settings", Settings.from_env({"RATE_LIMIT_TRUST_PROXY": "true"}))
    # The last hop is appended by our own proxy and cannot be forged.
    assert main._client_key(_request("1.2.3.4, 10.0.0.7")) == "10.0.0.7"
    assert main._client_key(_request()) == "203.0.113.9"


def test_client_key_uses_peer_when_proxy_untrusted(monkeypatch):
    monkeypatch.setattr(main, "settings", Settings.from_env({"RATE_LIMIT_TRUST_PROXY": "false"}))
    assert main._client_key(_request("1.2.3.4, 10.0.0.7")) == "203.0.113.9"


def test_events_returns_503_when_subscriber_cap_reached(monkeypatch):
    full = Broker(max_subscribers=1)
    assert full.subscribe() is not None
    monkeypatch.setattr(main, "broker", full)
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(main.api_events())
    assert excinfo.value.status_code == 503
    assert excinfo.value.headers["Retry-After"] == "30"


def test_api_index_describes_endpoints():
    assert asyncio.run(api_index()) == {
        "name": "Security Intelligence Live Feed API",
        "version": "0.2.0-rc.1",
        "endpoints": [
            "/health",
            "/api/feed",
            "/api/items",
            "/api/stats",
            "/api/search",
            "/api/events",
            "/api/sources",
        ],
    }
