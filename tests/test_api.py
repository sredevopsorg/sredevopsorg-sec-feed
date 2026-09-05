import asyncio

from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount

from app.main import api_index, app


def test_api_is_pure_json_api():
    """The backend no longer serves the frontend (no static/FileResponse routes)."""
    assert not any(isinstance(route, Mount) for route in app.routes)
    assert all(getattr(route, "path", None) != "/" for route in app.routes)


def test_cors_middleware_enabled():
    assert any(
        getattr(mw.cls, "__name__", "") == CORSMiddleware.__name__
        for mw in app.user_middleware
    )


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
