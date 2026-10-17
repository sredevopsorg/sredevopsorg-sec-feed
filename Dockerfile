# Production API image — pure JSON API, runs as a non-root user.
#
# Dependencies are installed from pyproject.toml + uv.lock in a builder stage,
# then only the resulting virtualenv is copied into the runtime stage. Bump
# the Python and uv base images deliberately (Renovate can do this):
#   docker buildx imagetools inspect docker.io/python:3.13-slim
#   docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.13.1
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM docker.io/python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the locked dependency graph into /app/.venv. The app itself is not a
# package (tool.uv.package = false), so --no-install-project is correct.
FROM base AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Runtime stage: the venv only; no uv binary or build cache.
FROM base AS runtime

ENV PATH="/app/.venv/bin:${PATH}"

COPY --from=builder /app/.venv /app/.venv
COPY app ./app
# Versioned schema migrations are applied by `python -m app.migrate upgrade`
# (one-shot compose service / Kubernetes Job), then verified at API startup.
COPY migrations ./migrations

# Persistent SQLite database location (writable by the app user).
RUN mkdir -p /app/data \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin app \
    && chown -R app:app /app

USER app

VOLUME /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
