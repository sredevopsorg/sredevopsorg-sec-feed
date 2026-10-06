# Production API image — pure JSON API, runs as a non-root user.
# Base image pinned by tag *and* digest for reproducibility; bump the digest
# when upgrading Python (Renovate can do this):
#   docker buildx imagetools inspect docker.io/python:3.13-slim
FROM docker.io/python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code.
COPY app ./app

# Persistent SQLite database location (writable by the app user).
RUN mkdir -p /app/data && useradd --uid 10001 --create-home --shell /usr/sbin/nologin app && chown -R app:app /app

USER app

VOLUME /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
