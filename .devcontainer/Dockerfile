# Development image (not shipped to production). Adds git/dev tooling and the
# test dependencies; runs as root for convenient source mounts and hot reload.
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# Keeps the container alive for VS Code to attach. The dev compose override
# runs `uvicorn --reload` for plain `docker compose up`.
CMD ["sleep", "infinity"]
