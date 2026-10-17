# Contributing to the Security Intelligence Live Feed

Thanks for taking the time to contribute. This repository is a FastAPI-backed
security feed for Linux, cloud, and Kubernetes content, with a dependency-free
static frontend.

## Table of contents

- [I have a question](#i-have-a-question)
- [Reporting bugs](#reporting-bugs)
- [Suggesting enhancements](#suggesting-enhancements)
- [Development setup](#development-setup)
- [Dependencies](#dependencies)
- [Tests](#tests)
- [Pull requests](#pull-requests)
- [Code style](#code-style)
- [Security](#security)
- [License](#license)

## I have a question

Read [README.md](README.md), [docs/architecture.md](docs/architecture.md), and
the [ADRs](docs/adr/) first. If the answer is not there, search the
[issue tracker](https://github.com/sredevopsorg/sredevopsorg-sec-feed/issues)
and open a new issue with as much context as possible.

## Reporting bugs

Before filing:

- Reproduce against the latest `main`.
- Check whether the problem is a configuration issue (see `.env.example`,
  `README.md`, and the environment-variable tables).
- Search existing issues.

Include the OS, container runtime, Python/uv version, the exact command you
ran, the expected and actual behavior, and relevant logs. Do **not** report
security vulnerabilities in public issues; see [Security](#security).

## Suggesting enhancements

Open an issue describing the current behavior, the proposed change, and why it
is useful for this project. Keep the scope focused; discuss large changes in an
issue before opening a pull request.

## Development setup

Container-first development is the default:

```bash
cp .env.example .env   # then set POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB
docker compose up --build
```

- UI: <http://localhost:8080>
- API: <http://localhost:8000> (also reachable at `/api` through the UI origin)

For host development, install [uv](https://docs.astral.sh/uv/) 0.13.1 or newer
and Python 3.13:

```bash
uv sync --frozen
uv run --frozen uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The frontend is plain HTML/CSS/JS in `frontend/`; serve it with any static file
server and point `window.__API_BASE_URL__` at the API. Do not add npm,
bundlers, or CDN scripts.

## Dependencies

Direct dependencies are declared in `pyproject.toml`. The full resolved and
hash-pinned graph is committed in `uv.lock`; `requirements*.txt` files are no
longer used.

To update dependencies:

1. Edit the relevant pin in `pyproject.toml`.
2. Run `uv lock` (or `uv lock --upgrade` to refresh transitives).
3. Run `uv lock --check`, `uv sync --frozen`, and the test suite.
4. Run the runtime audit (CI does this in the `audit` job):

   ```bash
   uv sync --frozen --no-dev
   uvx --from pip-audit==2.10.1 pip-audit \
     --path .venv/lib/python3.13/site-packages --strict
   uv sync --frozen
   ```

5. Commit `pyproject.toml` and `uv.lock` together.

Never hand-edit `uv.lock`, and do not install packages ad hoc into the project
environment. Renovate raises dependency and image-digest updates; lock-file
maintenance refreshes transitives.

## Tests

```bash
uv sync --frozen
uv run --frozen pytest -q
```

The Postgres adapter tests skip unless `TEST_DATABASE_URL` is set. CI provides
a disposable PostgreSQL 16 service; locally you can run one with Docker:

```bash
docker run --rm -d --name sec-feed-test-pg \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=feed_test \
  -p 5433:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5433/feed_test \
  uv run --frozen pytest -q
```

Frontend edits should pass `node --check frontend/app.js`.

## Pull requests

- Target `main`. CI runs on pull requests and pushes to `main`; both must be
  green.
- A stacked PR (base = another feature branch) must be retargeted to `main` as
  soon as its base merges.
- Keep changes focused, update tests and docs with behavior changes, and
  describe how you verified the change.
- Update the README sources/API/schema tables and AGENTS.md when behavior,
  ports, invariants, or the feed-item contract change.

## Code style

There is no linter or formatter configured. Keep Python PEP 8-ish and
readable; use type hints and `from __future__ import annotations` where the
surrounding module does. Keep SQL parameterized and search wildcards escaped.
Prefer the existing module boundaries and the `Storage` port over new
abstractions.

## Security

Report vulnerabilities privately to **devsecops@sredevops.org** as described in
[SECURITY.md](SECURITY.md). Never open a public issue with exploit details or
credentials.

## License

By contributing, you agree that your contribution is licensed under the
project's MIT license (see [LICENSE](LICENSE)).

## Attribution

This guide is based on **contributing-gen**.
[Make your own](https://github.com/bttger/contributing-gen)!
