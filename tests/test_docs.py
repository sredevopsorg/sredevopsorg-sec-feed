"""Guards against README drift for documented environment variables.

The project documents every knob in the README tables. When a variable is
documented but no longer read by Settings (or the reverse), operators get a
setting that silently does nothing. This test fails on that mismatch.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CONFIG = ROOT / "app" / "config.py"

# Variables consumed outside Settings (compose, CI, one-shot commands, tests).
NON_CONFIG_VARS = {
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "TEST_DATABASE_URL",
    "ALLOW_REMOTE_TEST_DB",
    "FEED_APP_PASSWORD",
}

# The API table begins with a GET row; an HTTP method is not an env var.
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

_TABLE_VAR = re.compile(r"^\|\s*`([A-Z][A-Z0-9_]+)`")


def documented_env_vars(text: str) -> set[str]:
    names: set[str] = set()
    for line in text.splitlines():
        match = _TABLE_VAR.match(line)
        if match:
            names.add(match.group(1))
    return names


def test_every_documented_env_var_is_read_by_settings():
    documented = documented_env_vars(README.read_text(encoding="utf-8")) - HTTP_METHODS
    assert documented, "the README env tables should not be empty"

    config = CONFIG.read_text(encoding="utf-8")
    missing = sorted(
        name for name in documented - NON_CONFIG_VARS if f'"{name}"' not in config
    )
    assert missing == [], f"documented but not read by app/config.py: {missing}"
