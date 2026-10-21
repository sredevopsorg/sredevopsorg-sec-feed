import pytest

from app.config import Settings, _bool, settings


def test_settings_defaults():
    s = Settings.from_env({})
    assert s.database_url is None
    assert s.admin_database_url is None
    assert s.sqlite_db_path.endswith("/data/feed.db")
    assert s.opensearch_url is None
    assert s.opensearch_index == "security-feed"
    assert s.cors_origins == ()
    assert s.log_level == "INFO"
    assert s.smtp_port == 587
    assert s.alert_from == "security-feed@example.com"
    assert s.db_pool_min_size == 1
    assert s.db_pool_max_size == 4
    assert s.db_pool_timeout == 30.0
    assert s.db_pool_max_idle == 600.0
    assert s.db_pool_max_lifetime == 3600.0
    assert s.db_prepare_threshold is None
    assert s.db_connect_timeout == 10
    assert s.db_sslmode == "prefer"
    assert s.db_sslrootcert is None
    assert s.db_application_name == "security-feed"
    assert s.db_statement_timeout_ms == 15000
    assert s.db_idle_tx_timeout_ms == 30000
    assert s.db_lock_timeout_ms == 5000
    assert s.rate_limit_per_minute == 120
    assert s.rate_limit_trust_proxy is True
    assert s.max_sse_subscribers == 100
    assert s.nvd_window_days == 7
    assert s.kev_source_days == 7
    assert s.feed_cache_ttl == 600
    assert s.retention_days == 180
    assert s.epss_max_cves == 200
    assert s.osv_max_cves_per_run == 50


def test_settings_cors_denies_by_default():
    """CORS fails closed unless an explicit allow-list is configured."""
    assert Settings.from_env({}).cors_origins == ()
    assert Settings.from_env({"CORS_ORIGINS": "*"}).cors_origins == ("*",)


def test_settings_rate_limit_overrides():
    s = Settings.from_env({
        "RATE_LIMIT_PER_MINUTE": "0",
        "RATE_LIMIT_TRUST_PROXY": "false",
        "MAX_SSE_SUBSCRIBERS": "5",
    })
    assert s.rate_limit_per_minute == 0
    assert s.rate_limit_trust_proxy is False
    assert s.max_sse_subscribers == 5
    # An invalid rate falls back to the default rather than breaking startup.
    assert Settings.from_env({"RATE_LIMIT_PER_MINUTE": "nope"}).rate_limit_per_minute == 120


def test_bool_parsing():
    assert _bool(None) is False
    assert _bool(None, True) is True
    for truthy in ("1", "true", "TRUE", "yes", "on", " On "):
        assert _bool(truthy) is True
    for falsy in ("0", "false", "no", "off", ""):
        assert _bool(falsy) is False


def test_settings_csv_parsing():
    s = Settings.from_env({"CORS_ORIGINS": " https://a.example.com , https://b.example.com ,, "})
    assert s.cors_origins == ("https://a.example.com", "https://b.example.com")


def test_settings_int_parsing():
    assert Settings.from_env({"SMTP_PORT": "2525"}).smtp_port == 2525
    assert Settings.from_env({"SMTP_PORT": "not-a-number"}).smtp_port == 587


def test_settings_db_pool_parsing():
    s = Settings.from_env({
        "DB_POOL_MIN_SIZE": "2",
        "DB_POOL_MAX_SIZE": "8",
        "DB_PREPARE_THRESHOLD": "5",
        "DB_CONNECT_TIMEOUT": "30",
        "DB_SSLMODE": "require",
        "DB_APPLICATION_NAME": "feed-api",
    })
    assert s.db_pool_min_size == 2
    assert s.db_pool_max_size == 8
    assert s.db_prepare_threshold == 5
    assert s.db_connect_timeout == 30
    assert s.db_sslmode == "require"
    assert s.db_application_name == "feed-api"


def test_settings_db_prepare_threshold_optional():
    assert Settings.from_env({}).db_prepare_threshold is None
    assert Settings.from_env({"DB_PREPARE_THRESHOLD": ""}).db_prepare_threshold is None
    assert Settings.from_env({"DB_PREPARE_THRESHOLD": "not-a-number"}).db_prepare_threshold is None
    assert Settings.from_env({"DB_PREPARE_THRESHOLD": "0"}).db_prepare_threshold == 0


def test_settings_source_windows_parsing():
    s = Settings.from_env({"NVD_WINDOW_DAYS": "3", "KEV_SOURCE_DAYS": "14"})
    assert s.nvd_window_days == 3
    assert s.kev_source_days == 14
    assert Settings.from_env({"NVD_WINDOW_DAYS": "nope"}).nvd_window_days == 7


def test_settings_refresh_and_retention_parsing():
    s = Settings.from_env({
        "FEED_CACHE_TTL": "120",
        "RETENTION_DAYS": "30",
        "EPSS_MAX_CVES": "50",
        "OSV_MAX_CVES_PER_RUN": "10",
    })
    assert s.feed_cache_ttl == 120
    assert s.retention_days == 30
    assert s.epss_max_cves == 50
    assert s.osv_max_cves_per_run == 10
    # A TTL below the floor would hammer upstreams; retention 0 disables.
    assert Settings.from_env({"FEED_CACHE_TTL": "1"}).feed_cache_ttl == 30
    assert Settings.from_env({"RETENTION_DAYS": "-5"}).retention_days == 0


def test_settings_optional_values():
    s = Settings.from_env({
        "DATABASE_URL": "postgresql://u:p@host/db",
        "OPENSEARCH_URL": "http://os:9200",
        "GITHUB_TOKEN": "tok",
        "DISCORD_WEBHOOK_URL": "https://discord.example.com",
    })
    assert s.database_url == "postgresql://u:p@host/db"
    assert s.opensearch_url == "http://os:9200"
    assert s.github_token == "tok"
    assert s.discord_webhook_url == "https://discord.example.com"


def test_modules_read_config_from_settings():
    """Search and alerts consume the central Settings object."""
    from app import alerts, search

    assert search.OPENSEARCH_URL is settings.opensearch_url
    assert search.INDEX_NAME == settings.opensearch_index
    assert alerts.DISCORD_WEBHOOK_URL is settings.discord_webhook_url
    assert alerts.SMTP_PORT == settings.smtp_port


def test_remote_database_requires_ssl():
    """A remote DSN must not silently fall back to plaintext (libpq 'prefer')."""
    with pytest.raises(ValueError, match="plaintext"):
        Settings.from_env({"DATABASE_URL": "postgresql://u:p@db.example.com:5432/feed"})

    s = Settings.from_env({
        "DATABASE_URL": "postgresql://u:p@db.example.com:5432/feed",
        "DB_SSLMODE": "require",
    })
    assert s.db_sslmode == "require"

    # Local service names and loopback keep the convenient default.
    for host in ("postgres", "localhost", "127.0.0.1", "db"):
        assert Settings.from_env({"DATABASE_URL": f"postgresql://u:p@{host}:5432/feed"}).db_sslmode == "prefer"


def test_admin_database_url_is_validated_too():
    with pytest.raises(ValueError, match="plaintext"):
        Settings.from_env({"ADMIN_DATABASE_URL": "postgresql://u:p@db.example.com:5432/feed"})
    s = Settings.from_env({
        "ADMIN_DATABASE_URL": "postgresql://u:p@db.example.com:5432/feed",
        "DB_SSLMODE": "verify-full",
    })
    assert s.admin_database_url.endswith("/feed")


def test_settings_db_timeout_and_pool_parsing():
    s = Settings.from_env({
        "DB_POOL_TIMEOUT": "12.5",
        "DB_POOL_MAX_IDLE": "120",
        "DB_POOL_MAX_LIFETIME": "900",
        "DB_STATEMENT_TIMEOUT_MS": "7000",
        "DB_IDLE_TX_TIMEOUT_MS": "20000",
        "DB_LOCK_TIMEOUT_MS": "3000",
    })
    assert s.db_pool_timeout == 12.5
    assert s.db_pool_max_idle == 120.0
    assert s.db_pool_max_lifetime == 900.0
    assert s.db_statement_timeout_ms == 7000
    assert s.db_idle_tx_timeout_ms == 20000
    assert s.db_lock_timeout_ms == 3000
    # Negative timeouts are meaningless; clamp to "disabled".
    assert Settings.from_env({"DB_STATEMENT_TIMEOUT_MS": "-1"}).db_statement_timeout_ms == 0


def test_settings_rejects_invalid_pool_bounds():
    with pytest.raises(ValueError, match="POOL"):
        Settings.from_env({"DB_POOL_MIN_SIZE": "5", "DB_POOL_MAX_SIZE": "2"})
    with pytest.raises(ValueError, match="POOL"):
        Settings.from_env({"DB_POOL_MAX_SIZE": "0"})


def test_settings_sslrootcert_must_exist(tmp_path):
    with pytest.raises(ValueError, match="DB_SSLROOTCERT"):
        Settings.from_env({
            "DB_SSLROOTCERT": str(tmp_path / "missing.pem"),
            "DB_SSLMODE": "verify-full",
        })
    cert = tmp_path / "ca.pem"
    cert.write_text("placeholder")
    s = Settings.from_env({"DB_SSLROOTCERT": str(cert), "DB_SSLMODE": "verify-full"})
    assert s.db_sslrootcert == str(cert)
