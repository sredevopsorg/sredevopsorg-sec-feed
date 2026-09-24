from app.config import Settings, _bool, settings


def test_settings_defaults():
    s = Settings.from_env({})
    assert s.database_url is None
    assert s.sqlite_db_path.endswith("/data/feed.db")
    assert s.opensearch_url is None
    assert s.opensearch_index == "security-feed"
    assert s.cors_origins == ()
    assert s.log_level == "INFO"
    assert s.smtp_port == 587
    assert s.alert_from == "security-feed@example.com"
    assert s.db_pool_min_size == 1
    assert s.db_pool_max_size == 4
    assert s.db_prepare_threshold is None
    assert s.db_connect_timeout == 10
    assert s.db_sslmode == "prefer"
    assert s.db_application_name == "security-feed"
    assert s.rate_limit_per_minute == 120
    assert s.rate_limit_trust_proxy is True
    assert s.max_sse_subscribers == 100


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
    """Search, alerts, and OSSF consume the central Settings object."""
    from app import alerts, ossf, search

    assert search.OPENSEARCH_URL is settings.opensearch_url
    assert search.INDEX_NAME == settings.opensearch_index
    assert alerts.DISCORD_WEBHOOK_URL is settings.discord_webhook_url
    assert alerts.SMTP_PORT == settings.smtp_port
    assert ossf.GITHUB_TOKEN is settings.github_token
