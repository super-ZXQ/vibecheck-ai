"""PostgreSQL production DATABASE_URL security contract.

SQLite filesystem path security (symlink / traversal under /data) does not
apply to PostgreSQL. Equivalent production risks are invalid schemes,
missing host/db name, and missing credentials.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings, validate_production_database_url


def _prod(url: str) -> Settings:
    return Settings(
        _env_file=None,
        app_env="production",
        production_config_confirmed=True,
        database_url=url,
        cors_allowed_origins=["https://vibecheck.example"],
        trusted_hosts=["127.0.0.1", "vibecheck.example", "testserver"],
    )


class TestValidateProductionDatabaseUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "postgresql+asyncpg://user:pass@127.0.0.1:5432/vibecheck",
            "postgresql://user:pass@db.example:5432/vibecheck",
            "postgres+asyncpg://user:pass@10.0.0.5:5432/vibe",
        ],
    )
    def test_accepts_postgresql_urls(self, url):
        validate_production_database_url(url)
        _prod(url)

    @pytest.mark.parametrize(
        "url,match",
        [
            ("sqlite:////data/vibecheck.db", "postgresql"),
            ("sqlite:///relative.db", "postgresql"),
            ("sqlite:///:memory:", "postgresql"),
            ("http://user:pass@db/vibecheck", "postgresql"),
            ("postgresql://example", "credentials|database name|host"),
            ("postgresql+asyncpg://user@/db", "host"),
            ("postgresql+asyncpg://user:pass@host", "database name"),
        ],
    )
    def test_rejects_invalid_urls(self, url, match):
        with pytest.raises((ValueError, ValidationError), match=match):
            validate_production_database_url(url)
            _prod(url)


class TestVerifyDatabaseListPath:
    """SQLite PRAGMA database_list path check is obsolete for PostgreSQL."""

    def test_verify_is_noop_for_postgresql(self):
        from app.db import database

        assert database._verify_database_list_path(object()) is None

    def test_validate_production_database_path_requires_postgresql(self):
        from app.db import database

        with pytest.raises(ValueError, match="postgresql"):
            database.validate_production_database_path("sqlite:////data/x.db")
        path = database.validate_production_database_path(
            "postgresql+asyncpg://user:pass@h:5432/db"
        )
        assert path is not None
