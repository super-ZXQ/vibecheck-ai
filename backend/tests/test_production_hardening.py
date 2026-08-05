"""Production configuration, readiness, host, and response-header gates."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.main as main_module
from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Initialize the global database service against an isolated file."""
    db_path = tmp_path / "production-hardening.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url",
        f"sqlite:///{db_path}",
    )
    from app.db import database

    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


def make_production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "production",
        "production_config_confirmed": True,
        "database_url": "sqlite:////data/vibecheck.db",
        "cors_allowed_origins": ["https://vibecheck.example"],
        "trusted_hosts": ["127.0.0.1", "vibecheck.example", "testserver"],
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


class TestStrictProductionConfiguration:
    def test_production_requires_explicit_confirmation(self):
        with pytest.raises(ValidationError, match="production_config_confirmed"):
            Settings(
                _env_file=None,
                app_env="production",
                database_url="sqlite:////data/vibecheck.db",
            )

    @pytest.mark.parametrize(
        "database_url",
        [
            "sqlite:///relative.db",
            "sqlite:///./relative.db",
            "sqlite:///../escape.db",
            "sqlite:////tmp/vibecheck.db",
            "sqlite:////data/../tmp/vibecheck.db",
            "sqlite:////data",
            "sqlite:///:memory:",
            "postgresql://example",
        ],
    )
    def test_production_rejects_non_persistent_database_urls(
        self,
        database_url,
    ):
        with pytest.raises(ValidationError, match="SQLite .db file under /data"):
            make_production_settings(database_url=database_url)

    @pytest.mark.parametrize(
        "database_url",
        [
            "sqlite:////data/vibecheck.db",
            "sqlite:////data/vibecheck-production.db",
        ],
    )
    def test_production_accepts_persistent_database_urls(self, database_url):
        configured = make_production_settings(database_url=database_url)
        assert configured.database_url == database_url

    def test_development_keeps_relative_sqlite_path(self):
        configured = Settings(
            _env_file=None,
            app_env="development",
            database_url="sqlite:///./vibecheck.db",
        )
        assert configured.database_url == "sqlite:///./vibecheck.db"

    def test_production_rejects_remote_http_cors_origin(self):
        with pytest.raises(ValidationError, match="must use HTTPS"):
            make_production_settings(
                cors_allowed_origins=["http://vibecheck.example"],
            )

    def test_trusted_hosts_rejects_wildcard(self):
        with pytest.raises(ValidationError, match="explicit host name"):
            make_production_settings(trusted_hosts=["*"])

    def test_production_requires_loopback_healthcheck_host(self):
        with pytest.raises(ValidationError, match="must include 127.0.0.1"):
            make_production_settings(
                trusted_hosts=["vibecheck.example"],
            )

    def test_production_accepts_loopback_and_public_hosts(self):
        configured = make_production_settings(
            trusted_hosts=["127.0.0.1", "vibecheck.example.com"],
        )
        assert configured.trusted_hosts == [
            "127.0.0.1",
            "vibecheck.example.com",
        ]

    def test_localhost_http_is_available_for_local_production_verification(self):
        configured = make_production_settings(
            cors_allowed_origins=["http://localhost:3000"],
            trusted_hosts=["localhost", "127.0.0.1", "testserver"],
        )
        assert configured.app_env == "production"


class TestProductionApplicationSurface:
    def test_production_disables_documentation_endpoints(self):
        production_app = create_app(make_production_settings())
        assert production_app.docs_url is None
        assert production_app.redoc_url is None
        assert production_app.openapi_url is None

        client = TestClient(production_app)
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = client.get(path)
            assert response.status_code == 404

    def test_untrusted_host_is_rejected(self):
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get(
            "/api/health",
            headers={"Host": "attacker.example"},
        )
        assert response.status_code == 400

    def test_loopback_healthcheck_host_is_accepted(self, test_db):
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get(
            "/api/ready",
            headers={"Host": "127.0.0.1"},
        )
        assert response.status_code == 200

    def test_security_headers_are_present_on_api_and_error_responses(self):
        production_app = create_app(make_production_settings())
        client = TestClient(production_app)

        for path in ("/api/health", "/does-not-exist"):
            response = client.get(path)
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert response.headers["permissions-policy"] == (
                "camera=(), microphone=(), geolocation=(), payment=()"
            )
            assert "default-src 'none'" in response.headers[
                "content-security-policy"
            ]
            assert response.headers["strict-transport-security"] == (
                "max-age=31536000; includeSubDomains"
            )

    def test_cors_allows_only_configured_origin_without_credentials(self):
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).options(
            "/api/check",
            headers={
                "Origin": "https://vibecheck.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Accept",
            },
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == (
            "https://vibecheck.example"
        )
        assert "access-control-allow-credentials" not in response.headers
        allowed_methods = response.headers["access-control-allow-methods"]
        assert set(allowed_methods.split(", ")) == {"GET", "POST", "OPTIONS"}
        allowed_headers = response.headers["access-control-allow-headers"].lower()
        assert "content-type" in allowed_headers
        assert "accept" in allowed_headers
        assert "authorization" not in allowed_headers

    def test_cors_does_not_allow_unconfigured_origin(self):
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).options(
            "/api/check",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
            },
        )

        assert "access-control-allow-origin" not in response.headers

    def test_invalid_input_responses_do_not_echo_sensitive_values(self, test_db):
        production_app = create_app(make_production_settings())
        client = TestClient(production_app)
        sensitive_url = (
            "https://" + "sample-user" + ":" + "sample-pass"
            + "@github.com/owner/repository"
        )

        invalid_repo = client.post(
            "/api/check",
            json={"repo_url": sensitive_url},
        )
        invalid_task = client.get("/api/check/not-a-task-id")

        assert invalid_repo.status_code == 400
        assert invalid_repo.json()["detail"]["error_code"] == "INVALID_REPO_URL"
        assert sensitive_url not in invalid_repo.text
        assert invalid_task.status_code == 422
        assert invalid_task.json()["detail"]["error_code"] == "INVALID_TASK_ID"
        assert "not-a-task-id" not in invalid_task.text
        combined = (invalid_repo.text + invalid_task.text).lower()
        for forbidden in (
            "traceback",
            "exception",
            "sample-user",
            "sample-pass",
            "/app/",
            "c:\\",
        ):
            assert forbidden not in combined


class TestReadiness:
    def test_ready_when_database_schema_is_initialized(self, test_db):
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get("/api/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}

    def test_not_ready_response_is_fixed_and_safe(self, monkeypatch):
        def fail_readiness() -> None:
            raise RuntimeError("sensitive internal database detail")

        monkeypatch.setattr(
            main_module,
            "check_database_ready",
            fail_readiness,
        )
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get("/api/ready")

        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert "sensitive" not in response.text

    @pytest.mark.parametrize(
        "missing_table",
        [
            "tasks",
            "scan_results",
            "assessment_results",
            "repair_results",
        ],
    )
    def test_not_ready_when_required_table_is_missing(
        self,
        test_db,
        missing_table,
    ):
        from app.db import database

        conn = database._get_connection()
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute(f"DROP TABLE {missing_table}")
            conn.commit()
        finally:
            conn.close()

        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get("/api/ready")

        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert missing_table not in response.text

    def test_not_ready_when_database_connection_fails(self, monkeypatch):
        def fail_readiness() -> None:
            raise OSError("C:\\sensitive\\database\\path")

        monkeypatch.setattr(
            main_module,
            "check_database_ready",
            fail_readiness,
        )
        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get("/api/ready")

        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert "sensitive" not in response.text

    def test_not_ready_when_database_is_corrupt(self, test_db):
        test_db.write_bytes(b"not a sqlite database")

        production_app = create_app(make_production_settings())
        response = TestClient(production_app).get("/api/ready")

        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert "sqlite" not in response.text.lower()
