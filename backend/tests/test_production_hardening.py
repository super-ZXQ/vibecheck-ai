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
    import app.db.database as database

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

    def test_production_rejects_default_database_path(self):
        with pytest.raises(ValidationError, match="persistent path"):
            Settings(
                _env_file=None,
                app_env="production",
                production_config_confirmed=True,
            )

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

        response = TestClient(production_app).get("/docs")
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
