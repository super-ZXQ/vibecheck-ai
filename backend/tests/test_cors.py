"""CORS middleware tests — P0-8.

Verifies the FastAPI CORSMiddleware configuration:
1. Allowed origin receives Access-Control-Allow-Origin header
2. Disallowed origin does NOT receive Allow-Origin header
3. OPTIONS preflight returns correct headers
4. Only GET, POST, OPTIONS methods are allowed
5. Only Content-Type and Accept headers are allowed
6. allow_credentials is False — Access-Control-Allow-Credentials
   header must NOT be present (not asserted as the string "false")
7. Wildcard "*" is never used regardless of configuration
8. Health endpoint works with CORS headers for allowed origin
"""

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Set up a temporary test database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    import app.db.database as database
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(test_db):
    """Create a TestClient with the test database."""
    from app.main import app
    with TestClient(app) as c:
        yield c


ALLOWED_ORIGIN = "http://localhost:3000"
DISALLOWED_ORIGIN = "http://evil.example.com"


# ===========================================================================
# Tests
# ===========================================================================

class TestCorsAllowedOrigin:
    """CORS headers for allowed origins."""

    def test_get_allowed_origin_returns_cors_header(self, client):
        """GET from an allowed origin includes Access-Control-Allow-Origin."""
        response = client.get(
            "/api/health",
            headers={"Origin": ALLOWED_ORIGIN},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN

    def test_get_allowed_origin_no_credentials_header(self, client):
        """allow_credentials=False — the credentials header must NOT exist.

        We assert the header is absent, not that it equals "false".
        """
        response = client.get(
            "/api/health",
            headers={"Origin": ALLOWED_ORIGIN},
        )
        assert response.status_code == 200
        assert "access-control-allow-credentials" not in {
            k.lower() for k in response.headers.keys()
        }

    def test_post_allowed_origin_returns_cors_header(self, client):
        """POST from an allowed origin includes Access-Control-Allow-Origin."""
        response = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/test/repo"},
            headers={"Origin": ALLOWED_ORIGIN},
        )
        # May be 202 (created) or 429 (queue full) — either way CORS header
        # should be present for allowed origin
        assert response.status_code in (202, 429)
        assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


class TestCorsDisallowedOrigin:
    """CORS headers for disallowed origins."""

    def test_get_disallowed_origin_no_allow_origin(self, client):
        """GET from a disallowed origin does NOT include Allow-Origin."""
        response = client.get(
            "/api/health",
            headers={"Origin": DISALLOWED_ORIGIN},
        )
        assert response.status_code == 200
        allow_origin = response.headers.get("access-control-allow-origin")
        assert allow_origin is None or allow_origin != DISALLOWED_ORIGIN

    def test_get_no_origin_no_cors_headers(self, client):
        """GET without Origin header does not include CORS headers."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") is None


class TestCorsPreflight:
    """OPTIONS preflight request handling."""

    def test_options_preflight_allowed_origin(self, client):
        """OPTIONS preflight from allowed origin returns correct headers."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
        # Methods header should include GET, POST, OPTIONS
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "GET" in allow_methods
        assert "POST" in allow_methods
        assert "OPTIONS" in allow_methods

    def test_options_preflight_disallowed_origin(self, client):
        """OPTIONS preflight from disallowed origin returns 400."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": DISALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 400

    def test_options_preflight_no_credentials_header(self, client):
        """OPTIONS preflight must NOT include Allow-Credentials header."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-credentials" not in {
            k.lower() for k in response.headers.keys()
        }


class TestCorsAllowedMethods:
    """Verify only GET, POST, OPTIONS are allowed."""

    def test_allowed_methods_include_get_post_options(self, client):
        """Preflight response lists GET, POST, OPTIONS."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        allow_methods = response.headers.get("access-control-allow-methods", "")
        methods = [m.strip() for m in allow_methods.split(",")]
        assert "GET" in methods
        assert "POST" in methods
        assert "OPTIONS" in methods

    def test_allowed_methods_exclude_delete_put_patch(self, client):
        """DELETE, PUT, PATCH must NOT be in allowed methods."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "DELETE" not in allow_methods
        assert "PUT" not in allow_methods
        assert "PATCH" not in allow_methods


class TestCorsAllowedHeaders:
    """Verify only Content-Type and Accept headers are allowed."""

    def test_preflight_allows_content_type(self, client):
        """Preflight requesting Content-Type returns it in Allow-Headers."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200
        allow_headers = response.headers.get("access-control-allow-headers", "")
        assert "content-type" in allow_headers.lower()

    def test_preflight_allows_accept(self, client):
        """Preflight requesting Accept returns it in Allow-Headers."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Accept",
            },
        )
        assert response.status_code == 200
        allow_headers = response.headers.get("access-control-allow-headers", "")
        assert "accept" in allow_headers.lower()


class TestCorsNoWildcard:
    """Verify wildcard '*' is never used."""

    def test_no_wildcard_in_allow_origin(self, client):
        """Allow-Origin is never '*' — always the specific origin."""
        response = client.get(
            "/api/health",
            headers={"Origin": ALLOWED_ORIGIN},
        )
        assert response.status_code == 200
        allow_origin = response.headers.get("access-control-allow-origin")
        assert allow_origin != "*"
        assert allow_origin == ALLOWED_ORIGIN

    def test_default_config_has_no_wildcard(self):
        """The default settings must not contain '*' in cors_allowed_origins."""
        from app.core.config import settings
        assert "*" not in settings.cors_allowed_origins
        assert "http://localhost:3000" in settings.cors_allowed_origins
