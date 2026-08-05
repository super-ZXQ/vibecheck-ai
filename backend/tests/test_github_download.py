"""HTTP mock tests for download_tarball — streaming, redirects, and error handling.

ALL network calls are mocked. No real HTTP requests are made.
ALL test data is synthetic — no real credentials or repositories are used.

Test scenarios (9 groups):
1. Normal github.com → codeload.github.com redirect (success)
2. Redirect request does NOT contain Authorization header
3. Redirect to non-whitelisted domain → rejected
4. HTTP/FTP protocol redirect → rejected
5. More than max redirects → rejected
6. Content-Length exceeds limit → early rejection
7. No Content-Length but streaming content exceeds limit → mid-stream abort
8. 404, 403, 429, 500 → specific error messages
9. Download failure → temp file cleaned up
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.github import (
    DownloadResult,
    GitHubDownloadError,
    cleanup_download,
    download_tarball,
)

# --- Mock infrastructure ---

class MockResponse:
    """Simulates an httpx.Response for testing."""

    def __init__(
        self,
        status_code: int = 200,
        headers: dict | None = None,
        content: bytes = b"",
        is_redirect: bool = False,
        stream_chunks: list[bytes] | None = None,
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._content = content
        self.is_redirect = is_redirect
        self._stream_chunks = stream_chunks or ([content] if content else [])
        self._closed = False

    async def aiter_bytes(self, chunk_size=65536):
        """Simulate streaming response."""
        for chunk in self._stream_chunks:
            if self._closed:
                break
            # Respect chunk_size
            for i in range(0, len(chunk), chunk_size):
                yield chunk[i:i + chunk_size]

    def close(self):
        self._closed = True

    async def aclose(self):
        self._closed = True


class MockClient:
    """Simulates httpx.AsyncClient for testing."""

    def __init__(self, responses: list[MockResponse]):
        """responses: list of MockResponse, returned in order for each .get() call."""
        self._responses = list(responses)
        self._call_index = 0
        self.request_log: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url, headers=None, follow_redirects=False):
        """Return the next queued response, logging the request."""
        if self._call_index >= len(self._responses):
            raise RuntimeError("No more mock responses queued")

        response = self._responses[self._call_index]
        self._call_index += 1

        self.request_log.append({
            "url": url,
            "headers": dict(headers) if headers else {},
            "follow_redirects": follow_redirects,
        })

        return response


def make_mock_client(responses: list[MockResponse]) -> MockClient:
    """Create a MockClient with the given responses."""
    return MockClient(responses)


REPO_URL = "https://github.com/testuser/testrepo"

# Synthetic tarball content (not a real archive, just bytes for testing)
SMALL_CONTENT = b"\x1f\x8b\x08\x00" + b"\x00" * 100  # ~104 bytes, fake gzip header


# --- Test 1: Normal redirect from github.com to codeload.github.com ---

class TestNormalRedirectDownload:
    """Test successful download with github.com → codeload.github.com redirect."""

    @pytest.mark.asyncio
    async def test_successful_download_with_redirect(self, tmp_path, monkeypatch):
        """Normal github.com → codeload redirect should download successfully."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 10 * 1024 * 1024)

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "https://codeload.github.com/testuser/testrepo/tar.gz"},
        )
        success_resp = MockResponse(
            status_code=200,
            headers={"content-length": str(len(SMALL_CONTENT))},
            content=SMALL_CONTENT,
        )

        client = make_mock_client([redirect_resp, success_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            result = await download_tarball(REPO_URL)

        assert isinstance(result, DownloadResult)
        assert result.file_size == len(SMALL_CONTENT)
        assert result.temp_file.exists()
        assert result.temp_file.read_bytes() == SMALL_CONTENT
        assert result.repo_info.owner == "testuser"
        assert result.repo_info.repo == "testrepo"

        # Cleanup
        cleanup_download(result.temp_file)
        assert not result.temp_file.exists()


# --- Test 2: Redirect request does NOT contain Authorization ---

class TestAuthHeaderStripping:
    """Test that Authorization is stripped on cross-host redirects."""

    @pytest.mark.asyncio
    async def test_auth_stripped_on_redirect(self, tmp_path, monkeypatch):
        """Authorization header must be removed when redirecting to codeload."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 10 * 1024 * 1024)
        monkeypatch.setattr("app.core.config.settings.github_token", "ghp_synthetic_token")

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "https://codeload.github.com/testuser/testrepo/tar.gz"},
        )
        success_resp = MockResponse(
            status_code=200,
            headers={"content-length": str(len(SMALL_CONTENT))},
            content=SMALL_CONTENT,
        )

        client = make_mock_client([redirect_resp, success_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            result = await download_tarball(REPO_URL)

        # First request (to github.com) should have Authorization
        assert "Authorization" in client.request_log[0]["headers"]

        # Second request (to codeload.github.com) should NOT have Authorization
        assert "Authorization" not in client.request_log[1]["headers"]
        assert "authorization" not in client.request_log[1]["headers"]

        cleanup_download(result.temp_file)


# --- Test 3: Redirect to non-whitelisted domain ---

class TestNonWhitelistedRedirect:
    """Test that redirects to non-whitelisted domains are rejected."""

    @pytest.mark.asyncio
    async def test_redirect_to_evil_domain_rejected(self, tmp_path, monkeypatch):
        """Redirect to evil.com must be rejected."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "https://evil.com/steal/data"},
        )

        client = make_mock_client([redirect_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="disallowed host"):
                await download_tarball(REPO_URL)

        # Temp file should be cleaned up
        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0


# --- Test 4: HTTP/FTP protocol redirect rejected ---

class TestProtocolRedirect:
    """Test that non-HTTPS redirect protocols are rejected."""

    @pytest.mark.asyncio
    async def test_http_redirect_rejected(self, tmp_path, monkeypatch):
        """HTTP redirect (not HTTPS) must be rejected."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "http://codeload.github.com/testuser/testrepo/tar.gz"},
        )

        client = make_mock_client([redirect_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="disallowed"):
                await download_tarball(REPO_URL)

    @pytest.mark.asyncio
    async def test_ftp_redirect_rejected(self, tmp_path, monkeypatch):
        """FTP redirect must be rejected."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "ftp://codeload.github.com/testuser/testrepo/tar.gz"},
        )

        client = make_mock_client([redirect_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="disallowed"):
                await download_tarball(REPO_URL)


# --- Test 5: Too many redirects ---

class TestMaxRedirects:
    """Test that exceeding max redirects is rejected."""

    @pytest.mark.asyncio
    async def test_too_many_redirects(self, tmp_path, monkeypatch):
        """More than 5 redirects must be rejected."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        # Create 7 redirect responses (exceeds max of 5)
        redirects = [
            MockResponse(
                status_code=302,
                is_redirect=True,
                headers={"location": f"https://codeload.github.com/testuser/testrepo/r{i}"},
            )
            for i in range(7)
        ]

        client = make_mock_client(redirects)

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="Too many redirects"):
                await download_tarball(REPO_URL)

        # Temp file should be cleaned up
        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0


# --- Test 6: Content-Length exceeds limit ---

class TestContentLengthExceedsLimit:
    """Test early rejection when Content-Length exceeds limit."""

    @pytest.mark.asyncio
    async def test_content_length_too_large(self, tmp_path, monkeypatch):
        """Content-Length exceeding limit should trigger early rejection."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 1000)

        success_resp = MockResponse(
            status_code=200,
            headers={"content-length": "999999"},  # Way over 1000
            content=b"x" * 100,
        )

        client = make_mock_client([success_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="Content-Length"):
                await download_tarball(REPO_URL)

        # Temp file should be cleaned up
        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0


# --- Test 7: No Content-Length, streaming exceeds limit ---

class TestStreamingExceedsLimit:
    """Test mid-stream abort when no Content-Length and streaming exceeds limit."""

    @pytest.mark.asyncio
    async def test_streaming_exceeds_limit_no_content_length(self, tmp_path, monkeypatch):
        """Without Content-Length, streaming should abort when size exceeds limit."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 200)

        # No content-length header, but content is larger than limit
        large_content = b"\x00" * 500
        success_resp = MockResponse(
            status_code=200,
            headers={},  # No content-length
            content=large_content,
        )

        client = make_mock_client([success_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="streaming"):
                await download_tarball(REPO_URL)

        # Temp file should be cleaned up
        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0


# --- Test 8: HTTP error status codes ---

class TestHttpErrorCodes:
    """Test that HTTP error codes return specific error messages."""

    @pytest.mark.asyncio
    async def test_404_returns_not_found(self, tmp_path, monkeypatch):
        """404 should return 'not found or private' error."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        resp = MockResponse(status_code=404)
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="not found|private"):
                await download_tarball(REPO_URL)

    @pytest.mark.asyncio
    async def test_403_returns_rate_limit(self, tmp_path, monkeypatch):
        """403 should return rate limit or forbidden error."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        resp = MockResponse(status_code=403)
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="rate limit|forbidden"):
                await download_tarball(REPO_URL)

    @pytest.mark.asyncio
    async def test_429_returns_rate_limit(self, tmp_path, monkeypatch):
        """429 should return rate limit error."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        resp = MockResponse(status_code=429)
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="rate limit"):
                await download_tarball(REPO_URL)

    @pytest.mark.asyncio
    async def test_500_returns_download_failed(self, tmp_path, monkeypatch):
        """500 should return generic download failed error."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        resp = MockResponse(status_code=500)
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError, match="HTTP 500"):
                await download_tarball(REPO_URL)


# --- Test 9: Download failure cleans up temp file ---

class TestTempFileCleanup:
    """Test that temp files are cleaned up on download failure."""

    @pytest.mark.asyncio
    async def test_cleanup_on_404(self, tmp_path, monkeypatch):
        """Temp file should be cleaned up after 404 error."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        resp = MockResponse(status_code=404)
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError):
                await download_tarball(REPO_URL)

        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0

    @pytest.mark.asyncio
    async def test_cleanup_on_streaming_abort(self, tmp_path, monkeypatch):
        """Temp file should be cleaned up after streaming size abort."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 100)

        large_content = b"\x00" * 500
        resp = MockResponse(
            status_code=200,
            headers={},
            content=large_content,
        )
        client = make_mock_client([resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError):
                await download_tarball(REPO_URL)

        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0

    @pytest.mark.asyncio
    async def test_cleanup_on_redirect_to_evil(self, tmp_path, monkeypatch):
        """Temp file should be cleaned up after redirect to evil domain."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        redirect_resp = MockResponse(
            status_code=302,
            is_redirect=True,
            headers={"location": "https://evil.com/steal"},
        )
        client = make_mock_client([redirect_resp])

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError):
                await download_tarball(REPO_URL)

        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0

    @pytest.mark.asyncio
    async def test_cleanup_on_max_redirects(self, tmp_path, monkeypatch):
        """Temp file should be cleaned up after too many redirects."""
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))

        redirects = [
            MockResponse(
                status_code=302,
                is_redirect=True,
                headers={"location": f"https://codeload.github.com/testuser/testrepo/r{i}"},
            )
            for i in range(7)
        ]
        client = make_mock_client(redirects)

        with patch("app.core.github.httpx.AsyncClient", return_value=client):
            with pytest.raises(GitHubDownloadError):
                await download_tarball(REPO_URL)

        downloads = list(Path(tmp_path).glob("download-*.tar.gz"))
        assert len(downloads) == 0


# --- Client construction: direct connect vs explicit proxy ---


class TestClientTrustEnv:
    """download_tarball must ignore ambient proxies unless DOWNLOAD_PROXY is set.

    httpx defaults to trust_env=True, which picks up HTTP_PROXY/HTTPS_PROXY
    environment variables that often point at a local proxy that is not
    reachable from the worker process, breaking every download. We force
    trust_env=False (direct connect) unless an explicit DOWNLOAD_PROXY is
    configured.
    """

    def _capture_async_client_kwargs(self, monkeypatch, tmp_path):
        monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path))
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 10 * 1024 * 1024)

        captured: dict = {}

        class RecordingAsyncClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self._inner = make_mock_client([
                    MockResponse(
                        status_code=200,
                        headers={"content-length": str(len(SMALL_CONTENT))},
                        content=SMALL_CONTENT,
                    )
                ])

            async def __aenter__(self):
                return self._inner

            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(
            "app.core.github.httpx.AsyncClient", RecordingAsyncClient
        )
        return captured

    @pytest.mark.asyncio
    async def test_direct_connect_by_default(self, tmp_path, monkeypatch):
        """No DOWNLOAD_PROXY → client is created with trust_env=False and no proxy."""
        captured = self._capture_async_client_kwargs(monkeypatch, tmp_path)
        monkeypatch.setattr("app.core.config.settings.download_proxy", None)

        result = await download_tarball(REPO_URL)
        assert result.temp_file.exists()
        cleanup_download(result.temp_file)

        assert captured.get("trust_env") is False
        assert "proxy" not in captured

    @pytest.mark.asyncio
    async def test_explicit_proxy_is_used(self, tmp_path, monkeypatch):
        """DOWNLOAD_PROXY set → client passes proxy AND keeps trust_env=False."""
        captured = self._capture_async_client_kwargs(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "app.core.config.settings.download_proxy",
            "http://127.0.0.1:8080",
        )

        result = await download_tarball(REPO_URL)
        assert result.temp_file.exists()
        cleanup_download(result.temp_file)

        assert captured.get("trust_env") is False
        assert captured.get("proxy") == "http://127.0.0.1:8080"
