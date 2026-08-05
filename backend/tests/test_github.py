"""Tests for GitHub URL validation and redirect host checking.

These tests do NOT make real network requests.
They test URL parsing, validation, and redirect host checking only.
"""

import pytest

from app.core.github import GitHubDownloadError, is_allowed_redirect, parse_repo_url

# --- Valid URL tests ---

class TestParseRepoUrl:
    """Test GitHub URL parsing and validation."""

    @pytest.mark.parametrize("url,owner,repo", [
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World"),
        ("https://github.com/microsoft/vscode", "microsoft", "vscode"),
        ("https://github.com/user/repo.with.dots", "user", "repo.with.dots"),
        ("https://github.com/user/repo-with-dashes", "user", "repo-with-dashes"),
        ("https://github.com/user/repo/", "user", "repo"),
        ("https://github.com/user/repo.git", "user", "repo"),
        ("https://github.com/User123/My_Repo", "User123", "My_Repo"),
    ])
    def test_valid_urls(self, url, owner, repo):
        """Valid GitHub URLs should parse correctly."""
        result = parse_repo_url(url)
        assert result.owner == owner
        assert result.repo == repo
        assert result.url == url

    @pytest.mark.parametrize("url", [
        "",  # empty
        None,  # None
        123,  # non-string
        "not a url",
        "ftp://github.com/user/repo",  # non-https
        "http://github.com/user/repo",  # http not https
        "git@github.com:user/repo.git",  # SSH
        "https://gitlab.com/user/repo",  # non-github
        "https://github.com/user/repo?branch=main",  # query params
        "https://github.com/user/repo#section",  # fragment
        "https://github.com/user",  # missing repo
        "https://github.com/",  # missing owner and repo
        "https://github.com/user/repo/extra/path",  # extra path
        "https://github.com/settings/profile",  # reserved word
        "https://github.com/users/octocat",  # reserved word
        "https://github.com/search?q=test",  # reserved word with query
        "https://github.com/orgs/microsoft",  # reserved word
    ])
    def test_invalid_urls(self, url):
        """Invalid URLs should raise GitHubDownloadError."""
        with pytest.raises(GitHubDownloadError):
            parse_repo_url(url)

    def test_url_is_stripped(self):
        """URLs with leading/trailing whitespace should be handled."""
        result = parse_repo_url("  https://github.com/user/repo  ")
        assert result.owner == "user"
        assert result.repo == "repo"


class TestIsAllowedRedirect:
    """Test redirect host and scheme checking — HTTPS only."""

    @pytest.mark.parametrize("url", [
        "https://github.com/user/repo/tarball",
        "https://codeload.github.com/user/repo/tar.gz",
        "https://codeload.github.com/some/path",
    ])
    def test_allowed_hosts(self, url):
        """HTTPS redirects to github.com and codeload.github.com should be allowed."""
        assert is_allowed_redirect(url) is True

    @pytest.mark.parametrize("url", [
        "https://evil.com/path",
        "https://attacker.com/github.com",
        "https://github.com.evil.com/path",
        "http://github.com/some/path",  # HTTP not allowed for redirects
        "http://codeload.github.com/some/path",  # HTTP not allowed
        "ftp://codeload.github.com/path",  # FTP not allowed
        "not a url",
        "",
    ])
    def test_disallowed_hosts(self, url):
        """Non-HTTPS or non-allowed hosts should be rejected."""
        assert is_allowed_redirect(url) is False


class TestStripAuthHeaders:
    """Test that auth headers are properly stripped on cross-host redirects."""

    def test_strips_authorization(self):
        from app.core.github import _strip_auth_headers
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer ghp_test",
            "User-Agent": "VibeCheck/0.1",
        }
        result = _strip_auth_headers(headers)
        assert "Authorization" not in result
        assert "authorization" not in result
        assert result["Accept"] == "application/json"
        assert result["User-Agent"] == "VibeCheck/0.1"

    def test_strips_cookie(self):
        from app.core.github import _strip_auth_headers
        headers = {
            "Cookie": "session=abc123",
            "Authorization": "Bearer token",
        }
        result = _strip_auth_headers(headers)
        assert "Cookie" not in result
        assert "Authorization" not in result

    def test_strips_all_auth_variants(self):
        from app.core.github import _strip_auth_headers
        headers = {
            "authorization": "Bearer lower",
            "COOKIE": "session=x",
            "X-API-Key": "key123",
            "X-Auth-Token": "token456",
            "Proxy-Authorization": "Basic xyz",
        }
        result = _strip_auth_headers(headers)
        assert len(result) == 0

    def test_preserves_non_auth_headers(self):
        from app.core.github import _strip_auth_headers
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/octet-stream",
            "User-Agent": "VibeCheck/0.1",
        }
        result = _strip_auth_headers(headers)
        assert result == headers
