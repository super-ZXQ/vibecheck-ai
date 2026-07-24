"""GitHub repository URL validation and safe tarball download.

Security guarantees:
- Only accepts github.com/owner/repo standard URLs.
- Download redirects only allowed to github.com and codeload.github.com.
- Archive size checked before returning to caller.
- Never executes any code from the downloaded repository.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.core.config import settings


class GitHubDownloadError(Exception):
    """Raised when URL validation or download fails."""


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    repo: str
    url: str


# --- URL validation ---

_GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?)/"
    r"([A-Za-z0-9._-]+?)(?:\.git)?/?$"
)


def parse_repo_url(url: str) -> RepoInfo:
    """Parse and validate a GitHub repository URL.

    Only accepts: https://github.com/{owner}/{repo}
    Rejects: non-github URLs, SSH URLs, URLs with query/fragment,
             URLs with extra path segments, private repo indicators.
    """
    if not url or not isinstance(url, str):
        raise GitHubDownloadError("URL is required")

    url = url.strip()

    # Reject non-https schemes
    if not url.startswith("https://"):
        raise GitHubDownloadError("Only HTTPS URLs are accepted")

    parsed = urlparse(url)

    # Host must be exactly github.com
    if parsed.hostname != "github.com":
        raise GitHubDownloadError(
            f"Only github.com URLs are accepted, got: {parsed.hostname}"
        )

    # No query parameters or fragments
    if parsed.query or parsed.fragment:
        raise GitHubDownloadError("URL must not contain query parameters or fragments")

    # Match against strict pattern
    match = _GITHUB_URL_PATTERN.match(url)
    if not match:
        raise GitHubDownloadError(
            "Invalid GitHub URL format. Expected: https://github.com/{owner}/{repo}"
        )

    owner = match.group(1)
    repo = match.group(2)

    # Reject obvious non-repo paths (check both owner and repo)
    reserved = {"settings", "orgs", "users", "search", "explore", "topics",
                "trending", "collections", "events", "sponsors", "marketplace",
                "new", "notifications", "login", "signup", "sessions", "about",
                "pricing", "security", "customer-stories", "readme", "enterprise"}
    if owner.lower() in reserved:
        raise GitHubDownloadError(f"'{owner}' is a reserved path, not a repository owner")
    if repo.lower() in reserved:
        raise GitHubDownloadError(f"'{repo}' is not a valid repository name")

    return RepoInfo(owner=owner, repo=repo, url=url)


def is_allowed_redirect(redirect_url: str) -> bool:
    """Check if a redirect URL points to an allowed host with an allowed scheme."""
    try:
        parsed = urlparse(redirect_url)
        if parsed.scheme not in ("https", "http"):
            return False
        return parsed.hostname in settings.allowed_redirect_hosts
    except Exception:
        return False


# --- Tarball download ---


async def download_tarball(repo_url: str) -> bytes:
    """Download a public GitHub repository as a tarball.

    Returns the raw tarball bytes.
    Raises GitHubDownloadError on any failure.

    Security:
    - Redirects are followed manually, each checked against allowed hosts.
    - Archive size is checked against MAX_ARCHIVE_SIZE.
    - No code from the repository is ever executed.
    """
    repo_info = parse_repo_url(repo_url)

    # Use github.com tarball endpoint (redirects to codeload.github.com)
    tarball_url = f"https://github.com/{repo_info.owner}/{repo_info.repo}/tarball"

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VibeCheck/0.1",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    timeout = httpx.Timeout(settings.download_timeout, connect=10.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(
            tarball_url, headers=headers, follow_redirects=False
        )

        # Follow redirects manually with host checking
        redirect_count = 0
        max_redirects = 5

        while response.is_redirect:
            redirect_count += 1
            if redirect_count > max_redirects:
                raise GitHubDownloadError("Too many redirects")

            redirect_url = response.headers.get("location", "")
            if not redirect_url:
                raise GitHubDownloadError("Redirect response missing Location header")

            if not is_allowed_redirect(redirect_url):
                # Extract host for error message without exposing full redirect URL
                parsed = urlparse(redirect_url)
                raise GitHubDownloadError(
                    f"Redirect to disallowed host: {parsed.hostname}"
                )

            response = await client.get(
                redirect_url, headers=headers, follow_redirects=False
            )

        # Check HTTP status
        if response.status_code == 404:
            raise GitHubDownloadError(
                "Repository not found, does not exist, or is private"
            )
        if response.status_code == 403:
            raise GitHubDownloadError(
                "GitHub API rate limit exceeded, please try again later"
            )
        if response.status_code == 429:
            raise GitHubDownloadError(
                "GitHub API rate limit exceeded, please try again later"
            )
        if response.status_code != 200:
            raise GitHubDownloadError(
                f"Download failed: HTTP {response.status_code}"
            )

        content = response.content

        # Check archive size
        if len(content) > settings.max_archive_size:
            raise GitHubDownloadError(
                f"Archive too large: {len(content)} bytes "
                f"(limit: {settings.max_archive_size} bytes)"
            )

        return content
