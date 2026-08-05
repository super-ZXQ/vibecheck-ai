"""GitHub repository URL validation and safe tarball download.

Security guarantees:
- Only accepts github.com/owner/repo standard URLs.
- Download redirects only allowed to github.com and codeload.github.com via HTTPS.
- Cross-host redirects strip Authorization, Cookie, and all auth headers.
- Streaming download: chunk-by-chunk size check, never loads full archive in memory.
- Content-Length used for early rejection only; streaming accumulation is authoritative.
- Downloaded content written directly to an isolated temp file.
- On any failure, temp file is deleted via try/finally.
- Never executes any code from the downloaded repository.
"""

import logging
import os
import re
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class GitHubDownloadError(Exception):
    """Raised when URL validation or download fails.

    ``code`` (optional) carries a machine-readable category so callers can
    classify the failure without parsing the message text. The message is
    never derived from repository content (avoids leaking repo names and
    keeps substring-based classification reliable).
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    repo: str
    url: str


@dataclass
class DownloadResult:
    """Result of a tarball download — path to the temp file containing the archive."""
    temp_file: Path
    repo_info: RepoInfo
    file_size: int


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
    """Check if a redirect URL points to an allowed host via HTTPS only."""
    try:
        parsed = urlparse(redirect_url)
        if parsed.scheme != "https":
            return False
        return parsed.hostname in settings.allowed_redirect_hosts
    except Exception:
        return False


# --- Auth header management ---

# Headers that must be stripped when crossing host boundaries
_AUTH_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie",
    "proxy-authorization", "x-api-key", "x-auth-token",
})


def _strip_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with all auth-related headers removed."""
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _AUTH_HEADERS
    }


def _build_initial_headers() -> dict[str, str]:
    """Build headers for the initial request to github.com."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VibeCheck/0.1",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


# --- Streaming download ---


def _remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree — force-remove read-only files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def _safe_remove_tree(path: Path) -> bool:
    """Remove a directory tree, handling read-only files. Returns True on success.

    On persistent failure, logs an error message without sensitive content
    (file paths in temp dirs are not considered sensitive).
    """
    if not path.exists():
        return True
    try:
        shutil.rmtree(path, onerror=_remove_readonly)
        if path.exists():
            logger.error(
                "Failed to fully clean up temp directory: %s "
                "(some files may remain)", path
            )
            return False
        return True
    except Exception as e:
        logger.error(
            "Failed to clean up temp directory: %s (error: %s, no sensitive content)",
            path, type(e).__name__
        )
        return False


def _safe_remove_file(path: Path) -> bool:
    """Remove a single file, handling read-only. Returns True on success.

    On failure, logs an error message without sensitive content.
    """
    if not path.exists():
        return True
    try:
        os.chmod(str(path), stat.S_IWRITE)
        os.remove(str(path))
        return True
    except Exception as e:
        logger.error(
            "Failed to clean up temp file: %s (error: %s, no sensitive content)",
            path, type(e).__name__
        )
        return False


async def download_tarball(repo_url: str) -> DownloadResult:
    """Download a public GitHub repository tarball via streaming.

    Downloads directly to an isolated temp file with chunk-by-chunk size
    enforcement. Never holds the full archive in memory.

    Security:
    - Streaming: accumulates bytes, aborts immediately when MAX_ARCHIVE_SIZE exceeded.
    - Content-Length checked for early rejection only (not authoritative).
    - Redirects followed manually; cross-host redirects strip auth headers.
    - Only HTTPS redirects allowed.
    - Max 5 redirects.
    - Temp file cleaned up on any failure via try/finally.
    - No code from the repository is ever executed.

    Returns:
        DownloadResult with path to temp file (caller must clean up).

    Raises:
        GitHubDownloadError on any failure.
    """
    repo_info = parse_repo_url(repo_url)

    tarball_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/tarball"
    headers = _build_initial_headers()
    timeout = httpx.Timeout(settings.download_timeout, connect=10.0)

    # Create isolated temp file
    tmp_root = Path(settings.tmp_dir)
    tmp_root.mkdir(parents=True, exist_ok=True)
    task_id = uuid.uuid4().hex[:12]
    temp_file = tmp_root / f"download-{task_id}.tar.gz"

    download_succeeded = False
    total_written = 0

    try:
        # Download directly, ignoring ambient HTTP_PROXY/HTTPS_PROXY env vars
        # (which often point at a local proxy that is unreachable from this
        # process). An explicit DOWNLOAD_PROXY opt-in is honored instead.
        client_kwargs: dict = {"timeout": timeout, "trust_env": False}
        if settings.download_proxy:
            client_kwargs["proxy"] = settings.download_proxy
        async with httpx.AsyncClient(**client_kwargs) as client:
            current_url = tarball_url
            current_headers = headers
            redirect_count = 0
            max_redirects = 5

            while True:
                response = await client.get(
                    current_url, headers=current_headers, follow_redirects=False
                )

                # Handle redirects
                if response.is_redirect:
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise GitHubDownloadError(
                            f"Too many redirects (max {max_redirects})"
                        )

                    redirect_url = response.headers.get("location", "")
                    if not redirect_url:
                        raise GitHubDownloadError(
                            "Redirect response missing Location header"
                        )

                    if not is_allowed_redirect(redirect_url):
                        parsed = urlparse(redirect_url)
                        raise GitHubDownloadError(
                            f"Redirect to disallowed host or scheme: "
                            f"{parsed.scheme}://{parsed.hostname}"
                        )

                    # Strip auth headers when crossing host boundaries
                    redirect_parsed = urlparse(redirect_url)
                    original_parsed = urlparse(current_url)
                    if redirect_parsed.hostname != original_parsed.hostname:
                        current_headers = _strip_auth_headers(current_headers)

                    current_url = redirect_url
                    await response.aclose()
                    continue

                # Check HTTP status codes
                if response.status_code == 404:
                    raise GitHubDownloadError(
                        "Repository not found, does not exist, or is private",
                        code="REPOSITORY_NOT_FOUND",
                    )
                if response.status_code == 403:
                    raise GitHubDownloadError(
                        "GitHub API rate limit exceeded or access forbidden",
                        code="GITHUB_RATE_LIMITED",
                    )
                if response.status_code == 429:
                    raise GitHubDownloadError(
                        "GitHub API rate limit exceeded, please try again later",
                        code="GITHUB_RATE_LIMITED",
                    )
                if response.status_code != 200:
                    raise GitHubDownloadError(
                        f"Download failed: HTTP {response.status_code}",
                        code="DOWNLOAD_FAILED",
                    )

                # Early rejection via Content-Length (advisory only)
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        cl = int(content_length)
                        if cl > settings.max_archive_size:
                            raise GitHubDownloadError(
                                f"Archive too large (Content-Length): {cl} bytes "
                                f"(limit: {settings.max_archive_size} bytes)",
                                code="DOWNLOAD_TOO_LARGE",
                            )
                    except ValueError:
                        pass  # Malformed Content-Length, rely on streaming check

                # Streaming download with cumulative size enforcement
                with open(temp_file, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        total_written += len(chunk)
                        if total_written > settings.max_archive_size:
                            raise GitHubDownloadError(
                                f"Archive too large during streaming: "
                                f"{total_written} bytes "
                                f"(limit: {settings.max_archive_size} bytes)",
                                code="DOWNLOAD_TOO_LARGE",
                            )
                        f.write(chunk)

                download_succeeded = True
                break

    except GitHubDownloadError:
        raise
    except httpx.TimeoutException:
        raise GitHubDownloadError(
            f"Download timed out after {settings.download_timeout}s",
            code="DOWNLOAD_FAILED",
        )
    except httpx.ConnectError:
        raise GitHubDownloadError(
            "Connection to GitHub failed",
            code="DOWNLOAD_FAILED",
        )
    except Exception:
        raise GitHubDownloadError(
            "Download failed",
            code="DOWNLOAD_FAILED",
        )
    finally:
        if not download_succeeded:
            _safe_remove_file(temp_file)

    if not download_succeeded:
        raise GitHubDownloadError("Download failed for unknown reason")

    return DownloadResult(
        temp_file=temp_file,
        repo_info=repo_info,
        file_size=total_written,
    )


def cleanup_download(temp_file: Path) -> None:
    """Clean up a downloaded temp file. Safe to call multiple times."""
    _safe_remove_file(temp_file)
