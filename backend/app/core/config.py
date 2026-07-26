"""VibeCheck configuration — all security limits, timeouts, and thresholds.

Sensitive values (GitHub Token, LLM API Key) are read from environment variables
and NEVER hardcoded. This module is the single source of truth for all limits.
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- GitHub download ---
    github_token: str | None = None  # Optional, read from env GITHUB_TOKEN
    download_timeout: int = 60  # seconds
    allowed_redirect_hosts: list[str] = [
        "github.com",
        "codeload.github.com",
    ]

    # --- Archive size limits (enforced during download & extraction) ---
    max_archive_size: int = 50 * 1024 * 1024  # 50 MB compressed
    max_extracted_total_size: int = 200 * 1024 * 1024  # 200 MB total
    max_file_count: int = 2000  # max number of files
    max_single_file_size: int = 10 * 1024 * 1024  # 10 MB per file

    # --- Scan limits ---
    scan_timeout: int = 120  # seconds
    scan_concurrency: int = 1  # single worker, low concurrency
    # No line limit: files under scan_max_file_size are scanned in full.
    # Removing max_line_read prevents missing secrets in later lines.
    scan_max_file_size: int = 1024 * 1024  # 1 MB — skip files larger than this
    # Safety bound: each rule may return at most this many Findings per
    # file. Prevents result amplification from files containing thousands
    # of format-correct tokens. When the limit is reached the rule stops
    # building Findings but never returns raw secret content.
    scan_max_findings_per_rule_per_file: int = 100

    @field_validator("scan_max_findings_per_rule_per_file")
    @classmethod
    def enforce_min_findings_limit(cls, v: int) -> int:
        """Ensure the per-rule finding limit is at least 1.

        A limit of 0 would silently disable ALL detection for every rule,
        which is never the intended configuration. Clamp to 1 so at least
        one finding per rule per file is always retained.
        """
        return max(1, v)

    scan_ignore_dirs: list[str] = [
        "node_modules", ".next", "dist", "build", "coverage",
        "__pycache__", ".git", "vendor", ".venv", "venv",
        ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    ]

    # --- Persisted result limits (P0-5) ---
    # Task-level caps on what gets persisted, NOT on what gets scanned.
    # P0-4 per-rule/per-file limits remain unchanged.
    # These prevent unbounded result_json from consuming database space.
    scan_max_persisted_findings_per_task: int = 1000
    scan_max_persisted_notices_per_task: int = 500
    scan_max_persisted_skipped_files_per_task: int = 2000
    scan_max_persisted_scan_errors_per_task: int = 500
    scan_max_result_json_bytes: int = 8 * 1024 * 1024  # 8 MB
    scan_binary_extensions: list[str] = [
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
        ".pyc", ".pyo", ".class", ".jar", ".war",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flv",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".sqlite", ".db", ".db3", ".s3db",
    ]

    # --- LLM ---
    llm_timeout: int = 30  # seconds
    llm_api_key: str | None = None  # read from env LLM_API_KEY

    # --- Temp directory ---
    tmp_dir: str = "/tmp/vibecheck"  # isolated temp root

    # --- Database ---
    database_url: str = "sqlite:///./vibecheck.db"

    # --- Task queue ---
    max_pending_tasks: int = 5  # max pending tasks in queue
    max_running_tasks: int = 1  # only 1 task runs at a time (MVP)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
