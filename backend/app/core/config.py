"""VibeCheck configuration — all security limits, timeouts, and thresholds.

Sensitive values (GitHub Token, LLM API Key) are read from environment variables
and NEVER hardcoded. This module is the single source of truth for all limits.
"""

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
    max_line_read: int = 5000  # only read first N lines per file
    scan_max_file_size: int = 1024 * 1024  # 1 MB — skip files larger than this
    scan_ignore_dirs: list[str] = [
        "node_modules", ".next", "dist", "build", "coverage",
        "__pycache__", ".git", "vendor", ".venv", "venv",
        ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    ]
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
