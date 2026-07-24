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

    # --- LLM ---
    llm_timeout: int = 30  # seconds
    llm_api_key: str | None = None  # read from env LLM_API_KEY

    # --- Temp directory ---
    tmp_dir: str = "/tmp/vibecheck"  # isolated temp root

    # --- Database ---
    database_url: str = "sqlite:///./vibecheck.db"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
