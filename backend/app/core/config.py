"""VibeCheck configuration — all security limits, timeouts, and thresholds.

Sensitive values (GitHub Token, LLM API Key) are read from environment variables
and NEVER hardcoded. This module is the single source of truth for all limits.
"""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Runtime environment ---
    app_env: Literal["development", "test", "production"] = "development"
    production_config_confirmed: bool = False

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
    # All limits must be positive integers (ge=1). A limit of 0 would
    # silently disable ALL persistence for that collection type, and a
    # negative limit would cause incorrect slice behavior (items[:-1]).
    scan_max_persisted_findings_per_task: int = Field(default=1000, ge=1)
    scan_max_persisted_notices_per_task: int = Field(default=500, ge=1)
    scan_max_persisted_skipped_files_per_task: int = Field(default=2000, ge=1)
    scan_max_persisted_scan_errors_per_task: int = Field(default=500, ge=1)
    scan_max_result_json_bytes: int = Field(default=8 * 1024 * 1024, ge=1)

    # --- Assessment limits (P0-6) ---
    # Technical size limits for assessment results. These are NOT policy
    # values — they do not affect scoring. They prevent unbounded
    # assessment_json from consuming database space.
    # assessment_max_blocking_reasons: max items in blocking_reasons list.
    # assessment_max_json_bytes: max serialized assessment_json size.
    assessment_max_blocking_reasons: int = Field(default=100, ge=1)
    assessment_max_json_bytes: int = Field(default=2 * 1024 * 1024, ge=1)

    # --- Repair plan limits (P0-7) ---
    # Technical size limits for repair plan results. These are NOT policy
    # values — they do not affect action mapping, action priority, fixed
    # safety texts, blocking repair order, or agent prompt safety
    # constraints. They prevent unbounded repair_json from consuming
    # database space.
    # Runtime clamping via max(1, int(value)) ensures that even if the
    # config object is erroneously modified to 0 or negative at runtime,
    # the engine still functions correctly.
    repair_max_groups: int = Field(default=200, ge=1)
    repair_max_related_files_per_group: int = Field(default=100, ge=1)
    repair_max_agent_prompt_chars: int = Field(default=65536, ge=1)
    repair_max_json_bytes: int = Field(default=2 * 1024 * 1024, ge=1)

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

    # --- CORS (P0-8) ---
    # Only the configured origins are allowed. The wildcard "*" is
    # explicitly forbidden. Origins come from the CORS_ALLOWED_ORIGINS
    # environment variable (JSON array string) or the default list.
    cors_allowed_origins: list[str] = [
        "http://localhost:3000",
    ]
    trusted_hosts: list[str] = [
        "localhost",
        "127.0.0.1",
        "testserver",
    ]

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def validate_cors_allowed_origins(cls, value: object) -> list[str]:
        """Accept only a non-empty, deterministic list of pure HTTP origins."""
        if not isinstance(value, list) or not value:
            raise ValueError("cors_allowed_origins must be a non-empty list")

        origins: list[str] = []
        seen: set[str] = set()
        for origin in value:
            if (
                not isinstance(origin, str)
                or not origin
                or origin != origin.strip()
                or any(char.isspace() for char in origin)
            ):
                raise ValueError("each CORS origin must be a non-empty string")
            if origin == "*":
                raise ValueError("wildcard CORS origin is forbidden")

            parsed = urlsplit(origin)
            try:
                parsed.port
            except ValueError as exc:
                raise ValueError("CORS origin has an invalid port") from exc

            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or origin != f"{parsed.scheme}://{parsed.netloc}"
            ):
                raise ValueError("CORS entries must be pure HTTP(S) origins")

            if origin not in seen:
                seen.add(origin)
                origins.append(origin)

        return origins

    @field_validator("trusted_hosts", mode="before")
    @classmethod
    def validate_trusted_hosts(cls, value: object) -> list[str]:
        """Allow only an explicit non-empty host list; never trust all hosts."""
        if not isinstance(value, list) or not value:
            raise ValueError("trusted_hosts must be a non-empty list")

        hosts: list[str] = []
        seen: set[str] = set()
        for host in value:
            if (
                not isinstance(host, str)
                or not host
                or host != host.strip()
                or any(char.isspace() for char in host)
                or host == "*"
                or "://" in host
                or "/" in host
                or "@" in host
            ):
                raise ValueError("each trusted host must be an explicit host name")
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        """Fail closed when production starts with development defaults."""
        if self.app_env != "production":
            return self

        if not self.production_config_confirmed:
            raise ValueError(
                "production_config_confirmed must be true in production"
            )
        if self.database_url == "sqlite:///./vibecheck.db":
            raise ValueError(
                "production database_url must use an explicit persistent path"
            )
        if "*" in self.trusted_hosts:
            raise ValueError("wildcard trusted host is forbidden in production")
        if "127.0.0.1" not in self.trusted_hosts:
            raise ValueError(
                "production trusted_hosts must include 127.0.0.1"
            )

        for origin in self.cors_allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError(
                    "production CORS origins must use HTTPS except localhost"
                )

        return self

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
