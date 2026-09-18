"""Failure categories, retry policy, and backoff helpers for background tasks.

User-facing API error_code values stay desensitized and stable. Failure
categories are internal classification used for retry decisions and metrics
labels (never repo_url / task_id / secrets).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from app.core.config import settings

# --- Failure categories (internal) ---

DOWNLOAD_TIMEOUT = "DOWNLOAD_TIMEOUT"
GITHUB_RATE_LIMITED = "GITHUB_RATE_LIMITED"
GITHUB_TEMPORARY_ERROR = "GITHUB_TEMPORARY_ERROR"
DOWNLOAD_TOO_LARGE = "DOWNLOAD_TOO_LARGE"
INVALID_REPOSITORY = "INVALID_REPOSITORY"
INVALID_ARCHIVE = "INVALID_ARCHIVE"
EXTRACTION_LIMIT_EXCEEDED = "EXTRACTION_LIMIT_EXCEEDED"
SCAN_TIMEOUT = "SCAN_TIMEOUT"
TEMP_STORAGE_EXHAUSTED = "TEMP_STORAGE_EXHAUSTED"
LLM_RATE_LIMITED = "LLM_RATE_LIMITED"
LLM_TIMEOUT = "LLM_TIMEOUT"
LLM_INVALID_RESPONSE = "LLM_INVALID_RESPONSE"
INTERNAL_TRANSIENT = "INTERNAL_TRANSIENT"
INTERNAL_PERMANENT = "INTERNAL_PERMANENT"

ALL_CATEGORIES: frozenset[str] = frozenset(
    {
        DOWNLOAD_TIMEOUT,
        GITHUB_RATE_LIMITED,
        GITHUB_TEMPORARY_ERROR,
        DOWNLOAD_TOO_LARGE,
        INVALID_REPOSITORY,
        INVALID_ARCHIVE,
        EXTRACTION_LIMIT_EXCEEDED,
        SCAN_TIMEOUT,
        TEMP_STORAGE_EXHAUSTED,
        LLM_RATE_LIMITED,
        LLM_TIMEOUT,
        LLM_INVALID_RESPONSE,
        INTERNAL_TRANSIENT,
        INTERNAL_PERMANENT,
    }
)

# Only these categories may be retried (bounded attempts + backoff).
RETRYABLE_CATEGORIES: frozenset[str] = frozenset(
    {
        DOWNLOAD_TIMEOUT,
        GITHUB_RATE_LIMITED,
        GITHUB_TEMPORARY_ERROR,
        LLM_RATE_LIMITED,
        LLM_TIMEOUT,
        SCAN_TIMEOUT,
        TEMP_STORAGE_EXHAUSTED,
        INTERNAL_TRANSIENT,
    }
)

# Map stable public error codes → failure categories.
_ERROR_CODE_CATEGORY: dict[str, str] = {
    "DOWNLOAD_FAILED": GITHUB_TEMPORARY_ERROR,
    "DOWNLOAD_TIMEOUT": DOWNLOAD_TIMEOUT,
    "GITHUB_RATE_LIMITED": GITHUB_RATE_LIMITED,
    "REPOSITORY_NOT_FOUND": INVALID_REPOSITORY,
    "PRIVATE_REPOSITORY": INVALID_REPOSITORY,
    "INVALID_REPO_URL": INVALID_REPOSITORY,
    "DOWNLOAD_TOO_LARGE": DOWNLOAD_TOO_LARGE,
    "UNSAFE_ARCHIVE": INVALID_ARCHIVE,
    "INVALID_ARCHIVE": INVALID_ARCHIVE,
    "INVALID_UPLOAD": INVALID_ARCHIVE,
    "UPLOAD_TOO_LARGE": DOWNLOAD_TOO_LARGE,
    "EXTRACTION_LIMIT_EXCEEDED": EXTRACTION_LIMIT_EXCEEDED,
    "EXTRACT_TIMEOUT": INTERNAL_TRANSIENT,
    "SCAN_TIMEOUT": SCAN_TIMEOUT,
    "ASSESSMENT_TIMEOUT": INTERNAL_TRANSIENT,
    "REPAIR_PLAN_TIMEOUT": INTERNAL_TRANSIENT,
    "SCAN_INTERNAL_ERROR": INTERNAL_TRANSIENT,
    "SCAN_RESULT_PERSIST_FAILED": INTERNAL_TRANSIENT,
    "ASSESSMENT_INTERNAL_ERROR": INTERNAL_TRANSIENT,
    "ASSESSMENT_PERSIST_FAILED": INTERNAL_TRANSIENT,
    "REPAIR_PLAN_INTERNAL_ERROR": INTERNAL_TRANSIENT,
    "REPAIR_PLAN_PERSIST_FAILED": INTERNAL_TRANSIENT,
    "TEMP_STORAGE_EXHAUSTED": TEMP_STORAGE_EXHAUSTED,
    "INTERNAL_ERROR": INTERNAL_TRANSIENT,
    "SERVICE_RESTARTED": INTERNAL_TRANSIENT,
    "TASK_CANCELLED": INTERNAL_PERMANENT,
    "DEAD_TASK": INTERNAL_PERMANENT,
}


def category_for_error_code(error_code: str | None) -> str:
    """Classify a public error code into an internal failure category."""
    if not error_code:
        return INTERNAL_PERMANENT
    return _ERROR_CODE_CATEGORY.get(error_code, INTERNAL_PERMANENT)


def is_retryable(category: str | None) -> bool:
    """Return True only for transient categories that may be retried."""
    return category in RETRYABLE_CATEGORIES


def compute_backoff_seconds(attempt_count: int, *, jitter: bool = True) -> float:
    """Exponential backoff with optional full jitter, capped by settings."""
    base = max(1, settings.retry_base_seconds)
    cap = max(base, settings.retry_max_seconds)
    exp = base * (2 ** max(0, attempt_count - 1))
    delay = float(min(exp, cap))
    if jitter and delay > 0:
        delay = random.uniform(0.0, delay)
    return max(0.0, delay)


@dataclass(frozen=True)
class RetryDecision:
    should_retry: bool
    category: str
    next_attempt_at: str | None


def decide_retry(
    *,
    error_code: str | None,
    attempt_count: int,
    category: str | None = None,
) -> RetryDecision:
    """Decide whether a failed attempt should be re-queued.

    attempt_count is the number of attempts already made (including the
    current failed one). Reaching max_attempts stops further retries.
    """
    from datetime import datetime, timedelta, timezone

    from app.db.database import now_iso

    cat = category or category_for_error_code(error_code)
    max_attempts = max(1, settings.max_task_attempts)
    if not is_retryable(cat) or attempt_count >= max_attempts:
        return RetryDecision(False, cat, None)

    delay = compute_backoff_seconds(attempt_count)
    next_at = (
        datetime.now(timezone.utc) + timedelta(seconds=delay)
    ).isoformat()
    return RetryDecision(True, cat, next_at or now_iso())
