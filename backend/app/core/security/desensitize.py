"""Unified desensitization module — the single entry point for masking secrets.

Design principles:
- mask_secret(value, secret_type): masks a single secret value by type.
- mask_snippet(line_text): collects ALL secret ranges in a line, merges
  overlapping ranges, then replaces from back to front to avoid column
  index invalidation.
- Idempotent: re-processing already-masked content never exposes extra chars.
  Already-masked values (containing <REDACTED>, ..., *** etc.) are skipped
  by the assignment pattern so the output is stable.
- Original snippets NEVER enter Finding, logs, exceptions, or test output.

Security guarantees:
- Long keys (github_token, aws_access_key, google_api_key): keep first 4
  and last 4 characters only.
- Short keys (<=8 chars): replaced with <REDACTED>.
- Private key body: replaced with <PRIVATE_KEY_REDACTED>.
- Connection string passwords: replaced with ***.
- Password/secret/token assignment values: replaced with <REDACTED>.
"""

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# --- Secret type constants ---
# ---------------------------------------------------------------------------

PRIVATE_KEY = "private_key"
GITHUB_TOKEN = "github_token"
AWS_ACCESS_KEY = "aws_access_key"
AWS_SECRET_KEY = "aws_secret_key"
GOOGLE_API_KEY = "google_api_key"
PASSWORD = "password"
SECRET = "secret"
TOKEN = "token"
CONNECTION_STRING = "connection_string"
GENERIC = "generic"


# ---------------------------------------------------------------------------
# --- Already-masked indicators (for idempotency) ---
# ---------------------------------------------------------------------------

_MASKED_INDICATORS: tuple[str, ...] = (
    "<REDACTED>",
    "<PRIVATE_KEY_REDACTED>",
    "***",
    "...",
)


def _is_already_masked(value: str) -> bool:
    """Check if a value already contains masking indicators."""
    return any(indicator in value for indicator in _MASKED_INDICATORS)


# ---------------------------------------------------------------------------
# --- mask_secret: single value masking ---
# ---------------------------------------------------------------------------

def mask_secret(value: str, secret_type: str) -> str:
    """Mask a single secret value based on its type.

    Idempotent: if the value has already been masked, it is returned as-is
    or further redacted -- never expanded.

    Args:
        value: The raw secret value (already extracted by a rule).
        secret_type: One of the secret type constants above.

    Returns:
        A masked string that cannot be used to reconstruct the original.
    """
    if not value:
        return value

    if secret_type == PRIVATE_KEY:
        return "<PRIVATE_KEY_REDACTED>"

    if secret_type == AWS_SECRET_KEY:
        return "<REDACTED>"

    if secret_type in (PASSWORD, SECRET, TOKEN, GENERIC):
        return "<REDACTED>"

    if secret_type == CONNECTION_STRING:
        return _mask_connection_string(value)

    # For keys with a recognizable prefix (github_token, aws_access_key, google_api_key)
    if secret_type in (GITHUB_TOKEN, AWS_ACCESS_KEY, GOOGLE_API_KEY):
        return _mask_key_with_prefix(value)

    # Fallback: full redaction
    return "<REDACTED>"


def _mask_key_with_prefix(value: str) -> str:
    """Mask a key that has a known prefix, keeping first 4 and last 4 chars.

    Keys <= 8 chars are fully redacted.
    """
    if len(value) <= 8:
        return "<REDACTED>"
    prefix = value[:4]
    suffix = value[-4:]
    return f"{prefix}...{suffix}"


def _mask_connection_string(value: str) -> str:
    """Mask the password portion of a connection string.

    Replaces the password between the first ':' after scheme and the '@'
    before the host with '***'.

    Example: postgres://user:secretpass@host:5432/db
             -> postgres://user:***@host:5432/db
    """
    # Match scheme://user:password@host
    pattern = re.compile(
        r"^([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@]+):([^@]+)@(.*)$"
    )
    match = pattern.match(value)
    if match:
        scheme_user = match.group(1)
        host_rest = match.group(3)
        return f"{scheme_user}:***@{host_rest}"
    # If no password found, redact entirely to be safe
    return "<REDACTED>"


# ---------------------------------------------------------------------------
# --- mask_snippet: multi-secret line masking ---
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _SecretRange:
    """A detected secret range within a line of text."""
    start: int          # 0-based, inclusive
    end: int            # 0-based, exclusive
    secret_type: str
    masked_value: str


# Patterns for detecting prefix-based tokens within a line of text.
# Each pattern uses a capture group for the secret value.
# NOTE: AWS_SECRET_KEY (40-char base64) is intentionally excluded here --
# it is too broad for line-level masking and causes false positives.
# The AWS_SECRET_KEY rule handles it with proper context (aws_secret_access_key=).
_SNIPPET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # GitHub Token: ghp_ + 36 chars
    (re.compile(r"(ghp_[A-Za-z0-9]{36})"), GITHUB_TOKEN),
    # AWS Access Key: AKIA + 16 chars
    (re.compile(r"(AKIA[A-Z0-9]{16})"), AWS_ACCESS_KEY),
    # Google API Key: AIza + 35 chars
    (re.compile(r"(AIza[A-Za-z0-9_\-]{35})"), GOOGLE_API_KEY),
    # Connection string with password: scheme://user:password@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:[^@\s]+@\S+)"), CONNECTION_STRING),
]

# Separate pattern for assignment-style secrets (password=, secret=, etc.)
# Captures the value portion (group 2) for masking.
# Longer keywords listed first to ensure correct alternation matching
# (e.g., "aws_secret_access_key" before "aws_secret" before "secret").
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(aws_secret_access_key|secret_access_key|aws_secret"
    r"|password|passwd|pwd|secret|api_key|apikey|token|access_token)"
    r"\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"
)


def mask_snippet(line_text: str) -> str:
    """Mask ALL secrets in a line of text.

    Collects all secret ranges (from all pattern types), merges overlapping
    ranges, then replaces from back to front to preserve column indices.

    Idempotent: already-masked values are skipped by the assignment pattern,
    so re-processing never exposes additional characters.

    The original snippet must NEVER appear in Finding, logs, or exceptions.

    Args:
        line_text: A single line of text (may contain multiple secrets).

    Returns:
        The line with all secrets masked. Idempotent.
    """
    if not line_text:
        return line_text

    ranges: list[_SecretRange] = []

    # 1. Collect prefix-based token ranges
    for pattern, stype in _SNIPPET_PATTERNS:
        for match in pattern.finditer(line_text):
            group = match.group(1)
            masked = mask_secret(group, stype)
            ranges.append(_SecretRange(
                start=match.start(1),
                end=match.end(1),
                secret_type=stype,
                masked_value=masked,
            ))

    # 2. Collect assignment-style secret ranges (value portion only)
    for match in _ASSIGNMENT_PATTERN.finditer(line_text):
        value = match.group(2)
        # Skip env var references
        if value.startswith("${") or value.startswith("process.env") or value.startswith("os."):
            continue
        # Skip already-masked values (idempotency)
        if _is_already_masked(value):
            continue
        masked = mask_secret(value, GENERIC)
        ranges.append(_SecretRange(
            start=match.start(2),
            end=match.end(2),
            secret_type=GENERIC,
            masked_value=masked,
        ))

    if not ranges:
        return line_text

    # 3. Sort ranges by start position
    ranges.sort(key=lambda r: (r.start, r.end))

    # 4. Merge overlapping ranges -- keep the earliest (already sorted)
    merged: list[_SecretRange] = []
    for r in ranges:
        if merged and r.start < merged[-1].end:
            # Overlap: extend the previous range if this one ends later
            if r.end > merged[-1].end:
                merged[-1] = _SecretRange(
                    start=merged[-1].start,
                    end=r.end,
                    secret_type=merged[-1].secret_type,
                    masked_value=merged[-1].masked_value,
                )
            # If fully contained, skip
        else:
            merged.append(r)

    # 5. Replace from back to front to preserve indices
    result = line_text
    for r in reversed(merged):
        result = result[:r.start] + r.masked_value + result[r.end:]

    return result
