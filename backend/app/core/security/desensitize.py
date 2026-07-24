"""Unified desensitization module — the single entry point for masking secrets.

Design principles:
- mask_secret(value, secret_type): masks a single secret value by type.
- mask_snippet(line_text): collects ALL secret ranges in a line, merges
  overlapping ranges, then replaces from back to front to avoid column
  index invalidation.
- Idempotent: re-processing already-masked content never exposes extra chars.
  Already-masked values are detected by is_already_masked() using STRICT
  complete-value matching only — never substring checks.
- is_env_reference(value, is_quoted): shared environment variable reference
  detection. Uses strict full-match patterns. Quoted values are NEVER
  treated as env references (they are literal strings).
- is_low_entropy(value, prefix_len): detects obviously repetitive placeholder
  bodies in explicit-format tokens.
- parse_assignment_value: unified assignment value parser shared by ALL rules
  and mask_snippet. Supports quoted JSON/TOML keys, quoted values with
  escapes, and unquoted values with escapes (does NOT stop at #).
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
# --- Strict already-masked detection (shared by rules and mask_snippet) ---
# ---------------------------------------------------------------------------

# System-generated masked format: exactly 4 word-chars + "..." + 4 word-chars.
# \w includes [A-Za-z0-9_], matching prefixes like "ghp_" and "AKIA".
_MASKED_FORMAT_PATTERN = re.compile(r"\w{4}\.\.\.\w{4}")


def is_already_masked(value: str) -> bool:
    """Check if a value is an EXACT canonical masked value.

    Only recognizes complete canonical values:
    - Complete value equals <REDACTED>
    - Complete value equals <PRIVATE_KEY_REDACTED>
    - Complete value is all asterisks
    - Explicitly matches system-generated "first4...last4" format

    NEVER uses substring matching like "contains ..." or "contains ***".
    This prevents real secrets containing "...", "***", or "<REDACTED>"
    as substrings from being mistakenly treated as already masked.
    """
    if value == "<REDACTED>":
        return True
    if value == "<PRIVATE_KEY_REDACTED>":
        return True
    if value and all(c == "*" for c in value):
        return True
    if _MASKED_FORMAT_PATTERN.fullmatch(value):
        return True
    return False


# ---------------------------------------------------------------------------
# --- Strict environment variable reference detection (shared) ---
# ---------------------------------------------------------------------------

# Strict full-match patterns for environment variable references.
# Only these EXACT patterns are recognized as env references.
# $VAR requires uppercase (standard env var convention) so that values like
# "$uperSecret123" (lowercase u) are NOT treated as env references.
_ENV_REF_PATTERNS: tuple[re.Pattern, ...] = (
    # $VAR (uppercase env var name)
    re.compile(r"^\$[A-Z_][A-Z0-9_]*$"),
    # ${VAR}
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    # ${VAR:-default}
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:-.+\}$"),
    # process.env.NAME
    re.compile(r"^process\.env\.[A-Za-z_][A-Za-z0-9_]*$"),
    # process.env["NAME"]
    re.compile(r"""^process\.env\["[A-Za-z_][A-Za-z0-9_]*"\]$"""),
    # os.environ["NAME"]
    re.compile(r"""^os\.environ\["[A-Za-z_][A-Za-z0-9_]*"\]$"""),
    # os.getenv("NAME")
    re.compile(r"""^os\.getenv\("[A-Za-z_][A-Za-z0-9_]*"\)$"""),
)


def is_env_reference(value: str, is_quoted: bool = False) -> bool:
    """Check if a value is an environment variable reference.

    If is_quoted is True, the value was quoted in the source (e.g.,
    password="$value"), making it a literal string — NOT an env reference.
    Returns False for quoted values.

    If unquoted, uses strict full-match patterns ONLY:
    $VAR, ${VAR}, ${VAR:-default}, process.env.NAME,
    process.env["NAME"], os.environ["NAME"], os.getenv("NAME")

    This function is SHARED between rules.py and mask_snippet — they must
    use the exact same implementation.
    """
    if is_quoted:
        return False
    value = value.strip()
    return any(pattern.match(value) for pattern in _ENV_REF_PATTERNS)


# ---------------------------------------------------------------------------
# --- Low-entropy placeholder detection (shared) ---
# ---------------------------------------------------------------------------

def is_low_entropy(value: str, prefix_len: int = 0) -> bool:
    """Check if the body (value minus prefix) is low-entropy.

    Returns True if the body consists entirely of a single repeated
    character. Used by explicit-format token rules (R001-R004) to
    downgrade obvious placeholder values (e.g., ghp_AAAAAA...) to
    low severity / low confidence / non-blocking.

    Args:
        value:      The full matched value (including prefix).
        prefix_len: Length of the fixed prefix to exclude (e.g., 4 for "ghp_").
    """
    body = value[prefix_len:]
    if not body or len(body) < 4:
        return False
    return len(set(body)) == 1


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

    Accurately captures scheme://user:password@host and replaces ONLY
    the password with '***'.

    Example: postgres://user:secretpass@host:5432/db
             -> postgres://user:***@host:5432/db
    """
    pattern = re.compile(
        r"^([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+):([^@\s]+)@(.*)$"
    )
    match = pattern.match(value)
    if match:
        scheme_user = match.group(1)
        host_rest = match.group(3)
        return f"{scheme_user}:***@{host_rest}"
    return "<REDACTED>"


# ---------------------------------------------------------------------------
# --- Unified assignment value parser ---
# ---------------------------------------------------------------------------

def parse_assignment_value(
    line: str, key_end: int,
) -> tuple[int, int, str, bool] | None:
    """Parse an assignment value starting after a key-name match.

    This is the SINGLE shared parser used by PasswordAssignmentRule,
    GenericTokenAssignmentRule, AWSSecretKeyRule, ProductionEnvWithSecretRule,
    and mask_snippet. No rule or function may duplicate this logic.

    Starting from ``key_end``, finds the assignment operator (``=`` or
    ``:``) -- skipping whitespace and optional closing quote of a quoted
    key (JSON/TOML style: "key": value, 'key': value, "key" = value).

    Then parses the value which may be:

    - **Double-quoted** with escape characters (``\\"`` inside ``"..."``)
    - **Single-quoted** with escape characters (``\\'`` inside ``'...'``)
    - **Unquoted** -- stops at whitespace ONLY (does NOT stop at ``#``).
      Supports backslash escape characters in unquoted values.

    Args:
        line:    The full line of text.
        key_end: Position in ``line`` right after the key name.

    Returns:
        ``(value_start, value_end, value_content, is_quoted)`` or ``None``.

        - ``value_start``: 0-based start of value content (after opening quote)
        - ``value_end``:   0-based end of value content (before closing quote)
        - ``value_content``: the value with escape characters processed
          (quotes stripped)
        - ``is_quoted``: True if the value was quoted, False if unquoted

        If no assignment operator or no value is found, returns ``None``.
    """
    i = key_end

    # --- Find assignment operator (= or :) skipping whitespace ---
    # Also skip a closing quote if the key was quoted (JSON/TOML style:
    # "key": value, 'key' = value, "key" = "value").
    found_op = False
    while i < len(line):
        ch = line[i]
        if ch.isspace():
            i += 1
        elif ch in ('"', "'"):
            # Skip closing quote of a quoted key (JSON/TOML)
            i += 1
        elif ch in "=:":
            found_op = True
            i += 1
            break
        else:
            # Non-space, non-quote, non-operator -- not an assignment
            return None

    if not found_op:
        return None

    # --- Skip whitespace after operator ---
    while i < len(line) and line[i].isspace():
        i += 1

    if i >= len(line):
        return None

    # --- Quoted value (double or single) ---
    if line[i] in ('"', "'"):
        quote_char = line[i]
        value_start = i + 1
        j = value_start
        content_chars: list[str] = []
        while j < len(line):
            if line[j] == "\\" and j + 1 < len(line):
                # Escape: include the escaped character literally
                content_chars.append(line[j + 1])
                j += 2
            elif line[j] == quote_char:
                # Closing quote found
                return (value_start, j, "".join(content_chars), True)
            else:
                content_chars.append(line[j])
                j += 1
        # Unterminated quote -- take everything to end of line
        return (value_start, len(line), "".join(content_chars), True)

    # --- Unquoted value ---
    # Stops at whitespace ONLY. Does NOT stop at # — a # without preceding
    # whitespace is part of the value (e.g., password=alpha#omega).
    # Supports backslash escape characters.
    value_start = i
    j = i
    content_chars: list[str] = []
    while j < len(line):
        if line[j] == "\\" and j + 1 < len(line):
            content_chars.append(line[j + 1])
            j += 2
        elif line[j].isspace():
            break
        else:
            content_chars.append(line[j])
            j += 1
    value_end = j
    value_content = "".join(content_chars)
    if not value_content:
        return None
    return (value_start, value_end, value_content, False)


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
_SNIPPET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(ghp_[A-Za-z0-9]{36})"), GITHUB_TOKEN),
    (re.compile(r"(AKIA[A-Z0-9]{16})"), AWS_ACCESS_KEY),
    (re.compile(r"(AIza[A-Za-z0-9_\-]{35})"), GOOGLE_API_KEY),
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:[^@\s]+@\S+)"), CONNECTION_STRING),
]

# Key-only pattern for assignment-style secrets.
# Matches the KEY NAME only — value is parsed by parse_assignment_value().
# \b word boundaries prevent matching key names inside env var values
# like ${DB_PASSWORD:-default} where _ is a word character (no \b).
_ASSIGNMENT_KEY_PATTERN = re.compile(
    r"(?i)\b(aws_secret_access_key|secret_access_key|aws_secret"
    r"|password|passwd|pwd|secret|api_key|apikey|token|access_token)\b"
)


def mask_snippet(line_text: str) -> str:
    """Mask ALL secrets in a line of text.

    Conservative masking strategy: any identified assignment value is masked
    unless it is an EXACT canonical masked value (is_already_masked) or an
    unquoted environment variable reference (is_env_reference). Quoted values
    are NEVER treated as env references — they are literal strings.

    Idempotent: already-masked values are skipped, so re-processing never
    exposes additional characters.

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
    for match in _ASSIGNMENT_KEY_PATTERN.finditer(line_text):
        result = parse_assignment_value(line_text, match.end())
        if result is None:
            continue
        value_start, value_end, value, is_quoted = result
        # Skip env var references (only unquoted ones)
        if is_env_reference(value, is_quoted):
            continue
        # Skip already-masked values (strict complete-value check)
        if is_already_masked(value):
            continue
        masked = mask_secret(value, GENERIC)
        ranges.append(_SecretRange(
            start=value_start,
            end=value_end,
            secret_type=GENERIC,
            masked_value=masked,
        ))

    if not ranges:
        return line_text

    # 3. Sort ranges by start position
    ranges.sort(key=lambda r: (r.start, r.end))

    # 4. Merge overlapping ranges
    merged: list[_SecretRange] = []
    for r in ranges:
        if merged and r.start < merged[-1].end:
            if r.end > merged[-1].end:
                merged[-1] = _SecretRange(
                    start=merged[-1].start,
                    end=r.end,
                    secret_type=merged[-1].secret_type,
                    masked_value=merged[-1].masked_value,
                )
        else:
            merged.append(r)

    # 5. Replace from back to front to preserve indices
    result = line_text
    for r in reversed(merged):
        result = result[:r.start] + r.masked_value + result[r.end:]

    return result