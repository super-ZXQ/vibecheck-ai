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
  bodies in explicit-format tokens, including all-same-character and
  short-period repetition (period 2-4) patterns.
- parse_assignment_value: unified assignment value parser shared by ALL rules
  and mask_snippet. Supports quoted JSON/TOML keys, quoted values with
  escapes, and unquoted values with escapes (does NOT stop at #).
- iter_assignments(line): unified entry point that identifies ALL key=value
  assignments in a line by first recognizing complete keys (NOT by searching
  for sensitive substrings). After parsing a value, the next search starts
  from value_end, so already-parsed value text is never re-scanned.
- classify_key(key): classifies a key into a sensitivity category using
  segment-based matching. Shared between rules and mask_snippet.
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
from typing import Iterator


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
# --- Key classification categories ---
# ---------------------------------------------------------------------------

CATEGORY_AWS_SECRET = "aws_secret"
CATEGORY_PASSWORD = "password"
CATEGORY_SECRET = "secret"


class Assignment:
    """A parsed key=value assignment from a line of text.

    Produced by iter_assignments(). Shared between all rules and
    mask_snippet — no rule may duplicate assignment parsing logic.

    SECURITY: This is a NON-dataclass internal read-only object.
    - ``dataclasses.asdict(assignment)`` raises ``TypeError`` because
      Assignment is not a dataclass. This prevents accidental leakage of
      ``key_raw``, ``key_normalized``, and ``value`` through serialization.
    - ``__repr__`` only shows position/quote/operator metadata — NEVER
      ``key_raw``, ``key_normalized``, or ``value``.
    - Logs, exceptions, and assertions must NEVER print the raw key or
      value. A malicious repo can embed a format-correct token in a
      variable name, so the key itself is treated as untrusted.
    - Assignment is an INTERNAL temporary parse object — it must NOT
      enter API models, persistence objects, or LLM input.
    """

    __slots__ = (
        "_key_raw",
        "_key_normalized",
        "_value_start",
        "_value_end",
        "_value",
        "_is_quoted",
        "_operator",
    )

    def __init__(
        self,
        key_raw: str,
        key_normalized: str,
        value_start: int,
        value_end: int,
        value: str,
        is_quoted: bool,
        operator: str,
    ) -> None:
        # Use object.__setattr__ to bypass __setattr__ restriction during init.
        object.__setattr__(self, "_key_raw", key_raw)
        object.__setattr__(self, "_key_normalized", key_normalized)
        object.__setattr__(self, "_value_start", value_start)
        object.__setattr__(self, "_value_end", value_end)
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_is_quoted", is_quoted)
        object.__setattr__(self, "_operator", operator)

    # --- Read-only properties (no setters) ---
    @property
    def key_raw(self) -> str:
        return self._key_raw

    @property
    def key_normalized(self) -> str:
        return self._key_normalized

    @property
    def value_start(self) -> int:
        return self._value_start

    @property
    def value_end(self) -> int:
        return self._value_end

    @property
    def value(self) -> str:
        return self._value

    @property
    def is_quoted(self) -> bool:
        return self._is_quoted

    @property
    def operator(self) -> str:
        return self._operator

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Assignment is read-only")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Assignment is read-only")

    def __repr__(self) -> str:
        """Safe repr that NEVER exposes key_raw, key_normalized, or value.

        Only shows position, quote flag, and operator — all of which are
        safe metadata. This prevents leakage when a malicious repo embeds
        a format-correct token in a variable name.
        """
        return (
            f"Assignment(value_start={self._value_start}, "
            f"value_end={self._value_end}, "
            f"is_quoted={self._is_quoted}, operator={self._operator!r})"
        )


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

    Returns True if the body is obviously repetitive, including:
    - All same character (period 1): AAAAAA...
    - Short-period repetition (period 2-4): ABAB..., ABCDABCD..., 12341234...

    The repeat unit is limited to 1-4 characters to prevent normal
    mixed-character values from being mistakenly downgraded.

    Used by explicit-format token rules (R001-R004) to downgrade obvious
    placeholder values (e.g., ghp_AAAAAA..., ghp_ABABABAB...) to
    low severity / low confidence / non-blocking.

    Args:
        value:      The full matched value (including prefix).
        prefix_len: Length of the fixed prefix to exclude (e.g., 4 for "ghp_").
    """
    body = value[prefix_len:]
    if not body or len(body) < 4:
        return False
    # Period 1: all same character
    if len(set(body)) == 1:
        return True
    # Period 2-4: short-period repetition (unit length 2, 3, or 4)
    for period in range(2, 5):
        if len(body) % period != 0:
            continue
        if len(body) < period * 2:
            continue
        unit = body[:period]
        if body == unit * (len(body) // period):
            return True
    return False


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
# --- Key normalization and classification (shared by rules + mask_snippet) ---
# ---------------------------------------------------------------------------

# Regex for splitting camelCase boundaries.
# Matches: uppercase run before Upper-lower (HTTPResponse -> HTTP, Response),
#          optional-uppercase + lowercase run (apiKey -> api, Key),
#          pure uppercase run (API).
_CAMEL_SPLIT = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")

# Regex for matching unquoted identifier keys.
# Supports letters, digits, underscores, hyphens, and dots to correctly
# recognize compound keys like my-api-key, openai.api.key, db.password.
# Must start with a letter or underscore.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")

# Single-keyword sets for each category (uppercase segments).
_PASSWORD_KEYWORDS: frozenset[str] = frozenset({"PASSWORD", "PASSWD", "PWD"})
_SECRET_KEYWORDS: frozenset[str] = frozenset({"SECRET", "TOKEN", "APIKEY"})

# Consecutive-pair keywords for the secret category.
_SECRET_PAIR_KEYWORDS: frozenset[tuple[str, str]] = frozenset({
    ("API", "KEY"),
    ("ACCESS", "KEY"),
    ("PRIVATE", "KEY"),
    ("CLIENT", "SECRET"),
    ("JWT", "SECRET"),
    ("ACCESS", "TOKEN"),
    ("GITHUB", "TOKEN"),
})


def _normalize_key_segments(key: str) -> list[str]:
    """Split a key into normalized uppercase segments.

    Splits by underscore, hyphen, dot, and camelCase boundaries.
    Returns a list of non-empty uppercase segments.

    Examples:
        DB_PASSWORD       -> ["DB", "PASSWORD"]
        OPENAI_API_KEY    -> ["OPENAI", "API", "KEY"]
        apiKey            -> ["API", "KEY"]
        db.password       -> ["DB", "PASSWORD"]
        SECRETARY_EMAIL   -> ["SECRETARY", "EMAIL"]
    """
    # Replace hyphens and dots with underscores for uniform splitting
    normalized = key.replace("-", "_").replace(".", "_")
    parts = normalized.split("_")

    segments: list[str] = []
    for part in parts:
        if not part:
            continue
        camel_parts = _CAMEL_SPLIT.findall(part)
        segments.extend(camel_parts)

    return [s.upper() for s in segments if s]


def _normalize_key(key: str) -> str:
    """Normalize a key to uppercase with underscore separators."""
    return "_".join(_normalize_key_segments(key))


# Exact normalized names for AWS secret keys (R003).
# Only these complete names trigger CATEGORY_AWS_SECRET — NOT broad
# segment-set matching, which caused false positives on names like
# AWS_CLIENT_SECRET, MY_SECRET_ACCESS_KEY_BACKUP, etc.
_AWS_SECRET_KEY_NAMES: frozenset[str] = frozenset({
    "AWS_SECRET_ACCESS_KEY",
    "SECRET_ACCESS_KEY",
    "AWS_SECRET",
})


def classify_key(key: str) -> str | None:
    """Classify a key into a sensitivity category using segment matching.

    Splits the key by underscore, hyphen, dot, and camelCase boundaries
    into normalized uppercase segments, then checks against sensitive
    keyword patterns.

    Priority: aws_secret > password > secret.

    Returns one of CATEGORY_AWS_SECRET, CATEGORY_PASSWORD, CATEGORY_SECRET,
    or None if the key is not sensitive.

    Matches (R006 / password):
        PASSWORD, DB_PASSWORD, DATABASE_PASSWORD, MYSQL_PWD, ADMIN_PASSWD

    Matches (R007 / secret):
        SECRET, JWT_SECRET, CLIENT_SECRET, TOKEN, ACCESS_TOKEN,
        GITHUB_TOKEN, API_KEY, MY_API_KEY, OPENAI_API_KEY

    Matches (R003 / aws_secret — EXACT normalized name only):
        AWS_SECRET_ACCESS_KEY, SECRET_ACCESS_KEY, AWS_SECRET

    Does NOT match (returns None):
        SECRETARY_EMAIL, TOKENIZER_MODEL, PASSWORDLESS_MODE,
        API_KEYBOARD_LAYOUT, ACCESS_TOKENIZER

    Does NOT produce CATEGORY_AWS_SECRET (but may produce CATEGORY_SECRET):
        AWS_CLIENT_SECRET, MY_SECRET_ACCESS_KEY_BACKUP,
        SECRET_DATABASE_ACCESS_KEY
    """
    segments = _normalize_key_segments(key)
    if not segments:
        return None
    key_normalized = "_".join(segments)

    # AWS secret (highest priority) — exact normalized name match ONLY.
    # No broad segment-set matching to avoid false positives on names
    # like AWS_CLIENT_SECRET or SECRET_DATABASE_ACCESS_KEY.
    if key_normalized in _AWS_SECRET_KEY_NAMES:
        return CATEGORY_AWS_SECRET

    # Password
    if any(s in _PASSWORD_KEYWORDS for s in segments):
        return CATEGORY_PASSWORD

    # Secret / token (single segment)
    if any(s in _SECRET_KEYWORDS for s in segments):
        return CATEGORY_SECRET

    # Secret / token (consecutive pair)
    for i in range(len(segments) - 1):
        if (segments[i], segments[i + 1]) in _SECRET_PAIR_KEYWORDS:
            return CATEGORY_SECRET

    return None


# ---------------------------------------------------------------------------
# --- Unified assignment value parser ---
# ---------------------------------------------------------------------------

def parse_assignment_value(
    line: str, key_end: int, is_quoted_key: bool = False,
) -> tuple[int, int, str, bool, str] | None:
    """Parse an assignment value starting after a key-name match.

    This is the SINGLE shared parser used by PasswordAssignmentRule,
    GenericTokenAssignmentRule, AWSSecretKeyRule, ProductionEnvWithSecretRule,
    and mask_snippet. No rule or function may duplicate this logic.

    Starting from ``key_end``, finds the assignment operator — strictly
    distinguishing real assignments from comparison/walrus/arrow operators:

    - **Unquoted keys**: only single ``=`` is accepted. ``==``, ``=>``,
      ``!=``, ``>=``, ``<=``, ``:=`` are ALL rejected.
    - **Quoted keys** (JSON/TOML style): ``=`` or ``:`` is accepted.
      ``:=`` is still rejected. Colon is NOT accepted for unquoted keys
      (so ``password: str`` is not treated as an assignment).

    Then parses the value which may be:

    - **Double-quoted** with escape characters (``\\"`` inside ``"..."``)
    - **Single-quoted** with escape characters (``\\'`` inside ``'...'``)
    - **Unquoted** -- stops at whitespace ONLY (does NOT stop at ``#``).
      Supports backslash escape characters in unquoted values.

    Args:
        line:          The full line of text.
        key_end:       Position in ``line`` right after the key name.
        is_quoted_key: Whether the key was quoted (JSON/TOML style).
                       Only quoted keys may use ``:`` as operator.

    Returns:
        ``(value_start, value_end, value_content, is_quoted, operator)``
        or ``None``.

        - ``value_start``: 0-based start of value content (after opening quote)
        - ``value_end``:   0-based end of value content (before closing quote)
        - ``value_content``: the value with escape characters processed
          (quotes stripped)
        - ``is_quoted``: True if the value was quoted, False if unquoted
        - ``operator``: the assignment operator (``"="`` or ``":"``)

        If no assignment operator or no value is found, returns ``None``.
    """
    i = key_end

    # --- Find assignment operator, strictly distinguishing from ==
    # !=, >=, <=, :=, => ---
    # Also skip a closing quote if the key was quoted (JSON/TOML style:
    # "key": value, 'key' = value, "key" = "value").
    found_op = False
    operator = ""
    while i < len(line):
        ch = line[i]
        if ch.isspace():
            i += 1
        elif ch in ('"', "'"):
            # Skip closing quote of a quoted key (JSON/TOML)
            i += 1
        elif ch == "=":
            # Reject == and => (comparison / arrow)
            if i + 1 < len(line) and line[i + 1] in "=>":
                return None
            found_op = True
            operator = "="
            i += 1
            break
        elif ch == ":":
            # Colon only allowed for quoted keys (JSON/TOML style).
            # Unquoted "password: str" must NOT be treated as assignment.
            if not is_quoted_key:
                return None
            # Reject := (walrus operator)
            if i + 1 < len(line) and line[i + 1] == "=":
                return None
            found_op = True
            operator = ":"
            i += 1
            break
        else:
            # Non-space, non-quote, non-operator -- not an assignment.
            # This rejects != (starts with !), >= (starts with >),
            # <= (starts with <), and any other non-operator prefix.
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
                return (value_start, j, "".join(content_chars), True, operator)
            else:
                content_chars.append(line[j])
                j += 1
        # Unterminated quote -- take everything to end of line
        return (value_start, len(line), "".join(content_chars), True, operator)

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
    return (value_start, value_end, value_content, False, operator)


# ---------------------------------------------------------------------------
# --- Unified assignment iterator (shared by ALL rules and mask_snippet) ---
# ---------------------------------------------------------------------------

def iter_assignments(line: str) -> Iterator[Assignment]:
    """Identify ALL key=value assignments in a line.

    This is the unified entry point that identifies assignments by first
    recognizing COMPLETE keys (NOT by searching for sensitive substrings).
    After parsing a value, the next search starts from after the value,
    so already-parsed value text is never re-scanned.

    Supported formats:
    - password = "value"           (simple unquoted key)
    - DB_PASSWORD = "value"        (uppercase compound key)
    - const OPENAI_API_KEY = "v"   (prefix keyword like const/let/export)
    - "api_key": "value"           (JSON double-quoted key)
    - 'jwt_secret' = 'value'       (TOML single-quoted key)
    - password="a" token="b"       (multiple assignments same line)

    Guarantees:
    1. Identifies the complete key first — never searches for sensitive
       substrings in the line.
    2. After parsing a value, the next search starts from value_end (or
       value_end + 1 for quoted values to skip the closing quote).
    3. Already-parsed value text is NEVER re-scanned.
    4. ${DB_PASSWORD:-default} inside a value is NOT treated as a second
       assignment key.

    Yields:
        Assignment objects (see Assignment dataclass).
    """
    i = 0
    n = len(line)

    while i < n:
        # Skip whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        # --- Try to match a key at position i ---
        key_raw: str | None = None
        key_end = i
        is_quoted_key = False

        if line[i] == '"' or line[i] == "'":
            # Quoted key (JSON/TOML style)
            quote_char = line[i]
            j = i + 1
            key_chars: list[str] = []
            while j < n:
                if line[j] == "\\" and j + 1 < n:
                    key_chars.append(line[j + 1])
                    j += 2
                elif line[j] == quote_char:
                    key_raw = "".join(key_chars)
                    j += 1  # consume closing quote
                    break
                else:
                    key_chars.append(line[j])
                    j += 1
            if key_raw is None:
                # Unterminated quote — advance past opening quote
                i += 1
                continue
            key_end = j  # position AFTER closing quote
            is_quoted_key = True
        else:
            # Unquoted identifier
            m = _IDENTIFIER.match(line, i)
            if m:
                key_raw = m.group()
                key_end = m.end()
                is_quoted_key = False
            else:
                # Not a key start — advance one character
                i += 1
                continue

        # --- Try to find assignment operator and value ---
        result = parse_assignment_value(line, key_end, is_quoted_key=is_quoted_key)
        if result is not None:
            value_start, value_end, value, is_quoted, operator = result
            yield Assignment(
                key_raw=key_raw,
                key_normalized=_normalize_key(key_raw),
                value_start=value_start,
                value_end=value_end,
                value=value,
                is_quoted=is_quoted,
                operator=operator,
            )
            # Advance past the value.
            # For quoted values, value_end is at the closing quote position;
            # we need +1 to skip past it.
            # For unquoted values, value_end is already at the next
            # whitespace or end-of-line.
            if is_quoted:
                i = value_end + 1
            else:
                i = value_end
        else:
            # No assignment found after this key — advance past the key
            i = key_end


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
# These are the EXPLICIT-FORMAT patterns shared by mask_snippet and
# mask_untrusted_text. They do NOT depend on key=value semantics.
_EXPLICIT_FORMAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(ghp_[A-Za-z0-9]{36})"), GITHUB_TOKEN),
    (re.compile(r"(AKIA[A-Z0-9]{16})"), AWS_ACCESS_KEY),
    (re.compile(r"(AIza[A-Za-z0-9_\-]{35})"), GOOGLE_API_KEY),
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:[^@\s]+@\S+)"), CONNECTION_STRING),
]


def _collect_explicit_format_ranges(text: str) -> list[_SecretRange]:
    """Collect all explicit-format secret ranges in arbitrary text.

    This is the SHARED range-collection logic used by both mask_snippet
    and mask_untrusted_text. It scans for GitHub tokens, AWS access keys,
    Google API keys, and connection strings — all of which have
    unambiguous format patterns that do NOT depend on key=value semantics.

    Args:
        text: Arbitrary text (may be a file path, directory name, or any
              user-controlled string).

    Returns:
        List of _SecretRange objects for detected explicit-format secrets.
    """
    ranges: list[_SecretRange] = []
    for pattern, stype in _EXPLICIT_FORMAT_PATTERNS:
        for match in pattern.finditer(text):
            group = match.group(1)
            masked = mask_secret(group, stype)
            ranges.append(_SecretRange(
                start=match.start(1),
                end=match.end(1),
                secret_type=stype,
                masked_value=masked,
            ))
    return ranges


def _apply_ranges(text: str, ranges: list[_SecretRange]) -> str:
    """Sort, merge, and apply secret ranges to text (back-to-front replace)."""
    if not ranges:
        return text
    ranges.sort(key=lambda r: (r.start, r.end))
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
    result = text
    for r in reversed(merged):
        result = result[:r.start] + r.masked_value + result[r.end:]
    return result


def mask_untrusted_text(text: str) -> str:
    """Mask explicit-format secrets in arbitrary user-controlled text.

    This is the GENERAL-PURPOSE path/identifier sanitization function.
    It masks GitHub tokens, AWS access keys, Google API keys, and
    connection strings in ANY text — including file paths, directory
    names, error messages, and other non-assignment contexts.

    Unlike mask_snippet, this function does NOT use key=value semantics
    or iter_assignments. It relies ONLY on explicit-format pattern
    matching, which is safe because these formats (ghp_+36, AKIA+16,
    AIza+35, scheme://user:pass@host) are unambiguous.

    Used to sanitize file_path in Finding, ScanNotice, SkippedFile, and
    ScanError — all of which may contain user-controlled path components
    (filenames, directory names) that could embed format-correct secrets.

    Args:
        text: Arbitrary user-controlled text (e.g., a POSIX relative path).

    Returns:
        The text with all explicit-format secrets masked. Plain paths
        without embedded secrets are returned unchanged.
    """
    if not text:
        return text
    ranges = _collect_explicit_format_ranges(text)
    return _apply_ranges(text, ranges)


def mask_snippet(line_text: str) -> str:
    """Mask ALL secrets in a line of text.

    Conservative masking strategy: any identified assignment value whose
    key is classified as sensitive is masked. The ONLY values skipped are
    EXACT canonical already-masked values (is_already_masked).

    Environment variable references (e.g., ${DB_PASSWORD}) are masked
    here too — mask_snippet is a DISPLAY SAFETY layer, not a rule layer.
    Rules may skip env references to avoid generating Findings, but
    mask_snippet must still mask them so no raw value appears in snippet
    output. Quoted values are NEVER treated as env references — they are
    literal strings and are always masked.

    Uses iter_assignments() to identify ALL key=value assignments by
    recognizing complete keys first (NOT by searching for sensitive
    substrings). classify_key() determines which keys are sensitive.
    Already-parsed value text is never re-scanned.

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

    # 1. Collect explicit-format token ranges (shared logic)
    ranges.extend(_collect_explicit_format_ranges(line_text))

    # 2. Collect assignment-style secret ranges using iter_assignments
    for assignment in iter_assignments(line_text):
        # Only mask if the key is classified as sensitive
        if classify_key(assignment.key_raw) is None:
            continue
        value = assignment.value
        if not value:
            continue
        # mask_snippet is a DISPLAY SAFETY layer — it masks ALL sensitive
        # key assignments, including environment variable references.
        # Rules may skip env references (no Finding generated), but
        # mask_snippet must still mask them to prevent any raw value
        # from appearing in snippet output.
        # Only EXACT canonical already-masked values are skipped.
        if is_already_masked(value):
            continue
        masked = mask_secret(value, GENERIC)
        ranges.append(_SecretRange(
            start=assignment.value_start,
            end=assignment.value_end,
            secret_type=GENERIC,
            masked_value=masked,
        ))

    return _apply_ranges(line_text, ranges)