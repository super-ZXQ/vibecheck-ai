"""Concrete rule implementations for the sensitive information scanner.

Rule list (11 rules):
  R001  GitHubTokenRule              -- ghp_ + 36 chars
  R002  AWSAccessKeyRule             -- AKIA + 16 chars
  R003  AWSSecretKeyRule             -- 40-char base64 in aws_secret context
  R004  GoogleAPIKeyRule             -- AIza + 35 chars
  R005  PrivateKeyRule               -- BEGIN/END private key blocks
  R006  PasswordAssignmentRule       -- password=, passwd=, pwd=
  R007  GenericTokenAssignmentRule   -- secret=, api_key=, token=
  R008  ConnectionStringRule         -- scheme://user:pass@host
  R009  EnvFilePresentRule           -- .env file exists (medium, non-blocking)
  R010  EnvExampleFileRule           -- .env.example exists (ScanNotice, not a finding)
  R011  ProductionEnvWithSecretRule  -- .env.production with hardcoded secrets

False positive control:
- Env var references (${...}, process.env.*, os.environ, os.getenv) are skipped.
- Placeholder values (changeme, foobar, etc.) are downgraded to low/low/non-blocking
  for generic assignment rules. Explicit-format tokens are NOT affected.
- AWS secret key only matched with context (aws_secret_access_key=).

Import structure (no circular imports):
- imports from: base, core.security.desensitize
- imported by:  default_rules
"""

from __future__ import annotations

import re
from typing import Optional

from app.core.config import settings
from app.core.security.desensitize import (
    CATEGORY_AWS_SECRET,
    CATEGORY_PASSWORD,
    CATEGORY_SECRET,
    GENERIC,
    classify_key,
    is_already_masked,
    is_env_reference,
    is_low_entropy,
    iter_assignments,
    iter_connection_strings,
    mask_secret,
    mask_snippet,
)
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    Rule,
    ScanNotice,
    Severity,
)


# ---------------------------------------------------------------------------
# --- Helper functions ---
# ---------------------------------------------------------------------------

# Known placeholder values -- exact match (case-insensitive).
# When a generic assignment rule matches one of these, the finding is
# downgraded to low severity / low confidence / non-blocking.
PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "foobar", "foo", "bar", "baz",
    "changeme", "change_me", "change-me",
    "example", "sample", "demo",
    "test", "testing", "test123", "testtest",
    "dummy", "placeholder", "temp", "temporary",
    "your_password", "your_secret", "your_token", "your_api_key",
    "your_password_here", "your_secret_here",
    "xxx", "xxxx", "xxxxx", "xxxxxxxx",
    "todo", "tbd", "fixme",
    "none", "null", "nil", "undefined",
    "password", "secret", "token", "apikey", "api_key",
    "<password>", "<secret>", "<token>", "<api_key>",
    "string", "str", "value", "val",
    "redacted", "masked", "hidden",
})


def _is_placeholder(value: str) -> bool:
    """Check if a value is an exact-match known placeholder (case-insensitive)."""
    return value.lower() in PLACEHOLDER_VALUES


def _is_likely_non_secret(value: str) -> bool:
    """Heuristic: check if a value in a production env file is likely not a secret.

    Used by ProductionEnvWithSecretRule to reduce noise.
    """
    lower = value.lower()
    if lower in ("true", "false", "yes", "no", "on", "off", "enabled", "disabled"):
        return True
    if value.isdigit():
        return True
    if len(value) < 4:
        return True
    # URLs without credentials
    if value.startswith(("http://", "https://", "ftp://")) and "@" not in value:
        return True
    # File paths
    if value.startswith(("/", "./", "../")):
        return True
    # Common non-sensitive config values (environment names, log levels, etc.)
    _COMMON_CONFIG_VALUES: frozenset[str] = frozenset({
        "production", "staging", "development", "dev", "prod", "test",
        "info", "debug", "warning", "error", "warn", "trace",
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1",
        "localhost", "127.0.0.1", "0.0.0.0",
        "api", "web", "worker", "scheduler", "celery",
        "json", "yaml", "xml", "text", "html",
        "redis", "postgres", "mysql", "mongodb", "sqlite",
    })
    if lower in _COMMON_CONFIG_VALUES:
        return True
    # Dotted identifiers like api.internal, db.production (hostnames)
    if re.match(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$", lower) and "@" not in value:
        return True
    return False


def _make_masked_snippet(line_text: str, max_length: int = 200) -> str:
    """Create a masked snippet from a line of text.

    SECURITY: The full original line is masked FIRST, then the masked text
    is truncated. This ensures secrets spanning the truncation boundary
    cannot survive as partial fragments in the output.
    The original snippet NEVER enters the Finding.
    """
    masked = mask_snippet(line_text)
    return masked[:max_length] if len(masked) > max_length else masked


class _LineSnippetCache:
    """Per-line masked-snippet cache.

    Ensures ``mask_snippet`` is called at most ONCE per line per rule,
    regardless of how many matches the rule produces on that line. All
    Findings generated from the same line share the same safe snippet.

    Usage::

        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            snippet = cache.get(i, line)   # computed once, then cached
    """

    __slots__ = ("_lines", "_cache")

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._cache: dict[int, str] = {}

    def get(self, index: int, line: str) -> str:
        snippet = self._cache.get(index)
        if snippet is None:
            snippet = _make_masked_snippet(line)
            self._cache[index] = snippet
        return snippet


# Risk ordering for BoundedFindingCollector.
# Higher number = higher risk. Used to compare Findings so that blocking
# critical findings are never evicted by low-entropy placeholders.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


def _finding_risk_key(f: Finding) -> tuple[int, int, int, int, int, str]:
    """Risk-sort key for a Finding.

    Higher tuple = higher risk. Ordering:
      1. is_blocking (True first)
      2. severity rank (critical > high > medium > low > info)
      3. confidence rank (high > medium > low)
      4. line_start (earlier = higher priority when risk ties)
      5. column_start (earlier = higher priority)
      6. rule_id (stable tiebreaker)
    """
    return (
        1 if f.is_blocking else 0,
        _SEVERITY_RANK.get(f.severity, 0),
        _CONFIDENCE_RANK.get(f.confidence, 0),
        -f.line_start if f.line_start is not None else 0,
        -f.column_start if f.column_start is not None else 0,
        f.rule_id,
    )


class BoundedFindingCollector:
    """Risk-priority bounded collector for a single rule's Findings.

    Keeps at most ``limit`` Findings per rule per file, but ALWAYS
    preserves the highest-risk ones. This prevents 100 low-entropy
    placeholder tokens from evicting the 101st real blocking token.

    Scanning continues across the ENTIRE file — the limit is never used
    as an early-exit gate. When the list is full:
    - A new candidate with risk <= the current minimum is SKIPPED (no
      Finding object constructed, no snippet computed).
    - A new candidate with risk > the current minimum REPLACES the
      minimum.

    After scanning, call ``finalize()`` to get the list restored to
    stable file order (by line_start, column_start, rule_id).

    Usage::

        collector = BoundedFindingCollector(limit=100)
        for i, line in enumerate(lines):
            for match in pattern.finditer(line):
                blocking, severity, confidence = classify(...)
                if not collector.should_accept(
                    blocking, severity, confidence,
                    i + 1, match.start(), self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(...))
        findings = collector.finalize()
    """

    __slots__ = ("_limit", "_findings", "_min_key", "_min_index")

    def __init__(self, limit: int) -> None:
        # Guard against misconfiguration (limit <= 0). At least 1 so
        # detection is never fully disabled.
        self._limit = max(1, limit)
        self._findings: list[Finding] = []
        self._min_key: tuple | None = None
        self._min_index: int = 0

    def _candidate_key(
        self,
        is_blocking: bool,
        severity: Severity,
        confidence: Confidence,
        line_start: int,
        column_start: int,
        rule_id: str,
    ) -> tuple[int, int, int, int, int, str]:
        return (
            1 if is_blocking else 0,
            _SEVERITY_RANK.get(severity, 0),
            _CONFIDENCE_RANK.get(confidence, 0),
            -line_start,
            -column_start,
            rule_id,
        )

    def should_accept(
        self,
        is_blocking: bool,
        severity: Severity,
        confidence: Confidence,
        line_start: int,
        column_start: int,
        rule_id: str,
    ) -> bool:
        """Check whether a candidate would be kept, WITHOUT constructing a Finding.

        Call this BEFORE building the Finding object and BEFORE computing
        the snippet. This avoids wasted work when the candidate would be
        evicted anyway.

        Returns True if:
        - The list is not yet full, OR
        - The candidate's risk is higher than the current minimum.
        """
        if len(self._findings) < self._limit:
            return True
        # List is full — compare against the minimum.
        candidate_key = self._candidate_key(
            is_blocking, severity, confidence, line_start, column_start, rule_id,
        )
        return candidate_key > (self._min_key or ())

    def add(self, finding: Finding) -> None:
        """Add a Finding to the collector, evicting the lowest-risk if full."""
        f_key = _finding_risk_key(finding)
        if len(self._findings) < self._limit:
            self._findings.append(finding)
            # Update min tracking
            if self._min_key is None or f_key < self._min_key:
                self._min_key = f_key
                self._min_index = len(self._findings) - 1
        else:
            # Full — replace the minimum if new is higher risk
            if f_key > (self._min_key or ()):
                self._findings[self._min_index] = finding
                # Recompute min (the replaced slot's old min is gone)
                self._recompute_min()

    def _recompute_min(self) -> None:
        """Recompute the minimum-risk slot after a replacement."""
        if not self._findings:
            self._min_key = None
            self._min_index = 0
            return
        min_key = _finding_risk_key(self._findings[0])
        min_index = 0
        for idx in range(1, len(self._findings)):
            k = _finding_risk_key(self._findings[idx])
            if k < min_key:
                min_key = k
                min_index = idx
        self._min_key = min_key
        self._min_index = min_index

    def finalize(self) -> list[Finding]:
        """Return findings in stable file order (line, column, rule_id)."""
        result = sorted(
            self._findings,
            key=lambda f: (
                f.line_start if f.line_start is not None else 0,
                f.column_start if f.column_start is not None else 0,
                f.rule_id,
            ),
        )
        return result


# ---------------------------------------------------------------------------
# --- R001: GitHub Token ---
# ---------------------------------------------------------------------------

class GitHubTokenRule(Rule):
    """Detect GitHub personal access tokens: ghp_ + 36 alphanumeric chars."""

    rule_id = "R001_GITHUB_TOKEN"
    rule_name = "GitHub Token"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    _pattern = re.compile(r"ghp_[A-Za-z0-9]{36}")

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                token = match.group()
                # Low-entropy placeholder downgrade (e.g., ghp_AAAAAA...)
                if is_low_entropy(token, prefix_len=4):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking
                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, match.start(), self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="GitHub personal access token detected",
                    category="token",
                    secret_type="github_token",
                    message="GitHub personal access token detected",
                    repair_template_key="rotate_github_token",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R002: AWS Access Key ---
# ---------------------------------------------------------------------------

class AWSAccessKeyRule(Rule):
    """Detect AWS access key IDs: AKIA + 16 uppercase alphanumeric chars."""

    rule_id = "R002_AWS_ACCESS_KEY"
    rule_name = "AWS Access Key"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    _pattern = re.compile(r"AKIA[A-Z0-9]{16}")

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                token = match.group()
                if is_low_entropy(token, prefix_len=4):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking
                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, match.start(), self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="AWS access key ID detected",
                    category="token",
                    secret_type="aws_access_key",
                    message="AWS access key ID detected",
                    repair_template_key="rotate_aws_credentials",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R003: AWS Secret Key (context-aware) ---
# ---------------------------------------------------------------------------

class AWSSecretKeyRule(Rule):
    """Detect AWS secret access keys: 40-char base64 in aws_secret context.

    Only matches when the key is classified as aws_secret by classify_key()
    (AWS_SECRET_ACCESS_KEY, SECRET_ACCESS_KEY, AWS_SECRET) AND the value
    is a 40-char base64-like string. This prevents false positives from
    random 40-character base64 strings (hashes, commit IDs, etc.).
    """

    rule_id = "R003_AWS_SECRET_KEY"
    rule_name = "AWS Secret Key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for assignment in iter_assignments(line):
                if classify_key(assignment.key_raw) != CATEGORY_AWS_SECRET:
                    continue
                value = assignment.value
                if not value:
                    continue
                # Must be a 40-char base64-like string
                if not re.fullmatch(r"[A-Za-z0-9/+]{40}", value):
                    continue
                if is_env_reference(value, assignment.is_quoted):
                    continue
                if _is_placeholder(value):
                    continue
                # Low-entropy placeholder downgrade (e.g., all same char)
                if is_low_entropy(value, prefix_len=0):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking
                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, assignment.value_start, self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=assignment.value_start,
                    column_end=assignment.value_end,
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="AWS secret access key detected",
                    category="token",
                    secret_type="aws_secret_key",
                    message="AWS secret access key detected",
                    repair_template_key="rotate_aws_credentials",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R004: Google API Key ---
# ---------------------------------------------------------------------------

class GoogleAPIKeyRule(Rule):
    """Detect Google API keys: AIza + 35 chars."""

    rule_id = "R004_GOOGLE_API_KEY"
    rule_name = "Google API Key"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    _pattern = re.compile(r"AIza[A-Za-z0-9_\-]{35}")

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                token = match.group()
                if is_low_entropy(token, prefix_len=4):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking
                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, match.start(), self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="Google API key detected",
                    category="token",
                    secret_type="google_api_key",
                    message="Google API key detected",
                    repair_template_key="rotate_google_api_key",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R005: Private Key (BEGIN/END pairing) ---
# ---------------------------------------------------------------------------

class PrivateKeyRule(Rule):
    """Detect private key blocks using explicit BEGIN/END header pairs.

    Covers: RSA, EC, OPENSSH, PKCS8 (PRIVATE KEY), DSA, PGP PRIVATE KEY BLOCK.

    Uses a single-pass O(n) state machine — no nested loops. Walks through
    all lines exactly once, tracking at most one pending BEGIN at a time.

    Pending semantics (revised):
    - While a BEGIN is pending (no matching END found yet), the scanner
      ONLY looks for the matching END header. Any new BEGIN headers that
      appear before the END are IGNORED — they do NOT replace the
      pending BEGIN and do NOT produce Findings.
    - This means ``BEGIN / BEGIN / END`` produces ONE Finding spanning
      from the FIRST BEGIN (line 1) to the END (line 3).
    - At file end, if a pending BEGIN remains, at most ONE incomplete
      Finding is emitted.
    - Consecutive COMPLETE keys (BEGIN + END pairs) still produce
      separate Findings.

    - snippet_masked is ALWAYS <PRIVATE_KEY_REDACTED>, never the key content.
    - 10000 consecutive BEGINs: O(n), at most 1 incomplete Finding.
    """

    rule_id = "R005_PRIVATE_KEY"
    rule_name = "Private Key"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    # Explicit BEGIN/END pairing table
    _KEY_PAIRS: dict[str, str] = {
        "-----BEGIN RSA PRIVATE KEY-----": "-----END RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----": "-----END EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----": "-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----": "-----END PRIVATE KEY-----",  # PKCS8
        "-----BEGIN DSA PRIVATE KEY-----": "-----END DSA PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----": "-----END PGP PRIVATE KEY BLOCK-----",
    }

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        """Single-pass O(n) scan using a state machine.

        While a BEGIN is pending, ONLY the matching END is searched for.
        New BEGIN headers encountered before the END are IGNORED — they
        do not replace the pending BEGIN. This keeps the FIRST BEGIN's
        line number as the block start, so ``BEGIN / BEGIN / END``
        yields line_start=1, line_end=3.
        """
        findings: list[Finding] = []
        limit = settings.scan_max_findings_per_rule_per_file
        # pending holds info about an unclosed BEGIN: (header, end_header,
        # begin_line_1based, col_start, col_end)
        pending: tuple[str, str, int, int, int] | None = None

        for i, line in enumerate(lines):
            # --- If we have a pending BEGIN, ONLY look for the matching END ---
            if pending is not None:
                begin_header, end_header, begin_line, col_s, col_e = pending
                if end_header in line:
                    # Found matching END — emit complete finding.
                    if len(findings) >= limit:
                        return findings
                    key_type = begin_header.strip("-").strip()
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line_start=begin_line,
                        line_end=i + 1,
                        column_start=col_s,
                        column_end=col_e,
                        snippet_masked="<PRIVATE_KEY_REDACTED>",
                        is_blocking=self.is_blocking,
                        finding_type=self.finding_type,
                        description=f"Private key block detected ({key_type})",
                        category="private_key",
                        secret_type="private_key",
                        message="Private key block detected",
                        repair_template_key="rotate_private_key",
                    ))
                    pending = None
                # While pending, IGNORE any new BEGIN headers on this line.
                # Only the matching END can close the block.
                continue

            # --- No pending BEGIN: check for a BEGIN header on this line ---
            begin_header: str | None = None
            begin_pos = -1
            end_header_matched: str | None = None
            for bh, eh in self._KEY_PAIRS.items():
                pos = line.find(bh)
                if pos != -1:
                    begin_header = bh
                    begin_pos = pos
                    end_header_matched = eh
                    break

            if begin_header is None:
                continue

            # Check if END is on the same line (after BEGIN)
            if end_header_matched is not None:
                end_pos = line.find(end_header_matched, begin_pos + len(begin_header))
                if end_pos != -1:
                    # Complete on same line
                    if len(findings) >= limit:
                        return findings
                    key_type = begin_header.strip("-").strip()
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        confidence=self.confidence,
                        file_path=file_path,
                        line_start=i + 1,
                        line_end=i + 1,
                        column_start=begin_pos,
                        column_end=begin_pos + len(begin_header),
                        snippet_masked="<PRIVATE_KEY_REDACTED>",
                        is_blocking=self.is_blocking,
                        finding_type=self.finding_type,
                        description=f"Private key block detected ({key_type})",
                        category="private_key",
                        secret_type="private_key",
                        message="Private key block detected",
                        repair_template_key="rotate_private_key",
                    ))
                else:
                    # Set as pending — END not found yet
                    pending = (
                        begin_header, end_header_matched,
                        i + 1, begin_pos, begin_pos + len(begin_header),
                    )

        # --- End of file: emit at most ONE incomplete finding for unclosed BEGIN ---
        if pending is not None:
            old_header, _, old_line, old_cs, old_ce = pending
            old_type = old_header.strip("-").strip()
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=self.confidence,
                file_path=file_path,
                line_start=old_line,
                line_end=old_line,
                column_start=old_cs,
                column_end=old_ce,
                snippet_masked="<PRIVATE_KEY_REDACTED>",
                is_blocking=self.is_blocking,
                finding_type=self.finding_type,
                description=(
                    f"Incomplete private key block -- BEGIN header found "
                    f"without matching END ({old_type})"
                ),
                category="private_key",
                secret_type="private_key",
                message="Private key block detected",
                repair_template_key="rotate_private_key",
            ))

        return findings


# ---------------------------------------------------------------------------
# --- R006: Password Assignment ---
# ---------------------------------------------------------------------------

class PasswordAssignmentRule(Rule):
    """Detect password assignments using unified assignment parsing.

    Uses iter_assignments() to find ALL key=value assignments, then
    classify_key() to filter for password-category keys (PASSWORD,
    DB_PASSWORD, DATABASE_PASSWORD, MYSQL_PWD, ADMIN_PASSWD, etc.).

    False positive control:
    - Env var references are skipped.
    - Placeholder values (changeme, foobar, etc.) are downgraded to
      low severity / low confidence / non-blocking.

    NOTE: This is a generic heuristic — non-blocking. Only explicit-format
    tokens (R001-R005) and complete private keys are blocking.
    """

    rule_id = "R006_PASSWORD_ASSIGNMENT"
    rule_name = "Password Assignment"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = False
    finding_type = FindingType.CONTENT

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for assignment in iter_assignments(line):
                if classify_key(assignment.key_raw) != CATEGORY_PASSWORD:
                    continue
                value = assignment.value
                if not value:
                    continue
                if is_env_reference(value, assignment.is_quoted):
                    continue
                if is_already_masked(value):
                    continue

                # Determine severity/confidence based on placeholder check
                if _is_placeholder(value):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking

                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, assignment.value_start, self.rule_id,
                ):
                    continue
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=assignment.value_start,
                    column_end=assignment.value_end,
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="Hardcoded password assignment detected",
                    category="password",
                    secret_type="password",
                    message="Hardcoded password assignment detected",
                    repair_template_key="use_env_var_password",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R007: Generic Token Assignment ---
# ---------------------------------------------------------------------------

class GenericTokenAssignmentRule(Rule):
    """Detect generic token/secret assignments using unified assignment parsing.

    Uses iter_assignments() to find ALL key=value assignments, then
    classify_key() to filter for sensitive keys.

    Handles TWO categories:
    1. CATEGORY_SECRET — standard secret/token keys (SECRET, JWT_SECRET,
       TOKEN, ACCESS_TOKEN, GITHUB_TOKEN, API_KEY, etc.)
    2. CATEGORY_AWS_SECRET — AWS secret key names (AWS_SECRET_ACCESS_KEY,
       SECRET_ACCESS_KEY, AWS_SECRET) when the value does NOT meet R003's
       strict 40-char base64 format. This provides a non-blocking fallback
       so short or non-standard AWS secret values are still detected.

    When the value DOES meet R003's strict format, R007 skips it — R003
    (higher priority, blocking) will catch it. The scanner's dedup logic
    ensures no duplicate findings on the same line/column.

    False positive control:
    - Env var references are skipped.
    - Placeholder values are downgraded to low/low/non-blocking.
    - Explicit-format tokens (ghp_, AKIA, AIza) are NOT affected by downgrade
      because they are caught by their specific rules with higher priority.

    NOTE: This is a generic heuristic — non-blocking. Only explicit-format
    tokens (R001-R005) and complete private keys are blocking.
    """

    rule_id = "R007_GENERIC_TOKEN_ASSIGNMENT"
    rule_name = "Generic Token Assignment"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = False
    finding_type = FindingType.CONTENT

    # R003 strict format: 40-char base64-like string
    _AWS_STRICT_FORMAT = re.compile(r"[A-Za-z0-9/+]{40}")

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for assignment in iter_assignments(line):
                category = classify_key(assignment.key_raw)

                # Only handle SECRET and AWS_SECRET categories
                if category == CATEGORY_SECRET:
                    pass  # Standard secret processing below
                elif category == CATEGORY_AWS_SECRET:
                    # Skip if value meets R003 strict format — R003 will
                    # catch it with higher priority and blocking status.
                    if self._AWS_STRICT_FORMAT.fullmatch(assignment.value):
                        continue
                    # Otherwise, fall through to generate a non-blocking
                    # generic finding (AWS secret with non-standard value).
                else:
                    continue

                value = assignment.value
                if not value:
                    continue
                if value.lower() in ("true", "false"):
                    # Boolean flag (e.g. has_auth_token: true) — not a credential.
                    continue
                if is_env_reference(value, assignment.is_quoted):
                    continue
                if is_already_masked(value):
                    continue

                # Findings in test files are heuristic matches on test
                # fixtures (fake keys/tokens) — downgrade to low severity
                # instead of scoring as high.
                is_test_file = (
                    file_path.startswith("tests/")
                    or "/tests/" in file_path
                    or file_path.startswith("test/")
                    or "/test/" in file_path
                )

                if _is_placeholder(value) or is_test_file:
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking

                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, assignment.value_start, self.rule_id,
                ):
                    continue

                # Use appropriate description based on category
                if category == CATEGORY_AWS_SECRET:
                    description = "AWS secret key with non-standard value detected"
                    secret_type = "aws_secret_key_generic"
                    repair_template_key = "rotate_aws_credentials"
                else:
                    description = "Hardcoded secret/token assignment detected"
                    secret_type = "generic_token"
                    repair_template_key = "use_env_var_secret"

                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=assignment.value_start,
                    column_end=assignment.value_end,
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description=description,
                    category="secret",
                    secret_type=secret_type,
                    message=description,
                    repair_template_key=repair_template_key,
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R008: Connection String ---
# ---------------------------------------------------------------------------

class ConnectionStringRule(Rule):
    """Detect connection strings with embedded passwords.

    Pattern: scheme://user:password@host

    Uses the SHARED ``iter_connection_strings`` matcher from
    ``app.core.security.desensitize`` — the SAME matcher used by
    ``mask_untrusted_text`` and ``mask_snippet``. No rule may maintain
    a duplicate connection-string regex. The host/rest group stops at
    source/config separators (quotes, backtick, comma, semicolon, right
    bracket, right brace, whitespace), so multiple connection strings
    on the same line are matched SEPARATELY — each produces its own
    Finding and each password is masked.

    NOTE: Medium confidence, non-blocking. This is a heuristic detection;
    a future strict high-confidence mode may be added separately.
    """

    rule_id = "R008_CONNECTION_STRING"
    rule_name = "Connection String"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = False
    finding_type = FindingType.CONTENT

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            for match in iter_connection_strings(line):
                # group 3 is the password in the shared pattern
                password = match.group(3)

                # 1. Skip environment variable references
                if is_env_reference(password):
                    continue
                # 2. Skip already-masked values
                if is_already_masked(password):
                    continue

                # 3. Placeholder / weak passwords: generate low/low/non-blocking
                if _is_placeholder(password):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    # 4. Other hardcoded passwords: medium confidence, non-blocking
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking

                if not collector.should_accept(
                    blocking, severity, confidence, i + 1, match.start(3), self.rule_id,
                ):
                    continue

                # 5. snippet always replaces password with ***
                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(3),
                    column_end=match.end(3),
                    snippet_masked=snippet,
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="Connection string with embedded password detected",
                    category="connection_string",
                    secret_type="connection_string",
                    message="Connection string with embedded password detected",
                    repair_template_key="use_env_var_connection_string",
                ))
        return collector.finalize()


# ---------------------------------------------------------------------------
# --- R009: .env File Present ---
# ---------------------------------------------------------------------------

class EnvFilePresentRule(Rule):
    """Detect .env file existence.

    The .env file itself is at most medium risk (non-blocking).
    The real risk is determined by the content rules that scan inside it.
    """

    rule_id = "R009_ENV_FILE_PRESENT"
    rule_name = ".env File Present"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    is_blocking = False
    finding_type = FindingType.FILE

    def check_file(self, file_path: str, file_size: int) -> Finding | ScanNotice | None:
        basename = file_path.split("/")[-1]
        if basename == ".env":
            return Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=self.confidence,
                file_path=file_path,
                line_start=None,
                line_end=None,
                column_start=None,
                column_end=None,
                snippet_masked="",
                is_blocking=self.is_blocking,
                finding_type=self.finding_type,
                description=".env file detected -- may contain environment secrets",
                category="env_file",
                secret_type="env_file",
                message=".env file detected -- may contain environment secrets",
                repair_template_key="secure_env_file",
            )
        return None


# ---------------------------------------------------------------------------
# --- R010: .env.example File (ScanNotice, not a security finding) ---
# ---------------------------------------------------------------------------

class EnvExampleFileRule(Rule):
    """Detect .env.example or .env.sample files.

    This is NOT a security finding. It returns a ScanNotice providing
    informational context about the project.
    """

    rule_id = "R010_ENV_EXAMPLE_FILE"
    rule_name = ".env Example File"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    is_blocking = False
    finding_type = FindingType.FILE

    def check_file(self, file_path: str, file_size: int) -> Finding | ScanNotice | None:
        basename = file_path.split("/")[-1]
        if basename in (".env.example", ".env.sample", ".env.template"):
            return ScanNotice(
                rule_id=self.rule_id,
                message=f"Environment example file found: {basename}",
                file_path=file_path,
            )
        return None


# ---------------------------------------------------------------------------
# --- R011: Production Env With Secret ---
# ---------------------------------------------------------------------------

class ProductionEnvWithSecretRule(Rule):
    """Detect hardcoded secrets in production environment files.

    Scans .env.production, .env.prod, .env.staging for KEY=VALUE patterns
    where ALL of the following are true:
    1. The file is a production environment config file.
    2. The variable NAME has sensitive semantics (classify_key returns
       non-None — covers password, secret, token, api_key, access_key,
       private_key, client_secret, jwt_secret, etc.).
    3. The VALUE is not a placeholder, env reference, masked content,
       boolean, pure number, or common non-sensitive config value.

    Uses iter_assignments() for unified assignment parsing and
    classify_key() for sensitive key detection.

    Dedup: R011 is only suppressed on the SAME LINE where it column-overlaps
    with a higher-priority specific format rule (R001-R005). R011 on a
    different line is always kept, even if the same file has specific
    findings on other lines.
    """

    rule_id = "R011_PRODUCTION_ENV_WITH_SECRET"
    rule_name = "Production Env With Secret"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    is_blocking = True
    finding_type = FindingType.CONTENT

    _env_filenames = frozenset({".env.production", ".env.prod", ".env.staging"})

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        basename = file_path.split("/")[-1]
        if basename not in self._env_filenames:
            return []

        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        cache = _LineSnippetCache(lines)
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            for assignment in iter_assignments(line):
                # --- Requirement 1: variable name must have sensitive semantics ---
                if classify_key(assignment.key_raw) is None:
                    continue

                value = assignment.value
                if not value:
                    continue

                # --- Requirement 2: value must not be excluded ---
                if is_env_reference(value, assignment.is_quoted):
                    continue
                if _is_placeholder(value):
                    continue
                if is_already_masked(value):
                    continue
                if _is_likely_non_secret(value):
                    continue

                if not collector.should_accept(
                    self.is_blocking, self.severity, self.confidence,
                    i + 1, assignment.value_start, self.rule_id,
                ):
                    continue

                snippet = cache.get(i, line)
                collector.add(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=assignment.value_start,
                    column_end=assignment.value_end,
                    snippet_masked=snippet,
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="Production environment file contains hardcoded secret",
                    category="production_env",
                    secret_type="production_secret",
                    message="Production environment file contains hardcoded secret",
                    repair_template_key="use_env_var_production",
                ))
        return collector.finalize()
