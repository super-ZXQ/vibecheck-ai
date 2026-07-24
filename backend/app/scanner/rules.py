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

from app.core.security.desensitize import (
    GENERIC,
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


# Indicators that a value has already been masked/redacted.
# Used to skip already-desensitized values in documentation or examples.
_MASKED_INDICATORS: frozenset[str] = frozenset({
    "<REDACTED>", "<PRIVATE_KEY_REDACTED>", "***",
})


def _is_already_masked(value: str) -> bool:
    """Check if a value appears to be already masked/redacted."""
    return any(indicator in value for indicator in _MASKED_INDICATORS)


def _is_env_reference(value: str) -> bool:
    """Check if a value is an environment variable reference, not a hardcoded secret.

    Skips:
    - ${VAR} or ${VAR:-default}  (shell/Docker env reference)
    - process.env.XXX            (Node.js)
    - os.environ['XXX']          (Python)
    - os.getenv('XXX')           (Python)
    - $VAR                       (shell variable)
    """
    value = value.strip()
    if value.startswith("${"):
        return True
    if value.startswith("process.env."):
        return True
    if value.startswith("os.environ"):
        return True
    if value.startswith("os.getenv"):
        return True
    if value.startswith("$") and len(value) > 1 and not value.startswith("$("):
        return True
    return False


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
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                token = match.group()
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="GitHub personal access token detected",
                ))
        return findings


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
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="AWS access key ID detected",
                ))
        return findings


# ---------------------------------------------------------------------------
# --- R003: AWS Secret Key (context-aware) ---
# ---------------------------------------------------------------------------

class AWSSecretKeyRule(Rule):
    """Detect AWS secret access keys: 40-char base64 in aws_secret context.

    Only matches when preceded by aws_secret, secret_access_key, or
    aws_secret_access_key assignment. This prevents false positives from
    random 40-character base64 strings (hashes, commit IDs, etc.).
    """

    rule_id = "R003_AWS_SECRET_KEY"
    rule_name = "AWS Secret Key"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = True
    finding_type = FindingType.CONTENT

    _pattern = re.compile(
        r"(?i)(aws_secret|secret_access_key|aws_secret_access_key)"
        r"\s*[:=]\s*['\"]?"
        r"([A-Za-z0-9/+]{40})"
        r"(?!['\"]?[A-Za-z0-9/+=])"
    )

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                value = match.group(2)
                if _is_env_reference(value) or _is_placeholder(value):
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(2),
                    column_end=match.end(2),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="AWS secret access key detected",
                ))
        return findings


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
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="Google API key detected",
                ))
        return findings


# ---------------------------------------------------------------------------
# --- R005: Private Key (BEGIN/END pairing) ---
# ---------------------------------------------------------------------------

class PrivateKeyRule(Rule):
    """Detect private key blocks using explicit BEGIN/END header pairs.

    Covers: RSA, EC, OPENSSH, PKCS8 (PRIVATE KEY), DSA, PGP PRIVATE KEY BLOCK.

    - If END is found: complete block, snippet = <PRIVATE_KEY_REDACTED>.
    - If END is missing: still blocking, but description notes incomplete block.
      Does NOT pretend to have located the complete key body.
    - snippet_masked is ALWAYS <PRIVATE_KEY_REDACTED>, never the key content.
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
        findings: list[Finding] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            for begin_header, end_header in self._KEY_PAIRS.items():
                begin_pos = line.find(begin_header)
                if begin_pos == -1:
                    continue

                # Found a BEGIN header
                begin_line = i + 1  # 1-based
                begin_col_start = begin_pos
                begin_col_end = begin_pos + len(begin_header)

                # Search for the corresponding END header
                end_line_num: Optional[int] = None
                for j in range(i, len(lines)):
                    if end_header in lines[j]:
                        end_line_num = j + 1  # 1-based
                        break

                if end_line_num is not None:
                    description = (
                        f"Private key block detected ({begin_header.strip('-').strip()})"
                    )
                    line_end = end_line_num
                    # Skip past the END line to avoid re-detecting
                    i = end_line_num  # 0-based, will be incremented below
                else:
                    description = (
                        f"Incomplete private key block -- BEGIN header found "
                        f"without matching END ({begin_header.strip('-').strip()})"
                    )
                    line_end = begin_line

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=begin_line,
                    line_end=line_end,
                    column_start=begin_col_start,
                    column_end=begin_col_end,
                    snippet_masked="<PRIVATE_KEY_REDACTED>",
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description=description,
                ))
                break  # Don't check other headers on the same line
            i += 1
        return findings


# ---------------------------------------------------------------------------
# --- R006: Password Assignment ---
# ---------------------------------------------------------------------------

class PasswordAssignmentRule(Rule):
    """Detect password assignments: password=, passwd=, pwd=.

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

    _pattern = re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"
    )

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                value = match.group(2)
                if _is_env_reference(value):
                    continue
                if _is_already_masked(value):
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

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(2),
                    column_end=match.end(2),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="Hardcoded password assignment detected",
                ))
        return findings


# ---------------------------------------------------------------------------
# --- R007: Generic Token Assignment ---
# ---------------------------------------------------------------------------

class GenericTokenAssignmentRule(Rule):
    """Detect generic token/secret assignments: secret=, api_key=, token=.

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

    _pattern = re.compile(
        r"(?i)(secret|api_key|apikey|token|access_token)"
        r"\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"
    )

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                value = match.group(2)
                if _is_env_reference(value):
                    continue
                if _is_already_masked(value):
                    continue

                if _is_placeholder(value):
                    severity = Severity.LOW
                    confidence = Confidence.LOW
                    blocking = False
                else:
                    severity = self.severity
                    confidence = self.confidence
                    blocking = self.is_blocking

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(2),
                    column_end=match.end(2),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=blocking,
                    finding_type=self.finding_type,
                    description="Hardcoded secret/token assignment detected",
                ))
        return findings


# ---------------------------------------------------------------------------
# --- R008: Connection String ---
# ---------------------------------------------------------------------------

class ConnectionStringRule(Rule):
    """Detect connection strings with embedded passwords.

    Pattern: scheme://user:password@host

    NOTE: Medium confidence, non-blocking. This is a heuristic detection;
    a future strict high-confidence mode may be added separately.
    """

    rule_id = "R008_CONNECTION_STRING"
    rule_name = "Connection String"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = False
    finding_type = FindingType.CONTENT

    _pattern = re.compile(
        r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:[^@\s]+@\S+"
    )

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines):
            for match in self._pattern.finditer(line):
                value = match.group()
                # Skip if the password portion is a placeholder
                # Extract password for placeholder check
                pw_match = re.search(r":([^@]+)@", value)
                if pw_match:
                    pw = pw_match.group(1)
                    if _is_env_reference(pw) or _is_placeholder(pw):
                        continue

                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=i + 1,
                    line_end=i + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    snippet_masked=_make_masked_snippet(line),
                    is_blocking=self.is_blocking,
                    finding_type=self.finding_type,
                    description="Connection string with embedded password detected",
                ))
        return findings


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
        if basename in (".env.example", ".env.sample"):
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
    where VALUE is not an env reference, not a placeholder, and not obviously
    non-secret.

    Dedup: If the same file already has findings from specific rules
    (R001-R008), this rule's findings are suppressed by the scanner's
    deduplication logic (see sensitive.py).
    """

    rule_id = "R011_PRODUCTION_ENV_WITH_SECRET"
    rule_name = "Production Env With Secret"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    is_blocking = True
    finding_type = FindingType.CONTENT

    _env_filenames = frozenset({".env.production", ".env.prod", ".env.staging"})
    _kv_pattern = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$")

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        basename = file_path.split("/")[-1]
        if basename not in self._env_filenames:
            return []

        findings: list[Finding] = []
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            match = self._kv_pattern.match(line_stripped)
            if not match:
                continue

            key = match.group(1)
            value = match.group(2).strip().strip("'\"")

            # Skip env references, placeholders, masked values, and likely non-secrets
            if _is_env_reference(value):
                continue
            if _is_placeholder(value):
                continue
            if _is_already_masked(value):
                continue
            if _is_likely_non_secret(value):
                continue

            # Find the value position in the original line (not stripped)
            value_start_in_orig = line.find(value, match.start(2) + (len(line_stripped) - len(line) if line != line_stripped else 0))
            # Fallback: search from the key position
            if value_start_in_orig == -1:
                value_start_in_orig = line.find(value)
            value_end_in_orig = value_start_in_orig + len(value) if value_start_in_orig != -1 else None

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                confidence=self.confidence,
                file_path=file_path,
                line_start=i + 1,
                line_end=i + 1,
                column_start=value_start_in_orig if value_start_in_orig != -1 else None,
                column_end=value_end_in_orig if value_end_in_orig is not None else None,
                snippet_masked=_make_masked_snippet(line),
                is_blocking=self.is_blocking,
                finding_type=self.finding_type,
                description=f"Production environment file contains potential secret: {key}=<REDACTED>",
            ))
        return findings
