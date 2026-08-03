"""Base models and Rule abstract class for the sensitive information scanner.

This module contains ONLY:
- Enum definitions (Severity, Confidence, FindingType)
- Data models (Finding, ScanNotice, SkippedFile, ScanError, ScanResult)
- Rule abstract class

It does NOT import any concrete rules or the scanner core, avoiding circular imports.

Column convention:
- column_start: 0-based, inclusive (first char of the secret)
- column_end:   0-based, exclusive (one past the last char)
- Example: "password=mypass" -- "mypass" is at [9, 15)
- Frontend display converts to 1-based as needed.

Immutability:
- All data models use @dataclass(frozen=True).
- ScanResult collections (findings, notices, skipped_files, scan_errors) use
  tuple, not list, to prevent mutation of frozen dataclass internals.

file_path safety:
- Finding, ScanNotice, SkippedFile, ScanError all sanitize file_path in
  __post_init__ via mask_untrusted_text. This provides a SELF-GUARANTEE:
  even if a rule is called directly (not through scan_directory),
  file_path can never contain a raw explicit-format secret.
- scan_directory ALSO applies mask_untrusted_text as a first layer —
  the __post_init__ is the second layer (defense in depth).
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.core.security.desensitize import mask_untrusted_text


SENSITIVE_DATA_DIMENSION = "sensitive_data_security"
INCOMPLETE_CONTENT_DIMENSION = "incomplete_content"
DEPLOYABILITY_PRODUCTION_DIMENSION = "deployability_production"
BASIC_SECURITY_DIMENSION = "basic_security"
DOCUMENTATION_CONSISTENCY_DIMENSION = "documentation_consistency"


# ---------------------------------------------------------------------------
# --- Enums ---
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Risk severity levels, from most to least severe."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Detection confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingType(str, Enum):
    """Whether a finding is line-level content or file-level property."""
    CONTENT = "content"   # line-level: has line_start, column_start, etc.
    FILE = "file"         # file-level: no line/column info


# ---------------------------------------------------------------------------
# --- Data models (all frozen, all collections are tuples) ---
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """A single detected sensitive information issue.

    Attributes:
        rule_id:       Machine-readable rule identifier (e.g., "R001_GITHUB_TOKEN").
        rule_name:     Human-readable rule name.
        severity:      Risk severity level.
        confidence:    Detection confidence.
        file_path:     POSIX-format relative path within the repository.
        line_start:    1-based line number where the issue starts (None for file-type).
        line_end:      1-based line number where the issue ends (None for file-type).
        column_start:  0-based, inclusive start column of the secret.
        column_end:    0-based, exclusive end column of the secret.
        snippet_masked: Masked snippet -- NEVER contains the original secret.
        is_blocking:   If True, this finding triggers BLOCKED status.
        finding_type:  CONTENT (line-level) or FILE (file-level).
        description:   Human-readable description of the issue.
        category:      Broad category (e.g., "token", "password", "private_key").
        secret_type:   Specific secret type identifier (e.g., "github_token").
        message:       Short human-readable message for display.
        repair_template_key: Stable identifier for the repair template
                       (full template not implemented in this phase).

    SECURITY: This dataclass must NEVER contain raw_value, raw_snippet,
    original_secret, or any field that holds the original secret text.
    """
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    column_start: Optional[int]
    column_end: Optional[int]
    snippet_masked: str
    is_blocking: bool
    finding_type: FindingType
    description: str
    category: str
    secret_type: str
    message: str
    repair_template_key: str
    dimension: str = SENSITIVE_DATA_DIMENSION

    def __post_init__(self) -> None:
        """Sanitize file_path via mask_untrusted_text (self-guarantee).

        Even if a rule is called directly with an unsanitized path
        containing an embedded secret, the Finding itself ensures
        file_path is safe. Uses object.__setattr__ because the
        dataclass is frozen.
        """
        object.__setattr__(self, "file_path", mask_untrusted_text(self.file_path))


@dataclass(frozen=True)
class ScanNotice:
    """A non-security notice (e.g., .env.example file present).

    Notices are NOT security findings and do not affect the score.
    They provide informational context about the project.
    """
    rule_id: str
    message: str
    file_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Sanitize file_path via mask_untrusted_text (self-guarantee).

        Skips None file_path (notices may not have a path).
        """
        if self.file_path is not None:
            object.__setattr__(
                self, "file_path", mask_untrusted_text(self.file_path)
            )


@dataclass(frozen=True)
class SkippedFile:
    """A file that was skipped during scanning.

    Attributes:
        file_path: POSIX-format relative path.
        reason:    Why the file was skipped (e.g., "binary", "too_large", "ignored_dir").
    """
    file_path: str
    reason: str

    def __post_init__(self) -> None:
        """Sanitize file_path via mask_untrusted_text (self-guarantee)."""
        object.__setattr__(self, "file_path", mask_untrusted_text(self.file_path))


@dataclass(frozen=True)
class ScanError:
    """An error encountered while scanning a specific file.

    error_message is always desensitized -- no sensitive content.
    """
    file_path: str
    error_type: str
    error_message: str

    def __post_init__(self) -> None:
        """Sanitize file_path via mask_untrusted_text (self-guarantee)."""
        object.__setattr__(self, "file_path", mask_untrusted_text(self.file_path))


@dataclass(frozen=True)
class ScanResult:
    """Complete result of a directory scan.

    All collection fields are tuples to ensure immutability of this frozen dataclass.
    """
    findings: tuple[Finding, ...]
    notices: tuple[ScanNotice, ...]
    skipped_files: tuple[SkippedFile, ...]
    scan_errors: tuple[ScanError, ...]
    total_files_scanned: int
    total_lines_scanned: int


class RepositoryProbe(ABC):
    """Per-scan state for rules that need a repository-wide view.

    A fresh probe is created for every scan. Implementations must retain only
    bounded derived state and must never expose raw repository content.
    """

    def observe_path(self, file_path: str) -> None:
        """Observe one validated, desensitized repository file path."""

    def observe_file(self, file_path: str, lines: list[str]) -> None:
        """Observe one validated, decoded repository file."""

    def finalize(self) -> list[Finding]:
        """Return deterministic repository-level findings."""
        return []


# ---------------------------------------------------------------------------
# --- Rule abstract class ---
# ---------------------------------------------------------------------------

class Rule(ABC):
    """Abstract base class for all scanning rules.

    Subclasses must set class attributes (rule_id, rule_name, severity, etc.)
    and override the appropriate scan method:

    - Content rules (finding_type = FindingType.CONTENT):
      Override scan_content() to scan file content line by line.

    - File rules (finding_type = FindingType.FILE):
      Override check_file() to check file-level properties (name, existence).

    The scanner calls scan_content() for content rules and check_file()
    for file rules. A rule should NOT override both.
    """

    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    is_blocking: bool = False
    finding_type: FindingType = FindingType.CONTENT
    dimension: str = SENSITIVE_DATA_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        """Scan file content line by line. Override for content-type rules.

        Args:
            file_path: POSIX-format relative path.
            lines:     List of lines (strings, without newline characters).

        Returns:
            List of Finding objects. Empty list if no issues found.
        """
        return []

    def check_file(self, file_path: str, file_size: int) -> Finding | ScanNotice | None:
        """Check file-level properties. Override for file-type rules.

        Args:
            file_path: POSIX-format relative path.
            file_size: File size in bytes.

        Returns:
            A Finding (security issue), a ScanNotice (informational), or None.
        """
        return None

    def create_repository_probe(self) -> RepositoryProbe | None:
        """Create isolated repository-level state for one scan, if needed."""
        return None
