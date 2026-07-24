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
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import Optional


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


@dataclass(frozen=True)
class ScanNotice:
    """A non-security notice (e.g., .env.example file present).

    Notices are NOT security findings and do not affect the score.
    They provide informational context about the project.
    """
    rule_id: str
    message: str
    file_path: Optional[str] = None


@dataclass(frozen=True)
class SkippedFile:
    """A file that was skipped during scanning.

    Attributes:
        file_path: POSIX-format relative path.
        reason:    Why the file was skipped (e.g., "binary", "too_large", "ignored_dir").
    """
    file_path: str
    reason: str


@dataclass(frozen=True)
class ScanError:
    """An error encountered while scanning a specific file.

    error_message is always desensitized -- no sensitive content.
    """
    file_path: str
    error_type: str
    error_message: str


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
