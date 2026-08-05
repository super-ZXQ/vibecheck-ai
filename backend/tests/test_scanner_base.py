"""Tests for scanner base models and Rule abstract class.

Verifies immutability (frozen dataclass), tuple collections, and enum values.

Test count: 5
"""

import dataclasses

import pytest

from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanResult,
    Severity,
)

# ============================================================================
# --- Immutability tests (3 tests) ---
# ============================================================================

class TestImmutability:
    """Verify that data models are truly immutable."""

    def test_finding_is_frozen(self):
        """Finding attributes cannot be modified after creation."""
        finding = Finding(
            rule_id="R001_GITHUB_TOKEN",
            rule_name="GitHub Token",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path="config.py",
            line_start=1,
            line_end=1,
            column_start=0,
            column_end=40,
            snippet_masked="<REDACTED>",
            is_blocking=True,
            finding_type=FindingType.CONTENT,
            description="test",
            category="token",
            secret_type="github_token",
            message="GitHub token detected",
            repair_template_key="R001_revoke_and_rotate",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            finding.rule_id = "CHANGED"  # type: ignore

    def test_scan_result_is_frozen(self):
        """ScanResult attributes cannot be modified after creation."""
        result = ScanResult(
            findings=(),
            notices=(),
            skipped_files=(),
            scan_errors=(),
            total_files_scanned=0,
            total_lines_scanned=0,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.total_files_scanned = 999  # type: ignore

    def test_scan_result_uses_tuples(self):
        """ScanResult collection fields are tuples, not lists."""
        result = ScanResult(
            findings=(),
            notices=(),
            skipped_files=(),
            scan_errors=(),
            total_files_scanned=0,
            total_lines_scanned=0,
        )
        assert isinstance(result.findings, tuple)
        assert isinstance(result.notices, tuple)
        assert isinstance(result.skipped_files, tuple)
        assert isinstance(result.scan_errors, tuple)


# ============================================================================
# --- Enum tests (2 tests) ---
# ============================================================================

class TestEnums:
    """Verify enum values are correct."""

    def test_severity_enum_values(self):
        """Severity enum has the expected values in order."""
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_confidence_enum_values(self):
        """Confidence enum has the expected values."""
        assert Confidence.HIGH == "high"
        assert Confidence.MEDIUM == "medium"
        assert Confidence.LOW == "low"
