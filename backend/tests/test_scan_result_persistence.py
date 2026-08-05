"""Tests for scan result serialization and database persistence (P0-5).

Covers:
A. Serialization tests:
   - Empty ScanResult
   - Single Finding
   - Notices, skipped_files, scan_errors
   - Enum and tuple conversion
   - Deterministic output
   - No raw test tokens in output

B. Database tests:
   - First save
   - Upsert (same task_id)
   - Read result
   - Read summary
   - Task not found
   - Malicious text does not break SQL
   - No raw secrets in result_json
"""

import json

import pytest

from app.db import database
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanError,
    ScanNotice,
    ScanResult,
    Severity,
    SkippedFile,
)
from app.services import task_manager
from app.services.scan_result_service import (
    SCHEMA_VERSION,
    get_scan_result,
    get_scan_summary,
    save_scan_result,
    serialize_scan_result,
)
from tests.conftest import (
    SYNTHETIC_AWS_KEY,
    SYNTHETIC_GITHUB_TOKEN,
)

# --- Fixtures ---

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Set up a temporary test database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


# --- Helpers ---

def _make_finding(**kwargs):
    """Create a Finding with sensible defaults."""
    defaults = dict(
        rule_id="R001_GITHUB_TOKEN",
        rule_name="GitHub Token",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="src/config.py",
        line_start=10,
        line_end=10,
        column_start=5,
        column_end=25,
        snippet_masked="ghp_****",
        is_blocking=True,
        finding_type=FindingType.CONTENT,
        description="GitHub token found",
        category="token",
        secret_type="github_token",
        message="Remove the token",
        repair_template_key="remove_secret",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_notice(**kwargs):
    defaults = dict(
        rule_id="R010_ENV_EXAMPLE",
        message="Example env file present",
        file_path=".env.example",
    )
    defaults.update(kwargs)
    return ScanNotice(**defaults)


def _make_skipped(**kwargs):
    defaults = dict(file_path="large.bin", reason="binary")
    defaults.update(kwargs)
    return SkippedFile(**defaults)


def _make_error(**kwargs):
    defaults = dict(
        file_path="bad.py",
        error_type="read_error",
        error_message="Unable to read file content",
    )
    defaults.update(kwargs)
    return ScanError(**defaults)


# ============================================================
# A. Serialization tests
# ============================================================

class TestSerializeEmpty:
    """Test serialization of an empty ScanResult."""

    def test_empty_result_structure(self):
        """Empty ScanResult should have correct top-level structure."""
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        assert serialized["schema_version"] == SCHEMA_VERSION
        assert serialized["findings"] == []
        assert serialized["notices"] == []
        assert serialized["skipped_files"] == []
        assert serialized["scan_errors"] == []
        assert serialized["summary"]["total_findings"] == 0
        assert serialized["summary"]["blocking_findings"] == 0
        assert serialized["summary"]["total_notices"] == 0
        assert serialized["summary"]["total_skipped_files"] == 0
        assert serialized["summary"]["total_scan_errors"] == 0
        assert serialized["summary"]["total_files_scanned"] == 0
        assert serialized["summary"]["total_lines_scanned"] == 0

    def test_empty_result_is_json_serializable(self):
        """Empty ScanResult should be JSON serializable."""
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        json_str = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        parsed = json.loads(json_str)
        assert parsed == serialized


class TestSerializeFinding:
    """Test serialization of a single Finding."""

    def test_single_finding_fields(self):
        """All Finding fields should be present in serialized output."""
        finding = _make_finding()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        assert len(serialized["findings"]) == 1
        f = serialized["findings"][0]
        assert f["rule_id"] == "R001_GITHUB_TOKEN"
        assert f["rule_name"] == "GitHub Token"
        assert f["severity"] == "critical"
        assert f["confidence"] == "high"
        assert f["file_path"] == "src/config.py"
        assert f["line_start"] == 10
        assert f["line_end"] == 10
        assert f["column_start"] == 5
        assert f["column_end"] == 25
        assert f["snippet_masked"] == "ghp_****"
        assert f["is_blocking"] is True
        assert f["finding_type"] == "content"
        assert f["description"] == "GitHub token found"
        assert f["category"] == "token"
        assert f["secret_type"] == "github_token"
        assert f["message"] == "Remove the token"
        assert f["repair_template_key"] == "remove_secret"

    def test_enum_values_are_strings(self):
        """Enum fields should be converted to stable string values."""
        finding = _make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            finding_type=FindingType.FILE,
        )
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        f = serialized["findings"][0]
        assert f["severity"] == "high"
        assert f["confidence"] == "medium"
        assert f["finding_type"] == "file"
        assert isinstance(f["severity"], str)
        assert isinstance(f["confidence"], str)
        assert isinstance(f["finding_type"], str)

    def test_none_fields_preserved(self):
        """None values should be preserved as null in JSON."""
        finding = _make_finding(
            line_start=None,
            line_end=None,
            column_start=None,
            column_end=None,
            finding_type=FindingType.FILE,
        )
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        f = serialized["findings"][0]
        assert f["line_start"] is None
        assert f["line_end"] is None
        assert f["column_start"] is None
        assert f["column_end"] is None

    def test_tuple_converted_to_list(self):
        """Tuple of findings should be converted to JSON array."""
        f1 = _make_finding(rule_id="R001")
        f2 = _make_finding(rule_id="R002", severity=Severity.HIGH)
        result = ScanResult(
            findings=(f1, f2), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=2, total_lines_scanned=20,
        )
        serialized = serialize_scan_result(result)
        assert isinstance(serialized["findings"], list)
        assert len(serialized["findings"]) == 2


class TestSerializeCollections:
    """Test serialization of notices, skipped_files, and scan_errors."""

    def test_notices_serialized(self):
        """ScanNotice should be serialized with correct fields."""
        notice = _make_notice()
        result = ScanResult(
            findings=(), notices=(notice,), skipped_files=(),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        assert len(serialized["notices"]) == 1
        n = serialized["notices"][0]
        assert n["rule_id"] == "R010_ENV_EXAMPLE"
        assert n["message"] == "Example env file present"
        assert n["file_path"] == ".env.example"

    def test_skipped_files_serialized(self):
        """SkippedFile should be serialized with correct fields."""
        skipped = _make_skipped()
        result = ScanResult(
            findings=(), notices=(), skipped_files=(skipped,),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        assert len(serialized["skipped_files"]) == 1
        s = serialized["skipped_files"][0]
        assert s["file_path"] == "large.bin"
        assert s["reason"] == "binary"

    def test_scan_errors_serialized(self):
        """ScanError should be serialized with correct fields."""
        error = _make_error()
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(error,), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        assert len(serialized["scan_errors"]) == 1
        e = serialized["scan_errors"][0]
        assert e["file_path"] == "bad.py"
        assert e["error_type"] == "read_error"
        assert e["error_message"] == "Unable to read file content"

    def test_notice_with_none_file_path(self):
        """ScanNotice with file_path=None should serialize correctly."""
        notice = _make_notice(file_path=None)
        result = ScanResult(
            findings=(), notices=(notice,), skipped_files=(),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        assert serialized["notices"][0]["file_path"] is None


class TestSerializeDeterminism:
    """Test that serialization output is deterministic."""

    def test_same_input_same_output(self):
        """Same ScanResult should produce identical serialized output."""
        finding = _make_finding()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        s1 = serialize_scan_result(result)
        s2 = serialize_scan_result(result)
        assert s1 == s2

    def test_json_output_is_deterministic(self):
        """JSON string output should be deterministic with sort_keys=True."""
        finding = _make_finding()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        json1 = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        json2 = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        assert json1 == json2


class TestSerializeSecurity:
    """Test that serialization does not leak raw secrets."""

    def test_no_raw_token_in_snippet_masked(self):
        """snippet_masked should not contain the raw token."""
        finding = _make_finding(snippet_masked="ghp_****")
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        json_str = json.dumps(serialized)
        assert SYNTHETIC_GITHUB_TOKEN not in json_str
        assert "ghp_" + "****" in json_str  # masked version is present

    def test_no_raw_secrets_in_full_output(self):
        """Full serialized output should not contain raw synthetic secrets."""
        finding = _make_finding(snippet_masked="[masked]")
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        json_str = json.dumps(serialized)
        assert SYNTHETIC_GITHUB_TOKEN not in json_str
        assert SYNTHETIC_AWS_KEY not in json_str


# ============================================================
# B. Database tests
# ============================================================

class TestSaveScanResult:
    """Test save_scan_result database operations."""

    def test_first_save(self, test_db):
        """First save should create a new row."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        finding = _make_finding()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=100,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert retrieved is not None
        assert retrieved["schema_version"] == SCHEMA_VERSION
        assert len(retrieved["findings"]) == 1

    def test_upsert_replaces_existing(self, test_db):
        """Saving with same task_id should replace the existing row."""
        task = task_manager.create_task(
            "https://github.com/test/repo2", "test", "repo2"
        )
        result1 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=100,
        )
        save_scan_result(task.id, result1)
        assert get_scan_summary(task.id)["total_files_scanned"] == 5

        result2 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=3, total_lines_scanned=50,
        )
        save_scan_result(task.id, result2)
        summary = get_scan_summary(task.id)
        assert summary["total_files_scanned"] == 3
        assert summary["total_lines_scanned"] == 50

    def test_summary_counts_correct(self, test_db):
        """Summary counts should match the actual data."""
        task = task_manager.create_task(
            "https://github.com/test/repo3", "test", "repo3"
        )
        f1 = _make_finding(is_blocking=True)
        f2 = _make_finding(rule_id="R002", is_blocking=False, severity=Severity.LOW)
        notice = _make_notice()
        skipped = _make_skipped()
        error = _make_error()
        result = ScanResult(
            findings=(f1, f2), notices=(notice,), skipped_files=(skipped,),
            scan_errors=(error,), total_files_scanned=10, total_lines_scanned=200,
        )
        save_scan_result(task.id, result)
        summary = get_scan_summary(task.id)
        assert summary["total_findings"] == 2
        assert summary["blocking_findings"] == 1
        assert summary["total_notices"] == 1
        assert summary["total_skipped_files"] == 1
        assert summary["total_scan_errors"] == 1
        assert summary["total_files_scanned"] == 10
        assert summary["total_lines_scanned"] == 200


class TestGetScanResult:
    """Test get_scan_result and get_scan_summary."""

    def test_get_result_not_found(self, test_db):
        """Non-existent task_id should return None."""
        assert get_scan_result("nonexistent-id") is None

    def test_get_summary_not_found(self, test_db):
        """Non-existent task_id should return None."""
        assert get_scan_summary("nonexistent-id") is None

    def test_get_result_has_correct_structure(self, test_db):
        """Retrieved result should have the correct top-level structure."""
        task = task_manager.create_task(
            "https://github.com/test/repo4", "test", "repo4"
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=5,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert "schema_version" in retrieved
        assert "findings" in retrieved
        assert "notices" in retrieved
        assert "skipped_files" in retrieved
        assert "scan_errors" in retrieved
        assert "summary" in retrieved

    def test_get_summary_has_correct_fields(self, test_db):
        """Retrieved summary should have all required fields."""
        task = task_manager.create_task(
            "https://github.com/test/repo5", "test", "repo5"
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=5,
        )
        save_scan_result(task.id, result)
        summary = get_scan_summary(task.id)
        expected_fields = {
            "total_findings", "blocking_findings", "total_notices",
            "total_skipped_files", "total_scan_errors",
            "total_files_scanned", "total_lines_scanned",
            "returned_findings", "findings_truncated",
            "returned_notices", "notices_truncated",
            "returned_skipped_files", "skipped_files_truncated",
            "returned_scan_errors", "scan_errors_truncated",
            "dimension_counts",
        }
        assert set(summary.keys()) == expected_fields


class TestDatabaseSecurity:
    """Test database security properties."""

    def test_malicious_text_in_file_path(self, test_db):
        """Malicious text in file_path should not break SQL."""
        task = task_manager.create_task(
            "https://github.com/test/repo6", "test", "repo6"
        )
        # SQL injection attempt in file_path
        malicious_path = "'; DROP TABLE scan_results; --"
        finding = _make_finding(file_path=malicious_path)
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result)
        # Table should still exist
        retrieved = get_scan_result(task.id)
        assert retrieved is not None
        assert len(retrieved["findings"]) == 1

    def test_no_raw_secrets_in_result_json(self, test_db):
        """result_json should not contain raw synthetic secrets."""
        task = task_manager.create_task(
            "https://github.com/test/repo7", "test", "repo7"
        )
        finding = _make_finding(snippet_masked="[masked]")
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        json_str = json.dumps(retrieved)
        assert SYNTHETIC_GITHUB_TOKEN not in json_str
        assert SYNTHETIC_AWS_KEY not in json_str
