"""P0-6 assessment boundary adversarial tests.

Covers:
A. Absolute path direct persistence in blocking_reasons.file_path
B. Absolute paths in description fields
C. Internal objects must not be stringified
D. Corrupted assessment_json (invalid JSON, wrong types, identity mismatch)
E. Runner fallback error classification
F. Strict int/bool type validation in serialization
G. Extended path sanitization (all POSIX absolute, Windows rooted, ~)
H. Database error boundary in get_assessment_result
I. Finding sort rejects unknown objects (no default=str)

All test strings are SYNTHETIC — format-correct but NOT real credentials.
"""

import json
import sqlite3
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
)
from app.db import database
from app.db.database import _get_connection
from app.main import app
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanResult,
    Severity,
)
from app.services import task_manager
from app.services.assessment_policy import (
    ASSESSMENT_SCHEMA_VERSION,
    ASSESSMENT_SCOPE,
    POLICY_VERSION,
)
from app.services.assessment_service import (
    AssessmentInternalError,
    AssessmentPersistError,
    AssessmentSerializationError,
    _clean_path_from_text,
    _normalize_sort_bool,
    _normalize_sort_int,
    _normalize_sort_str,
    _strict_bool,
    _strict_int,
    assess_scan_result,
    get_assessment_result,
    sanitize_assessment_file_path,
    save_assessment_result,
    serialize_assessment_result,
)
from app.services.scan_result_service import save_scan_result

# ---------------------------------------------------------------------------
# --- Synthetic test constants ---
# ---------------------------------------------------------------------------

_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
SYNTH_TOKEN_GHP = "ghp_" + _MIXED[:36]


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    with TestClient(app) as c:
        yield c
    database._initialized = False


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_finding_dict(**kwargs):
    defaults = dict(
        rule_id="R001_GITHUB_TOKEN",
        rule_name="GitHub Token",
        severity="critical",
        confidence="high",
        file_path="src/config.py",
        line_start=10, line_end=10,
        column_start=5, column_end=25,
        snippet_masked="ghp_****",
        is_blocking=True,
        finding_type="content",
        description="GitHub token found",
        category="token",
        secret_type="github_token",
        message="Remove the token",
        repair_template_key="remove_secret",
    )
    defaults.update(kwargs)
    return defaults


def _make_scan_result(findings=None, summary=None):
    return {
        "schema_version": 1,
        "findings": findings or [],
        "notices": [],
        "skipped_files": [],
        "scan_errors": [],
        "summary": summary or {
            "total_findings": len(findings or []),
            "blocking_findings": sum(
                1 for f in (findings or []) if f.get("is_blocking")
            ),
            "total_notices": 0,
            "total_skipped_files": 0,
            "total_scan_errors": 0,
            "total_files_scanned": 10,
            "total_lines_scanned": 100,
            "returned_findings": len(findings or []),
            "findings_truncated": False,
            "returned_notices": 0, "notices_truncated": False,
            "returned_skipped_files": 0, "skipped_files_truncated": False,
            "returned_scan_errors": 0, "scan_errors_truncated": False,
        },
    }


def _setup_task_with_scan(test_db, findings=None, files_scanned=10, lines_scanned=100):
    """Create task, save scan result, return (task_id, scan_updated_at)."""
    task = task_manager.create_task(
        "https://github.com/test/repo", "test", "repo"
    )
    scan_result = ScanResult(
        findings=tuple(findings or []),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=files_scanned,
        total_lines_scanned=lines_scanned,
    )
    save_scan_result(task.id, scan_result)
    from app.services.assessment_service import get_scan_result_with_timestamp
    scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
    return task.id, scan_dict, scan_updated


def _read_db_row(task_id):
    conn = _get_connection()
    try:
        return conn.execute(
            "SELECT created_at, updated_at, assessment_json, score, verdict "
            "FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        conn.close()


def _insert_assessment_json(task_id, raw_json, score=0, verdict="blocked"):
    """Directly insert/update assessment_results row with raw JSON.

    Uses REAL policy constants for schema_version, policy_version,
    and assessment_scope so that identity validation reaches the
    intended branch (not an early scope mismatch).
    """
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO assessment_results
               (task_id, schema_version, policy_version, assessment_scope,
                assessment_json, score, verdict, source_scan_updated_at,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'sync',
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
               ON CONFLICT(task_id) DO UPDATE SET
                   assessment_json=excluded.assessment_json,
                   score=excluded.score,
                   verdict=excluded.verdict""",
            (task_id, ASSESSMENT_SCHEMA_VERSION, POLICY_VERSION,
             ASSESSMENT_SCOPE, raw_json, score, verdict),
        )
        conn.commit()
    finally:
        conn.close()


def _make_valid_assessment_json(default_task_id, **overrides):
    """Build a fully valid assessment JSON dict with real policy constants.

    All fields use correct values by default. Pass overrides to
    corrupt exactly ONE field for targeted branch testing.

    The first parameter is named ``default_task_id`` (not ``task_id``)
    so that callers can override the ``task_id`` field via
    ``**overrides`` without a Python TypeError.
    """
    base = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "assessment_scope": ASSESSMENT_SCOPE,
        "task_id": default_task_id,
        "score": 50,
        "score_before_caps": 60,
        "verdict": "warning",
        "score_breakdown": [],
        "score_caps": [],
        "blocking_reasons": [],
        "coverage": {
            "status": "complete",
            "reasons": [],
            "total_findings": 0,
            "scored_findings": 0,
            "findings_truncated": False,
            "total_blocking_findings": 0,
            "returned_blocking_reasons": 0,
            "blocking_reasons_truncated": False,
            "total_scan_errors": 0,
            "total_files_scanned": 10,
            "total_skipped_files": 0,
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


# ============================================================
# A. Absolute path direct persistence
# ============================================================

class TestAbsolutePathPersistence:
    """Absolute paths in blocking_reasons.file_path are redacted."""

    @pytest.mark.parametrize("dangerous_path", [
        "/tmp/vibecheck/task-secret/repo/config.py",
        "/var/tmp/vibecheck/repo/.env",
        "C:\\Users\\alice\\AppData\\Local\\Temp\\vibecheck\\repo\\.env",
        "C:/Users/alice/AppData/Local/Temp/vibecheck/repo/.env",
        "\\\\server\\share\\temp\\repo\\.env",
        "../outside/.env",
    ])
    def test_dangerous_path_redacted_in_all_outputs(self, test_db, dangerous_path):
        """Dangerous paths in blocking_reasons.file_path are replaced
        with <redacted-path> in serialize, DB, and API response."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_PATH",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=dangerous_path,
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        # Check serialize return value
        safe = serialize_assessment_result(task_id, assessment, None, "now")
        for reason in safe["blocking_reasons"]:
            if reason.get("rule_id") == "R_PATH":
                assert reason["file_path"] == "<redacted-path>"

        # Check DB assessment_json
        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert dangerous_path not in retrieved_json

        # Check file_path equals <redacted-path>
        for reason in retrieved["blocking_reasons"]:
            if reason.get("rule_id") == "R_PATH":
                assert reason["file_path"] == "<redacted-path>"

        # Check no username or task-secret leakage
        assert "alice" not in retrieved_json
        assert "task-secret" not in retrieved_json

    def test_normal_paths_preserved(self, test_db):
        """Normal repo-relative paths are preserved."""
        normal_paths = [
            "src/config.py",
            ".env",
            "packages/api/settings.py",
        ]
        findings = [
            Finding(
                rule_id=f"R_NORM_{i}",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=path,
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )
            for i, path in enumerate(normal_paths)
        ]
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db, findings=findings)
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        for reason in retrieved["blocking_reasons"]:
            assert reason["file_path"] in normal_paths

    def test_path_sanitizer_idempotent(self):
        """Re-processing an already-redacted path is stable."""
        assert sanitize_assessment_file_path("<redacted-path>") == "<redacted-path>"
        assert sanitize_assessment_file_path("src/config.py") == "src/config.py"
        assert sanitize_assessment_file_path(None) == ""

    def test_nul_character_redacted(self):
        """NUL character in path triggers redaction."""
        assert sanitize_assessment_file_path("src/\x00config.py") == "<redacted-path>"

    def test_path_traversal_variants(self):
        """Various path traversal forms are redacted."""
        assert sanitize_assessment_file_path("../outside/.env") == "<redacted-path>"
        assert sanitize_assessment_file_path("..\\outside\\.env") == "<redacted-path>"
        assert sanitize_assessment_file_path("src/../../outside/.env") == "<redacted-path>"
        assert sanitize_assessment_file_path("src/..") == "<redacted-path>"


# ============================================================
# B. Description with absolute paths
# ============================================================

class TestDescriptionPathCleaning:
    """Absolute paths in description fields are replaced with <redacted-path>."""

    def test_path_in_score_breakdown_description(self, test_db):
        """score_breakdown.description absolute paths are cleaned."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_DESC_PATH",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found at /tmp/vibecheck/secret/repo/config.py",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)

        # Inject absolute path directly into score_breakdown.description
        # (score_breakdown.description is auto-generated by the engine,
        # so we inject the path post-assessment to test the serialization
        # boundary's _safe_masked_desc cleaning).
        dangerous = "/tmp/vibecheck/secret/repo/config.py"
        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["description"] = (
            f"Rule triggered at {dangerous}"
        )

        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert dangerous not in retrieved_json
        assert "<redacted-path>" in retrieved_json

    def test_path_in_score_caps_description(self, test_db):
        """score_caps.description absolute paths are cleaned."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db, files_scanned=0
        )
        assessment = assess_scan_result(task_id, scan_dict)

        # Inject path into score_caps description
        for cap in assessment["score_caps"]:
            cap["description"] = "Error at C:\\Users\\bob\\Temp\\repo\\scan.db"

        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert "C:\\Users\\bob\\Temp\\repo\\scan.db" not in retrieved_json
        assert "<redacted-path>" in retrieved_json
        assert "bob" not in retrieved_json

    def test_path_in_blocking_reasons_description(self, test_db):
        """blocking_reasons.description absolute paths are cleaned."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_BLK_DESC",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="Secret at /var/tmp/vibecheck/repo/.env",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert "/var/tmp/vibecheck/repo/.env" not in retrieved_json
        assert "<redacted-path>" in retrieved_json

    def test_path_in_coverage_reasons(self, test_db):
        """coverage.reasons absolute paths are cleaned."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db, files_scanned=0
        )
        assessment = assess_scan_result(task_id, scan_dict)

        # Inject path into coverage reasons
        assessment["coverage"]["reasons"].append(
            "Scan error at \\\\server\\share\\temp\\repo\\data.db"
        )

        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert "\\\\server\\share\\temp\\repo\\data.db" not in retrieved_json
        assert "<redacted-path>" in retrieved_json


# ============================================================
# C. Internal objects must not be stringified
# ============================================================

class TestInternalObjectRejection:
    """Non-string objects must not be str()'d into persistence."""

    def test_runtime_error_in_description_rejected(self, test_db):
        """RuntimeError in blocking_reasons.description is rejected.

        - str(RuntimeError) is NOT called
        - save fails with AssessmentInternalError semantic
        - No assessment_results row created/updated
        """
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        # Inject RuntimeError object into description
        assessment["blocking_reasons"].append({
            "rule_id": "R_TEST",
            "rule_name": "Test",
            "severity": "critical",
            "file_path": "config.py",
            "description": RuntimeError("sqlite failed at /tmp/private/database.db"),
        })

        # save_assessment_result should raise AssessmentInternalError
        with pytest.raises(AssessmentInternalError):
            save_assessment_result(task_id, assessment, scan_updated)

        # No assessment_results row should exist
        row = _read_db_row(task_id)
        assert row is None

    def test_custom_object_str_not_used(self, test_db):
        """Custom object with __str__ returning a token is rejected.

        The __str__ method must NOT be called for persistence.
        """
        class MaliciousObject:
            def __str__(self):
                return SYNTH_TOKEN_GHP

        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        assessment["blocking_reasons"].append({
            "rule_id": "R_MALICIOUS",
            "rule_name": "Test",
            "severity": "critical",
            "file_path": "config.py",
            "description": MaliciousObject(),
        })

        with pytest.raises(AssessmentInternalError):
            save_assessment_result(task_id, assessment, scan_updated)

        # Token must not appear anywhere
        row = _read_db_row(task_id)
        assert row is None

    def test_int_in_string_field_rejected(self, test_db):
        """Integer in a string field (rule_id) is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_INT_TEST",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)

        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["rule_id"] = 12345

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_list_in_string_field_rejected(self, test_db):
        """List in a string field is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_LIST_TEST",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)

        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["severity"] = ["critical"]

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_non_dict_entry_in_score_breakdown_rejected(self, test_db):
        """Non-dict entry in score_breakdown is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        assessment["score_breakdown"].append("not a dict")

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_non_dict_coverage_rejected(self, test_db):
        """Non-dict coverage is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        assessment["coverage"] = "not a dict"

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_non_list_score_breakdown_rejected(self, test_db):
        """Non-list score_breakdown is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        assessment["score_breakdown"] = "not a list"

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_occurrence_deductions_non_list_rejected(self, test_db):
        """Non-list occurrence_deductions is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_OCC_TEST",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)

        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["occurrence_deductions"] = "not a list"

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_exception_message_no_sensitive_info(self, test_db):
        """AssessmentSerializationError message contains no sensitive info."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        sensitive = "sqlite failed at /tmp/private/database.db"
        assessment["blocking_reasons"].append({
            "rule_id": "R_SENS",
            "rule_name": "Test",
            "severity": "critical",
            "file_path": "config.py",
            "description": RuntimeError(sensitive),
        })

        try:
            save_assessment_result(task_id, assessment, scan_updated)
            assert False, "Should have raised"
        except AssessmentInternalError as e:
            msg = str(e)
            assert "sqlite failed" not in msg
            assert "/tmp/private" not in msg
            assert sensitive not in msg


# ============================================================
# D. Corrupted assessment_json
# ============================================================

class TestCorruptedAssessmentJson:
    """Corrupted assessment_json returns 500 ASSESSMENT_INTERNAL_ERROR."""

    def _setup_completed_task_with_assessment(self, client_fixture):
        """Set up a completed task with a valid assessment, then corrupt it."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)
        save_assessment_result(task.id, assessment, scan_updated)
        task_manager.mark_completed(
            task.id, file_count=1, total_size=100, top_level_dir="repo"
        )
        return task.id

    def test_invalid_json(self, client):
        """Invalid JSON in assessment_json → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        _insert_assessment_json(task_id, "{invalid json}")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_json_array_not_dict(self, client):
        """JSON array (not dict) → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        _insert_assessment_json(task_id, "[1, 2, 3]")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_task_id_mismatch(self, client):
        """task_id in JSON doesn't match DB task_id → 500.

        Only task_id is corrupted; all other fields are valid so the
        validation reaches the task_id check branch.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(task_id, task_id="wrong-task-id")
        _insert_assessment_json(
            task_id, json.dumps(bad), score=50, verdict="warning"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_policy_version_mismatch(self, client):
        """policy_version mismatch → 500.

        Only policy_version is corrupted; all other fields are valid.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(
            task_id, policy_version="wrong-version"
        )
        _insert_assessment_json(
            task_id, json.dumps(bad), score=50, verdict="warning"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_score_out_of_range(self, client):
        """score > 100 → 500.

        Only score is corrupted; all other fields are valid so the
        validation reaches the score check branch.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(task_id, score=101)
        _insert_assessment_json(
            task_id, json.dumps(bad), score=101, verdict="warning"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_score_is_bool(self, client):
        """score=True (bool) → 500.

        bool is a subclass of int but must be rejected by strict
        type validation. Only score is corrupted.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(task_id, score=True)
        _insert_assessment_json(
            task_id, json.dumps(bad), score=1, verdict="warning"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_invalid_verdict(self, client):
        """Invalid verdict → 500.

        Only verdict is corrupted; all other fields are valid so the
        validation reaches the verdict check branch.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(task_id, verdict="invalid")
        _insert_assessment_json(
            task_id, json.dumps(bad), score=50, verdict="invalid"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_schema_version_mismatch(self, client):
        """schema_version mismatch → 500.

        Only schema_version is corrupted; all other fields are valid.
        """
        task_id = self._setup_completed_task_with_assessment(client)
        bad = _make_valid_assessment_json(task_id, schema_version=99)
        _insert_assessment_json(
            task_id, json.dumps(bad), score=50, verdict="warning"
        )

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_response_no_raw_json_leaked(self, client):
        """500 response does not leak raw JSON or exception details."""
        task_id = self._setup_completed_task_with_assessment(client)
        raw = "{invalid json with secret_token_xyz}"
        _insert_assessment_json(task_id, raw)

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        response_text = json.dumps(response.json())
        assert "secret_token_xyz" not in response_text
        assert "invalid json" not in response_text


# ============================================================
# E. Runner fallback error classification
# ============================================================

class TestRunnerFallbackError:
    """Runner catch-all maps to ASSESSMENT_INTERNAL_ERROR, not PERSIST_FAILED."""

    def test_runtime_error_maps_to_internal_error(self, test_db, tmp_path):
        """Mock run_assessment raising RuntimeError → ASSESSMENT_INTERNAL_ERROR."""
        import asyncio

        from app.scanner.base import ScanResult
        from app.services.background_runner import _process_task, reset_runner_state
        from app.services.scan_result_service import save_scan_result

        reset_runner_state()

        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        # Mock download, extract, scan to succeed
        from pathlib import Path

        from app.core.github import DownloadResult, parse_repo_url
        from app.core.safe_extract import ExtractionResult

        temp_file = Path(tmp_path) / "mock.tar.gz"
        temp_file.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 100)
        repo_info = parse_repo_url("https://github.com/test/repo")
        download_result = DownloadResult(
            temp_file=temp_file, repo_info=repo_info,
            file_size=temp_file.stat().st_size,
        )
        extract_dest = Path(tmp_path) / "extract"
        extract_dest.mkdir(parents=True, exist_ok=True)
        (extract_dest / "README.md").write_text("# Clean\n")
        extract_result = ExtractionResult(
            dest_dir=str(extract_dest), file_count=1,
            total_size=10, top_level_dir="extract",
        )
        mock_scan = ScanResult(
            findings=(), notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            return_value=extract_result,
        ), patch(
            "app.services.background_runner.scan_directory",
            return_value=mock_scan,
        ), patch(
            "app.services.background_runner.run_assessment",
            side_effect=RuntimeError("unexpected internal error"),
        ):
            asyncio.run(_process_task(task.id))

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == ASSESSMENT_INTERNAL_ERROR
        assert result.error_code != ASSESSMENT_PERSIST_FAILED

        reset_runner_state()


# ============================================================
# F. Strict int/bool type validation in serialization
# ============================================================

class TestStrictTypeValidation:
    """Strict type checking rejects bool-as-int, str-as-int, etc."""

    def test_strict_int_rejects_bool(self):
        """_strict_int rejects bool (which is int subclass)."""
        with pytest.raises(AssessmentSerializationError):
            _strict_int(True)
        with pytest.raises(AssessmentSerializationError):
            _strict_int(False)

    def test_strict_int_rejects_str(self):
        """_strict_int rejects string values."""
        with pytest.raises(AssessmentSerializationError):
            _strict_int("99")

    def test_strict_int_rejects_float(self):
        """_strict_int rejects float values."""
        with pytest.raises(AssessmentSerializationError):
            _strict_int(99.0)

    def test_strict_int_range_check(self):
        """_strict_int rejects out-of-range values (no clamping)."""
        with pytest.raises(AssessmentSerializationError):
            _strict_int(101, minimum=0, maximum=100)
        with pytest.raises(AssessmentSerializationError):
            _strict_int(-1, minimum=0, maximum=100)

    def test_strict_bool_rejects_int(self):
        """_strict_bool rejects int 0 and 1."""
        with pytest.raises(AssessmentSerializationError):
            _strict_bool(0)
        with pytest.raises(AssessmentSerializationError):
            _strict_bool(1)

    def test_strict_bool_rejects_str(self):
        """_strict_bool rejects string values."""
        with pytest.raises(AssessmentSerializationError):
            _strict_bool("false")

    def test_score_true_rejected_in_serialize(self, test_db):
        """score=True (bool) is rejected by serialize_assessment_result."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["score"] = True
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_score_string_rejected_in_serialize(self, test_db):
        """score='99' (str) is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["score"] = "99"
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_score_over_100_rejected_no_clamp(self, test_db):
        """score=101 is rejected (no clamping to 100)."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["score"] = 101
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_score_before_caps_negative_rejected(self, test_db):
        """score_before_caps=-1 is rejected (no clamping to 0)."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["score_before_caps"] = -1
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_applied_int_rejected_as_bool(self, test_db):
        """applied=1 (int, not bool) is rejected in score_caps."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db, files_scanned=0
        )
        assessment = assess_scan_result(task_id, scan_dict)
        for cap in assessment["score_caps"]:
            cap["applied"] = 1
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_findings_truncated_string_rejected(self, test_db):
        """findings_truncated='false' (str) is rejected in coverage."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["coverage"]["findings_truncated"] = "false"
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_occurrence_deductions_mixed_types_rejected(self, test_db):
        """occurrence_deductions=[1, '2'] is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_MIXED",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)
        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["occurrence_deductions"] = [1, "2"]
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_verdict_invalid_rejected_not_defaulted(self, test_db):
        """Invalid verdict is rejected, not silently changed to 'blocked'."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        assessment["verdict"] = "invalid"
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_finding_count_bool_rejected(self, test_db):
        """finding_count=True is rejected (bool is not int)."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_FC_BOOL",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        assessment = assess_scan_result(task_id, scan_dict)
        assert len(assessment["score_breakdown"]) > 0
        assessment["score_breakdown"][0]["finding_count"] = True
        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None


# ============================================================
# G. Extended path sanitization
# ============================================================

class TestExtendedPathSanitization:
    """All non-repo-relative paths are redacted."""

    @pytest.mark.parametrize("dangerous_path", [
        "/etc/passwd",
        "/root/.ssh/id_rsa",
        "/opt/app/config",
        "\\rooted\\secret",
        "~/private/.env",
        "~\\private\\.env",
    ])
    def test_extended_dangerous_paths_redacted(self, dangerous_path):
        """Paths that were previously allowed are now redacted."""
        assert sanitize_assessment_file_path(dangerous_path) == "<redacted-path>"

    def test_normal_paths_still_preserved(self):
        """Normal repo-relative paths are not affected."""
        assert sanitize_assessment_file_path("src/config.py") == "src/config.py"
        assert sanitize_assessment_file_path(".env") == ".env"
        assert sanitize_assessment_file_path("packages/api/settings.py") == "packages/api/settings.py"

    def test_var_tmp_text_cleaning_exact(self):
        """_clean_path_from_text replaces /var/tmp/... completely."""
        result = _clean_path_from_text(
            "err /var/tmp/task-secret/repo/.env done"
        )
        assert result == "err <redacted-path> done"

    def test_forward_slash_unc_in_text(self):
        """Forward-slash UNC paths are cleaned from text."""
        result = _clean_path_from_text(
            "scan at //server/share/temp/repo/data.db"
        )
        assert "//server" not in result
        assert "<redacted-path>" in result

    def test_no_residue_in_var_tmp(self):
        """No /var, username, task ID, or basename residue after cleaning."""
        result = _clean_path_from_text(
            "Error at /var/tmp/task-secret/repo/.env"
        )
        assert "/var" not in result
        assert "task-secret" not in result
        assert "repo" not in result
        assert ".env" not in result


# ============================================================
# H. Database error boundary in get_assessment_result
# ============================================================

class TestDatabaseErrorBoundary:
    """All database operations are inside the try boundary."""

    def test_init_db_error_raises_internal_error(self, test_db, monkeypatch):
        """init_db raising sqlite3.Error → AssessmentInternalError."""
        def _boom():
            raise sqlite3.Error("init failed")
        monkeypatch.setattr(
            "app.services.assessment_service.init_db", _boom
        )
        with pytest.raises(AssessmentInternalError):
            get_assessment_result("any-task-id")

    def test_get_connection_error_raises_internal_error(self, test_db, monkeypatch):
        """_get_connection raising sqlite3.Error → AssessmentInternalError."""
        def _boom():
            raise sqlite3.Error("connection failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection", _boom
        )
        with pytest.raises(AssessmentInternalError):
            get_assessment_result("any-task-id")

    def test_execute_error_raises_internal_error(self, test_db, monkeypatch):
        """execute raising sqlite3.Error → AssessmentInternalError."""
        class _BadConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.Error("execute failed")
            def close(self):
                pass
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadConn(),
        )
        with pytest.raises(AssessmentInternalError):
            get_assessment_result("any-task-id")


# ============================================================
# I. Finding sort rejects unknown objects (no default=str)
# ============================================================

class TestFindingSortNoDefaultStr:
    """Finding sort must not call __str__ on unknown objects."""

    def test_custom_object_in_sort_field_rejected(self, test_db):
        """A finding with a custom __str__ object in a sort field
        must raise AssessmentInternalError, not call __str__.

        The __str__ returns a synthetic token that must NOT appear
        in any output.
        """
        class MaliciousObject:
            def __str__(self):
                return SYNTH_TOKEN_GHP
            def __repr__(self):
                return "MaliciousObject()"

        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_SORT_OBJ",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )

        # Inject malicious object into a sort field BEFORE assessment.
        # assess_scan_result calls _finding_sort_key which must reject it.
        scan_dict["findings"][0]["description"] = MaliciousObject()

        with pytest.raises(AssessmentInternalError):
            assess_scan_result(task_id, scan_dict)

        # Token must not appear in any database row.
        row = _read_db_row(task_id)
        assert row is None

    def test_sort_deterministic_with_valid_types(self, test_db):
        """Sorting still works correctly with valid type fields."""
        findings = [
            Finding(
                rule_id="R_SORT_A",
                rule_name="Rule A",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path="z.py",
                line_start=5, line_end=5,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="A",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),
            Finding(
                rule_id="R_SORT_A",
                rule_name="Rule A",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="a.py",
                line_start=1, line_end=1,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="B",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),
        ]
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db, findings=findings
        )
        # Should not raise — all fields are valid types.
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        assert retrieved is not None
        # Critical blocking finding should be first in blocking_reasons.
        if retrieved["blocking_reasons"]:
            assert retrieved["blocking_reasons"][0]["severity"] == "critical"


# ============================================================
# J. save_assessment_result database error boundary
# ============================================================

class TestSaveAssessmentDatabaseBoundary:
    """All SQLite operations in save_assessment_result are wrapped."""

    def test_init_db_error_raises_persist_error(self, test_db, monkeypatch):
        """init_db raising sqlite3.Error → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        def _boom():
            raise sqlite3.Error("init failed")
        monkeypatch.setattr(
            "app.services.assessment_service.init_db", _boom
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_get_connection_error_raises_persist_error(
        self, test_db, monkeypatch
    ):
        """_get_connection raising sqlite3.Error → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        def _boom():
            raise sqlite3.Error("connection failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection", _boom
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)
        row = _read_db_row(task_id)
        assert row is None

    def test_query_created_at_failure_raises_persist_error(
        self, test_db, monkeypatch
    ):
        """SELECT created_at failure → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        class _BadConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.Error("execute failed")
            def commit(self):
                pass
            def rollback(self):
                pass
            def close(self):
                pass
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadConn(),
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_insert_failure_raises_persist_error(self, test_db, monkeypatch):
        """INSERT/UPDATE failure → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        _original_get_connection = _get_connection

        class _HalfBadConn:
            def __init__(self):
                self._real = _original_get_connection()
                self._insert_failed = False
            def execute(self, *args, **kwargs):
                sql = args[0] if args else ""
                if "INSERT" in sql and not self._insert_failed:
                    self._insert_failed = True
                    raise sqlite3.Error("insert failed")
                return self._real.execute(*args, **kwargs)
            def commit(self):
                self._real.commit()
            def rollback(self):
                self._real.rollback()
            def close(self):
                self._real.close()
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _HalfBadConn(),
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_commit_failure_raises_persist_error(self, test_db, monkeypatch):
        """commit failure → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        _original_get_connection = _get_connection

        class _BadCommitConn:
            def __init__(self):
                self._real = _original_get_connection()
            def execute(self, *args, **kwargs):
                return self._real.execute(*args, **kwargs)
            def commit(self):
                raise sqlite3.Error("commit failed")
            def rollback(self):
                pass
            def close(self):
                self._real.close()
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadCommitConn(),
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_close_failure_after_success_raises_persist_error(
        self, test_db, monkeypatch
    ):
        """Normal write succeeds, but close fails → AssessmentPersistError."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        _original_get_connection = _get_connection

        class _BadCloseConn:
            def __init__(self):
                self._real = _original_get_connection()
            def execute(self, *args, **kwargs):
                return self._real.execute(*args, **kwargs)
            def commit(self):
                self._real.commit()
            def rollback(self):
                self._real.rollback()
            def close(self):
                raise sqlite3.Error("close failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadCloseConn(),
        )
        with pytest.raises(AssessmentPersistError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_serialization_error_plus_close_error_preserves_serialization(
        self, test_db, monkeypatch
    ):
        """Serialization fails AND close fails → AssessmentInternalError
        (serialization error preserved, close error suppressed)."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        _original_get_connection = _get_connection

        class _BadCloseConn:
            def __init__(self):
                self._real = _original_get_connection()
            def execute(self, *args, **kwargs):
                return self._real.execute(*args, **kwargs)
            def commit(self):
                self._real.commit()
            def rollback(self):
                pass
            def close(self):
                raise sqlite3.Error("close failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadCloseConn(),
        )
        # Corrupt to cause serializationError
        assessment["score"] = True
        # Should raise AssessmentSerializationError (subclass of
        # AssessmentInternalError), NOT AssessmentPersistError.
        with pytest.raises(AssessmentInternalError) as exc_info:
            save_assessment_result(task_id, assessment, scan_updated)
        assert not isinstance(exc_info.value, AssessmentPersistError), \
            "Serialization error must NOT be wrapped as PersistError"

    def test_persist_error_message_no_sensitive_info(
        self, test_db, monkeypatch
    ):
        """AssessmentPersistError message has no str(exc) or DB details."""
        # Setup BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        sensitive = "secret_database_path /tmp/private/database.db"
        def _boom():
            raise sqlite3.Error(sensitive)
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection", _boom
        )
        try:
            save_assessment_result(task_id, assessment, scan_updated)
            assert False, "Should have raised"
        except AssessmentPersistError as e:
            msg = str(e)
            assert sensitive not in msg
            assert "secret_database_path" not in msg
            assert "/tmp/private" not in msg


# ============================================================
# K. Field-level Finding sort type validation
# ============================================================

class TestFieldLevelFindingSortTypes:
    """Each sort field has a fixed type; heterogeneous types are rejected."""

    def test_str_vs_int_file_path_raises_not_typeerror(self, test_db):
        """Two findings with file_path='a.py' and file_path=5 must
        raise AssessmentInternalError, not TypeError."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_MIX1",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="a.py",
                line_start=1, line_end=1,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="A",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        # Inject int into file_path of second finding
        scan_dict["findings"].append({
            "rule_id": "R_MIX1",
            "rule_name": "Test",
            "severity": "critical",
            "confidence": "high",
            "file_path": 5,
            "line_start": 2, "line_end": 2,
            "column_start": 1, "column_end": 10,
            "snippet_masked": "***",
            "is_blocking": False,
            "finding_type": "content",
            "description": "B",
            "category": "token",
            "secret_type": "github_token",
            "message": "Remove",
            "repair_template_key": "remove_secret",
        })
        with pytest.raises(AssessmentInternalError):
            assess_scan_result(task_id, scan_dict)

    def test_str_vs_int_rule_id_raises_not_typeerror(self, test_db):
        """Two findings with rule_id='R1' and rule_id=1 must raise
        AssessmentInternalError, not TypeError in sorted(groups.keys())."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R1",
                rule_name="Test",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path="a.py",
                line_start=1, line_end=1,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="A",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        scan_dict["findings"].append({
            "rule_id": 1,
            "rule_name": "Test",
            "severity": "high",
            "confidence": "medium",
            "file_path": "b.py",
            "line_start": 2, "line_end": 2,
            "column_start": 1, "column_end": 10,
            "snippet_masked": "***",
            "is_blocking": False,
            "finding_type": "content",
            "description": "B",
            "category": "token",
            "secret_type": "github_token",
            "message": "Remove",
            "repair_template_key": "remove_secret",
        })
        with pytest.raises(AssessmentInternalError):
            assess_scan_result(task_id, scan_dict)

    @pytest.mark.parametrize("field_name,bad_value", [
        ("is_blocking", 1),
        ("line_start", True),
        ("severity", 5),
        ("confidence", []),
        ("description", {}),
    ])
    def test_illegal_field_types_rejected(
        self, test_db, field_name, bad_value
    ):
        """Each illegal field type raises AssessmentInternalError."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(
            test_db,
            findings=[Finding(
                rule_id="R_ILLEGAL",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="Found",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            )],
        )
        scan_dict["findings"][0][field_name] = bad_value
        with pytest.raises(AssessmentInternalError):
            assess_scan_result(task_id, scan_dict)

    def test_valid_findings_shuffled_same_result(self, test_db):
        """Shuffled input finding order produces identical assessment."""
        findings_a = [
            Finding(
                rule_id="R_DETERM_A",
                rule_name="Rule A",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path="z.py",
                line_start=5, line_end=5,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="A",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),
            Finding(
                rule_id="R_DETERM_A",
                rule_name="Rule A",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="a.py",
                line_start=1, line_end=1,
                column_start=1, column_end=10,
                snippet_masked="***",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="B",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),
            Finding(
                rule_id="R_DETERM_B",
                rule_name="Rule B",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                file_path="m.py",
                line_start=3, line_end=3,
                column_start=2, column_end=8,
                snippet_masked="***",
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="C",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),
        ]
        # Run with original order
        task_a, scan_a, updated_a = _setup_task_with_scan(
            test_db, findings=findings_a
        )
        assessment_a = assess_scan_result(task_a, scan_a)
        save_assessment_result(task_a, assessment_a, updated_a)
        result_a = get_assessment_result(task_a)

        # Run with reversed order
        findings_b = list(reversed(findings_a))
        task_b, scan_b, updated_b = _setup_task_with_scan(
            test_db, findings=findings_b
        )
        assessment_b = assess_scan_result(task_b, scan_b)
        save_assessment_result(task_b, assessment_b, updated_b)
        result_b = get_assessment_result(task_b)

        # score_breakdown must be identical (same rule order, same deductions)
        assert result_a["score"] == result_b["score"]
        assert result_a["score_before_caps"] == result_b["score_before_caps"]
        assert (
            json.dumps(result_a["score_breakdown"], sort_keys=True)
            == json.dumps(result_b["score_breakdown"], sort_keys=True)
        )

    def test_normalize_sort_str_rejects_int(self):
        """_normalize_sort_str rejects int."""
        with pytest.raises(AssessmentInternalError):
            _normalize_sort_str(5)

    def test_normalize_sort_str_rejects_bool(self):
        """_normalize_sort_str rejects bool."""
        with pytest.raises(AssessmentInternalError):
            _normalize_sort_str(True)

    def test_normalize_sort_str_none_to_empty(self):
        """_normalize_sort_str(None) returns ''."""
        assert _normalize_sort_str(None) == ""

    def test_normalize_sort_int_rejects_bool(self):
        """_normalize_sort_int rejects bool (even though bool is int subclass)."""
        with pytest.raises(AssessmentInternalError):
            _normalize_sort_int(True)

    def test_normalize_sort_int_none_to_zero(self):
        """_normalize_sort_int(None) returns 0."""
        assert _normalize_sort_int(None) == 0

    def test_normalize_sort_bool_rejects_int(self):
        """_normalize_sort_bool rejects int 0 and 1."""
        with pytest.raises(AssessmentInternalError):
            _normalize_sort_bool(0)
        with pytest.raises(AssessmentInternalError):
            _normalize_sort_bool(1)

    def test_normalize_sort_bool_none_to_false(self):
        """_normalize_sort_bool(None) returns False."""
        assert _normalize_sort_bool(None) is False


# ============================================================
# L. URL preservation in path cleaning
# ============================================================

class TestURLPreservationInPathCleaning:
    """URLs are preserved while absolute paths are redacted."""

    @pytest.mark.parametrize("url_text", [
        "http://example.com/a",
        "https://github.com/test/repo",
        "git+https://example.com/repo.git",
        "http://example.com/docs",
    ])
    def test_url_preserved(self, url_text):
        """URLs are not broken by path cleaning."""
        assert _clean_path_from_text(url_text) == url_text

    def test_url_in_backticks_preserved(self):
        """URL in backticks is preserved exactly."""
        text = "See `https://github.com/test/repo`"
        assert _clean_path_from_text(text) == text

    @pytest.mark.parametrize("path_text,expected", [
        ("/var/tmp/task/repo/.env", "<redacted-path>"),
        ("/tmp/task/repo/.env", "<redacted-path>"),
        ("/etc/passwd", "<redacted-path>"),
        ("C:\\Users\\alice\\AppData\\Local\\Temp\\a.txt",
         "<redacted-path>"),
        ("\\\\server\\share\\temp\\a.txt", "<redacted-path>"),
        ("//server/share/temp/a.txt", "<redacted-path>"),
    ])
    def test_absolute_path_redacted(self, path_text, expected):
        """Absolute paths are still redacted."""
        assert _clean_path_from_text(path_text) == expected

    def test_var_tmp_exact_assertion(self):
        """Exact assertion for /var/tmp path cleaning."""
        assert _clean_path_from_text(
            "err /var/tmp/task-secret/repo/.env done"
        ) == "err <redacted-path> done"

    def test_url_and_path_mixed(self):
        """URL is preserved while path is redacted in same text."""
        text = "Repo: https://github.com/test/repo Error: /tmp/secret/.env"
        result = _clean_path_from_text(text)
        assert "https://github.com/test/repo" in result
        assert "/tmp/secret/.env" not in result
        assert "<redacted-path>" in result

    def test_no_residue_in_var_tmp(self):
        """No /var, username, task ID, or basename residue."""
        result = _clean_path_from_text(
            "Error at /var/tmp/task-secret/repo/.env"
        )
        assert "/var" not in result
        assert "task-secret" not in result
        assert "repo" not in result
        assert ".env" not in result

    def test_forward_slash_unc_in_text(self):
        """Forward-slash UNC paths are cleaned from text."""
        result = _clean_path_from_text(
            "scan at //server/share/temp/repo/data.db"
        )
        assert "//server" not in result
        assert "<redacted-path>" in result


# ============================================================
# M. get_assessment_result connection close semantics
# ============================================================

class TestGetAssessmentCloseSemantics:
    """Connection close is called exactly once; close failures are handled."""

    def test_row_not_found_close_called_once(self, test_db, monkeypatch):
        """When row is None, close is called exactly once."""
        close_count = [0]
        _original_get_connection = _get_connection

        class _CountingConn:
            def __init__(self):
                self._real = _original_get_connection()
            def execute(self, *args, **kwargs):
                return self._real.execute(*args, **kwargs)
            def close(self):
                close_count[0] += 1
                self._real.close()
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _CountingConn(),
        )
        # Call with non-existent task_id
        result = get_assessment_result("nonexistent-task-id")
        assert result is None
        assert close_count[0] == 1, f"Expected 1 close, got {close_count[0]}"

    def test_close_failure_after_success_raises_internal_error(
        self, test_db, monkeypatch
    ):
        """Normal read succeeds, but close fails → AssessmentInternalError."""
        # Setup and save BEFORE monkeypatch so the test fixture is not affected.
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        _original_get_connection = _get_connection

        class _BadCloseConn:
            def __init__(self):
                self._real = _original_get_connection()
            def execute(self, *args, **kwargs):
                return self._real.execute(*args, **kwargs)
            def close(self):
                raise sqlite3.Error("close failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadCloseConn(),
        )
        with pytest.raises(AssessmentInternalError):
            get_assessment_result(task_id)

    def test_query_failure_and_close_failure_raises_internal_error(
        self, test_db, monkeypatch
    ):
        """Both query and close fail → AssessmentInternalError (query
        error preserved, close error suppressed)."""
        class _BadConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.Error("query failed")
            def close(self):
                raise sqlite3.Error("close failed")
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadConn(),
        )
        with pytest.raises(AssessmentInternalError) as exc_info:
            get_assessment_result("any-task-id")
        # Message should be the DB read error, not the close error
        msg = str(exc_info.value)
        assert "close" not in msg.lower()

    def test_no_sensitive_info_in_error(self, test_db, monkeypatch):
        """Error messages do not leak underlying exception details."""
        sensitive = "secret_db_error_at /tmp/private/database.db"

        class _BadConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.Error(sensitive)
            def close(self):
                pass
        monkeypatch.setattr(
            "app.services.assessment_service._get_connection",
            lambda: _BadConn(),
        )
        with pytest.raises(AssessmentInternalError) as exc_info:
            get_assessment_result("any-task-id")
        msg = str(exc_info.value)
        assert sensitive not in msg
        assert "secret_db_error_at" not in msg
        assert "/tmp/private" not in msg
