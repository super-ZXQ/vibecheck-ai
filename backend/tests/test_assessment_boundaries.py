"""P0-6 assessment boundary adversarial tests.

Covers:
A. Absolute path direct persistence in blocking_reasons.file_path
B. Absolute paths in description fields
C. Internal objects must not be stringified
D. Corrupted assessment_json (invalid JSON, wrong types, identity mismatch)
E. Runner fallback error classification

All test strings are SYNTHETIC — format-correct but NOT real credentials.
"""

import copy
import json
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import database
from app.db.database import _get_connection
from app.services import task_manager
from app.services.assessment_service import (
    assess_scan_result,
    save_assessment_result,
    serialize_assessment_result,
    get_assessment_result,
    run_assessment,
    AssessmentInternalError,
    AssessmentSerializationError,
    sanitize_assessment_file_path,
)
from app.services.scan_result_service import save_scan_result
from app.scanner.base import (
    Finding, ScanResult, Severity, Confidence, FindingType,
)
from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
)


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
    """Directly insert/update assessment_results row with raw JSON."""
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO assessment_results
               (task_id, schema_version, policy_version, assessment_scope,
                assessment_json, score, verdict, source_scan_updated_at,
                created_at, updated_at)
               VALUES (?, 1, 'p0-6-v1', 'repository', ?, ?, ?, 'sync',
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
               ON CONFLICT(task_id) DO UPDATE SET
                   assessment_json=excluded.assessment_json,
                   score=excluded.score,
                   verdict=excluded.verdict""",
            (task_id, raw_json, score, verdict),
        )
        conn.commit()
    finally:
        conn.close()


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
        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert "/tmp/vibecheck/secret/repo/config.py" not in retrieved_json
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
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        assessment["score_breakdown"][0]["rule_id"] = 12345

        with pytest.raises(AssessmentSerializationError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_list_in_string_field_rejected(self, test_db):
        """List in a string field is rejected."""
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

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
        task_id, scan_dict, scan_updated = _setup_task_with_scan(test_db)
        assessment = assess_scan_result(task_id, scan_dict)

        if assessment["score_breakdown"]:
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
        """task_id in JSON doesn't match DB task_id → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        bad = {
            "schema_version": 1,
            "policy_version": "p0-6-v1",
            "assessment_scope": "repository",
            "task_id": "wrong-task-id",
            "score": 50,
            "verdict": "warning",
            "score_breakdown": [],
            "score_caps": [],
            "blocking_reasons": [],
            "coverage": {"status": "complete", "reasons": []},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        _insert_assessment_json(task_id, json.dumps(bad), score=50, verdict="warning")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_policy_version_mismatch(self, client):
        """policy_version mismatch → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        bad = {
            "schema_version": 1,
            "policy_version": "wrong-version",
            "assessment_scope": "repository",
            "task_id": task_id,
            "score": 50,
            "verdict": "warning",
            "score_breakdown": [],
            "score_caps": [],
            "blocking_reasons": [],
            "coverage": {"status": "complete", "reasons": []},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        _insert_assessment_json(task_id, json.dumps(bad), score=50, verdict="warning")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_score_out_of_range(self, client):
        """score > 100 → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        bad = {
            "schema_version": 1,
            "policy_version": "p0-6-v1",
            "assessment_scope": "repository",
            "task_id": task_id,
            "score": 999,
            "verdict": "pass",
            "score_breakdown": [],
            "score_caps": [],
            "blocking_reasons": [],
            "coverage": {"status": "complete", "reasons": []},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        _insert_assessment_json(task_id, json.dumps(bad), score=999, verdict="pass")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_invalid_verdict(self, client):
        """Invalid verdict → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        bad = {
            "schema_version": 1,
            "policy_version": "p0-6-v1",
            "assessment_scope": "repository",
            "task_id": task_id,
            "score": 50,
            "verdict": "invalid",
            "score_breakdown": [],
            "score_caps": [],
            "blocking_reasons": [],
            "coverage": {"status": "complete", "reasons": []},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        _insert_assessment_json(task_id, json.dumps(bad), score=50, verdict="invalid")

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == ASSESSMENT_INTERNAL_ERROR

    def test_schema_version_mismatch(self, client):
        """schema_version mismatch → 500."""
        task_id = self._setup_completed_task_with_assessment(client)
        bad = {
            "schema_version": 99,
            "policy_version": "p0-6-v1",
            "assessment_scope": "repository",
            "task_id": task_id,
            "score": 50,
            "verdict": "warning",
            "score_breakdown": [],
            "score_caps": [],
            "blocking_reasons": [],
            "coverage": {"status": "complete", "reasons": []},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        _insert_assessment_json(task_id, json.dumps(bad), score=50, verdict="warning")

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
        from app.services.background_runner import _process_task, reset_runner_state
        from app.services.scan_result_service import save_scan_result
        from app.scanner.base import ScanResult

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
        from app.core.github import DownloadResult, parse_repo_url
        from app.core.safe_extract import ExtractionResult
        from pathlib import Path

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
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=mock_scan,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=RuntimeError("unexpected internal error"),
                    ):
                        asyncio.run(_process_task(task.id))

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == ASSESSMENT_INTERNAL_ERROR
        assert result.error_code != ASSESSMENT_PERSIST_FAILED

        reset_runner_state()
