"""P0-10 persistence compatibility and security-policy isolation tests."""

from __future__ import annotations

import json

import pytest

from app.db import database
from app.db.database import _get_connection, now_iso
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    INCOMPLETE_CONTENT_DIMENSION,
    ScanResult,
    SENSITIVE_DATA_DIMENSION,
    Severity,
)
from app.services import task_manager
from app.services.assessment_service import AssessmentInternalError, assess_scan_result
from app.services.repair_service import (
    RepairPlanInternalError,
    generate_repair_plan,
)
from app.services.scan_result_service import (
    get_scan_result,
    get_scan_summary,
    serialize_scan_result,
)


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    database._initialized = False
    database.init_db()
    yield
    database._initialized = False


def _finding(dimension: str = SENSITIVE_DATA_DIMENSION) -> Finding:
    incomplete = dimension == INCOMPLETE_CONTENT_DIMENSION
    return Finding(
        rule_id="I001_TODO_COMMENT" if incomplete else "R006_PASSWORD_ASSIGNMENT",
        rule_name="Unfinished work comment" if incomplete else "Password Assignment",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        column_start=2,
        column_end=6,
        snippet_masked="# TODO" if incomplete else "password=****",
        is_blocking=False,
        finding_type=FindingType.CONTENT,
        description="Fixed description",
        category="unfinished_comment" if incomplete else "password",
        secret_type="" if incomplete else "password",
        message="Fixed advice",
        repair_template_key=(
            "complete_or_remove_todo_comment" if incomplete else "use_env_var_password"
        ),
        dimension=dimension,
    )


def _finding_dict(finding: Finding) -> dict:
    result = serialize_scan_result(ScanResult(
        findings=(finding,), notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=1, total_lines_scanned=1,
    ))
    return result["findings"][0]


def _scan_dict(findings: list[dict], *, multidimensional: bool) -> dict:
    sensitive_count = sum(
        finding.get("dimension", SENSITIVE_DATA_DIMENSION) == SENSITIVE_DATA_DIMENSION
        for finding in findings
    )
    incomplete_count = len(findings) - sensitive_count
    summary = {
        "total_findings": len(findings),
        "blocking_findings": sum(bool(finding["is_blocking"]) for finding in findings),
        "total_notices": 0,
        "total_skipped_files": 0,
        "total_scan_errors": 0,
        "total_files_scanned": 1,
        "total_lines_scanned": 10,
        "returned_findings": len(findings),
        "findings_truncated": False,
        "returned_notices": 0,
        "notices_truncated": False,
        "returned_skipped_files": 0,
        "skipped_files_truncated": False,
        "returned_scan_errors": 0,
        "scan_errors_truncated": False,
    }
    if multidimensional:
        summary["dimension_counts"] = {
            SENSITIVE_DATA_DIMENSION: sensitive_count,
            INCOMPLETE_CONTENT_DIMENSION: incomplete_count,
        }
    return {
        "schema_version": 2 if multidimensional else 1,
        "findings": findings,
        "notices": [],
        "skipped_files": [],
        "scan_errors": [],
        "summary": summary,
    }


def test_v2_serialization_round_trip_fields_and_counts():
    serialized = serialize_scan_result(ScanResult(
        findings=(_finding(), _finding(INCOMPLETE_CONTENT_DIMENSION)),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=1, total_lines_scanned=2,
    ))
    assert serialized["schema_version"] == 2
    assert [finding["dimension"] for finding in serialized["findings"]] == [
        SENSITIVE_DATA_DIMENSION,
        INCOMPLETE_CONTENT_DIMENSION,
    ]
    assert serialized["summary"]["dimension_counts"] == {
        SENSITIVE_DATA_DIMENSION: 1,
        INCOMPLETE_CONTENT_DIMENSION: 1,
    }
    assert json.loads(json.dumps(serialized, sort_keys=True)) == serialized


def test_v1_database_read_defaults_to_sensitive_without_rewrite(test_db):
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    legacy_finding = _finding_dict(_finding())
    legacy_finding.pop("dimension")
    legacy = _scan_dict([legacy_finding], multidimensional=False)
    summary = legacy["summary"]
    now = now_iso()
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO scan_results
               (task_id, schema_version, result_json, summary_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors, total_files_scanned,
                total_lines_scanned, created_at, updated_at)
               VALUES (?, 1, ?, ?, 1, 0, 0, 0, 0, 1, 10, ?, ?)""",
            (task.id, json.dumps(legacy), json.dumps(summary), now, now),
        )
        conn.commit()
    finally:
        conn.close()

    loaded = get_scan_result(task.id)
    loaded_summary = get_scan_summary(task.id)
    assert loaded["schema_version"] == 1
    assert loaded["findings"][0]["dimension"] == SENSITIVE_DATA_DIMENSION
    assert loaded_summary["dimension_counts"] == {
        SENSITIVE_DATA_DIMENSION: 1,
        INCOMPLETE_CONTENT_DIMENSION: 0,
    }
    conn = _get_connection()
    try:
        stored = json.loads(conn.execute(
            "SELECT result_json FROM scan_results WHERE task_id = ?", (task.id,)
        ).fetchone()["result_json"])
    finally:
        conn.close()
    assert "dimension" not in stored["findings"][0]


def test_incomplete_findings_do_not_change_assessment_or_repair_plan():
    task_id = "dimension-isolation-task"
    sensitive = _finding_dict(_finding())
    incomplete = _finding_dict(_finding(INCOMPLETE_CONTENT_DIMENSION))
    legacy_sensitive = dict(sensitive)
    legacy_sensitive.pop("dimension")

    baseline_scan = _scan_dict([legacy_sensitive], multidimensional=False)
    mixed_scan = _scan_dict([sensitive, incomplete], multidimensional=True)
    baseline_assessment = assess_scan_result(task_id, baseline_scan)
    mixed_assessment = assess_scan_result(task_id, mixed_scan)
    assert mixed_assessment == baseline_assessment

    def make_plan(scan_result, assessment):
        return generate_repair_plan(
            task_id=task_id,
            scan_result=scan_result,
            summary=scan_result["summary"],
            scan_updated_at="2026-01-01T00:00:00Z",
            assessment=assessment,
            assessment_updated_at="2026-01-01T00:00:01Z",
            assessment_policy_version="p0-6-v1",
            source_scan_updated_at="2026-01-01T00:00:00Z",
        )

    baseline_plan = make_plan(baseline_scan, baseline_assessment)
    mixed_plan = make_plan(mixed_scan, mixed_assessment)
    assert mixed_plan == baseline_plan
    assert "I001_TODO_COMMENT" not in mixed_plan["agent_prompt"]
    assert mixed_assessment["verdict"] != "blocked"


def test_malformed_persisted_findings_fail_closed():
    task_id = "malformed-dimension-task"
    scan_result = _scan_dict([], multidimensional=True)
    scan_result["findings"] = ["not-a-finding"]
    scan_result["summary"]["total_findings"] = 1
    scan_result["summary"]["dimension_counts"][SENSITIVE_DATA_DIMENSION] = 1

    with pytest.raises(AssessmentInternalError):
        assess_scan_result(task_id, scan_result)

    assessment = assess_scan_result(
        task_id, _scan_dict([], multidimensional=True)
    )
    with pytest.raises(RepairPlanInternalError):
        generate_repair_plan(
            task_id=task_id,
            scan_result=scan_result,
            summary=scan_result["summary"],
            scan_updated_at="2026-01-01T00:00:00Z",
            assessment=assessment,
            assessment_updated_at="2026-01-01T00:00:01Z",
            assessment_policy_version="p0-6-v1",
            source_scan_updated_at="2026-01-01T00:00:00Z",
        )
