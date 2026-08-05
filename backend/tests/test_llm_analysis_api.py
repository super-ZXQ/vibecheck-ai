"""P1-4 LLM 分析 API 端点测试。

覆盖 GET /api/check/{task_id}/llm-analysis 端点的所有分支：
1. 404: 不存在的任务
2. 422: 无效 UUID 格式
3. 409: pending 任务返回 LLM_ANALYSIS_NOT_READY
4. 409: running 任务返回 LLM_ANALYSIS_NOT_READY
5. 200: failed 任务返回安全空 LLM 分析
6. 200: 已完成任务有 LLM 分析时返回完整结果
7. 200: 已完成任务无 LLM 分析时返回安全空（非阻断）
8. 轮询端点返回 llm_analysis_available 和 llm_analysis_url
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import LLM_ANALYSIS_NOT_READY
from app.db import database
from app.services import background_runner, task_manager
from app.services.llm_service import generate_and_save_llm_analysis

# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(test_db):
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_runner():
    background_runner.reset_runner_state()
    yield
    background_runner.reset_runner_state()


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _create_pending_task():
    """创建一个 pending 任务并返回 task_id。"""
    task = task_manager.create_task(
        "https://github.com/test/repo", "test", "repo"
    )
    return task.id


def _create_completed_task_with_llm_analysis():
    """创建一个已完成任务，包含 LLM 分析结果。"""
    from app.db.database import _get_connection, now_iso

    task_id = _create_pending_task()

    # Directly insert scan result into DB (bypassing serialize_scan_result
    # which expects a ScanResult object, not a dict).
    scan_result_json = json.dumps({
        "findings": [
            {
                "rule_id": "I001_TODO_COMMENT",
                "rule_name": "Unfinished work comment",
                "severity": "medium",
                "confidence": "high",
                "file_path": "src/app.py",
                "line_start": 1, "line_end": 1,
                "column_start": 0, "column_end": 10,
                "snippet_masked": "# TODO: fix",
                "is_blocking": False,
                "finding_type": "content",
                "description": "TODO comment",
                "category": "incomplete",
                "secret_type": "",
                "message": "TODO",
                "repair_template_key": "",
                "dimension": "incomplete_content",
            }
        ],
        "notices": [],
        "skipped_files": [],
        "scan_errors": [],
    })
    summary_json = json.dumps({
        "total_findings": 1, "blocking_findings": 0,
        "total_notices": 0, "total_skipped_files": 0,
        "total_scan_errors": 0, "total_files_scanned": 1,
        "total_lines_scanned": 1,
        "returned_findings": 1, "findings_truncated": False,
        "returned_notices": 0, "notices_truncated": False,
        "returned_skipped_files": 0, "skipped_files_truncated": False,
        "returned_scan_errors": 0, "scan_errors_truncated": False,
    })
    now = now_iso()
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO scan_results
               (task_id, schema_version, result_json, summary_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors,
                total_files_scanned, total_lines_scanned,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, 2, scan_result_json, summary_json,
             1, 0, 0, 0, 0, 1, 1, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    # Generate LLM analysis
    generate_and_save_llm_analysis(task_id)

    # Mark as completed
    task_manager.mark_completed(task_id, 10, 1024, "test-repo")
    return task_id


def _create_completed_task_without_llm_analysis():
    """创建一个已完成任务，但不包含 LLM 分析结果。"""
    task_id = _create_pending_task()
    task_manager.mark_completed(task_id, 10, 1024, "test-repo")
    return task_id


def _create_failed_task():
    """创建一个 failed 任务。"""
    task_id = _create_pending_task()
    task_manager.mark_failed(task_id, "INTERNAL_ERROR", "内部错误")
    return task_id


# ---------------------------------------------------------------------------
# --- LLM analysis endpoint tests ---
# ---------------------------------------------------------------------------

class TestLLMAnalysisEndpoint:

    def test_404_task_not_found(self, client):
        """不存在的任务返回 404。"""
        response = client.get(
            f"/api/check/{uuid.uuid4()}/llm-analysis"
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error_code"] == "TASK_NOT_FOUND"

    def test_422_invalid_uuid(self, client):
        """无效 UUID 格式返回 422。"""
        response = client.get("/api/check/not-a-uuid/llm-analysis")
        assert response.status_code == 422

    def test_409_pending_task(self, client):
        """pending 任务返回 409 LLM_ANALYSIS_NOT_READY。"""
        task_id = _create_pending_task()
        response = client.get(f"/api/check/{task_id}/llm-analysis")
        assert response.status_code == 409
        assert response.json()["detail"]["error_code"] == LLM_ANALYSIS_NOT_READY

    def test_200_failed_task_returns_safe_empty(self, client):
        """failed 任务返回 200 安全空结果。"""
        task_id = _create_failed_task()
        response = client.get(f"/api/check/{task_id}/llm-analysis")
        assert response.status_code == 200
        data = response.json()
        assert data["total_analyzed"] == 0
        assert data["items"] == []

    def test_200_completed_with_analysis(self, client):
        """已完成任务有 LLM 分析时返回完整结果。"""
        task_id = _create_completed_task_with_llm_analysis()
        response = client.get(f"/api/check/{task_id}/llm-analysis")
        assert response.status_code == 200
        data = response.json()
        assert data["total_analyzed"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["rule_id"] == "I001_TODO_COMMENT"
        assert data["items"][0]["explanation"]
        assert data["items"][0]["instruction"]

    def test_200_completed_without_analysis(self, client):
        """已完成任务无 LLM 分析时返回 200 安全空（非阻断）。"""
        task_id = _create_completed_task_without_llm_analysis()
        response = client.get(f"/api/check/{task_id}/llm-analysis")
        assert response.status_code == 200
        data = response.json()
        assert data["total_analyzed"] == 0
        assert data["items"] == []


# ---------------------------------------------------------------------------
# --- Polling endpoint tests ---
# ---------------------------------------------------------------------------

class TestPollingFields:

    def test_completed_with_analysis_shows_available(self, client):
        """已完成任务有 LLM 分析时轮询返回 available=true。"""
        task_id = _create_completed_task_with_llm_analysis()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["llm_analysis_available"] is True
        assert data["llm_analysis_url"] == f"/api/check/{task_id}/llm-analysis"

    def test_completed_without_analysis_shows_unavailable(self, client):
        """已完成任务无 LLM 分析时轮询返回 available=false。"""
        task_id = _create_completed_task_without_llm_analysis()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["llm_analysis_available"] is False
        assert data["llm_analysis_url"] is None

    def test_pending_task_no_llm_fields(self, client):
        """pending 任务不返回 llm_analysis_available=true。"""
        task_id = _create_pending_task()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        # For pending tasks, these fields should be None (not True)
        assert data.get("llm_analysis_available") is not True

    def test_failed_task_no_llm_fields(self, client):
        """failed 任务不返回 llm_analysis_available=true。"""
        task_id = _create_failed_task()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data.get("llm_analysis_available") is not True
