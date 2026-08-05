r"""P0-6 安全评估 API 端点测试。

覆盖 GET /api/check/{task_id}/assessment 端点的所有分支：
1. Status 端点对有评估的已完成任务返回 security_score/verdict/url
2. Status 端点对无评估的遗留已完成任务返回 null
3. Assessment 端点对有评估的已完成任务返回完整结果（200）
4. Assessment 端点对 pending 任务返回 409 ASSESSMENT_NOT_READY
5. Assessment 端点对 running 任务返回 409 ASSESSMENT_NOT_READY
6. Assessment 端点对 failed 任务返回安全空评估（200, score=0, verdict=blocked）
7. Assessment 端点对 failed 任务不返回残留评估
8. Assessment 端点对无评估的已完成任务返回 409 ASSESSMENT_NOT_AVAILABLE
9. Assessment 端点对不存在的任务返回 404
10. Assessment 端点对无效 UUID 格式返回 422
11. Assessment 响应不含原始密钥（ghp_、AKIA）
12. Assessment 响应不含临时路径（/tmp/、C:\）
13. Status 端点对 pending/running 任务不含 security_score 字段
14. Assessment 响应包含所有必需的顶层字段
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import (
    ASSESSMENT_NOT_AVAILABLE,
    ASSESSMENT_NOT_READY,
)
from app.db import database
from app.main import app
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanResult,
    Severity,
)
from app.services import task_manager
from app.services.assessment_service import (
    assess_scan_result,
    get_scan_result_with_timestamp,
    save_assessment_result,
)
from app.services.scan_result_service import save_scan_result
from tests.conftest import (
    SYNTHETIC_AWS_KEY,
    SYNTHETIC_GITHUB_TOKEN,
)

# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """设置临时测试数据库和 TestClient。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    database._initialized = False
    database.init_db()
    with TestClient(app) as c:
        yield c
    database._initialized = False


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_finding(**kwargs):
    """创建一个 Finding 数据类实例，带有合理的默认值。"""
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


def _create_completed_task_with_assessment(client, findings=None, summary_overrides=None):
    """创建一个已完成任务，包含扫描结果和评估。

    流程：创建任务 → 保存扫描结果 → 读取持久化结果 → 计算评估 →
          保存评估 → 标记为已完成。
    """
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    scan_result = ScanResult(
        findings=tuple(findings or []),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )
    save_scan_result(task.id, scan_result)
    # 读取持久化的扫描结果并计算评估
    scan_data = get_scan_result_with_timestamp(task.id)  # 返回 (dict, updated_at)
    scan_dict, scan_updated = scan_data
    assessment = assess_scan_result(task.id, scan_dict)
    save_assessment_result(task.id, assessment, scan_updated)
    task_manager.mark_completed(task.id, file_count=5, total_size=1024, top_level_dir="repo")
    return task.id


def _create_completed_task_without_assessment(findings=None):
    """创建一个已完成的遗留任务（无评估结果）。

    模拟 P0-5 遗留任务：有扫描结果但无评估。
    """
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    scan_result = ScanResult(
        findings=tuple(findings or []),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )
    save_scan_result(task.id, scan_result)
    task_manager.mark_completed(task.id, file_count=5, total_size=1024, top_level_dir="repo")
    return task.id


def _create_pending_task():
    """创建一个 pending 状态的任务。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    return task.id


def _create_running_task():
    """创建一个 running 状态的任务。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    task_manager.mark_running(task.id, "scanning", 80)
    return task.id


def _create_failed_task():
    """创建一个 failed 状态的任务。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    task_manager.mark_failed(task.id, "INTERNAL_ERROR", "内部错误，请稍后重试。")
    return task.id


# ============================================================
# 测试类：TestAssessmentAPI
# ============================================================

class TestAssessmentAPI:
    """安全评估 API 端点测试。"""

    def test_status_returns_security_fields_for_completed_with_assessment(self, client):
        """Status 端点对有评估的已完成任务返回 security_score/verdict/url。"""
        finding = _make_finding(is_blocking=True)
        task_id = _create_completed_task_with_assessment(client, findings=[finding])

        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["security_score"] is not None
        assert data["security_verdict"] is not None
        assert data["assessment_url"] is not None
        assert data["assessment_url"] == f"/api/check/{task_id}/assessment"
        assert isinstance(data["security_score"], int)
        assert data["security_verdict"] in ("pass", "warning", "blocked")

    def test_status_returns_null_security_fields_for_legacy_completed(self, client):
        """Status 端点对无评估的遗留已完成任务返回 null。"""
        task_id = _create_completed_task_without_assessment()

        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["security_score"] is None
        assert data["security_verdict"] is None
        assert data["assessment_url"] is None

    def test_assessment_endpoint_returns_full_result(self, client):
        """Assessment 端点对有评估的已完成任务返回完整结果（200）。"""
        finding = _make_finding(is_blocking=True)
        task_id = _create_completed_task_with_assessment(client, findings=[finding])

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task_id
        assert data["schema_version"] == 1
        assert data["policy_version"] == "p0-6-v1"
        assert "score" in data
        assert "verdict" in data
        assert "score_breakdown" in data
        assert "score_caps" in data
        assert "blocking_reasons" in data
        assert "coverage" in data

    def test_assessment_endpoint_409_for_pending(self, client):
        """Assessment 端点对 pending 任务返回 409 ASSESSMENT_NOT_READY。"""
        task_id = _create_pending_task()

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == ASSESSMENT_NOT_READY

    def test_assessment_endpoint_409_for_running(self, client):
        """Assessment 端点对 running 任务返回 409 ASSESSMENT_NOT_READY。"""
        task_id = _create_running_task()

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == ASSESSMENT_NOT_READY

    def test_assessment_endpoint_safe_empty_for_failed(self, client):
        """Assessment 端点对 failed 任务返回安全空评估（200, score=0, verdict=blocked）。"""
        task_id = _create_failed_task()

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 200
        data = response.json()
        assert data["score"] == 0
        assert data["verdict"] == "blocked"
        assert data["score_breakdown"] == []
        assert data["score_caps"] == []
        assert data["blocking_reasons"] == []
        assert data["coverage"]["status"] == "partial"
        assert data["created_at"] is None
        assert data["updated_at"] is None

    def test_assessment_endpoint_no_residual_for_failed(self, client):
        """Assessment 端点对 failed 任务不返回残留评估。

        场景：评估已保存到数据库，但任务因后续步骤失败而标记为 failed。
        API 不应返回数据库中的残留评估，而应返回安全空评估。
        """
        # 1. 创建任务并保存扫描结果和评估
        finding = _make_finding(is_blocking=True)
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(finding,),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)
        scan_data = get_scan_result_with_timestamp(task.id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task.id, scan_dict)
        save_assessment_result(task.id, assessment, scan_updated)

        # 2. 将任务标记为 failed（模拟 mark_completed 失败的场景）
        task_manager.mark_failed(task.id, "INTERNAL_ERROR", "内部错误，请稍后重试。")

        # 3. API 应返回安全空评估，而非残留评估
        response = client.get(f"/api/check/{task.id}/assessment")
        assert response.status_code == 200
        data = response.json()
        assert data["score"] == 0
        assert data["verdict"] == "blocked"
        # 不应包含原始评估的分数
        assert data["score"] != assessment["score"]

    def test_assessment_endpoint_409_for_completed_without_assessment(self, client):
        """Assessment 端点对无评估的已完成任务返回 409 ASSESSMENT_NOT_AVAILABLE。"""
        task_id = _create_completed_task_without_assessment()

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == ASSESSMENT_NOT_AVAILABLE

    def test_assessment_endpoint_404_for_nonexistent(self, client):
        """Assessment 端点对不存在的任务返回 404。"""
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/check/{fake_id}/assessment")
        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["error_code"] == "TASK_NOT_FOUND"

    def test_assessment_endpoint_422_for_invalid_uuid(self, client):
        """Assessment 端点对无效 UUID 格式返回 422。"""
        response = client.get("/api/check/not-a-valid-uuid/assessment")
        assert response.status_code == 422
        data = response.json()
        assert data["detail"]["error_code"] == "INVALID_TASK_ID"

    def test_assessment_response_no_raw_secrets(self, client):
        """Assessment 响应不含原始密钥（ghp_、AKIA）。"""
        finding = _make_finding(
            snippet_masked="ghp_****",
            description="Found a GitHub token",
        )
        task_id = _create_completed_task_with_assessment(client, findings=[finding])

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 200
        json_str = json.dumps(response.json(), ensure_ascii=False)

        # 不应包含合成密钥
        assert SYNTHETIC_GITHUB_TOKEN not in json_str
        assert SYNTHETIC_AWS_KEY not in json_str

        # 不应包含原始密钥前缀+长字符串模式
        import re
        raw_token_pattern = re.compile(r"ghp_[A-Za-z0-9]{36}")
        raw_aws_pattern = re.compile(r"AKIA[A-Z0-9]{16}")
        assert not raw_token_pattern.search(json_str)
        assert not raw_aws_pattern.search(json_str)

    def test_assessment_response_no_temp_paths(self, client):
        r"""Assessment 响应不含临时路径（/tmp/、C:\）。"""
        finding = _make_finding(is_blocking=False)
        task_id = _create_completed_task_with_assessment(client, findings=[finding])

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 200
        json_str = json.dumps(response.json(), ensure_ascii=False)

        # 不应包含临时路径模式
        assert "/tmp/" not in json_str
        assert "C:\\" not in json_str
        assert "C:/" not in json_str

    def test_status_no_security_fields_for_pending_running(self, client):
        """Status 端点对 pending/running 任务不含 security_score 字段。

        pending/running 任务的 to_response() 不包含 security_score、
        security_verdict、assessment_url 字段。
        """
        # pending 任务
        pending_id = _create_pending_task()
        response = client.get(f"/api/check/{pending_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"
        # security_score 等字段不应存在或为 None
        assert "security_score" not in data or data["security_score"] is None
        assert "security_verdict" not in data or data["security_verdict"] is None
        assert "assessment_url" not in data or data["assessment_url"] is None

        # running 任务
        running_id = _create_running_task()
        response = client.get(f"/api/check/{running_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "security_score" not in data or data["security_score"] is None
        assert "security_verdict" not in data or data["security_verdict"] is None
        assert "assessment_url" not in data or data["assessment_url"] is None

    def test_assessment_response_has_all_required_fields(self, client):
        """Assessment 响应包含所有必需的顶层字段。"""
        finding = _make_finding(is_blocking=True)
        task_id = _create_completed_task_with_assessment(client, findings=[finding])

        response = client.get(f"/api/check/{task_id}/assessment")
        assert response.status_code == 200
        data = response.json()

        required_fields = [
            "schema_version",
            "policy_version",
            "assessment_scope",
            "task_id",
            "score",
            "score_before_caps",
            "verdict",
            "score_breakdown",
            "score_caps",
            "blocking_reasons",
            "coverage",
            "created_at",
            "updated_at",
        ]
        for field in required_fields:
            assert field in data, f"缺少必需字段: {field}"
