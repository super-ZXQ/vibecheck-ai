"""P0-7 修复计划 API 端点测试。

覆盖 GET /api/check/{task_id}/repair-plan 端点的所有分支：
1. 404: 不存在的任务返回 TASK_NOT_FOUND
2. 422: 无效 UUID 格式返回 INVALID_TASK_ID
3. 409: pending 任务返回 REPAIR_PLAN_NOT_READY（不读取 repair_results）
4. 409: running 任务返回 REPAIR_PLAN_NOT_READY（不读取 repair_results）
5. 200: failed 任务返回安全空修复计划（plan_status=partial，全零）
6. 200: 已完成任务有修复计划时返回完整计划
7. 409: 已完成任务无修复计划时返回 REPAIR_PLAN_NOT_AVAILABLE
8. 500: 未知状态任务返回 REPAIR_PLAN_INTERNAL_ERROR
9. 500: repair_json 损坏时返回 REPAIR_PLAN_INTERNAL_ERROR
10. 500: 身份字段不匹配时返回 REPAIR_PLAN_INTERNAL_ERROR
11. 轮询端点对有修复计划的已完成任务返回 repair_plan_available=true 和 repair_plan_url
12. 轮询端点对 pending 任务不返回 repair_plan_available=true
13. 轮询端点对 failed 任务不返回 repair_plan_available=true
14. 轮询端点对无修复计划的已完成任务返回 repair_plan_available=false
15. failed 任务即使有残留 repair_results 行也返回安全空计划（不泄露残留数据）
16. 安全空修复计划的结构验证（所有字段匹配预期值）
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import (
    REPAIR_PLAN_INTERNAL_ERROR,
    REPAIR_PLAN_NOT_AVAILABLE,
    REPAIR_PLAN_NOT_READY,
)
from app.db import database
from app.services import background_runner, task_manager
from app.services.repair_policy import (
    ACTION_REVOKE_OR_ROTATE_SECRET,
    AGENT_PROMPT_REQUIREMENTS,
    PARTIAL_DECLARATION,
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
)
from app.services.repair_service import (
    serialize_repair_plan,
)

# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path / "tmp"))
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

def _create_completed_task():
    """创建一个已完成任务并返回 task_id。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    task_manager.mark_completed(task.id, file_count=10, total_size=1000, top_level_dir="test-repo")
    return task.id


def _create_failed_task():
    """创建一个失败任务并返回 task_id。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    task_manager.mark_failed(task.id, "INTERNAL_ERROR", "内部错误")
    return task.id


def _create_pending_task():
    """创建一个 pending 状态的任务并返回 task_id。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    return task.id


def _create_running_task():
    """创建一个 running 状态的任务并返回 task_id。"""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    task_manager.mark_running(task.id, "scanning", 80)
    return task.id


def _make_valid_agent_prompt(plan_status="complete"):
    """Build a minimal valid agent_prompt containing all 11 requirements."""
    lines = [
        "# VibeCheck 安全修复指引",
        "",
    ]
    if plan_status == "partial":
        lines.append(PARTIAL_DECLARATION)
        lines.append("")
    lines.append("## 安全要求")
    lines.append("")
    for req in AGENT_PROMPT_REQUIREMENTS:
        lines.append(req)
    return "\n".join(lines)


def _insert_repair_plan(task_id, plan_status="complete"):
    """直接向 repair_results 表插入一条完整有效的修复计划记录。

    使用 serialize_repair_plan 构建符合冻结策略的安全计划，
    确保 get_repair_result 的严格验证能够通过。
    返回插入的 plan dict。
    """
    from app.db.database import _get_connection, now_iso
    now = now_iso()

    # Build a minimal plan dict — serialize_repair_plan will rebuild
    # all policy fields (title, description, steps, commands, etc.)
    # from the frozen RepairAction definition.
    raw_plan = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": plan_status,
        "summary": {
            "total_repair_groups": 1,
            "blocking_repair_groups": 1,
            "manual_review_required": False,
            "coverage_warning": False,
            "groups_truncated": False,
        },
        "repair_groups": [{
            "group_id": "RG001",
            "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
            "priority": 1,
            "blocking": True,
            "highest_severity": "critical",
            "highest_confidence": "high",
            "title": "placeholder",
            "description": "placeholder",
            "related_rule_ids": ["R001_GITHUB_TOKEN"],
            "related_files": ["config.py"],
            "total_related_files": 1,
            "returned_related_files": 1,
            "related_files_truncated": False,
            "finding_count": 1,
            "steps": ["placeholder"],
            "commands": [],
            "safety_notes": ["placeholder"],
            "verification_steps": ["placeholder"],
        }],
        "verification_steps": ["placeholder"],
        "agent_prompt": _make_valid_agent_prompt(plan_status),
        "source_scan_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_policy_version": "p0-6-v1",
        "created_at": now,
        "updated_at": now,
    }

    # Serialize to get a safe plan with all policy fields rebuilt
    safe_plan = serialize_repair_plan(
        task_id=task_id,
        repair_plan=raw_plan,
        source_scan_updated_at="2026-01-01T00:00:00Z",
        source_assessment_updated_at="2026-01-01T00:00:00Z",
        source_assessment_policy_version="p0-6-v1",
        created_at=now,
        updated_at=now,
    )
    repair_json_str = json.dumps(safe_plan, ensure_ascii=False, sort_keys=True)

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO repair_results
               (task_id, schema_version, policy_version, repair_scope,
                repair_json, plan_status, total_repair_groups,
                blocking_repair_groups, source_scan_updated_at,
                source_assessment_updated_at, source_assessment_policy_version,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, REPAIR_SCHEMA_VERSION, POLICY_VERSION, REPAIR_SCOPE,
             repair_json_str, plan_status,
             safe_plan["summary"]["total_repair_groups"],
             safe_plan["summary"]["blocking_repair_groups"],
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "p0-6-v1",
             now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return safe_plan


def _set_task_status(task_id, status):
    """直接更新 tasks 表中的 status 字段（用于模拟未知状态）。"""
    from app.db.database import _get_connection
    conn = _get_connection()
    try:
        conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
        conn.commit()
    finally:
        conn.close()


def _insert_corrupted_repair_json(task_id, corrupt_field="schema_version", corrupt_value=999):
    """向 repair_results 插入一条损坏的记录。

    - 如果 corrupt_field 为 None，插入字面上无效的 JSON 字符串。
    - 否则，插入有效 JSON 但将指定的身份字段设置为错误的值。
    """
    from app.db.database import _get_connection, now_iso
    now = now_iso()

    if corrupt_field is None:
        # 插入字面上无法解析的 JSON
        repair_json_str = "{this is not valid json"
    else:
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "complete",
            "summary": {"total_repair_groups": 1, "blocking_repair_groups": 1,
                         "manual_review_required": False, "coverage_warning": False,
                         "groups_truncated": False},
            "repair_groups": [],
            "verification_steps": [],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": now, "updated_at": now,
        }
        plan[corrupt_field] = corrupt_value
        repair_json_str = json.dumps(plan, ensure_ascii=False)

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO repair_results
               (task_id, schema_version, policy_version, repair_scope,
                repair_json, plan_status, total_repair_groups,
                blocking_repair_groups, source_scan_updated_at,
                source_assessment_updated_at, source_assessment_policy_version,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, REPAIR_SCHEMA_VERSION, POLICY_VERSION, REPAIR_SCOPE,
             repair_json_str, "complete", 1, 1,
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "p0-6-v1",
             now, now),
        )
        conn.commit()
    finally:
        conn.close()


# ============================================================
# 测试类：TestRepairAPI
# ============================================================

class TestRepairAPI:
    """P0-7 修复计划 API 端点测试。"""

    # --- 1. 404: 任务不存在 ---

    def test_404_task_not_found(self, client):
        """GET /api/check/{nonexistent_uuid}/repair-plan 返回 404 TASK_NOT_FOUND。"""
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/check/{fake_id}/repair-plan")
        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["error_code"] == "TASK_NOT_FOUND"

    # --- 2. 422: 无效 UUID ---

    def test_422_invalid_uuid(self, client):
        """GET /api/check/not-a-uuid/repair-plan 返回 422 INVALID_TASK_ID。"""
        response = client.get("/api/check/not-a-uuid/repair-plan")
        assert response.status_code == 422
        data = response.json()
        assert data["detail"]["error_code"] == "INVALID_TASK_ID"

    # --- 3. 409: pending 任务 ---

    def test_409_pending(self, client):
        """pending 任务返回 409 REPAIR_PLAN_NOT_READY（不读取 repair_results）。"""
        task_id = _create_pending_task()
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_NOT_READY

    # --- 4. 409: running 任务 ---

    def test_409_running(self, client):
        """running 任务返回 409 REPAIR_PLAN_NOT_READY（不读取 repair_results）。"""
        task_id = _create_running_task()
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_NOT_READY

    # --- 5. 200: failed 任务返回安全空计划 ---

    def test_200_failed_returns_safe_empty(self, client):
        """failed 任务返回 200，带有安全空修复计划（plan_status=partial，全零）。"""
        task_id = _create_failed_task()
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 200
        data = response.json()
        assert data["plan_status"] == "partial"
        assert data["summary"]["total_repair_groups"] == 0
        assert data["summary"]["blocking_repair_groups"] == 0
        assert data["repair_groups"] == []

    # --- 6. 200: 已完成任务有修复计划 ---

    def test_200_completed_with_plan(self, client):
        """已完成任务有修复计划时返回 200 完整计划。"""
        task_id = _create_completed_task()
        _insert_repair_plan(task_id)
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task_id
        assert data["schema_version"] == REPAIR_SCHEMA_VERSION
        assert data["policy_version"] == POLICY_VERSION
        assert data["repair_scope"] == REPAIR_SCOPE
        assert data["plan_status"] == "complete"
        assert data["summary"]["total_repair_groups"] == 1
        assert data["summary"]["blocking_repair_groups"] == 1
        assert isinstance(data["repair_groups"], list)
        assert isinstance(data["verification_steps"], list)

    # --- 7. 409: 已完成任务无修复计划 ---

    def test_409_completed_without_plan(self, client):
        """已完成任务无修复计划时返回 409 REPAIR_PLAN_NOT_AVAILABLE。"""
        task_id = _create_completed_task()
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_NOT_AVAILABLE

    # --- 8. 500: 未知状态 ---

    def test_500_unknown_status(self, client):
        """未知状态的任务返回 500 REPAIR_PLAN_INTERNAL_ERROR。"""
        task_id = _create_completed_task()
        _set_task_status(task_id, "unknown_status")
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_INTERNAL_ERROR

    # --- 9. 500: repair_json 损坏 ---

    def test_500_corrupted_repair_json(self, client):
        """已完成任务的 repair_json 损坏时返回 500 REPAIR_PLAN_INTERNAL_ERROR。"""
        task_id = _create_completed_task()
        _insert_corrupted_repair_json(task_id, corrupt_field=None)
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_INTERNAL_ERROR

    # --- 10. 500: 身份字段不匹配 ---

    def test_500_identity_mismatch(self, client):
        """已完成任务的 repair_json 中 schema_version 错误时返回 500。"""
        task_id = _create_completed_task()
        _insert_corrupted_repair_json(
            task_id, corrupt_field="schema_version", corrupt_value=999
        )
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_INTERNAL_ERROR

    # --- 11. 轮询端点：已完成任务有修复计划 ---

    def test_polling_returns_repair_fields(self, client):
        """GET /api/check/{task_id} 对有修复计划的已完成任务返回
        repair_plan_available=true 和 repair_plan_url。"""
        task_id = _create_completed_task()
        _insert_repair_plan(task_id)
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["repair_plan_available"] is True
        assert data["repair_plan_url"] == f"/api/check/{task_id}/repair-plan"

    # --- 12. 轮询端点：pending 任务 ---

    def test_polling_no_repair_fields_for_pending(self, client):
        """GET /api/check/{task_id} 对 pending 任务不返回
        repair_plan_available=true。"""
        task_id = _create_pending_task()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"
        # pending 任务的 to_response() 不包含 repair_plan_available 字段，
        # Pydantic 模型默认为 None
        assert data.get("repair_plan_available") is not True

    # --- 13. 轮询端点：failed 任务 ---

    def test_polling_no_repair_for_failed(self, client):
        """GET /api/check/{task_id} 对 failed 任务不返回
        repair_plan_available=true。"""
        task_id = _create_failed_task()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data.get("repair_plan_available") is not True

    # --- 14. 轮询端点：已完成任务无修复计划 ---

    def test_polling_no_repair_for_completed_without_plan(self, client):
        """GET /api/check/{task_id} 对无修复计划的已完成任务返回
        repair_plan_available=false。"""
        task_id = _create_completed_task()
        response = client.get(f"/api/check/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["repair_plan_available"] is False
        assert data["repair_plan_url"] is None

    # --- 15. failed 任务不读取 repair_results ---

    def test_failed_does_not_read_repair_results(self, client):
        """即使 repair_results 中有残留记录，failed 任务也返回安全空计划。

        场景：generate_and_save_repair_plan 成功持久化了修复计划，
        但后续 mark_completed 抛出异常导致任务标记为 failed。
        API 的 failed 分支必须在读取 repair_results 之前返回，
        不应泄露残留的修复计划数据。
        """
        task_id = _create_failed_task()
        # 插入一条残留的修复计划（plan_status=complete, total_repair_groups=1）
        inserted_plan = _insert_repair_plan(task_id, plan_status="complete")

        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 200
        data = response.json()

        # 应返回安全空计划，而非残留数据
        assert data["plan_status"] == "partial"
        assert data["summary"]["total_repair_groups"] == 0
        assert data["summary"]["blocking_repair_groups"] == 0

        # 确认不是残留计划的值
        assert data["plan_status"] != inserted_plan["plan_status"]
        assert (
            data["summary"]["total_repair_groups"]
            != inserted_plan["summary"]["total_repair_groups"]
        )

    # --- 16. 安全空修复计划结构验证 ---

    def test_safe_empty_plan_structure(self, client):
        """验证安全空修复计划的所有字段匹配预期结构。"""
        task_id = _create_failed_task()
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 200
        data = response.json()

        # 身份字段
        assert data["schema_version"] == REPAIR_SCHEMA_VERSION
        assert data["policy_version"] == POLICY_VERSION
        assert data["repair_scope"] == REPAIR_SCOPE
        assert data["task_id"] == task_id

        # plan_status 必须为 partial（failed 任务不可能有完整计划）
        assert data["plan_status"] == "partial"

        # summary 所有值为 0 或 False
        summary = data["summary"]
        assert summary["total_repair_groups"] == 0
        assert summary["blocking_repair_groups"] == 0
        assert summary["manual_review_required"] is False
        assert summary["coverage_warning"] is False
        assert summary["groups_truncated"] is False

        # 所有列表为空
        assert data["repair_groups"] == []
        assert data["verification_steps"] == []

        # agent_prompt 为空字符串
        assert data["agent_prompt"] == ""

        # 源版本链字段为 None
        assert data["source_scan_updated_at"] is None
        assert data["source_assessment_updated_at"] is None
        assert data["source_assessment_policy_version"] is None

        # 时间戳为 None
        assert data["created_at"] is None
        assert data["updated_at"] is None
