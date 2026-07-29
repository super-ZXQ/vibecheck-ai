"""P0-7 修复计划持久化层测试。

覆盖 app/services/repair_service.py 的数据库操作与序列化边界：
1. 首次保存修复计划，验证在 repair_results 表中创建行
2. Upsert：保存两次，更新已有行
3. created_at 在 upsert 时保持不变
4. updated_at 在 upsert 时刷新为更新值
5. 源版本链（source_scan_updated_at 等）正确保存
6. repair_json 超过 repair_max_json_bytes 时抛出 RepairPlanTooLargeError
7. task_id 或计划字段中的 SQL 注入模式被安全存储（参数化 SQL）
8. save_repair_result 调用 serialize_repair_plan 强制字段白名单
9. repair_groups 中的文件路径被脱敏（绝对路径变为 <redacted-path>）
10. 数据库失败时抛出 RepairPlanPersistError
11. get_repair_result 返回正确的计划
12. get_repair_result 在无计划时返回 None
13. get_repair_result 在 JSON 损坏时抛出 RepairPlanInternalError
14. get_repair_result 在身份字段不匹配时抛出 RepairPlanInternalError
15. get_repair_plan_available 在计划存在时返回 True
16. get_repair_plan_available 在无计划时返回 False
17. 序列化边界拒绝非 dict 修复计划
18. 序列化边界拒绝无效 plan_status
19. 序列化边界拒绝非 list 的 repair_groups
20. 序列化边界通过 mask_untrusted_text 脱敏字符串字段
"""

import json
import time

import pytest

from app.db import database
from app.db.database import _get_connection, init_db, reset_db, now_iso
from app.services.repair_policy import POLICY_VERSION, REPAIR_SCHEMA_VERSION, REPAIR_SCOPE
from app.services.repair_service import (
    save_repair_result, get_repair_result, get_repair_plan_available,
    serialize_repair_plan, generate_repair_plan,
    RepairPlanInternalError, RepairPlanPersistError, RepairPlanTooLargeError,
    RepairPlanSerializationError,
)
from app.services.task_manager import create_task, mark_completed


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


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_repair_plan(task_id="test-task", plan_status="complete"):
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": plan_status,
        "summary": {"total_repair_groups": 1, "blocking_repair_groups": 1,
                     "manual_review_required": False, "coverage_warning": False,
                     "groups_truncated": False},
        "repair_groups": [{"group_id": "RG001", "action_code": "REVOKE_OR_ROTATE_SECRET",
                           "priority": 1, "blocking": True, "highest_severity": "critical",
                           "highest_confidence": "high", "title": "Test", "description": "Test",
                           "related_rule_ids": ["R001"], "related_files": ["config.py"],
                           "total_related_files": 1, "returned_related_files": 1,
                           "related_files_truncated": False, "finding_count": 1,
                           "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                           "verification_steps": ["verify1"]}],
        "verification_steps": ["step1"],
        "agent_prompt": "test prompt",
        "source_scan_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_policy_version": "p0-6-v1",
        "created_at": None, "updated_at": None,
    }


def _read_db_row(task_id):
    conn = _get_connection()
    try:
        return conn.execute(
            "SELECT * FROM repair_results WHERE task_id = ?", (task_id,)
        ).fetchone()
    finally:
        conn.close()


def _make_task(repo_url="https://github.com/test/repo"):
    """Create a task (required for the repair_results FK constraint) and
    mark it completed to simulate the realistic pre-repair state.

    Returns the generated task id.
    """
    task = create_task(repo_url, "test", "repo")
    mark_completed(task.id, file_count=10, total_size=1024, top_level_dir="test-repo")
    return task.id


def _save_minimal_plan(task_id, plan=None,
                       source_scan_updated_at="2026-01-01T00:00:00Z",
                       source_assessment_updated_at="2026-01-01T00:00:00Z",
                       source_assessment_policy_version="p0-6-v1"):
    """Persist a minimal valid repair plan for the given task_id."""
    plan = plan if plan is not None else _make_repair_plan(task_id=task_id)
    return save_repair_result(
        task_id=task_id,
        repair_plan=plan,
        source_scan_updated_at=source_scan_updated_at,
        source_assessment_updated_at=source_assessment_updated_at,
        source_assessment_policy_version=source_assessment_policy_version,
    )


def _insert_raw_repair_row(task_id, repair_json_str, plan_status="complete"):
    """Insert a raw row into repair_results bypassing serialize_repair_plan.

    Used to plant corrupted JSON or mismatched identity fields for negative
    read-path tests.
    """
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
             repair_json_str, plan_status, 1, 1,
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "p0-6-v1",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    finally:
        conn.close()


def _create_task_raw(task_id):
    """Insert a task with a caller-supplied id (for SQL-injection task_id)."""
    ts = "2026-01-01T00:00:00Z"
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO tasks
               (id, repo_url, owner, repo_name, status, stage, progress,
                error_code, error_message, file_count, total_size, top_level_dir,
                created_at, updated_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL)""",
            (task_id, "https://github.com/test/repo", "test", "repo",
             "completed", "finished", 100, ts, ts),
        )
        conn.commit()
    finally:
        conn.close()


# ============================================================
# 测试类：TestRepairPersistence
# ============================================================

class TestRepairPersistence:
    """P0-7 修复计划持久化层测试。"""

    # --- 1. Insert ---
    def test_save_creates_row(self, test_db):
        """save_repair_result 应在 repair_results 表中创建一行。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)

        row = _read_db_row(task_id)
        assert row is not None
        assert row["task_id"] == task_id
        assert row["schema_version"] == REPAIR_SCHEMA_VERSION
        assert row["policy_version"] == POLICY_VERSION
        assert row["repair_scope"] == REPAIR_SCOPE
        assert row["plan_status"] == "complete"
        assert row["total_repair_groups"] == 1
        assert row["blocking_repair_groups"] == 1
        assert row["created_at"] is not None
        assert row["updated_at"] is not None
        assert row["repair_json"] is not None

    # --- 2. Upsert ---
    def test_upsert_updates_existing_row(self, test_db):
        """调用 save_repair_result 两次应更新已有行，而非创建第二行。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)
        _save_minimal_plan(task_id)

        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM repair_results WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        finally:
            conn.close()
        assert row["cnt"] == 1

    # --- 3. created_at preserved ---
    def test_created_at_preserved_on_upsert(self, test_db):
        """第一次保存设置 created_at，第二次保存应保持不变。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)
        created_at_1 = _read_db_row(task_id)["created_at"]

        time.sleep(0.02)
        _save_minimal_plan(task_id)
        created_at_2 = _read_db_row(task_id)["created_at"]

        assert created_at_2 == created_at_1

    # --- 4. updated_at refreshed ---
    def test_updated_at_refreshed_on_upsert(self, test_db):
        """第二次保存应将 updated_at 刷新为更新值。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)
        updated_at_1 = _read_db_row(task_id)["updated_at"]

        time.sleep(0.02)
        _save_minimal_plan(task_id)
        updated_at_2 = _read_db_row(task_id)["updated_at"]

        assert updated_at_2 != updated_at_1

    # --- 5. Source version chain saved ---
    def test_source_version_chain_saved(self, test_db):
        """source_scan_updated_at / source_assessment_updated_at /
        source_assessment_policy_version 应正确存入列与 JSON。"""
        task_id = _make_task()
        scan_ts = "2026-02-03T04:05:06Z"
        assess_ts = "2026-02-03T05:06:07Z"
        assess_pv = "p0-6-v1"
        plan = _make_repair_plan(task_id=task_id)
        plan["source_scan_updated_at"] = scan_ts
        plan["source_assessment_updated_at"] = assess_ts
        plan["source_assessment_policy_version"] = assess_pv

        _save_minimal_plan(
            task_id, plan=plan,
            source_scan_updated_at=scan_ts,
            source_assessment_updated_at=assess_ts,
            source_assessment_policy_version=assess_pv,
        )

        row = _read_db_row(task_id)
        assert row["source_scan_updated_at"] == scan_ts
        assert row["source_assessment_updated_at"] == assess_ts
        assert row["source_assessment_policy_version"] == assess_pv

        retrieved = get_repair_result(task_id)
        assert retrieved["source_scan_updated_at"] == scan_ts
        assert retrieved["source_assessment_updated_at"] == assess_ts
        assert retrieved["source_assessment_policy_version"] == assess_pv

    # --- 6. JSON size limit ---
    def test_json_size_limit_raises_too_large(self, test_db, monkeypatch):
        """repair_json 超过 repair_max_json_bytes 时应抛出 RepairPlanTooLargeError。"""
        task_id = _make_task()
        monkeypatch.setattr("app.core.config.settings.repair_max_json_bytes", 100)

        with pytest.raises(RepairPlanTooLargeError):
            _save_minimal_plan(task_id)

        # 行不应被写入（超限在 INSERT 之前抛出）
        assert _read_db_row(task_id) is None

    # --- 7. SQL injection safety ---
    def test_sql_injection_safety(self, test_db):
        """task_id 或计划字段中的 SQL 注入模式应被安全存储（参数化 SQL）。"""
        malicious = "'; DROP TABLE repair_results;--"

        # Part A: 恶意字符串存入 source_* 列与计划字符串字段。
        # 注意：列值来自 save_repair_result 参数，JSON 值来自 plan dict，
        # 两者都设为 malicious 以确保一致。
        task_id = _make_task()
        plan = _make_repair_plan(task_id=task_id)
        plan["repair_groups"][0]["title"] = malicious
        plan["repair_groups"][0]["description"] = malicious
        plan["source_scan_updated_at"] = malicious
        plan["source_assessment_updated_at"] = malicious
        plan["source_assessment_policy_version"] = malicious
        _save_minimal_plan(
            task_id, plan=plan,
            source_scan_updated_at=malicious,
            source_assessment_updated_at=malicious,
            source_assessment_policy_version=malicious,
        )

        # 表仍然存在，值被正确存储
        row = _read_db_row(task_id)
        assert row is not None
        assert row["source_scan_updated_at"] == malicious
        assert row["source_assessment_policy_version"] == malicious

        retrieved = get_repair_result(task_id)
        assert retrieved["source_scan_updated_at"] == malicious
        assert retrieved["repair_groups"][0]["title"] == malicious

        # Part B: 恶意 task_id 本身
        _create_task_raw(malicious)
        plan2 = _make_repair_plan(task_id=malicious)
        _save_minimal_plan(malicious, plan=plan2)
        row2 = _read_db_row(malicious)
        assert row2 is not None
        assert row2["task_id"] == malicious

        # 两张表均可查询（未被 DROP）
        conn = _get_connection()
        try:
            rr = conn.execute(
                "SELECT COUNT(*) as c FROM repair_results"
            ).fetchone()
            tk = conn.execute("SELECT COUNT(*) as c FROM tasks").fetchone()
        finally:
            conn.close()
        assert rr["c"] >= 2
        assert tk["c"] >= 2

    # --- 8. Explicit serialization (field whitelist) ---
    def test_explicit_serialization_whitelist(self, test_db):
        """save_repair_result 调用 serialize_repair_plan 强制字段白名单
        与身份常量，额外字段不应进入 repair_json。"""
        task_id = _make_task()
        plan = _make_repair_plan(task_id=task_id)
        plan["extra_secret_field"] = "should-not-persist"
        plan["schema_version"] = 999          # 应被常量覆盖
        plan["policy_version"] = "wrong"      # 应被常量覆盖
        plan["repair_scope"] = "wrong-scope"  # 应被常量覆盖

        _save_minimal_plan(task_id, plan=plan)

        retrieved = get_repair_result(task_id)
        assert "extra_secret_field" not in retrieved
        assert retrieved["schema_version"] == REPAIR_SCHEMA_VERSION
        assert retrieved["policy_version"] == POLICY_VERSION
        assert retrieved["repair_scope"] == REPAIR_SCOPE
        assert retrieved["task_id"] == task_id

        # repair_json 文本中也不应出现额外字段
        row = _read_db_row(task_id)
        assert "extra_secret_field" not in row["repair_json"]

    # --- 9. Path desensitization ---
    def test_path_desensitization(self, test_db):
        """repair_groups 中的绝对路径应被脱敏为 <redacted-path>，
        相对路径保持不变。"""
        task_id = _make_task()
        plan = _make_repair_plan(task_id=task_id)
        plan["repair_groups"][0]["related_files"] = [
            "/etc/secrets/config.py",       # POSIX 绝对路径
            "C:\\Users\\admin\\keys.txt",   # Windows 盘符路径
            "\\\\server\\share\\secret.env",# UNC 路径
            "~/config/.env",                # 用户主目录路径
            "src/relative/path.py",          # 相对路径（应保留）
            "../escape/attempt.py",         # 路径穿越（应脱敏）
        ]

        _save_minimal_plan(task_id, plan=plan)

        retrieved = get_repair_result(task_id)
        files = retrieved["repair_groups"][0]["related_files"]
        assert files[0] == "<redacted-path>"
        assert files[1] == "<redacted-path>"
        assert files[2] == "<redacted-path>"
        assert files[3] == "<redacted-path>"
        assert files[4] == "src/relative/path.py"
        assert files[5] == "<redacted-path>"

    # --- 10. DB error classification ---
    def test_db_error_raises_persist_error(self, test_db, monkeypatch):
        """数据库失败时应抛出 RepairPlanPersistError。"""

        def _raise_db_error(*_args, **_kwargs):
            raise RuntimeError("Simulated database failure")

        monkeypatch.setattr(
            "app.services.repair_service._get_connection", _raise_db_error
        )
        task_id = _make_task()

        with pytest.raises(RepairPlanPersistError):
            _save_minimal_plan(task_id)

    # --- 11. get_repair_result returns the correct plan ---
    def test_get_repair_result_returns_plan(self, test_db):
        """get_repair_result 应返回已持久化的正确计划。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)

        retrieved = get_repair_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id
        assert retrieved["schema_version"] == REPAIR_SCHEMA_VERSION
        assert retrieved["policy_version"] == POLICY_VERSION
        assert retrieved["repair_scope"] == REPAIR_SCOPE
        assert retrieved["plan_status"] == "complete"
        assert isinstance(retrieved["repair_groups"], list)
        assert len(retrieved["repair_groups"]) == 1
        assert retrieved["repair_groups"][0]["group_id"] == "RG001"
        assert retrieved["created_at"] is not None
        assert retrieved["updated_at"] is not None

    # --- 12. get_repair_result returns None when absent ---
    def test_get_repair_result_returns_none_when_absent(self, test_db):
        """get_repair_result 在无计划时应返回 None。"""
        task_id = _make_task()
        assert get_repair_result(task_id) is None

    # --- 13. get_repair_result raises on corrupted JSON ---
    def test_get_repair_result_raises_on_corrupted_json(self, test_db):
        """get_repair_result 在 JSON 损坏时应抛出 RepairPlanInternalError。"""
        task_id = _make_task()
        _insert_raw_repair_row(task_id, "{this is not valid json")

        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    # --- 14. get_repair_result raises on identity mismatch ---
    @pytest.mark.parametrize("field,value", [
        ("schema_version", 999),
        ("policy_version", "wrong-version"),
        ("repair_scope", "wrong-scope"),
        ("task_id", "mismatched-task-id"),
    ])
    def test_get_repair_result_raises_on_identity_mismatch(
        self, test_db, field, value
    ):
        """get_repair_result 在身份字段（schema_version / policy_version /
        repair_scope / task_id）不匹配时应抛出 RepairPlanInternalError。"""
        task_id = _make_task()
        plan = _make_repair_plan(task_id=task_id)
        safe = serialize_repair_plan(
            task_id, plan, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"
        )
        safe[field] = value
        _insert_raw_repair_row(task_id, json.dumps(safe, ensure_ascii=False))

        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    # --- 15. get_repair_plan_available returns True ---
    def test_get_repair_plan_available_true(self, test_db):
        """get_repair_plan_available 在计划存在时应返回 True。"""
        task_id = _make_task()
        _save_minimal_plan(task_id)
        assert get_repair_plan_available(task_id) is True

    # --- 16. get_repair_plan_available returns False ---
    def test_get_repair_plan_available_false(self, test_db):
        """get_repair_plan_available 在无计划时应返回 False。"""
        task_id = _make_task()
        assert get_repair_plan_available(task_id) is False

    # --- 17. Serialize boundary rejects non-dict repair plan ---
    def test_serialize_rejects_non_dict(self):
        """serialize_repair_plan 应拒绝非 dict 的修复计划。"""
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", "not-a-dict", None, "2026-01-01T00:00:00Z"
            )

        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", ["list", "not", "dict"], None, "2026-01-01T00:00:00Z"
            )

        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", None, None, "2026-01-01T00:00:00Z"
            )

    # --- 18. Serialize boundary rejects invalid plan_status ---
    def test_serialize_rejects_invalid_plan_status(self):
        """serialize_repair_plan 应拒绝无效的 plan_status。"""
        plan = _make_repair_plan(task_id="task-1")
        plan["plan_status"] = "invalid"
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", plan, None, "2026-01-01T00:00:00Z"
            )

        plan2 = _make_repair_plan(task_id="task-1")
        plan2["plan_status"] = 123  # 非 str
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", plan2, None, "2026-01-01T00:00:00Z"
            )

    # --- 19. Serialize boundary rejects non-list repair_groups ---
    def test_serialize_rejects_non_list_repair_groups(self):
        """serialize_repair_plan 应拒绝非 list 的 repair_groups。"""
        plan = _make_repair_plan(task_id="task-1")
        plan["repair_groups"] = "not-a-list"
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", plan, None, "2026-01-01T00:00:00Z"
            )

        plan2 = _make_repair_plan(task_id="task-1")
        plan2["repair_groups"] = {"not": "a-list"}
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", plan2, None, "2026-01-01T00:00:00Z"
            )

        # 非列表的 verification_steps 也应被拒绝
        plan3 = _make_repair_plan(task_id="task-1")
        plan3["verification_steps"] = "not-a-list"
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                "task-1", plan3, None, "2026-01-01T00:00:00Z"
            )

    # --- 20. Serialize boundary masks string fields via mask_untrusted_text ---
    def test_serialize_masks_string_fields(self):
        """serialize_repair_plan 应通过 mask_untrusted_text 脱敏字符串字段中的
        显式格式密钥（ghp_ / AKIA / 连接字符串密码）。"""
        token = "ghp_" + "a" * 36
        aws_key = "AKIA" + "ABCDEFGH1234567" + "0"
        conn_str = "postgres://user:sup3rS3cr3tPass@db.example.com:5432/mydb"

        plan = _make_repair_plan(task_id="task-1")
        plan["repair_groups"][0]["title"] = token
        plan["repair_groups"][0]["description"] = (
            f"Found {token} and {aws_key} in {conn_str}"
        )
        plan["repair_groups"][0]["related_files"] = [
            f"src/{token}/config.py"
        ]
        plan["agent_prompt"] = f"secret is {token} here"

        safe = serialize_repair_plan(
            "task-1", plan, None, "2026-01-01T00:00:00Z"
        )
        serialized = json.dumps(safe, ensure_ascii=False)

        # 原始密钥值不应出现在序列化结果中
        assert token not in serialized
        assert aws_key not in serialized
        assert "sup3rS3cr3tPass" not in serialized

        # 显式格式 token 被脱敏为 first4...last4 形式
        assert safe["repair_groups"][0]["title"] == "ghp_...aaaa"

        # 连接字符串密码被替换为 ***
        assert ":***@" in safe["repair_groups"][0]["description"]

        # agent_prompt 中的 token 也被脱敏
        assert token not in safe["agent_prompt"]
        assert "ghp_...aaaa" in safe["agent_prompt"]
