"""P0-6 安全评估结果持久化测试。

覆盖 assessment_service.py 的数据库操作：
1. 首次保存评估结果，验证可读回
2. Upsert：保存两次，验证 created_at 不变、updated_at 变化
3. policy_version 正确保存（应为 "p0-6-v1"）
4. source_scan_updated_at 正确保存（匹配 scan_results.updated_at）
5. assessment_json 字节限制：monkeypatch 为 100，验证抛出 AssessmentResultTooLargeError
6. SQL 注入文本在 finding 字段中不会破坏持久化
7. assessment_json 中无原始密钥（检查 ghp_、AKIA 模式）
8. get_assessment_score_verdict 返回 (score, verdict) 元组
9. get_assessment_score_verdict 对不存在的任务返回 None
10. get_assessment_result 对不存在的任务返回 None
11. run_assessment 从 SQLite 读取（非临时目录），计算并持久化
12. run_assessment 在无扫描结果时抛出 AssessmentInternalError
13. 完整往返：创建任务 → 保存扫描 → run_assessment → get_assessment_result
"""

import json
import time

import pytest

from app.db import database
from app.db.database import _get_connection
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanResult,
    Severity,
)
from app.services import task_manager
from app.services.assessment_service import (
    AssessmentInternalError,
    AssessmentResultTooLargeError,
    assess_scan_result,
    get_assessment_result,
    get_assessment_score_verdict,
    get_scan_result_with_timestamp,
    run_assessment,
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
def test_db(tmp_path, monkeypatch):
    """设置临时测试数据库。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    database._initialized = False
    database.init_db()
    yield db_path
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


def _setup_task_with_scan_result(task_id="test-task-1", findings=None):
    """创建一个任务，保存扫描结果，返回 task_id。

    注意：task_id 参数仅用于文档说明，实际 task_id 由 create_task 生成。
    """
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    # 使用创建的任务的 ID
    scan_result = ScanResult(
        findings=tuple(findings or []),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )
    save_scan_result(task.id, scan_result)
    return task.id


def _read_assessment_row_columns(task_id):
    """直接从数据库读取 assessment_results 行的列值。"""
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT created_at, updated_at, policy_version, source_scan_updated_at, "
            "assessment_json, score, verdict "
            "FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return row
    finally:
        conn.close()


# ============================================================
# 测试类：TestAssessmentPersistence
# ============================================================

class TestAssessmentPersistence:
    """安全评估结果持久化测试。"""

    def test_first_save_and_read_back(self, test_db):
        """首次保存评估结果，验证可以通过 get_assessment_result 读回。"""
        task_id = _setup_task_with_scan_result()
        scan_data = get_scan_result_with_timestamp(task_id)
        assert scan_data is not None
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        # 读回验证
        retrieved = get_assessment_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id
        assert retrieved["schema_version"] == 1
        assert retrieved["policy_version"] == "p0-6-v1"
        assert "score" in retrieved
        assert "verdict" in retrieved
        assert "score_breakdown" in retrieved
        assert "score_caps" in retrieved
        assert "blocking_reasons" in retrieved
        assert "coverage" in retrieved

    def test_upsert_preserves_created_at_updates_updated_at(self, test_db):
        """保存两次，验证 created_at 不变，updated_at 变化。"""
        task_id = _setup_task_with_scan_result()
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data

        # 第一次保存
        assessment1 = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment1, scan_updated)
        row1 = _read_assessment_row_columns(task_id)
        assert row1 is not None
        created_at_1 = row1["created_at"]
        updated_at_1 = row1["updated_at"]

        # 等待一小段时间确保时间戳不同
        time.sleep(0.01)

        # 第二次保存（upsert）
        assessment2 = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment2, scan_updated)
        row2 = _read_assessment_row_columns(task_id)
        assert row2 is not None
        created_at_2 = row2["created_at"]
        updated_at_2 = row2["updated_at"]

        # created_at 应保持不变
        assert created_at_2 == created_at_1
        # updated_at 应已更新
        assert updated_at_2 != updated_at_1

    def test_policy_version_saved_correctly(self, test_db):
        """policy_version 应正确保存为 "p0-6-v1"。"""
        task_id = _setup_task_with_scan_result()
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        row = _read_assessment_row_columns(task_id)
        assert row["policy_version"] == "p0-6-v1"

        # 同时验证 assessment_json 中的 policy_version
        retrieved = get_assessment_result(task_id)
        assert retrieved["policy_version"] == "p0-6-v1"

    def test_source_scan_updated_at_saved_correctly(self, test_db):
        """source_scan_updated_at 应匹配 scan_results.updated_at。"""
        task_id = _setup_task_with_scan_result()

        # 读取 scan_results 的 updated_at
        conn = _get_connection()
        try:
            scan_row = conn.execute(
                "SELECT updated_at FROM scan_results WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        finally:
            conn.close()
        assert scan_row is not None
        scan_updated_at = scan_row["updated_at"]

        # 保存评估
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, _ = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated_at)

        # 验证 assessment_results 的 source_scan_updated_at
        row = _read_assessment_row_columns(task_id)
        assert row["source_scan_updated_at"] == scan_updated_at

    def test_assessment_json_byte_limit(self, test_db, monkeypatch):
        """assessment_json 字节超限时应抛出 AssessmentResultTooLargeError。

        monkeypatch assessment_max_json_bytes 为 100，正常评估结果
        序列化后远超 100 字节。
        """
        task_id = _setup_task_with_scan_result()
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)

        # 设置极小的字节限制
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_json_bytes", 100
        )

        with pytest.raises(AssessmentResultTooLargeError):
            save_assessment_result(task_id, assessment, scan_updated)

    def test_sql_injection_text_in_finding_fields(self, test_db):
        """SQL 注入文本在 finding 字段中不会破坏持久化。

        所有 SQL 操作使用参数化查询，应能安全处理恶意文本。
        """
        malicious_text = "'; DROP TABLE assessment_results; --"
        finding = _make_finding(
            file_path=malicious_text,
            description=malicious_text,
            message=malicious_text,
        )
        task_id = _setup_task_with_scan_result(findings=[finding])

        # 运行评估并保存
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        # 表应仍然存在且可读
        retrieved = get_assessment_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id

        # 直接验证表仍然存在
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM assessment_results"
            ).fetchone()
            assert row["cnt"] >= 1
        finally:
            conn.close()

    def test_no_raw_secrets_in_assessment_json(self, test_db):
        """assessment_json 中不应包含原始密钥模式（ghp_、AKIA）。"""
        finding = _make_finding(
            snippet_masked="ghp_****",
            description="Found a GitHub token",
        )
        task_id = _setup_task_with_scan_result(findings=[finding])

        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        retrieved = get_assessment_result(task_id)
        json_str = json.dumps(retrieved, ensure_ascii=False)

        # 不应包含合成密钥
        assert SYNTHETIC_GITHUB_TOKEN not in json_str
        assert SYNTHETIC_AWS_KEY not in json_str

        # 不应包含原始密钥前缀+长字符串模式
        # ghp_ 后跟 36 个字母数字字符 = 原始 GitHub token
        import re
        raw_token_pattern = re.compile(r"ghp_[A-Za-z0-9]{36}")
        raw_aws_pattern = re.compile(r"AKIA[A-Z0-9]{16}")
        assert not raw_token_pattern.search(json_str)
        assert not raw_aws_pattern.search(json_str)

    def test_get_assessment_score_verdict_returns_tuple(self, test_db):
        """get_assessment_score_verdict 应返回 (score, verdict) 元组。"""
        task_id = _setup_task_with_scan_result()
        scan_data = get_scan_result_with_timestamp(task_id)
        scan_dict, scan_updated = scan_data
        assessment = assess_scan_result(task_id, scan_dict)
        save_assessment_result(task_id, assessment, scan_updated)

        result = get_assessment_score_verdict(task_id)
        assert result is not None
        assert isinstance(result, tuple)
        assert len(result) == 2
        score, verdict = result
        assert isinstance(score, int)
        assert isinstance(verdict, str)
        assert verdict in ("pass", "warning", "blocked")

    def test_get_assessment_score_verdict_returns_none_for_nonexistent(self, test_db):
        """get_assessment_score_verdict 对不存在的任务应返回 None。"""
        result = get_assessment_score_verdict("nonexistent-task-id")
        assert result is None

    def test_get_assessment_result_returns_none_for_nonexistent(self, test_db):
        """get_assessment_result 对不存在的任务应返回 None。"""
        result = get_assessment_result("nonexistent-task-id")
        assert result is None

    def test_run_assessment_reads_from_sqlite_and_persists(self, test_db):
        """run_assessment 应从 SQLite 读取扫描结果，计算评估并持久化。

        验证 run_assessment 完成后：
        - 评估结果已持久化到 assessment_results 表
        - 可通过 get_assessment_result 读回
        - 可通过 get_assessment_score_verdict 读回轻量级字段
        """
        task_id = _setup_task_with_scan_result()

        # 运行评估编排器
        assessment = run_assessment(task_id)
        assert assessment is not None
        assert assessment["task_id"] == task_id

        # 验证已持久化
        retrieved = get_assessment_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id

        # 验证轻量级读取
        score_verdict = get_assessment_score_verdict(task_id)
        assert score_verdict is not None
        assert score_verdict[0] == assessment["score"]
        assert score_verdict[1] == assessment["verdict"]

    def test_run_assessment_raises_internal_error_without_scan_result(self, test_db):
        """run_assessment 在无扫描结果时应抛出 AssessmentInternalError。"""
        # 创建任务但不保存扫描结果
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )

        with pytest.raises(AssessmentInternalError):
            run_assessment(task.id)

    def test_full_round_trip(self, test_db):
        """完整往返测试：创建任务 → 保存扫描 → run_assessment → get_assessment_result。

        验证整个评估流程的端到端正确性。
        """
        # 1. 创建任务并保存扫描结果（含一个阻断级发现项）
        finding = _make_finding(
            rule_id="R001_GITHUB_TOKEN",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            is_blocking=True,
        )
        task_id = _setup_task_with_scan_result(findings=[finding])

        # 2. 运行评估
        assessment = run_assessment(task_id)
        assert assessment is not None
        assert assessment["task_id"] == task_id
        assert assessment["policy_version"] == "p0-6-v1"
        assert assessment["schema_version"] == 1

        # 阻断级发现项应导致 blocked 判定
        assert assessment["verdict"] == "blocked"
        assert assessment["score"] <= 49

        # 3. 从数据库读回
        retrieved = get_assessment_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id
        assert retrieved["score"] == assessment["score"]
        assert retrieved["verdict"] == assessment["verdict"]
        assert retrieved["score_breakdown"] == assessment["score_breakdown"]
        assert retrieved["blocking_reasons"] == assessment["blocking_reasons"]

        # 4. 验证轻量级读取一致
        score, verdict = get_assessment_score_verdict(task_id)
        assert score == assessment["score"]
        assert verdict == assessment["verdict"]
