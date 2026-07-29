"""P0-6 对抗性不变量测试。

覆盖以下对抗性场景：

1. Finding 确定性全排序：
   - 两个 Finding 在基础排序键相同时，description/column_start/column_end
     不同，[A,B] 和 [B,A] 产生完全一致的 AssessmentResult。
   - 同 rule_id 且 category 不一致时，输出仍然确定。
   - blocking_reasons 截断后的子集和顺序仍然确定。

2. 防御性脱敏：
   - 合成 Token 放入 score_breakdown.description/rule_id、score_caps.description、
     blocking_reasons.description/file_path、coverage.reasons、未知嵌套字段。
   - save_assessment_result 后，serialize_assessment_result 返回值、json.dumps、
     SQLite assessment_json、API 响应、repr 全部不含完整 Token。
   - assessment["task_id"] = "wrong-task" → 持久化主键和 JSON task_id
     均为真实 task_id，wrong-task 不进入持久化结果。

3. 时间戳一致性：
   - 首次保存后 JSON 时间与数据库列一致。
   - 第二次 upsert 后 JSON created_at 不变、数据库 created_at 不变。
   - JSON updated_at 和数据库 updated_at 同步更新。
   - API 返回时间与数据库一致。

4. Policy 不可变性：
   - 尝试修改 critical 扣分应抛出 TypeError。
   - 尝试修改 blocking cap 应抛出 FrozenInstanceError。
   - 失败修改后评分结果不变。
   - policy_version 不变。

5. 结果上限运行时防御：
   - runtime 0 → 最多保留 1 条，不绕过限制。
   - runtime -1 → 不得出现 blocking[:-1]。
   - runtime 合法正数 → 正常工作。
   - 大量 blocking Finding → 截断正确。

IMPORTANT: All test strings are SYNTHETIC — format-correct but NOT real
credentials. No actual permissions or validity.
"""

import copy
import json
import time
from dataclasses import FrozenInstanceError
from types import MappingProxyType
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import database
from app.db.database import _get_connection
from app.services import task_manager
from app.services.assessment_policy import (
    POLICY_VERSION,
    SEVERITY_BASE_POINTS,
    CONFIDENCE_PERCENT,
    RULE_CAP_BY_SEVERITY,
    CAP_BLOCKING,
    ScoreCap,
)
from app.services.assessment_service import (
    assess_scan_result,
    save_assessment_result,
    serialize_assessment_result,
    get_assessment_result,
    run_assessment,
    AssessmentResultTooLargeError,
)
from app.services.scan_result_service import save_scan_result
from app.scanner.base import (
    Finding, ScanResult, Severity, Confidence, FindingType,
)
from tests.conftest import (
    SYNTHETIC_GITHUB_TOKEN,
    SYNTHETIC_AWS_KEY,
)


# ---------------------------------------------------------------------------
# --- Synthetic test constants ---
# ---------------------------------------------------------------------------

# Runtime-constructed mixed-character values to avoid low-entropy patterns.
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTH_TOKEN_GHP = "ghp_" + _MIXED[:36]
SYNTH_TOKEN_AKIA = "AKIA" + _MIXED_UPPER[:16]
SYNTH_TOKEN_AIZA = "AIza" + _MIXED[:35]


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

def _make_finding_dict(**kwargs):
    """创建一个发现项字典（持久化格式）。"""
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
    """创建一个扫描结果字典。"""
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


def _strip_nondeterministic(result: dict) -> dict:
    """Remove task_id, created_at, updated_at for comparison."""
    stripped = copy.deepcopy(result)
    stripped.pop("task_id", None)
    stripped.pop("created_at", None)
    stripped.pop("updated_at", None)
    return stripped


def _read_db_row(task_id):
    """Read assessment_results row columns directly from DB."""
    conn = _get_connection()
    try:
        return conn.execute(
            "SELECT created_at, updated_at, assessment_json, score, verdict "
            "FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        conn.close()


# ============================================================
# 1. Finding 确定性全排序对抗测试
# ============================================================

class TestDeterministicFullOrdering:
    """Finding 确定性全排序对抗测试。

    构造两个 Finding，其基础排序键完全相同（is_blocking, severity,
    confidence, file_path, line_start, rule_id），但 description、
    column_start、column_end 不同。验证 [A,B] 和 [B,A] 产生完全一致的
    AssessmentResult（除 task_id 和时间戳外）。
    """

    def test_adversarial_pair_ab_vs_ba_identical(self):
        """[A, B] 和 [B, A] 产生完全一致的 AssessmentResult。

        两个 Finding 在基础排序键上完全相同，但 description、column_start、
        column_end 不同。全排序键必须区分它们并产生确定性顺序。
        """
        finding_a = _make_finding_dict(
            rule_id="R_SAME_KEY",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="same/file.py",
            line_start=42,
            line_end=42,
            column_start=1,
            column_end=10,
            description="Finding A description",
            rule_name="Same Rule",
            category="token",
            finding_type="content",
            secret_type="github_token",
            message="Message A",
            repair_template_key="remove_secret",
            snippet_masked="ghp_****",
        )
        finding_b = _make_finding_dict(
            rule_id="R_SAME_KEY",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="same/file.py",
            line_start=42,
            line_end=42,
            column_start=20,
            column_end=30,
            description="Finding B description",
            rule_name="Same Rule",
            category="token",
            finding_type="content",
            secret_type="github_token",
            message="Message B",
            repair_template_key="remove_secret",
            snippet_masked="ghp_****",
        )

        scan_ab = _make_scan_result([finding_a, finding_b])
        scan_ba = _make_scan_result([finding_b, finding_a])

        result_ab = assess_scan_result("test-task", scan_ab)
        result_ba = assess_scan_result("test-task", scan_ba)

        # 除 task_id 和时间戳外，完整 AssessmentResult 完全一致
        assert _strip_nondeterministic(result_ab) == _strip_nondeterministic(result_ba)

    def test_adversarial_pair_occurrence_deductions_deterministic(self):
        """同一 rule_id 内两个 Finding 的 occurrence_deductions 顺序确定。

        Finding A (column_start=1) 应排在 Finding B (column_start=20) 之前，
        所以 A 获得 100% repeat multiplier，B 获得 75%。
        无论输入顺序如何，结果一致。
        """
        finding_a = _make_finding_dict(
            rule_id="R_DEDUCT",
            severity="critical",
            confidence="high",
            is_blocking=False,
            file_path="same.py",
            line_start=1,
            column_start=1,
            column_end=5,
            description="A",
        )
        finding_b = _make_finding_dict(
            rule_id="R_DEDUCT",
            severity="critical",
            confidence="high",
            is_blocking=False,
            file_path="same.py",
            line_start=1,
            column_start=20,
            column_end=25,
            description="B",
        )

        scan_ab = _make_scan_result([finding_a, finding_b])
        scan_ba = _make_scan_result([finding_b, finding_a])

        result_ab = assess_scan_result("test-task", scan_ab)
        result_ba = assess_scan_result("test-task", scan_ba)

        # occurrence_deductions 应完全一致
        breakdown_ab = result_ab["score_breakdown"][0]
        breakdown_ba = result_ba["score_breakdown"][0]
        assert breakdown_ab["occurrence_deductions"] == breakdown_ba["occurrence_deductions"]

    def test_same_rule_id_inconsistent_category_deterministic(self):
        """同 rule_id 且 category 不一致时，输出仍然确定。

        category 是 rule 级常量，但如果输入中 category 不一致，
        引擎取第一个 finding 的 category。排序后第一个 finding
        是确定的，所以 category 也是确定的。
        """
        finding_a = _make_finding_dict(
            rule_id="R_CAT",
            severity="critical",
            confidence="high",
            is_blocking=False,
            file_path="a.py",
            line_start=1,
            column_start=1,
            description="A",
            category="token",
        )
        finding_b = _make_finding_dict(
            rule_id="R_CAT",
            severity="critical",
            confidence="high",
            is_blocking=False,
            file_path="a.py",
            line_start=1,
            column_start=20,
            description="B",
            category="password",
        )

        scan_ab = _make_scan_result([finding_a, finding_b])
        scan_ba = _make_scan_result([finding_b, finding_a])

        result_ab = assess_scan_result("test-task", scan_ab)
        result_ba = assess_scan_result("test-task", scan_ba)

        assert _strip_nondeterministic(result_ab) == _strip_nondeterministic(result_ba)

    def test_blocking_reasons_truncation_subset_deterministic(self):
        """blocking_reasons 截断后的子集和顺序仍然确定。

        构造大量 blocking Finding（超过 max_blocking_reasons），
        验证不同输入顺序产生相同的截断子集。
        """
        findings = []
        for i in range(20):
            findings.append(_make_finding_dict(
                rule_id=f"R_BLK_{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"file_{i}.py",
                line_start=i + 1,
                description=f"Blocking finding {i}",
            ))

        scan_order_1 = _make_scan_result(copy.deepcopy(findings))

        # 反转顺序
        reversed_findings = list(reversed(findings))
        scan_order_2 = _make_scan_result(copy.deepcopy(reversed_findings))

        result_1 = assess_scan_result("test-task", scan_order_1)
        result_2 = assess_scan_result("test-task", scan_order_2)

        # blocking_reasons 完全一致（包括顺序）
        assert result_1["blocking_reasons"] == result_2["blocking_reasons"]

    def test_completely_identical_findings_order_independent(self):
        """完全相同的 Finding 顺序无关。

        两个完全相同的 Finding（所有字段相同）在任何顺序下
        都应产生相同的结果。
        """
        finding = _make_finding_dict(
            rule_id="R_IDENTICAL",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="same.py",
            line_start=1,
            column_start=1,
            column_end=10,
            description="Identical",
        )
        finding_copy = copy.deepcopy(finding)

        scan_1 = _make_scan_result([finding, copy.deepcopy(finding_copy)])
        scan_2 = _make_scan_result([copy.deepcopy(finding_copy), finding])

        result_1 = assess_scan_result("test-task", scan_1)
        result_2 = assess_scan_result("test-task", scan_2)

        assert _strip_nondeterministic(result_1) == _strip_nondeterministic(result_2)


# ============================================================
# 2. 防御性脱敏对抗测试
# ============================================================

class TestDefensiveDesensitization:
    """防御性脱敏对抗测试。

    使用运行时构造、格式正确但无权限的合成 Token，分别放入各字段，
    验证 save_assessment_result 后所有输出渠道都不含完整 Token。
    """

    def test_token_in_score_breakdown_description(self, test_db):
        """score_breakdown.description 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(Finding(
                rule_id="R_TOKEN_DESC",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description=f"Token: {SYNTH_TOKEN_GHP}",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        # 在 description 中注入 Token（模拟调用方错误）
        for entry in assessment["score_breakdown"]:
            entry["description"] = f"Token: {SYNTH_TOKEN_GHP}"

        save_assessment_result(task.id, assessment, scan_updated)

        # 检查 serialize_assessment_result 返回值
        safe = serialize_assessment_result(task.id, assessment, None, "now")
        safe_json = json.dumps(safe, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in safe_json

        # 检查 DB 中的 assessment_json
        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json

        # 检查 repr
        assert SYNTH_TOKEN_GHP not in repr(retrieved)

    def test_token_in_score_breakdown_rule_id(self, test_db):
        """score_breakdown.rule_id 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(Finding(
                rule_id=SYNTH_TOKEN_GHP,
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
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
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json
        assert SYNTH_TOKEN_AKIA not in retrieved_json

    def test_token_in_score_caps_description(self, test_db):
        """score_caps.description 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        # Set findings_truncated to trigger a score cap
        scan_dict["summary"]["findings_truncated"] = True
        assessment = assess_scan_result(task.id, scan_dict)

        # 在 score_caps description 中注入 Token
        for cap in assessment["score_caps"]:
            cap["description"] = f"Cap: {SYNTH_TOKEN_GHP}"

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json

    def test_token_in_blocking_reasons_description(self, test_db):
        """blocking_reasons.description 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(Finding(
                rule_id="R_BLK_TOKEN",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description=f"Secret: {SYNTH_TOKEN_GHP}",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json

    def test_token_in_blocking_reasons_file_path(self, test_db):
        """blocking_reasons.file_path 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        # file_path 中嵌入 Token
        malicious_path = f"src/{SYNTH_TOKEN_GHP}/config.py"
        scan_result = ScanResult(
            findings=(Finding(
                rule_id="R_PATH_TOKEN",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=malicious_path,
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
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json

    def test_token_in_coverage_reasons(self, test_db):
        """coverage.reasons 中的 Token 被脱敏。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=0, total_lines_scanned=0,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        # 在 coverage.reasons 中注入 Token
        assessment["coverage"]["reasons"].append(
            f"Error: {SYNTH_TOKEN_GHP} leaked"
        )

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in retrieved_json

    def test_unknown_nested_fields_discarded(self, test_db):
        """未知嵌套字段被丢弃，不进入持久化结果。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(Finding(
                rule_id="R_UNKNOWN",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="config.py",
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
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        # 注入未知字段（含 Token）
        assessment["malicious_field"] = SYNTH_TOKEN_GHP
        assessment["score_breakdown"][0]["malicious_nested"] = SYNTH_TOKEN_AKIA
        assessment["coverage"]["malicious_coverage"] = SYNTH_TOKEN_AIZA

        save_assessment_result(task.id, assessment, scan_updated)

        retrieved = get_assessment_result(task.id)
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)

        # 未知字段不应出现在持久化结果中
        assert "malicious_field" not in retrieved
        assert "malicious_nested" not in retrieved.get("score_breakdown", [{}])[0]
        assert "malicious_coverage" not in retrieved.get("coverage", {})
        # Token 不应泄露
        assert SYNTH_TOKEN_GHP not in retrieved_json
        assert SYNTH_TOKEN_AKIA not in retrieved_json
        assert SYNTH_TOKEN_AIZA not in retrieved_json

    def test_wrong_task_id_not_persisted(self, test_db):
        """assessment["task_id"] = "wrong-task" → 持久化主键和 JSON task_id
        均为真实 task_id，wrong-task 不进入持久化结果。
        """
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        real_task_id = task.id
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)

        # 篡改 task_id
        assessment["task_id"] = "wrong-task-id"

        save_assessment_result(real_task_id, assessment, scan_updated)

        # DB 主键必须是真实 task_id
        row = _read_db_row(real_task_id)
        assert row is not None

        # JSON task_id 必须是真实 task_id
        retrieved = get_assessment_result(real_task_id)
        assert retrieved["task_id"] == real_task_id
        assert retrieved["task_id"] != "wrong-task-id"

        # wrong-task-id 不应出现在任何持久化结果中
        retrieved_json = json.dumps(retrieved, ensure_ascii=False)
        assert "wrong-task-id" not in retrieved_json

    def test_api_response_no_token(self, client):
        """GET /api/check/{task_id}/assessment 响应不含完整 Token。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(Finding(
                rule_id="R_API_TOKEN",
                rule_name="Test",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=f"src/{SYNTH_TOKEN_GHP}/config.py",
                line_start=1, line_end=1,
                column_start=1, column_end=20,
                snippet_masked="ghp_****",
                is_blocking=True,
                finding_type=FindingType.CONTENT,
                description=f"Found: {SYNTH_TOKEN_GHP}",
                category="token",
                secret_type="github_token",
                message="Remove",
                repair_template_key="remove_secret",
            ),),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=1, total_lines_scanned=1,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)
        save_assessment_result(task.id, assessment, scan_updated)
        task_manager.mark_completed(task.id, file_count=1, total_size=100, top_level_dir="repo")

        response = client.get(f"/api/check/{task.id}/assessment")
        assert response.status_code == 200

        response_json = json.dumps(response.json(), ensure_ascii=False)
        assert SYNTH_TOKEN_GHP not in response_json
        assert SYNTH_TOKEN_AKIA not in response_json

    def test_already_masked_string_stable(self):
        """已经脱敏的字符串重复处理后保持稳定。"""
        # 模拟已脱敏的值
        masked_values = [
            "ghp_...yZ3a",
            "AKIA...GHIJ",
            "<REDACTED>",
            "<PRIVATE_KEY_REDACTED>",
            "*****",
        ]
        for val in masked_values:
            safe = serialize_assessment_result(
                "test-task",
                {"score": 100, "verdict": "pass", "score_breakdown": [{"description": val}]},
                None, "now",
            )
            # 重复处理后值不变
            assert safe["score_breakdown"][0]["description"] == val


# ============================================================
# 3. 时间戳一致性测试
# ============================================================

class TestTimestampConsistency:
    """时间戳一致性测试。

    验证 JSON 中的 created_at/updated_at 与数据库列完全一致。
    """

    def test_first_save_json_matches_db_columns(self, test_db):
        """首次保存后 JSON 时间与数据库列一致。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)
        assessment = assess_scan_result(task.id, scan_dict)
        persisted = save_assessment_result(task.id, assessment, scan_updated)

        # 读取 DB 列
        row = _read_db_row(task.id)
        assert row is not None

        # JSON created_at == DB created_at
        assert persisted["created_at"] == row["created_at"]
        # JSON updated_at == DB updated_at
        assert persisted["updated_at"] == row["updated_at"]

        # 从 DB 读回的 JSON 也一致
        retrieved = get_assessment_result(task.id)
        assert retrieved["created_at"] == row["created_at"]
        assert retrieved["updated_at"] == row["updated_at"]

    def test_upsert_preserves_created_at_in_json_and_db(self, test_db):
        """第二次 upsert 后 JSON created_at 不变、数据库 created_at 不变。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        from app.services.assessment_service import get_scan_result_with_timestamp
        scan_dict, scan_updated = get_scan_result_with_timestamp(task.id)

        # 第一次保存
        assessment1 = assess_scan_result(task.id, scan_dict)
        persisted1 = save_assessment_result(task.id, assessment1, scan_updated)
        row1 = _read_db_row(task.id)

        # 验证第一次保存的 JSON 和 DB 一致
        assert persisted1["created_at"] == row1["created_at"]
        assert persisted1["updated_at"] == row1["updated_at"]

        time.sleep(0.01)

        # 第二次保存（upsert）
        assessment2 = assess_scan_result(task.id, scan_dict)
        persisted2 = save_assessment_result(task.id, assessment2, scan_updated)
        row2 = _read_db_row(task.id)

        # created_at 不变（JSON 和 DB 都不变）
        assert persisted2["created_at"] == persisted1["created_at"]
        assert row2["created_at"] == row1["created_at"]
        assert persisted2["created_at"] == row2["created_at"]

        # updated_at 变化（JSON 和 DB 同步更新）
        assert persisted2["updated_at"] != persisted1["updated_at"]
        assert row2["updated_at"] != row1["updated_at"]
        assert persisted2["updated_at"] == row2["updated_at"]

    def test_api_returns_db_timestamps(self, client):
        """API 返回的时间戳与数据库列一致。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
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
        task_manager.mark_completed(task.id, file_count=1, total_size=100, top_level_dir="repo")

        # 读取 DB 列
        row = _read_db_row(task.id)
        assert row is not None

        # API 响应
        response = client.get(f"/api/check/{task.id}/assessment")
        assert response.status_code == 200
        data = response.json()

        # API 返回的时间戳与 DB 列一致
        assert data["created_at"] == row["created_at"]
        assert data["updated_at"] == row["updated_at"]

    def test_run_assessment_returns_persisted_version(self, test_db):
        """run_assessment 返回最终持久化版本，不是保存前的旧版本。"""
        task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
        scan_result = ScanResult(
            findings=(),
            notices=(), skipped_files=(), scan_errors=(),
            total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, scan_result)

        persisted = run_assessment(task.id)

        # run_assessment 返回的应有真实时间戳（非 None）
        assert persisted["created_at"] is not None
        assert persisted["updated_at"] is not None

        # 与 DB 列一致
        row = _read_db_row(task.id)
        assert row is not None
        assert persisted["created_at"] == row["created_at"]
        assert persisted["updated_at"] == row["updated_at"]

        # 与从 DB 读回的一致
        retrieved = get_assessment_result(task.id)
        assert retrieved == persisted


# ============================================================
# 4. Policy 不可变性测试
# ============================================================

class TestPolicyImmutability:
    """Policy 不可变性测试。

    验证策略字典和 cap 对象不可变，修改会抛出异常。
    """

    def test_modify_severity_base_points_raises_type_error(self):
        """尝试修改 SEVERITY_BASE_POINTS 应抛出 TypeError。"""
        with pytest.raises(TypeError):
            SEVERITY_BASE_POINTS["critical"] = 999

    def test_modify_confidence_percent_raises_type_error(self):
        """尝试修改 CONFIDENCE_PERCENT 应抛出 TypeError。"""
        with pytest.raises(TypeError):
            CONFIDENCE_PERCENT["high"] = 50

    def test_modify_rule_cap_raises_type_error(self):
        """尝试修改 RULE_CAP_BY_SEVERITY 应抛出 TypeError。"""
        with pytest.raises(TypeError):
            RULE_CAP_BY_SEVERITY["critical"] = 999

    def test_modify_score_cap_raises_frozen_instance_error(self):
        """尝试修改 ScoreCap 对象应抛出 FrozenInstanceError。"""
        with pytest.raises(FrozenInstanceError):
            CAP_BLOCKING.cap_value = 999

    def test_modify_score_cap_description_raises_frozen_instance_error(self):
        """尝试修改 ScoreCap.description 应抛出 FrozenInstanceError。"""
        with pytest.raises(FrozenInstanceError):
            CAP_BLOCKING.description = "modified"

    def test_scoring_unchanged_after_failed_modification(self):
        """失败的修改不影响评分结果。"""
        # 尝试修改（会失败）
        try:
            SEVERITY_BASE_POINTS["critical"] = 999
        except TypeError:
            pass

        try:
            CAP_BLOCKING.cap_value = 999
        except FrozenInstanceError:
            pass

        # 评分结果应不变
        finding = _make_finding_dict(
            rule_id="R_IMMUTABLE",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)

        # critical blocking → score capped at 49
        assert result["score"] == 49
        assert result["verdict"] == "blocked"

    def test_policy_version_unchanged(self):
        """policy_version 保持 p0-6-v1 不变。"""
        assert POLICY_VERSION == "p0-6-v1"

        # 尝试修改后 policy_version 仍不变
        try:
            SEVERITY_BASE_POINTS["critical"] = 999
        except TypeError:
            pass

        assert POLICY_VERSION == "p0-6-v1"

    def test_severity_base_points_is_mapping_proxy(self):
        """SEVERITY_BASE_POINTS 是 MappingProxyType（不可变）。"""
        assert isinstance(SEVERITY_BASE_POINTS, MappingProxyType)

    def test_confidence_percent_is_mapping_proxy(self):
        """CONFIDENCE_PERCENT 是 MappingProxyType（不可变）。"""
        assert isinstance(CONFIDENCE_PERCENT, MappingProxyType)

    def test_rule_cap_is_mapping_proxy(self):
        """RULE_CAP_BY_SEVERITY 是 MappingProxyType（不可变）。"""
        assert isinstance(RULE_CAP_BY_SEVERITY, MappingProxyType)


# ============================================================
# 5. 结果上限运行时防御测试
# ============================================================

class TestRuntimeMaxReasonsDefense:
    """结果上限运行时防御测试。

    验证 assessment_max_blocking_reasons 的运行时防御：
    - 0 → max(1, 0) = 1，不绕过限制
    - -1 → max(1, -1) = 1，不出现 blocking[:-1]
    - 合法正数 → 正常工作
    - 大量 blocking Finding → 截断正确
    """

    def test_runtime_zero_retains_at_least_one(self, monkeypatch):
        """runtime 值为 0 时最多保留 1 条，不绕过限制。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 0
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_ZERO_{i}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"f{i}.py",
                line_start=i + 1,
                description=f"Blocking {i}",
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)

        # 应保留至少 1 条（max(1, 0) = 1）
        assert len(result["blocking_reasons"]) == 1
        assert result["coverage"]["returned_blocking_reasons"] == 1
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_runtime_negative_one_no_reverse_slice(self, monkeypatch):
        """runtime 值为 -1 时不得出现 blocking[:-1]。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", -1
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_NEG_{i}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"f{i}.py",
                line_start=i + 1,
                description=f"Blocking {i}",
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)

        # blocking[:-1] 会保留 9 条（去掉最后一条），这是错误的。
        # max(1, -1) = 1，应只保留 1 条。
        assert len(result["blocking_reasons"]) == 1
        assert result["coverage"]["returned_blocking_reasons"] == 1
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_runtime_valid_positive(self, monkeypatch):
        """runtime 合法正数正常工作。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 3
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_POS_{i}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"f{i}.py",
                line_start=i + 1,
                description=f"Blocking {i}",
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)

        assert len(result["blocking_reasons"]) == 3
        assert result["coverage"]["returned_blocking_reasons"] == 3
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_large_blocking_findings_truncated(self, monkeypatch):
        """大量 blocking Finding 被正确截断。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 5
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_LARGE_{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"f{i}.py",
                line_start=i + 1,
                description=f"Blocking {i}",
            )
            for i in range(100)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)

        assert len(result["blocking_reasons"]) == 5
        assert result["coverage"]["returned_blocking_reasons"] == 5
        assert result["coverage"]["total_blocking_findings"] == 100
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_default_value_100(self):
        """默认 assessment_max_blocking_reasons 仍为 100。"""
        from app.core.config import settings
        assert settings.assessment_max_blocking_reasons == 100

    def test_runtime_truncation_subset_deterministic(self, monkeypatch):
        """截断后的子集在多次运行中确定。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 3
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_DET_{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"f{i}.py",
                line_start=i + 1,
                description=f"Blocking {i}",
            )
            for i in range(20)
        ]
        scan_result = _make_scan_result(findings)

        result1 = assess_scan_result("test-task", copy.deepcopy(scan_result))
        result2 = assess_scan_result("test-task", copy.deepcopy(scan_result))

        assert result1["blocking_reasons"] == result2["blocking_reasons"]
        assert len(result1["blocking_reasons"]) == 3
