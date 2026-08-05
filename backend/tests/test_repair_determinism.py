"""P0-7 修复计划确定性测试。

覆盖范围（B. 确定性测试）：
1. 相同输入产生相同输出（排除 task_id、created_at、updated_at）
2. 发现顺序不影响输出
3. dict key 插入顺序不影响输出
4. group_id 稳定（RG001, RG002, ... 确定性顺序）
5. related_files 始终按字母序排序
6. 多个相同聚合 key 的 blocking 发现产生相同顺序的分组
7. blocking 与非 blocking 混合时 blocking 分组始终在前
8. 不同 task_id 相同发现产生相同计划内容
9. json.dumps(sort_keys=True) 产生相同字符串
10. 修复分组 9 级排序验证
11. 无随机性（10 次运行结果一致）
12. 不依赖 Python hash()
13. 不同 secret_type 产生独立分组（不合并）
14. 不同 rule_id 产生独立分组（不合并）
15. VERIFY_NO_SECRET_REMAINS 与 RERUN_SECURITY_SCAN 全局仅出现一次
"""

from __future__ import annotations

import copy
import json

import pytest

from app.db import database
from app.services.repair_service import generate_repair_plan
from app.services.repair_policy import (
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
    SEVERITY_ORDER,
    CONFIDENCE_ORDER,
    ACTION_REVOKE_OR_ROTATE_SECRET,
    ACTION_VERIFY_NO_SECRET_REMAINS,
    ACTION_RERUN_SECURITY_SCAN,
)


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

def _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                  repair_template_key="rotate_github_token",
                  is_blocking=True, severity="critical", confidence="high",
                  file_path="config.py"):
    return {
        "rule_id": rule_id, "rule_name": "Test", "severity": severity,
        "confidence": confidence, "file_path": file_path,
        "line_start": 1, "line_end": 1, "column_start": 1, "column_end": 10,
        "snippet_masked": "ghp_****", "is_blocking": is_blocking,
        "finding_type": "secret", "description": "Test",
        "category": "secret", "secret_type": secret_type, "message": "Test",
        "repair_template_key": repair_template_key,
    }


def _make_scan_result(findings):
    return {
        "schema_version": 1, "findings": findings,
        "notices": [], "skipped_files": [], "scan_errors": [],
        "summary": {
            "total_findings": len(findings),
            "blocking_findings": sum(1 for f in findings if f.get("is_blocking")),
            "total_notices": 0, "total_skipped_files": 0, "total_scan_errors": 0,
            "total_files_scanned": 10, "total_lines_scanned": 100,
            "returned_findings": len(findings), "findings_truncated": False,
            "returned_notices": 0, "notices_truncated": False,
            "returned_skipped_files": 0, "skipped_files_truncated": False,
            "returned_scan_errors": 0, "scan_errors_truncated": False,
        },
    }


def _make_assessment(task_id):
    return {
        "schema_version": 1, "policy_version": "p0-6-v1",
        "assessment_scope": "sensitive_data_security",
        "task_id": task_id, "score": 50, "score_before_caps": 60,
        "verdict": "warning", "score_breakdown": [], "score_caps": [],
        "blocking_reasons": [],
        "coverage": {"status": "complete", "reasons": [], "total_findings": 0,
                     "scored_findings": 0, "findings_truncated": False,
                     "total_blocking_findings": 0, "returned_blocking_reasons": 0,
                     "blocking_reasons_truncated": False, "total_scan_errors": 0,
                     "total_files_scanned": 10, "total_skipped_files": 0},
    }


def _generate(task_id, findings):
    scan = _make_scan_result(findings)
    return generate_repair_plan(
        task_id=task_id, scan_result=scan, summary=scan["summary"],
        scan_updated_at="2026-01-01T00:00:00Z",
        assessment=_make_assessment(task_id),
        assessment_updated_at="2026-01-01T00:00:00Z",
        assessment_policy_version="p0-6-v1",
        source_scan_updated_at="2026-01-01T00:00:00Z",
    )


def _strip_variable_fields(plan):
    """Remove task_id, created_at, updated_at for comparison."""
    result = copy.deepcopy(plan)
    result.pop("task_id", None)
    result.pop("created_at", None)
    result.pop("updated_at", None)
    result.pop("source_scan_updated_at", None)
    result.pop("source_assessment_updated_at", None)
    result.pop("source_assessment_policy_version", None)
    return result


def _partial_sort_key(group):
    """Reconstruct the first 5 levels of the deterministic sort key from a
    serialized repair group.

    Levels: (blocking, priority, severity_order, confidence_order,
    action_code). The remaining levels (repair_template_key, rule_id,
    secret_type, related_files_first) are not present in the serialized
    group output, but levels 1-5 being sorted is a strong determinism
    signal.
    """
    return (
        0 if group["blocking"] else 1,
        group["priority"],
        SEVERITY_ORDER.get(group["highest_severity"], 99),
        CONFIDENCE_ORDER.get(group["highest_confidence"], 99),
        group["action_code"],
    )


# ===========================================================================
# B. Determinism tests
# ===========================================================================

class TestRepairDeterminism:
    """P0-7 修复计划确定性测试。"""

    # --- 1. Same input produces same output ---

    def test_same_input_same_output(self, test_db):
        findings = [_make_finding()]
        plan_a = _generate("task-1", findings)
        plan_b = _generate("task-1", findings)
        # 身份常量稳定
        assert plan_a["schema_version"] == REPAIR_SCHEMA_VERSION
        assert plan_a["policy_version"] == POLICY_VERSION
        assert plan_a["repair_scope"] == REPAIR_SCOPE
        # 排除可变字段后完全一致
        assert _strip_variable_fields(plan_a) == _strip_variable_fields(plan_b)

    # --- 2. Finding order does not matter ---

    def test_finding_order_does_not_matter(self, test_db):
        findings_a = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", file_path="a.py"),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="c.py"),
        ]
        findings_b = list(reversed(findings_a))
        plan_a = _generate("task-1", findings_a)
        plan_b = _generate("task-1", findings_b)
        assert _strip_variable_fields(plan_a) == _strip_variable_fields(plan_b)

    # --- 3. Dict key insertion order does not matter ---

    def test_dict_key_order_does_not_matter(self, test_db):
        finding = _make_finding()
        # Serialize and reparse with different key orders
        json_str = json.dumps(finding, sort_keys=True)
        finding_a = json.loads(json_str)
        # Manually construct a version with different key order
        finding_c = {k: finding[k] for k in reversed(list(finding.keys()))}
        plan_a = _generate("task-1", [finding_a])
        plan_c = _generate("task-1", [finding_c])
        assert _strip_variable_fields(plan_a) == _strip_variable_fields(plan_c)

    # --- 4. group_id stable (RG001, RG002, ... deterministic order) ---

    def test_group_id_stable(self, test_db):
        findings_a = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py"),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
        ]
        findings_b = list(reversed(findings_a))
        plan_a = _generate("task-1", findings_a)
        plan_b = _generate("task-1", findings_b)
        # group_id -> action_code 映射在两种输入顺序下完全一致
        ids_a = {g["group_id"]: g["action_code"] for g in plan_a["repair_groups"]}
        ids_b = {g["group_id"]: g["action_code"] for g in plan_b["repair_groups"]}
        assert ids_a == ids_b
        # group_id 必须为 RG001, RG002, ... 连续递增
        for plan in (plan_a, plan_b):
            for idx, g in enumerate(plan["repair_groups"]):
                assert g["group_id"] == f"RG{idx + 1:03d}"

    # --- 5. related_files always sorted alphabetically ---

    def test_related_files_sorted(self, test_db):
        findings = [
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="zeta.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="alpha.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="mid.py"),
        ]
        plan = _generate("task-1", findings)
        assert len(plan["repair_groups"]) > 0
        for g in plan["repair_groups"]:
            files = g["related_files"]
            assert files == sorted(files), (
                f"related_files not sorted in group {g['group_id']}: {files}"
            )

    # --- 6. Multiple blocking findings with same group produce stable order ---

    def test_multiple_blocking_findings_same_group(self, test_db):
        findings_a = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", file_path="a.py"),
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", file_path="b.py"),
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", file_path="c.py"),
        ]
        findings_b = list(reversed(findings_a))
        plan_a = _generate("task-1", findings_a)
        plan_b = _generate("task-1", findings_b)
        assert _strip_variable_fields(plan_a) == _strip_variable_fields(plan_b)
        # 相同聚合 key 的 blocking 发现应合并为同一分组
        revoke_groups = [g for g in plan_a["repair_groups"]
                         if g["action_code"] == ACTION_REVOKE_OR_ROTATE_SECRET]
        assert len(revoke_groups) == 1
        assert revoke_groups[0]["finding_count"] == 3
        # related_files 排序去重
        assert revoke_groups[0]["related_files"] == ["a.py", "b.py", "c.py"]

    # --- 7. Mixed blocking and non-blocking always blocking first ---

    def test_mixed_blocking_and_non_blocking(self, test_db):
        findings = [
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="c.py"),
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", is_blocking=True,
                          file_path="a.py"),
        ]
        plan = _generate("task-1", findings)
        blocking_groups = [g for g in plan["repair_groups"] if g["blocking"]]
        non_blocking_groups = [g for g in plan["repair_groups"] if not g["blocking"]]
        assert len(blocking_groups) > 0
        assert len(non_blocking_groups) > 0
        # 所有 blocking 分组的 group_id 都小于第一个非 blocking 分组
        first_non_blocking_id = non_blocking_groups[0]["group_id"]
        for g in blocking_groups:
            assert g["group_id"] < first_non_blocking_id

    # --- 8. Different task_id, same content ---

    def test_different_task_id_same_content(self, test_db):
        findings = [
            _make_finding(),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
        ]
        plan_a = _generate("task-1", findings)
        plan_b = _generate("task-2", findings)
        # _strip_variable_fields 已移除 task_id，内容应完全一致
        assert _strip_variable_fields(plan_a) == _strip_variable_fields(plan_b)

    # --- 9. json.dumps(sort_keys=True) deterministic ---

    def test_json_serialization_deterministic(self, test_db):
        findings = [
            _make_finding(),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="c.py"),
        ]
        plan_a = _generate("task-1", findings)
        plan_b = _generate("task-1", findings)
        str_a = json.dumps(
            _strip_variable_fields(plan_a), sort_keys=True, ensure_ascii=False
        )
        str_b = json.dumps(
            _strip_variable_fields(plan_b), sort_keys=True, ensure_ascii=False
        )
        assert str_a == str_b

    # --- 10. repair_groups 9-level sort order ---

    def test_repair_groups_sort_order(self, test_db):
        # Create findings with different severities, confidences, action_codes
        # to verify the multi-level sort is correct
        findings = [
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="low", confidence="low", file_path="z.py"),
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", is_blocking=True,
                          severity="critical", confidence="high", file_path="a.py"),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", is_blocking=True,
                          severity="high", confidence="medium", file_path="m.py"),
        ]
        plan = _generate("task-1", findings)
        # Blocking groups should come before non-blocking
        blocking_groups = [g for g in plan["repair_groups"] if g["blocking"]]
        non_blocking_groups = [g for g in plan["repair_groups"] if not g["blocking"]]
        assert len(non_blocking_groups) > 0
        assert all(g["group_id"] < non_blocking_groups[0]["group_id"]
                   for g in blocking_groups)
        # Within blocking, priority ascending
        for i in range(len(blocking_groups) - 1):
            assert blocking_groups[i]["priority"] <= blocking_groups[i + 1]["priority"]
        # Within non-blocking, priority ascending
        for i in range(len(non_blocking_groups) - 1):
            assert non_blocking_groups[i]["priority"] <= non_blocking_groups[i + 1]["priority"]
        # Verify partial sort key (levels 1-5) is globally sorted
        keys = [_partial_sort_key(g) for g in plan["repair_groups"]]
        assert keys == sorted(keys), f"Groups not sorted by partial key: {keys}"
        # Determinism: reversed input produces identical sort order
        plan_rev = _generate("task-1", list(reversed(findings)))
        keys_rev = [_partial_sort_key(g) for g in plan_rev["repair_groups"]]
        assert keys == keys_rev

    # --- 11. No randomness (10 runs identical) ---

    def test_no_randomness(self, test_db):
        findings = [
            _make_finding(),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password", is_blocking=False,
                          severity="medium", file_path="c.py"),
        ]
        serialized_runs = []
        for _ in range(10):
            plan = _generate("task-1", findings)
            serialized_runs.append(
                json.dumps(
                    _strip_variable_fields(plan),
                    sort_keys=True, ensure_ascii=False,
                )
            )
        assert all(r == serialized_runs[0] for r in serialized_runs)

    # --- 12. No hash dependency ---

    def test_no_hash_dependency(self, test_db):
        # We cannot change PYTHONHASHSEED within a running process, but we
        # verify stability across many runs and confirm the sort relies on
        # explicit comparable keys (int/str/bool), never on Python hash().
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py"),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
            _make_finding(rule_id="R004_GOOGLE_API_KEY", secret_type="google_api_key",
                          repair_template_key="rotate_google_api_key", file_path="c.py"),
            _make_finding(rule_id="R005_PRIVATE_KEY", secret_type="private_key",
                          repair_template_key="rotate_private_key", file_path="d.py"),
        ]
        baseline = json.dumps(
            _strip_variable_fields(_generate("task-1", findings)),
            sort_keys=True, ensure_ascii=False,
        )
        for _ in range(10):
            plan = _generate("task-1", findings)
            serialized = json.dumps(
                _strip_variable_fields(plan), sort_keys=True, ensure_ascii=False
            )
            assert serialized == baseline
        # 排序 key 的每个分量都是确定性可比类型（int/str/bool），
        # 不依赖 Python hash() 的随机化。
        plan = _generate("task-1", findings)
        for g in plan["repair_groups"]:
            assert isinstance(g["blocking"], bool)
            assert isinstance(g["priority"], int)
            assert isinstance(g["action_code"], str)
            assert isinstance(g["highest_severity"], str)
            assert isinstance(g["highest_confidence"], str)
        # 分组顺序由显式 sort key 决定，partial key 应有序
        keys = [_partial_sort_key(g) for g in plan["repair_groups"]]
        assert keys == sorted(keys)
        # 反转输入顺序后，分组顺序（含完整字段）仍完全一致
        plan_rev = _generate("task-1", list(reversed(findings)))
        assert _strip_variable_fields(plan) == _strip_variable_fields(plan_rev)

    # --- 13. Aggregation key correctness (different secret_type) ---

    def test_aggregation_key_correctness(self, test_db):
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", is_blocking=False,
                          severity="medium", file_path="a.py"),
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="aws_access_key",
                          repair_template_key="rotate_github_token", is_blocking=False,
                          severity="medium", file_path="b.py"),
        ]
        plan = _generate("task-1", findings)
        # 不同 secret_type 不应合并：REVOKE_OR_ROTATE_SECRET 应有 2 个分组
        revoke_groups = [g for g in plan["repair_groups"]
                         if g["action_code"] == ACTION_REVOKE_OR_ROTATE_SECRET]
        assert len(revoke_groups) == 2
        # 每个分组 finding_count == 1（未合并）
        for g in revoke_groups:
            assert g["finding_count"] == 1
        # 两个分组的 related_files 不同
        files = {g["related_files"][0] for g in revoke_groups}
        assert files == {"a.py", "b.py"}

    # --- 14. Aggregation key correctness (different rule_id) ---

    def test_aggregation_key_correctness_2(self, test_db):
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", is_blocking=False,
                          severity="medium", file_path="a.py"),
            _make_finding(rule_id="R099_CUSTOM_TOKEN", secret_type="github_token",
                          repair_template_key="rotate_github_token", is_blocking=False,
                          severity="medium", file_path="b.py"),
        ]
        plan = _generate("task-1", findings)
        revoke_groups = [g for g in plan["repair_groups"]
                         if g["action_code"] == ACTION_REVOKE_OR_ROTATE_SECRET]
        assert len(revoke_groups) == 2
        for g in revoke_groups:
            assert g["finding_count"] == 1
        # 两个分组的 related_rule_ids 不同
        # R099_CUSTOM_TOKEN is unknown → sanitized to <unknown-rule>
        rule_ids = {g["related_rule_ids"][0] for g in revoke_groups}
        assert rule_ids == {"R001_GITHUB_TOKEN", "<unknown-rule>"}

    # --- 15. Global singleton stability ---

    def test_global_singleton_stability(self, test_db):
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py"),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          repair_template_key="rotate_aws_credentials", file_path="b.py"),
            _make_finding(rule_id="R004_GOOGLE_API_KEY", secret_type="google_api_key",
                          repair_template_key="rotate_google_api_key", file_path="c.py"),
            _make_finding(rule_id="R005_PRIVATE_KEY", secret_type="private_key",
                          repair_template_key="rotate_private_key", file_path="d.py"),
        ]
        plan = _generate("task-1", findings)
        verify_count = sum(
            1 for g in plan["repair_groups"]
            if g["action_code"] == ACTION_VERIFY_NO_SECRET_REMAINS
        )
        rerun_count = sum(
            1 for g in plan["repair_groups"]
            if g["action_code"] == ACTION_RERUN_SECURITY_SCAN
        )
        assert verify_count == 1
        assert rerun_count == 1
        # 单例分组的 finding_count 应等于 blocking 发现总数（4），
        # 无论有多少个 blocking 发现，单例只出现一次。
        for g in plan["repair_groups"]:
            if g["action_code"] == ACTION_VERIFY_NO_SECRET_REMAINS:
                assert g["finding_count"] == 4
            if g["action_code"] == ACTION_RERUN_SECURITY_SCAN:
                assert g["finding_count"] == 4
