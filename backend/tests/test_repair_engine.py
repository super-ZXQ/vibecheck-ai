"""P0-7 修复策略与引擎综合测试。

覆盖范围：
A. repair_policy.py 策略常量与映射
   - 策略常量不可变（MappingProxyType、frozen dataclass）
   - 12 个 action_code 全部存在且有效
   - 9 个 repair_template_key 全部有显式映射
   - R001-R011 规则全部有模板映射
   - 未知模板 key 产生 partial 与 MANUAL_REVIEW_REQUIRED
   - blocking 发现始终以 REVOKE_OR_ROTATE_SECRET 开头
   - blocking use_env_var_* 发现不能跳过撤销步骤
   - BLOCKING_ACTION_SEQUENCE 恰好 9 个动作且顺序正确

B. repair_service.py generate_repair_plan 核心生成逻辑
   - 生成计划结构完整
   - 空发现 → complete 计划、0 个分组
   - blocking 发现 → 9 个 blocking 动作
   - 非 blocking 发现 → 模板特定动作
   - 未知模板 key → plan_status=partial + MANUAL_REVIEW_REQUIRED
   - VERIFY_NO_SECRET_REMAINS 全局仅出现一次
   - RERUN_SECURITY_SCAN 全局仅出现一次
   - related_files 排序去重
   - related_files_truncated 超限截断
   - groups_truncated 超限截断
   - partial 条件检测
   - PARTIAL_DECLARATION 出现在 partial 计划中
"""

from __future__ import annotations

import dataclasses
from types import MappingProxyType

import pytest

from app.services.repair_policy import *
from app.services import repair_policy as _rp
from app.services.repair_service import generate_repair_plan, RepairPlanInternalError
from app.db import database


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

def _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                  repair_template_key="rotate_github_token",
                  is_blocking=True, severity="critical", confidence="high",
                  file_path="config.py"):
    return {
        "rule_id": rule_id, "rule_name": "Test Rule", "severity": severity,
        "confidence": confidence, "file_path": file_path,
        "line_start": 1, "line_end": 1, "column_start": 1, "column_end": 10,
        "snippet_masked": "ghp_****", "is_blocking": is_blocking,
        "finding_type": "secret", "description": "Test finding",
        "category": "secret", "secret_type": secret_type, "message": "Test",
        "repair_template_key": repair_template_key,
    }


def _make_scan_result(findings=None, files_scanned=10, lines_scanned=100):
    return {
        "schema_version": 1,
        "findings": findings or [],
        "notices": [], "skipped_files": [], "scan_errors": [],
        "summary": {
            "total_findings": len(findings or []),
            "blocking_findings": sum(1 for f in findings or [] if f.get("is_blocking")),
            "total_notices": 0, "total_skipped_files": 0, "total_scan_errors": 0,
            "total_files_scanned": files_scanned, "total_lines_scanned": lines_scanned,
            "returned_findings": len(findings or []), "findings_truncated": False,
            "returned_notices": 0, "notices_truncated": False,
            "returned_skipped_files": 0, "skipped_files_truncated": False,
            "returned_scan_errors": 0, "scan_errors_truncated": False,
        },
    }


def _make_assessment(task_id, coverage_status="complete", findings_truncated=False):
    return {
        "schema_version": 1, "policy_version": "p0-6-v1",
        "assessment_scope": "sensitive_data_security",
        "task_id": task_id, "score": 50, "score_before_caps": 60,
        "verdict": "warning", "score_breakdown": [], "score_caps": [],
        "blocking_reasons": [],
        "coverage": {
            "status": coverage_status, "reasons": [],
            "total_findings": 0, "scored_findings": 0,
            "findings_truncated": findings_truncated,
            "total_blocking_findings": 0, "returned_blocking_reasons": 0,
            "blocking_reasons_truncated": False,
            "total_scan_errors": 0, "total_files_scanned": 10,
            "total_skipped_files": 0,
        },
    }


def _make_plan(findings=None, task_id="test-task-id",
               coverage_status="complete", assessment_findings_truncated=False,
               files_scanned=10, lines_scanned=100,
               summary_overrides=None):
    """构建 scan_result、summary、assessment 并调用 generate_repair_plan。"""
    scan_result = _make_scan_result(
        findings=findings, files_scanned=files_scanned, lines_scanned=lines_scanned,
    )
    if summary_overrides:
        scan_result["summary"].update(summary_overrides)
    assessment = _make_assessment(
        task_id, coverage_status=coverage_status,
        findings_truncated=assessment_findings_truncated,
    )
    return generate_repair_plan(
        task_id=task_id,
        scan_result=scan_result,
        summary=scan_result["summary"],
        scan_updated_at="2026-01-01T00:00:00Z",
        assessment=assessment,
        assessment_updated_at="2026-01-01T00:00:00Z",
        assessment_policy_version="p0-6-v1",
        source_scan_updated_at="2026-01-01T00:00:00Z",
    )


# ===========================================================================
# A. Policy tests
# ===========================================================================

class TestRepairPolicy:
    """repair_policy.py 策略常量与映射测试。"""

    # --- Immutability: MappingProxyType ---

    def test_action_priority_is_immutable_mapping_proxy(self):
        assert isinstance(ACTION_PRIORITY, MappingProxyType)
        with pytest.raises(TypeError):
            ACTION_PRIORITY["NEW_ACTION"] = 999

    def test_severity_order_is_immutable_mapping_proxy(self):
        assert isinstance(SEVERITY_ORDER, MappingProxyType)
        with pytest.raises(TypeError):
            SEVERITY_ORDER["new_severity"] = 99

    def test_confidence_order_is_immutable_mapping_proxy(self):
        assert isinstance(CONFIDENCE_ORDER, MappingProxyType)
        with pytest.raises(TypeError):
            CONFIDENCE_ORDER["new_confidence"] = 99

    def test_rule_template_map_is_immutable_mapping_proxy(self):
        assert isinstance(RULE_TEMPLATE_MAP, MappingProxyType)
        with pytest.raises(TypeError):
            RULE_TEMPLATE_MAP["R999_UNKNOWN"] = "unknown"

    def test_template_mappings_is_immutable_mapping_proxy(self):
        assert isinstance(_rp._TEMPLATE_MAPPINGS, MappingProxyType)
        with pytest.raises(TypeError):
            _rp._TEMPLATE_MAPPINGS["new_key"] = ()

    def test_actions_by_code_is_immutable_mapping_proxy(self):
        assert isinstance(_rp._ACTIONS_BY_CODE, MappingProxyType)
        with pytest.raises(TypeError):
            _rp._ACTIONS_BY_CODE["NEW_CODE"] = _rp._ACTION_REVOKE_OR_ROTATE

    # --- Immutability: frozen dataclass ---

    def test_repair_action_is_frozen_dataclass(self):
        action = get_action(ACTION_REVOKE_OR_ROTATE_SECRET)
        assert dataclasses.is_dataclass(action)
        # frozen dataclass: 赋值属性应抛出 FrozenInstanceError
        with pytest.raises(dataclasses.FrozenInstanceError):
            action.priority = 999
        with pytest.raises(dataclasses.FrozenInstanceError):
            action.title = "modified"

    def test_all_repair_actions_are_frozen(self):
        for code in ACTION_CODES:
            action = get_action(code)
            assert dataclasses.is_dataclass(action)
            with pytest.raises(dataclasses.FrozenInstanceError):
                action.priority = 0

    # --- 12 action codes ---

    def test_all_12_action_codes_exist_and_valid(self):
        assert len(ACTION_CODES) == 12
        assert len(set(ACTION_CODES)) == 12  # 无重复
        for code in ACTION_CODES:
            assert is_valid_action_code(code)
            # 每个 code 都有对应的 RepairAction 定义
            action = get_action(code)
            assert action.action_code == code
            # 每个 code 都有优先级
            assert code in ACTION_PRIORITY

    def test_action_codes_match_constants(self):
        expected = {
            ACTION_REVOKE_OR_ROTATE_SECRET,
            ACTION_CREATE_REPLACEMENT_SECRET,
            ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
            ACTION_REMOVE_HARDCODED_SECRET,
            ACTION_UPDATE_GITIGNORE,
            ACTION_REVIEW_SECRET_USAGE,
            ACTION_CLEAN_GIT_HISTORY,
            ACTION_VERIFY_NO_SECRET_REMAINS,
            ACTION_RERUN_SECURITY_SCAN,
            ACTION_REVIEW_SCAN_COVERAGE,
            ACTION_RESOLVE_SCAN_ERROR,
            ACTION_MANUAL_REVIEW_REQUIRED,
        }
        assert set(ACTION_CODES) == expected

    def test_unknown_action_code_is_invalid(self):
        assert not is_valid_action_code("UNKNOWN_ACTION")
        assert not is_valid_action_code("")

    # --- 9 repair_template_key mappings ---

    def test_all_9_template_keys_have_explicit_mappings(self):
        assert len(KNOWN_TEMPLATE_KEYS) == 9
        for key in KNOWN_TEMPLATE_KEYS:
            actions = get_template_actions(key)
            assert actions is not None, f"Template key {key} returned None"
            assert isinstance(actions, tuple)
            assert len(actions) > 0, f"Template key {key} has empty actions"
            for ac in actions:
                assert is_valid_action_code(ac), (
                    f"Template {key} has invalid action code: {ac}"
                )

    def test_known_template_keys_count(self):
        expected_keys = {
            "rotate_github_token",
            "rotate_aws_credentials",
            "rotate_google_api_key",
            "rotate_private_key",
            "use_env_var_password",
            "use_env_var_secret",
            "use_env_var_connection_string",
            "secure_env_file",
            "use_env_var_production",
        }
        assert KNOWN_TEMPLATE_KEYS == expected_keys

    # --- R001-R011 rule mappings ---

    def test_r001_r011_rules_all_have_template_mappings(self):
        expected_rules = [
            "R001_GITHUB_TOKEN",
            "R002_AWS_ACCESS_KEY",
            "R003_AWS_SECRET_KEY",
            "R004_GOOGLE_API_KEY",
            "R005_PRIVATE_KEY",
            "R006_PASSWORD_ASSIGNMENT",
            "R007_GENERIC_TOKEN_ASSIGNMENT",
            "R008_CONNECTION_STRING",
            "R009_ENV_FILE_PRESENT",
            "R010_ENV_EXAMPLE_FILE",
            "R011_PRODUCTION_ENV_WITH_SECRET",
        ]
        for rule_id in expected_rules:
            assert rule_id in RULE_TEMPLATE_MAP, (
                f"Rule {rule_id} missing from RULE_TEMPLATE_MAP"
            )
        # R010 产生 notices 而非 findings，模板为空字符串
        assert RULE_TEMPLATE_MAP["R010_ENV_EXAMPLE_FILE"] == ""
        # 除 R010 外，所有规则映射到已知模板 key
        for rule_id in expected_rules:
            tk = RULE_TEMPLATE_MAP[rule_id]
            if tk:
                assert is_known_template_key(tk), (
                    f"Rule {rule_id} maps to unknown template: {tk}"
                )

    # --- Unknown template key ---

    def test_unknown_template_key_produces_none(self):
        assert get_template_actions("unknown_template") is None
        assert not is_known_template_key("unknown_template")
        # 空字符串也是未知
        assert get_template_actions("") is None
        assert not is_known_template_key("")

    # --- Blocking sequence starts with REVOKE_OR_ROTATE_SECRET ---

    def test_blocking_sequence_starts_with_revoke_or_rotate(self):
        assert BLOCKING_ACTION_SEQUENCE[0] == ACTION_REVOKE_OR_ROTATE_SECRET

    # --- Blocking use_env_var_* cannot skip revocation ---

    def test_blocking_use_env_var_findings_cannot_skip_revocation(self):
        """use_env_var_* 模板不含撤销步骤，但 BLOCKING_ACTION_SEQUENCE 始终包含。"""
        env_var_keys = [
            "use_env_var_password",
            "use_env_var_secret",
            "use_env_var_connection_string",
            "use_env_var_production",
        ]
        for key in env_var_keys:
            actions = get_template_actions(key)
            assert actions is not None
            # use_env_var_* 模板不含撤销/替换凭据步骤
            assert ACTION_REVOKE_OR_ROTATE_SECRET not in actions
            assert ACTION_CREATE_REPLACEMENT_SECRET not in actions
        # 但 blocking 序列始终包含撤销和替换
        assert ACTION_REVOKE_OR_ROTATE_SECRET in BLOCKING_ACTION_SEQUENCE
        assert ACTION_CREATE_REPLACEMENT_SECRET in BLOCKING_ACTION_SEQUENCE
        # 因此 blocking 发现（无论模板 key 是什么）始终经过撤销步骤

    # --- BLOCKING_ACTION_SEQUENCE exactly 9 actions in correct order ---

    def test_blocking_action_sequence_has_exactly_9_actions(self):
        assert len(BLOCKING_ACTION_SEQUENCE) == 9

    def test_blocking_action_sequence_correct_order(self):
        expected = (
            ACTION_REVOKE_OR_ROTATE_SECRET,
            ACTION_CREATE_REPLACEMENT_SECRET,
            ACTION_MOVE_TO_ENVIRONMENT_VARIABLE,
            ACTION_REMOVE_HARDCODED_SECRET,
            ACTION_UPDATE_GITIGNORE,
            ACTION_REVIEW_SECRET_USAGE,
            ACTION_CLEAN_GIT_HISTORY,
            ACTION_VERIFY_NO_SECRET_REMAINS,
            ACTION_RERUN_SECURITY_SCAN,
        )
        assert BLOCKING_ACTION_SEQUENCE == expected

    def test_blocking_action_sequence_no_duplicates(self):
        assert len(BLOCKING_ACTION_SEQUENCE) == len(set(BLOCKING_ACTION_SEQUENCE))

    def test_blocking_action_sequence_all_valid_codes(self):
        for code in BLOCKING_ACTION_SEQUENCE:
            assert is_valid_action_code(code)

    # --- Global singleton actions ---

    def test_global_singleton_actions_includes_verify_and_rerun(self):
        assert ACTION_VERIFY_NO_SECRET_REMAINS in GLOBAL_SINGLETON_ACTIONS
        assert ACTION_RERUN_SECURITY_SCAN in GLOBAL_SINGLETON_ACTIONS
        assert ACTION_REVIEW_SCAN_COVERAGE in GLOBAL_SINGLETON_ACTIONS
        assert ACTION_RESOLVE_SCAN_ERROR in GLOBAL_SINGLETON_ACTIONS
        assert ACTION_MANUAL_REVIEW_REQUIRED in GLOBAL_SINGLETON_ACTIONS

    # --- Policy version ---

    def test_policy_version_is_p0_7_v1(self):
        assert POLICY_VERSION == "p0-7-v1"

    def test_supported_assessment_policy_versions(self):
        assert is_supported_assessment_policy("p0-6-v1")
        assert not is_supported_assessment_policy("p0-5-v1")
        assert not is_supported_assessment_policy("p0-7-v1")


# ===========================================================================
# B. Engine tests
# ===========================================================================

class TestRepairEngine:
    """repair_service.py generate_repair_plan 引擎测试。"""

    # --- Plan structure ---

    def test_generate_repair_plan_correct_structure(self):
        plan = _make_plan(findings=[])
        required_fields = {
            "schema_version", "policy_version", "repair_scope", "task_id",
            "plan_status", "summary", "repair_groups", "verification_steps",
            "agent_prompt", "source_scan_updated_at",
            "source_assessment_updated_at",
            "source_assessment_policy_version",
            "created_at", "updated_at",
        }
        assert required_fields.issubset(plan.keys())
        assert plan["schema_version"] == REPAIR_SCHEMA_VERSION
        assert plan["policy_version"] == POLICY_VERSION
        assert plan["repair_scope"] == REPAIR_SCOPE
        assert plan["task_id"] == "test-task-id"
        assert plan["source_scan_updated_at"] == "2026-01-01T00:00:00Z"
        assert plan["source_assessment_updated_at"] == "2026-01-01T00:00:00Z"
        assert plan["source_assessment_policy_version"] == "p0-6-v1"
        assert plan["created_at"] is None
        assert plan["updated_at"] is None
        # summary 子结构
        summary = plan["summary"]
        assert "total_repair_groups" in summary
        assert "blocking_repair_groups" in summary
        assert "manual_review_required" in summary
        assert "coverage_warning" in summary
        assert "groups_truncated" in summary

    def test_repair_group_structure(self):
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(findings=[finding])
        assert len(plan["repair_groups"]) > 0
        g = plan["repair_groups"][0]
        group_fields = {
            "group_id", "action_code", "priority", "blocking",
            "highest_severity", "highest_confidence", "title", "description",
            "related_rule_ids", "related_files", "total_related_files",
            "returned_related_files", "related_files_truncated",
            "finding_count", "steps", "commands", "safety_notes",
            "verification_steps",
        }
        assert group_fields.issubset(g.keys())

    # --- Empty findings ---

    def test_empty_findings_complete_plan_zero_groups(self):
        plan = _make_plan(findings=[])
        assert plan["plan_status"] == "complete"
        assert len(plan["repair_groups"]) == 0
        assert plan["summary"]["total_repair_groups"] == 0
        assert plan["summary"]["blocking_repair_groups"] == 0
        assert plan["summary"]["manual_review_required"] is False
        assert plan["summary"]["coverage_warning"] is False
        assert plan["summary"]["groups_truncated"] is False

    # --- Blocking findings produce all 9 blocking actions ---

    def test_blocking_findings_produce_all_9_blocking_actions(self):
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(findings=[finding])
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        for ac in BLOCKING_ACTION_SEQUENCE:
            assert ac in action_codes, f"Missing blocking action: {ac}"

    def test_blocking_findings_produce_blocking_groups(self):
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(findings=[finding])
        blocking_groups = [g for g in plan["repair_groups"] if g["blocking"]]
        assert len(blocking_groups) > 0
        assert plan["summary"]["blocking_repair_groups"] == len(blocking_groups)

    # --- Non-blocking findings produce template-specific actions ---

    def test_non_blocking_findings_produce_template_specific_actions(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="use_env_var_password",
            rule_id="R006_PASSWORD_ASSIGNMENT",
            secret_type="password",
        )
        plan = _make_plan(findings=[finding])
        assert plan["plan_status"] == "complete"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        expected = get_template_actions("use_env_var_password")
        assert set(action_codes) == set(expected)
        # 不应包含 blocking 专属动作
        assert ACTION_REVOKE_OR_ROTATE_SECRET not in action_codes
        assert ACTION_CREATE_REPLACEMENT_SECRET not in action_codes
        assert ACTION_CLEAN_GIT_HISTORY not in action_codes
        assert ACTION_VERIFY_NO_SECRET_REMAINS not in action_codes
        assert ACTION_RERUN_SECURITY_SCAN not in action_codes

    def test_non_blocking_rotate_template_includes_revocation(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="rotate_github_token",
            rule_id="R001_GITHUB_TOKEN",
            secret_type="github_token",
        )
        plan = _make_plan(findings=[finding])
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        expected = get_template_actions("rotate_github_token")
        assert set(action_codes) == set(expected)
        assert ACTION_REVOKE_OR_ROTATE_SECRET in action_codes

    # --- Unknown template key -> partial + MANUAL_REVIEW_REQUIRED ---

    def test_unknown_template_key_sets_partial_and_manual_review(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="unknown_template",
            rule_id="R999_UNKNOWN",
            secret_type="unknown",
        )
        plan = _make_plan(findings=[finding])
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_MANUAL_REVIEW_REQUIRED in action_codes
        assert plan["summary"]["manual_review_required"] is True

    def test_missing_template_key_sets_partial(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="",
            rule_id="R999_UNKNOWN",
            secret_type="unknown",
        )
        plan = _make_plan(findings=[finding])
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_MANUAL_REVIEW_REQUIRED in action_codes

    # --- VERIFY_NO_SECRET_REMAINS appears only once globally ---

    def test_verify_no_secret_remains_appears_only_once(self):
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py", is_blocking=True),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          file_path="b.py", is_blocking=True),
            _make_finding(rule_id="R005_PRIVATE_KEY", secret_type="private_key",
                          file_path="c.py", is_blocking=True),
        ]
        plan = _make_plan(findings=findings)
        verify_count = sum(
            1 for g in plan["repair_groups"]
            if g["action_code"] == ACTION_VERIFY_NO_SECRET_REMAINS
        )
        assert verify_count == 1

    # --- RERUN_SECURITY_SCAN appears only once globally ---

    def test_rerun_security_scan_appears_only_once(self):
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py", is_blocking=True),
            _make_finding(rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
                          file_path="b.py", is_blocking=True),
            _make_finding(rule_id="R004_GOOGLE_API_KEY", secret_type="google_api_key",
                          file_path="c.py", is_blocking=True),
        ]
        plan = _make_plan(findings=findings)
        rerun_count = sum(
            1 for g in plan["repair_groups"]
            if g["action_code"] == ACTION_RERUN_SECURITY_SCAN
        )
        assert rerun_count == 1

    def test_rerun_security_scan_once_even_with_partial(self):
        """partial 计划中 RERUN_SECURITY_SCAN 仍只出现一次。"""
        findings = [
            _make_finding(rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
                          file_path="a.py", is_blocking=True),
        ]
        plan = _make_plan(
            findings=findings,
            summary_overrides={"findings_truncated": True},
        )
        assert plan["plan_status"] == "partial"
        rerun_count = sum(
            1 for g in plan["repair_groups"]
            if g["action_code"] == ACTION_RERUN_SECURITY_SCAN
        )
        assert rerun_count == 1

    # --- Related files sorted and deduplicated ---

    def test_related_files_sorted_and_deduplicated(self):
        findings = [
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password",
                          is_blocking=False, file_path="zeta.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password",
                          is_blocking=False, file_path="alpha.py"),
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password",
                          is_blocking=False, file_path="alpha.py"),  # 重复
            _make_finding(rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                          repair_template_key="use_env_var_password",
                          is_blocking=False, file_path="mid.py"),
        ]
        plan = _make_plan(findings=findings)
        # 找到包含全部 3 个唯一文件的分组
        found_group = False
        for g in plan["repair_groups"]:
            files = g["related_files"]
            if len(files) >= 2:
                # 验证已排序
                assert files == sorted(files), f"Files not sorted: {files}"
                # 验证无重复
                assert len(files) == len(set(files)), (
                    f"Duplicate files in group: {files}"
                )
            if g["action_code"] == ACTION_MOVE_TO_ENVIRONMENT_VARIABLE:
                found_group = True
                assert g["related_files"] == ["alpha.py", "mid.py", "zeta.py"]
                assert g["total_related_files"] == 3
                assert g["returned_related_files"] == 3
                assert g["related_files_truncated"] is False
        assert found_group, "MOVE_TO_ENVIRONMENT_VARIABLE group not found"

    # --- related_files_truncated when limit exceeded ---

    def test_related_files_truncated_when_limit_exceeded(self, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.repair_max_related_files_per_group", 2,
        )
        findings = [
            _make_finding(
                rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                repair_template_key="use_env_var_password",
                is_blocking=False, file_path=f"file_{i}.py",
            )
            for i in range(5)
        ]
        plan = _make_plan(findings=findings)
        assert plan["plan_status"] == "partial"  # 文件截断导致 partial
        # 模板产生的分组应有 5 个文件，超过 limit=2，截断为 True
        # partial 计划还会追加 RERUN_SECURITY_SCAN 单例分组（无文件），不检查它
        template_action_codes = set(get_template_actions("use_env_var_password"))
        truncated_groups = [
            g for g in plan["repair_groups"]
            if g["action_code"] in template_action_codes
        ]
        assert len(truncated_groups) > 0
        for g in truncated_groups:
            assert g["related_files_truncated"] is True
            assert len(g["related_files"]) <= 2
            assert g["total_related_files"] == 5
            assert g["returned_related_files"] == 2

    def test_related_files_not_truncated_within_limit(self, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.repair_max_related_files_per_group", 100,
        )
        findings = [
            _make_finding(
                rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                repair_template_key="use_env_var_password",
                is_blocking=False, file_path="a.py",
            ),
            _make_finding(
                rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                repair_template_key="use_env_var_password",
                is_blocking=False, file_path="b.py",
            ),
        ]
        plan = _make_plan(findings=findings)
        for g in plan["repair_groups"]:
            assert g["related_files_truncated"] is False

    # --- groups_truncated when limit exceeded ---

    def test_groups_truncated_when_limit_exceeded(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.repair_max_groups", 3)
        # 不同 rule_id/secret_type/template_key 产生大量独立分组
        findings = [
            _make_finding(
                rule_id="R006_PASSWORD_ASSIGNMENT", secret_type="password",
                repair_template_key="use_env_var_password",
                is_blocking=False, file_path="a.py",
            ),
            _make_finding(
                rule_id="R007_GENERIC_TOKEN_ASSIGNMENT", secret_type="token",
                repair_template_key="use_env_var_secret",
                is_blocking=False, file_path="b.py",
            ),
            _make_finding(
                rule_id="R008_CONNECTION_STRING", secret_type="connection_string",
                repair_template_key="use_env_var_connection_string",
                is_blocking=False, file_path="c.py",
            ),
            _make_finding(
                rule_id="R009_ENV_FILE_PRESENT", secret_type="env_file",
                repair_template_key="secure_env_file",
                is_blocking=False, file_path="d.py",
            ),
        ]
        plan = _make_plan(findings=findings)
        assert plan["summary"]["groups_truncated"] is True
        assert len(plan["repair_groups"]) <= 3
        assert plan["plan_status"] == "partial"

    def test_groups_not_truncated_within_limit(self):
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(findings=[finding])
        assert plan["summary"]["groups_truncated"] is False

    # --- Partial condition detection ---

    def test_partial_when_findings_truncated(self):
        plan = _make_plan(
            findings=[],
            summary_overrides={"findings_truncated": True},
        )
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVIEW_SCAN_COVERAGE in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_partial_when_scan_errors(self):
        plan = _make_plan(
            findings=[],
            summary_overrides={"total_scan_errors": 1},
        )
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_RESOLVE_SCAN_ERROR in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_partial_when_no_files_scanned(self):
        plan = _make_plan(findings=[], files_scanned=0)
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVIEW_SCAN_COVERAGE in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_partial_when_coverage_partial(self):
        plan = _make_plan(findings=[], coverage_status="partial")
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVIEW_SCAN_COVERAGE in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_partial_when_assessment_findings_truncated(self):
        plan = _make_plan(findings=[], assessment_findings_truncated=True)
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVIEW_SCAN_COVERAGE in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_partial_when_blocking_findings_mismatch(self):
        """summary.blocking_findings 大于实际返回的 blocking 数量。"""
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(
            findings=[finding],
            summary_overrides={"blocking_findings": 5},
        )
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVIEW_SCAN_COVERAGE in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    def test_complete_when_no_partial_conditions(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="use_env_var_password",
            rule_id="R006_PASSWORD_ASSIGNMENT",
            secret_type="password",
        )
        plan = _make_plan(findings=[finding])
        assert plan["plan_status"] == "complete"
        assert plan["summary"]["coverage_warning"] is False

    # --- PARTIAL_DECLARATION appears in partial plans ---

    def test_partial_declaration_in_partial_plan_agent_prompt(self):
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="unknown_template",
            rule_id="R999_UNKNOWN",
            secret_type="unknown",
        )
        plan = _make_plan(findings=[finding])
        assert plan["plan_status"] == "partial"
        assert PARTIAL_DECLARATION in plan["agent_prompt"]

    def test_partial_declaration_in_partial_plan_verification_steps(self):
        plan = _make_plan(
            findings=[],
            summary_overrides={"findings_truncated": True},
        )
        assert plan["plan_status"] == "partial"
        assert any(
            PARTIAL_DECLARATION in step for step in plan["verification_steps"]
        )

    def test_no_partial_declaration_in_complete_plan(self):
        plan = _make_plan(findings=[])
        assert plan["plan_status"] == "complete"
        assert PARTIAL_DECLARATION not in plan["agent_prompt"]
        assert not any(
            PARTIAL_DECLARATION in step for step in plan["verification_steps"]
        )

    # --- Blocking use_env_var_* findings get revocation (engine level) ---

    def test_blocking_use_env_var_finding_gets_revocation(self):
        """blocking 的 use_env_var_* 发现仍走完整 blocking 序列，含撤销步骤。"""
        finding = _make_finding(
            is_blocking=True,
            repair_template_key="use_env_var_password",
            rule_id="R006_PASSWORD_ASSIGNMENT",
            secret_type="password",
        )
        plan = _make_plan(findings=[finding])
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_REVOKE_OR_ROTATE_SECRET in action_codes
        assert ACTION_CREATE_REPLACEMENT_SECRET in action_codes
        # 同时也包含 use_env_var_password 模板中没有的 CLEAN_GIT_HISTORY
        assert ACTION_CLEAN_GIT_HISTORY in action_codes
        assert ACTION_VERIFY_NO_SECRET_REMAINS in action_codes
        assert ACTION_RERUN_SECURITY_SCAN in action_codes

    # --- Determinism ---

    def test_deterministic_output_same_input(self):
        """相同输入产生相同的 plan_status、repair_groups 动作序列。"""
        finding = _make_finding(is_blocking=True)
        plan1 = _make_plan(findings=[finding])
        plan2 = _make_plan(findings=[finding])
        assert plan1["plan_status"] == plan2["plan_status"]
        codes1 = [g["action_code"] for g in plan1["repair_groups"]]
        codes2 = [g["action_code"] for g in plan2["repair_groups"]]
        assert codes1 == codes2

    def test_finding_order_does_not_affect_output(self):
        """发现顺序不影响输出。"""
        finding_a = _make_finding(
            rule_id="R001_GITHUB_TOKEN", secret_type="github_token",
            file_path="a.py", is_blocking=True,
        )
        finding_b = _make_finding(
            rule_id="R002_AWS_ACCESS_KEY", secret_type="aws_access_key",
            file_path="b.py", is_blocking=True,
        )
        plan1 = _make_plan(findings=[finding_a, finding_b])
        plan2 = _make_plan(findings=[finding_b, finding_a])
        codes1 = [g["action_code"] for g in plan1["repair_groups"]]
        codes2 = [g["action_code"] for g in plan2["repair_groups"]]
        assert codes1 == codes2

    # --- Group ID assignment ---

    def test_group_ids_are_sequential(self):
        finding = _make_finding(is_blocking=True)
        plan = _make_plan(findings=[finding])
        group_ids = [g["group_id"] for g in plan["repair_groups"]]
        for idx, gid in enumerate(group_ids):
            assert gid == f"RG{idx + 1:03d}"

    # --- Consistency validation errors ---

    def test_unsupported_assessment_policy_raises_error(self):
        finding = _make_finding(is_blocking=False)
        scan_result = _make_scan_result(findings=[finding])
        assessment = _make_assessment("test-task-id")
        with pytest.raises(RepairPlanInternalError):
            generate_repair_plan(
                task_id="test-task-id",
                scan_result=scan_result,
                summary=scan_result["summary"],
                scan_updated_at="2026-01-01T00:00:00Z",
                assessment=assessment,
                assessment_updated_at="2026-01-01T00:00:00Z",
                assessment_policy_version="p0-5-v1",  # 不支持
                source_scan_updated_at="2026-01-01T00:00:00Z",
            )

    def test_task_id_mismatch_raises_error(self):
        finding = _make_finding(is_blocking=False)
        scan_result = _make_scan_result(findings=[finding])
        assessment = _make_assessment("different-task-id")
        with pytest.raises(RepairPlanInternalError):
            generate_repair_plan(
                task_id="test-task-id",
                scan_result=scan_result,
                summary=scan_result["summary"],
                scan_updated_at="2026-01-01T00:00:00Z",
                assessment=assessment,
                assessment_updated_at="2026-01-01T00:00:00Z",
                assessment_policy_version="p0-6-v1",
                source_scan_updated_at="2026-01-01T00:00:00Z",
            )

    def test_scan_timestamp_mismatch_raises_error(self):
        finding = _make_finding(is_blocking=False)
        scan_result = _make_scan_result(findings=[finding])
        assessment = _make_assessment("test-task-id")
        with pytest.raises(RepairPlanInternalError):
            generate_repair_plan(
                task_id="test-task-id",
                scan_result=scan_result,
                summary=scan_result["summary"],
                scan_updated_at="2026-01-01T00:00:00Z",
                assessment=assessment,
                assessment_updated_at="2026-01-01T00:00:00Z",
                assessment_policy_version="p0-6-v1",
                source_scan_updated_at="2026-01-02T00:00:00Z",  # 不匹配
            )
