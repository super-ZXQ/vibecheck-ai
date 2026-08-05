"""P0-7 repair plan security boundary tests.

覆盖范围:
C. 脱敏边界测试 (TestDesensitization)
   - 修复计划 JSON 不含原始密钥模式 (ghp_, AKIA, AIza)
   - 修复计划 JSON 不含 snippet_masked 字段值
   - agent_prompt 不含 snippet_masked 值
   - 修复计划 JSON 不含 repo_url / owner / repo_name / github.com
   - 修复计划 JSON 不含数据库路径
   - 修复计划 JSON 不含临时路径
   - 严格类型校验: 非字符串 rule_id 被拒绝
   - 严格类型校验: 非整数 line_start 被拒绝
   - 严格类型校验: 非布尔 is_blocking 被拒绝

D. 命令安全测试 (TestCommandSafety)
   - 无 echo $TOKEN / echo $ 命令
   - 无 printenv 命令
   - 无 git grep -n 输出匹配行命令
   - 无 git push --force / git push -f 命令
   - 无 git reset --hard 命令
   - 无 git clean -fd / git clean -f 命令
   - 无 rm -rf / rm -r 命令
   - 无 git-filter-repo 命令
   - 无 BFG / bfg 命令
   - 所有命令来自固定白名单
   - VERIFY_NO_SECRET_REMAINS 分组命令安全
   - CLEAN_GIT_HISTORY 分组命令安全
   - REVIEW_SECRET_USAGE 分组命令安全

E. 部分计划测试 (TestPartialPlan)
   - findings_truncated -> partial
   - scan_errors -> partial
   - no_files_scanned -> partial
   - coverage_partial -> partial
   - blocking_count_mismatch -> partial
   - groups_truncated -> partial
   - related_files_truncated -> partial
   - unknown_template -> partial + MANUAL_REVIEW_REQUIRED
   - partial 计划包含 PARTIAL_DECLARATION
   - complete 计划不含 PARTIAL_DECLARATION

I. 配置限制测试 (TestConfigLimits)
   - 默认 repair_max_groups = 200
   - 默认 repair_max_related_files_per_group = 100
   - 默认 repair_max_agent_prompt_chars = 65536
   - 默认 repair_max_json_bytes = 2MB
   - 运行时配置为 0 时 max(1, int(value)) 防御
"""

from __future__ import annotations

import json

import pytest

from app.core.config import settings
from app.db import database
from app.services.repair_policy import *
from app.services.repair_policy import (
    _COMMAND_ALLOWLIST,
    get_allowed_commands,
    is_command_allowed,
)
from app.services.repair_service import (
    RepairPlanInternalError,
    RepairPlanTooLargeError,
    generate_repair_plan,
    serialize_repair_plan,
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


def _make_scan_result(findings=None):
    return {
        "schema_version": 1, "findings": findings or [],
        "notices": [], "skipped_files": [], "scan_errors": [],
        "summary": {
            "total_findings": len(findings or []),
            "blocking_findings": sum(1 for f in findings or [] if f.get("is_blocking")),
            "total_notices": 0, "total_skipped_files": 0, "total_scan_errors": 0,
            "total_files_scanned": 10, "total_lines_scanned": 100,
            "returned_findings": len(findings or []), "findings_truncated": False,
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


def _generate_plan(findings=None):
    scan = _make_scan_result(findings)
    return generate_repair_plan(
        task_id="test-task", scan_result=scan, summary=scan["summary"],
        scan_updated_at="2026-01-01T00:00:00Z",
        assessment=_make_assessment("test-task"),
        assessment_updated_at="2026-01-01T00:00:00Z",
        assessment_policy_version="p0-6-v1",
        source_scan_updated_at="2026-01-01T00:00:00Z",
    )


def _generate_plan_custom(findings=None, summary_overrides=None,
                          assessment=None, task_id="test-task"):
    """带覆盖选项的计划生成辅助函数。"""
    scan = _make_scan_result(findings)
    if summary_overrides:
        scan["summary"].update(summary_overrides)
    return generate_repair_plan(
        task_id=task_id, scan_result=scan, summary=scan["summary"],
        scan_updated_at="2026-01-01T00:00:00Z",
        assessment=assessment or _make_assessment(task_id),
        assessment_updated_at="2026-01-01T00:00:00Z",
        assessment_policy_version="p0-6-v1",
        source_scan_updated_at="2026-01-01T00:00:00Z",
    )


def _serialize_plan(plan, task_id="test-task"):
    """序列化计划并返回安全 dict。"""
    return serialize_repair_plan(
        task_id=task_id,
        repair_plan=plan,
        source_scan_updated_at="2026-01-01T00:00:00Z",
        source_assessment_updated_at="2026-01-01T00:00:00Z",
        source_assessment_policy_version="p0-6-v1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )


def _serialize_to_json(plan, task_id="test-task"):
    """序列化计划并返回 JSON 字符串。"""
    safe_plan = _serialize_plan(plan, task_id=task_id)
    return json.dumps(safe_plan, ensure_ascii=False)


def _all_commands(plan):
    """收集所有修复分组中的所有命令。"""
    commands = []
    for group in plan["repair_groups"]:
        commands.extend(group.get("commands", []))
    return commands


def _all_text_from_plan(plan):
    """递归提取计划中所有字符串值，用于脱敏检查。"""
    texts = []

    def _extract(obj):
        if isinstance(obj, str):
            texts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _extract(v)
        elif isinstance(obj, list):
            for item in obj:
                _extract(item)

    _extract(plan)
    return texts


# ===========================================================================
# C. Desensitization tests
# ===========================================================================

class TestDesensitization:
    """脱敏边界测试: 确保修复计划输出不泄露敏感信息。"""

    # --- C1: No raw secret patterns in serialized JSON ---

    def test_repair_json_no_raw_secret(self):
        """序列化后的 JSON 不含 ghp_、AKIA、AIza 等原始密钥前缀。"""
        finding = _make_finding(secret_type="github_token")
        # _make_finding 默认包含 snippet_masked="ghp_****"
        plan = _generate_plan([finding])
        plan_json = _serialize_to_json(plan)

        # 原始密钥前缀不应出现在序列化输出中
        assert "ghp_" not in plan_json, "Raw GitHub token prefix leaked"
        assert "AKIA" not in plan_json, "Raw AWS key prefix leaked"
        assert "AIza" not in plan_json, "Raw Google API key prefix leaked"

    # --- C2: No snippet_masked values in serialized JSON ---

    def test_repair_json_no_snippet_masked(self):
        """序列化后的 JSON 不含 snippet_masked 字段或其值。"""
        finding = _make_finding()
        # snippet_masked 的值是 "ghp_****"
        plan = _generate_plan([finding])
        plan_json = _serialize_to_json(plan)

        # snippet_masked 字段名不应出现
        assert "snippet_masked" not in plan_json, (
            "snippet_masked field name leaked into serialized plan"
        )
        # snippet_masked 的值不应出现
        assert "ghp_****" not in plan_json, (
            "snippet_masked value leaked into serialized plan"
        )

    # --- C3: No snippet_masked values in agent_prompt ---

    def test_agent_prompt_no_snippet_masked(self):
        """agent_prompt 不含 snippet_masked 字段名或其值。"""
        finding = _make_finding()
        plan = _generate_plan([finding])
        safe_plan = _serialize_plan(plan)
        agent_prompt = safe_plan["agent_prompt"]

        assert "snippet_masked" not in agent_prompt, (
            "snippet_masked field name leaked into agent prompt"
        )
        assert "ghp_****" not in agent_prompt, (
            "snippet_masked value leaked into agent prompt"
        )

    # --- C4: No repo_url / owner / repo_name in serialized JSON ---

    def test_repair_json_no_repo_url(self):
        """序列化后的 JSON 不含 github.com、repo_url、owner、repo_name。"""
        finding = _make_finding()
        plan = _generate_plan([finding])
        plan_json = _serialize_to_json(plan)

        forbidden_patterns = [
            "github.com",
            "repo_url",
            "owner",
            "repo_name",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in plan_json, (
                f"Forbidden pattern '{pattern}' leaked into serialized plan"
            )

    # --- C5: No database path in serialized JSON ---

    def test_repair_json_no_db_path(self):
        """序列化后的 JSON 不含 vibecheck.db 或数据库路径。"""
        finding = _make_finding()
        plan = _generate_plan([finding])
        plan_json = _serialize_to_json(plan)

        assert "vibecheck.db" not in plan_json, (
            "Database path leaked into serialized plan"
        )
        assert "sqlite:///" not in plan_json, (
            "Database URL scheme leaked into serialized plan"
        )

    # --- C6: No temp path in serialized JSON ---

    def test_repair_json_no_temp_path(self):
        """序列化后的 JSON 不含 /tmp/、C:\\、临时目录路径。"""
        finding = _make_finding(file_path="config.py")
        plan = _generate_plan([finding])
        plan_json = _serialize_to_json(plan)

        forbidden_path_patterns = [
            "/tmp/",
            "/tmp/vibecheck",
            "C:\\",
            "C:/",
            "/var/tmp/",
            "/home/",
            "/Users/",
        ]
        for pattern in forbidden_path_patterns:
            assert pattern not in plan_json, (
                f"Temp path pattern '{pattern}' leaked into serialized plan"
            )

    # --- C7: Strict type validation rejects non-string rule_id ---

    def test_strict_type_validation_rejects_non_str(self):
        """Finding 的 rule_id 为非字符串时抛出 RepairPlanInternalError。"""
        finding = _make_finding()
        finding["rule_id"] = 12345  # int, not str
        with pytest.raises(RepairPlanInternalError):
            _generate_plan([finding])

    # --- C8: Strict type validation rejects non-int line_start ---

    def test_strict_type_validation_rejects_non_int(self):
        """Finding 的 line_start 为非整数时抛出 RepairPlanInternalError。"""
        finding = _make_finding()
        finding["line_start"] = "not_an_int"  # str, not int
        with pytest.raises(RepairPlanInternalError):
            _generate_plan([finding])

    # --- C9: Strict type validation rejects non-bool is_blocking ---

    def test_strict_type_validation_rejects_non_bool(self):
        """Finding 的 is_blocking 为非布尔时抛出 RepairPlanInternalError。"""
        finding = _make_finding()
        finding["is_blocking"] = "yes"  # str, not bool
        with pytest.raises(RepairPlanInternalError):
            _generate_plan([finding])


# ===========================================================================
# D. Command safety tests
# ===========================================================================

class TestCommandSafety:
    """命令安全测试: 确保修复计划中的命令不泄露密钥或执行危险操作。"""

    # --- D10: No echo $TOKEN or echo $ ---

    def test_no_echo_token(self):
        """无命令包含 echo $TOKEN 或 echo $。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        assert len(commands) > 0, "Expected commands from blocking finding"
        for cmd in commands:
            assert "echo $" not in cmd, (
                f"Command contains 'echo $': {cmd}"
            )
            assert "echo $TOKEN" not in cmd, (
                f"Command contains 'echo $TOKEN': {cmd}"
            )

    # --- D11: No printenv ---

    def test_no_printenv(self):
        """无命令包含 printenv。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "printenv" not in cmd, (
                f"Command contains 'printenv': {cmd}"
            )

    # --- D12: No git grep -n that outputs matched lines ---

    def test_no_grep_full_match(self):
        """无命令包含 git grep -n 输出匹配行。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "git grep" not in cmd, (
                f"Command contains 'git grep': {cmd}"
            )
            assert "grep -n" not in cmd, (
                f"Command contains 'grep -n': {cmd}"
            )

    # --- D13: No git push --force or git push -f ---

    def test_no_force_push(self):
        """无命令包含 git push --force 或 git push -f。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "git push --force" not in cmd, (
                f"Command contains 'git push --force': {cmd}"
            )
            assert "git push -f" not in cmd, (
                f"Command contains 'git push -f': {cmd}"
            )
            assert "push --force" not in cmd, (
                f"Command contains 'push --force': {cmd}"
            )

    # --- D14: No git reset --hard ---

    def test_no_reset_hard(self):
        """无命令包含 git reset --hard。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "git reset --hard" not in cmd, (
                f"Command contains 'git reset --hard': {cmd}"
            )
            assert "reset --hard" not in cmd, (
                f"Command contains 'reset --hard': {cmd}"
            )

    # --- D15: No git clean -fd or git clean -f ---

    def test_no_clean_fd(self):
        """无命令包含 git clean -fd 或 git clean -f。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "git clean -fd" not in cmd, (
                f"Command contains 'git clean -fd': {cmd}"
            )
            assert "git clean -f" not in cmd, (
                f"Command contains 'git clean -f': {cmd}"
            )
            assert "clean -fd" not in cmd, (
                f"Command contains 'clean -fd': {cmd}"
            )

    # --- D16: No rm -rf or rm -r ---

    def test_no_rm_rf(self):
        """无命令包含 rm -rf 或 rm -r。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "rm -rf" not in cmd, (
                f"Command contains 'rm -rf': {cmd}"
            )
            assert "rm -r " not in cmd, (
                f"Command contains 'rm -r': {cmd}"
            )

    # --- D17: No git-filter-repo ---

    def test_no_git_filter_repo(self):
        """无命令包含 git-filter-repo。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "git-filter-repo" not in cmd, (
                f"Command contains 'git-filter-repo': {cmd}"
            )
            assert "git filter-repo" not in cmd, (
                f"Command contains 'git filter-repo': {cmd}"
            )

    # --- D18: No BFG or bfg ---

    def test_no_bfg(self):
        """无命令包含 BFG 或 bfg。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        for cmd in commands:
            assert "BFG" not in cmd, (
                f"Command contains 'BFG': {cmd}"
            )
            assert "bfg" not in cmd, (
                f"Command contains 'bfg': {cmd}"
            )

    # --- D19: All commands from fixed allowlist ---

    def test_commands_from_allowlist(self):
        """所有修复分组中的命令均来自固定白名单。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        commands = _all_commands(plan)
        assert len(commands) > 0, "Expected commands from blocking finding"
        for cmd in commands:
            assert is_command_allowed(cmd), (
                f"Command not in allowlist: {cmd}"
            )
            assert cmd in _COMMAND_ALLOWLIST, (
                f"Command not in _COMMAND_ALLOWLIST: {cmd}"
            )

    # --- D20: VERIFY_NO_SECRET_REMAINS group commands are safe ---

    def test_verify_no_secret_commands_are_safe(self):
        """VERIFY_NO_SECRET_REMAINS 分组命令安全。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        verify_groups = [
            g for g in plan["repair_groups"]
            if g["action_code"] == ACTION_VERIFY_NO_SECRET_REMAINS
        ]
        assert len(verify_groups) >= 1, (
            "VERIFY_NO_SECRET_REMAINS group not found"
        )
        expected_cmds = get_allowed_commands(ACTION_VERIFY_NO_SECRET_REMAINS)
        for group in verify_groups:
            cmds = group["commands"]
            assert len(cmds) == len(expected_cmds), (
                f"Expected {len(expected_cmds)} commands, got {len(cmds)}"
            )
            for cmd in cmds:
                assert is_command_allowed(cmd), (
                    f"VERIFY_NO_SECRET_REMAINS command not allowed: {cmd}"
                )
            assert tuple(cmds) == expected_cmds, (
                f"VERIFY_NO_SECRET_REMAINS commands mismatch: {cmds}"
            )

    # --- D21: CLEAN_GIT_HISTORY group commands are safe ---

    def test_clean_history_commands_are_safe(self):
        """CLEAN_GIT_HISTORY 分组命令安全 (仅 git log --oneline -20)。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        clean_groups = [
            g for g in plan["repair_groups"]
            if g["action_code"] == ACTION_CLEAN_GIT_HISTORY
        ]
        assert len(clean_groups) >= 1, (
            "CLEAN_GIT_HISTORY group not found"
        )
        expected_cmds = get_allowed_commands(ACTION_CLEAN_GIT_HISTORY)
        for group in clean_groups:
            cmds = group["commands"]
            assert len(cmds) == len(expected_cmds), (
                f"Expected {len(expected_cmds)} commands, got {len(cmds)}"
            )
            for cmd in cmds:
                assert is_command_allowed(cmd), (
                    f"CLEAN_GIT_HISTORY command not allowed: {cmd}"
                )
            assert tuple(cmds) == expected_cmds, (
                f"CLEAN_GIT_HISTORY commands mismatch: {cmds}"
            )
            # 确认只有 git log --oneline -20
            assert cmds == ["git log --oneline -20"], (
                f"CLEAN_GIT_HISTORY should only have 'git log --oneline -20', "
                f"got: {cmds}"
            )

    # --- D22: REVIEW_SECRET_USAGE group commands are safe ---

    def test_review_usage_commands_are_safe(self):
        """REVIEW_SECRET_USAGE 分组命令安全。"""
        plan = _generate_plan([_make_finding(is_blocking=True)])
        review_groups = [
            g for g in plan["repair_groups"]
            if g["action_code"] == ACTION_REVIEW_SECRET_USAGE
        ]
        assert len(review_groups) >= 1, (
            "REVIEW_SECRET_USAGE group not found"
        )
        expected_cmds = get_allowed_commands(ACTION_REVIEW_SECRET_USAGE)
        for group in review_groups:
            cmds = group["commands"]
            assert len(cmds) == len(expected_cmds), (
                f"Expected {len(expected_cmds)} commands, got {len(cmds)}"
            )
            for cmd in cmds:
                assert is_command_allowed(cmd), (
                    f"REVIEW_SECRET_USAGE command not allowed: {cmd}"
                )
            assert tuple(cmds) == expected_cmds, (
                f"REVIEW_SECRET_USAGE commands mismatch: {cmds}"
            )


# ===========================================================================
# E. Partial plan tests
# ===========================================================================

class TestPartialPlan:
    """部分计划测试: 验证 partial 状态触发条件和 PARTIAL_DECLARATION。"""

    # --- E23: findings_truncated -> partial ---

    def test_findings_truncated(self):
        """scan summary findings_truncated=True -> plan_status=partial。"""
        plan = _generate_plan_custom(
            findings=[],
            summary_overrides={"findings_truncated": True},
        )
        assert plan["plan_status"] == "partial"

    # --- E24: scan_errors -> partial ---

    def test_scan_errors(self):
        """scan summary total_scan_errors>0 -> plan_status=partial。"""
        plan = _generate_plan_custom(
            findings=[],
            summary_overrides={"total_scan_errors": 1},
        )
        assert plan["plan_status"] == "partial"

    # --- E25: no_files_scanned -> partial ---

    def test_no_files_scanned(self):
        """scan summary total_files_scanned=0 -> plan_status=partial。"""
        plan = _generate_plan_custom(
            findings=[],
            summary_overrides={"total_files_scanned": 0},
        )
        assert plan["plan_status"] == "partial"

    # --- E26: coverage_partial -> partial ---

    def test_coverage_partial(self):
        """assessment coverage.status='partial' -> plan_status=partial。"""
        assessment = _make_assessment("test-task")
        assessment["coverage"]["status"] = "partial"
        plan = _generate_plan_custom(
            findings=[],
            assessment=assessment,
        )
        assert plan["plan_status"] == "partial"

    # --- E27: blocking_count_mismatch -> partial ---

    def test_blocking_count_mismatch(self):
        """summary.blocking_findings > 实际 blocking 发现数 -> partial。"""
        finding = _make_finding(is_blocking=True)
        plan = _generate_plan_custom(
            findings=[finding],
            summary_overrides={"blocking_findings": 5},
        )
        assert plan["plan_status"] == "partial"

    # --- E28: groups_truncated -> partial ---

    def test_groups_truncated(self, monkeypatch):
        """repair groups 超过上限 -> plan_status=partial。"""
        monkeypatch.setattr("app.core.config.settings.repair_max_groups", 3)
        # 4 个不同模板产生 4+ 个独立分组
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
        plan = _generate_plan(findings)
        assert plan["plan_status"] == "partial"
        assert plan["summary"]["groups_truncated"] is True

    # --- E29: related_files_truncated -> partial ---

    def test_related_files_truncated(self, monkeypatch):
        """related_files 超过上限 -> plan_status=partial。"""
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
        plan = _generate_plan(findings)
        assert plan["plan_status"] == "partial"

    # --- E30: unknown_template -> partial + MANUAL_REVIEW_REQUIRED ---

    def test_unknown_template(self):
        """未知 repair_template_key -> partial + MANUAL_REVIEW_REQUIRED。"""
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="unknown_template",
            rule_id="R999_UNKNOWN",
            secret_type="unknown",
        )
        plan = _generate_plan([finding])
        assert plan["plan_status"] == "partial"
        action_codes = [g["action_code"] for g in plan["repair_groups"]]
        assert ACTION_MANUAL_REVIEW_REQUIRED in action_codes
        assert plan["summary"]["manual_review_required"] is True

    # --- E31: partial plan contains PARTIAL_DECLARATION ---

    def test_partial_declaration_in_plan(self):
        """partial 计划包含 PARTIAL_DECLARATION 文本。"""
        plan = _generate_plan_custom(
            findings=[],
            summary_overrides={"findings_truncated": True},
        )
        assert plan["plan_status"] == "partial"
        # PARTIAL_DECLARATION 应出现在 agent_prompt 或 verification_steps 中
        assert (
            PARTIAL_DECLARATION in plan["agent_prompt"]
            or any(PARTIAL_DECLARATION in step for step in plan["verification_steps"])
        ), "PARTIAL_DECLARATION not found in partial plan"

    # --- E32: complete plan does NOT contain PARTIAL_DECLARATION ---

    def test_complete_plan_no_partial_declaration(self):
        """complete 计划不含 PARTIAL_DECLARATION 文本。"""
        finding = _make_finding(
            is_blocking=False,
            repair_template_key="use_env_var_password",
            rule_id="R006_PASSWORD_ASSIGNMENT",
            secret_type="password",
        )
        plan = _generate_plan([finding])
        assert plan["plan_status"] == "complete"
        assert PARTIAL_DECLARATION not in plan["agent_prompt"]
        assert not any(
            PARTIAL_DECLARATION in step for step in plan["verification_steps"]
        )


# ===========================================================================
# I. Config limit tests
# ===========================================================================

class TestConfigLimits:
    """配置限制测试: 验证默认值和运行时防御。"""

    # --- I33: Default repair_max_groups is 200 ---

    def test_groups_default_200(self):
        """默认 repair_max_groups 为 200。"""
        assert settings.repair_max_groups == 200

    # --- I34: Default repair_max_related_files_per_group is 100 ---

    def test_related_files_default_100(self):
        """默认 repair_max_related_files_per_group 为 100。"""
        assert settings.repair_max_related_files_per_group == 100

    # --- I35: Default repair_max_agent_prompt_chars is 65536 ---

    def test_prompt_default_65536(self):
        """默认 repair_max_agent_prompt_chars 为 65536。"""
        assert settings.repair_max_agent_prompt_chars == 65536

    # --- I36: Default repair_max_json_bytes is 2MB ---

    def test_json_default_2mb(self):
        """默认 repair_max_json_bytes 为 2*1024*1024。"""
        assert settings.repair_max_json_bytes == 2 * 1024 * 1024

    # --- I37: Config zero defense via max(1, int(value)) ---

    def test_config_zero_defense(self, monkeypatch):
        """运行时将配置设为 0 时, max(1, int(0)) = 1 防御生效。

        当 repair_max_groups 被钳制为 1 且存在 mandatory groups（blocking
        finding 产生的 VERIFY_NO_SECRET_REMAINS + RERUN_SECURITY_SCAN）时，
        mandatory groups 数量超过 max_groups，正确抛出 RepairPlanTooLargeError
        而非静默丢弃安全动作。
        """
        monkeypatch.setattr("app.core.config.settings.repair_max_groups", 0)
        monkeypatch.setattr("app.core.config.settings.repair_max_related_files_per_group", 0)
        monkeypatch.setattr("app.core.config.settings.repair_max_agent_prompt_chars", 0)
        monkeypatch.setattr("app.core.config.settings.repair_max_json_bytes", 0)
        # _make_finding() 默认 is_blocking=True，会产生 mandatory singleton
        # groups (VERIFY_NO_SECRET_REMAINS + RERUN_SECURITY_SCAN = 2 个)。
        # max_groups 被钳制为 1，2 > 1 -> RepairPlanTooLargeError
        with pytest.raises(RepairPlanTooLargeError):
            _generate_plan([_make_finding()])
