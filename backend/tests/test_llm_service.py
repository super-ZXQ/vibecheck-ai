"""P1-4 LLM 分析服务单元测试。

覆盖 llm_service.py 的核心功能：
1. 回退模板查找（所有已知规则 + 未知规则）
2. 非阻断 finding 提取（过滤 R001-R005 阻断型）
3. LLM 提示词构建（安全字段，截断）
4. LLM 响应解析（JSON、markdown fence、无效格式）
5. 分析项生成（LLM 成功、LLM 失败回退、LLM 禁用）
6. 持久化与检索
7. 可用性检查
8. 非阻断契约（generate_and_save_llm_analysis 不抛出异常）
"""

import json
from unittest.mock import patch, MagicMock

import pytest

from app.db import database
from app.services import llm_service
from app.services.llm_fallback_templates import (
    get_fallback_template,
    GENERIC_FALLBACK,
    FALLBACK_TEMPLATES,
)
from app.services.llm_service import (
    SCHEMA_VERSION,
    _build_llm_prompt,
    _call_llm_api,
    _extract_non_blocking_findings,
    _generate_analysis_item,
    _is_blocking_finding,
    _parse_llm_response,
    generate_and_save_llm_analysis,
    get_llm_analysis,
    get_llm_analysis_available,
    get_llm_analysis_summary,
)


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


# ---------------------------------------------------------------------------
# --- Fallback templates ---
# ---------------------------------------------------------------------------

class TestFallbackTemplates:

    def test_known_rule_returns_template(self):
        """已知规则 ID 返回非 None 模板。"""
        template = get_fallback_template("R006_PASSWORD_ASSIGNMENT")
        assert template is not None
        assert template.explanation
        assert template.instruction

    def test_unknown_rule_returns_none(self):
        """未知规则 ID 返回 None。"""
        template = get_fallback_template("UNKNOWN_RULE")
        assert template is None

    def test_generic_fallback_has_content(self):
        """通用回退模板有内容。"""
        assert GENERIC_FALLBACK.explanation
        assert GENERIC_FALLBACK.instruction

    def test_all_non_blocking_rules_have_templates(self):
        """所有非阻断规则都有回退模板。"""
        # R006-R009, R011 (R010 是 notice，不需要)
        # I001-I005
        # D001-D010
        # B001-B005
        # C001-C004
        expected_rules = [
            "R006_PASSWORD_ASSIGNMENT",
            "R007_GENERIC_TOKEN_ASSIGNMENT",
            "R008_CONNECTION_STRING",
            "R009_ENV_FILE_PRESENT",
            "R011_PRODUCTION_ENV_WITH_SECRET",
            "I001_TODO_COMMENT",
            "I002_UNIMPLEMENTED_CODE",
            "I003_PLACEHOLDER_RETURN",
            "I004_DEBUG_BREAKPOINT",
            "I005_EXCESSIVE_DEBUG_OUTPUT",
            "D001_PRODUCTION_START",
            "D002_ENVIRONMENT_DOCUMENTATION",
            "D003_DEPENDENCY_LOCK",
            "D004_DEPLOYMENT_DOCUMENTATION",
            "D005_DOCKER_MISSING",
            "D006_DOCKER_MISSING_FROM",
            "D007_DOCKER_MUTABLE_BASE",
            "D008_DOCKER_ROOT_USER",
            "D009_DOCKER_MISSING_START",
            "D010_INVALID_DEPLOYMENT_CONFIG",
            "B001_API_AUTHENTICATION",
            "B002_INPUT_VALIDATION",
            "B003_RATE_LIMITING",
            "B004_PERMISSIVE_CORS",
            "B005_SQL_INJECTION",
            "C001_README_COMPLETENESS",
            "C002_TECH_STACK_MISMATCH",
            "C003_START_COMMAND_MISMATCH",
            "C004_PROJECT_STRUCTURE_MISMATCH",
        ]
        for rule_id in expected_rules:
            assert rule_id in FALLBACK_TEMPLATES, (
                f"Missing fallback template for {rule_id}"
            )

    def test_blocking_rules_not_in_templates(self):
        """阻断规则 R001-R005 不在回退模板中。"""
        blocking_rules = [
            "R001_GITHUB_TOKEN",
            "R002_AWS_ACCESS_KEY",
            "R003_AWS_SECRET_KEY",
            "R004_GOOGLE_API_KEY",
            "R005_PRIVATE_KEY",
        ]
        for rule_id in blocking_rules:
            assert rule_id not in FALLBACK_TEMPLATES, (
                f"Blocking rule {rule_id} should not have fallback template"
            )


# ---------------------------------------------------------------------------
# --- Blocking finding check ---
# ---------------------------------------------------------------------------

class TestBlockingCheck:

    def test_r001_is_blocking(self):
        assert _is_blocking_finding("R001_GITHUB_TOKEN") is True

    def test_r005_is_blocking(self):
        assert _is_blocking_finding("R005_PRIVATE_KEY") is True

    def test_r006_is_not_blocking(self):
        assert _is_blocking_finding("R006_PASSWORD_ASSIGNMENT") is False

    def test_i001_is_not_blocking(self):
        assert _is_blocking_finding("I001_TODO_COMMENT") is False

    def test_d001_is_not_blocking(self):
        assert _is_blocking_finding("D001_PRODUCTION_START") is False


# ---------------------------------------------------------------------------
# --- Finding extraction ---
# ---------------------------------------------------------------------------

class TestFindingExtraction:

    def test_empty_findings(self):
        result = _extract_non_blocking_findings({"findings": []})
        assert result == []

    def test_no_findings_key(self):
        result = _extract_non_blocking_findings({})
        assert result == []

    def test_filters_blocking_findings(self):
        """R001-R005 被过滤掉。"""
        scan_result = {
            "findings": [
                {"rule_id": "R001_GITHUB_TOKEN", "severity": "critical"},
                {"rule_id": "R006_PASSWORD_ASSIGNMENT", "severity": "high"},
                {"rule_id": "I001_TODO_COMMENT", "severity": "medium"},
            ]
        }
        result = _extract_non_blocking_findings(scan_result)
        assert len(result) == 2
        assert result[0]["rule_id"] == "R006_PASSWORD_ASSIGNMENT"
        assert result[1]["rule_id"] == "I001_TODO_COMMENT"

    def test_sorts_by_severity(self):
        """按严重级别排序（critical > high > medium > low > info）。"""
        scan_result = {
            "findings": [
                {"rule_id": "I001_TODO_COMMENT", "severity": "medium"},
                {"rule_id": "D005_DOCKER_MISSING", "severity": "low"},
                {"rule_id": "I002_UNIMPLEMENTED_CODE", "severity": "high"},
            ]
        }
        result = _extract_non_blocking_findings(scan_result)
        assert result[0]["severity"] == "high"
        assert result[1]["severity"] == "medium"
        assert result[2]["severity"] == "low"

    def test_limits_findings_count(self, monkeypatch):
        """超过 llm_max_findings_per_task 限制时截断。"""
        monkeypatch.setattr(
            "app.core.config.settings.llm_max_findings_per_task", 2
        )
        findings = [
            {"rule_id": f"I00{i}_TEST", "severity": "low"}
            for i in range(5)
        ]
        result = _extract_non_blocking_findings({"findings": findings})
        assert len(result) == 2

    def test_invalid_findings_skipped(self):
        """非 dict 或无 rule_id 的 finding 被跳过。"""
        scan_result = {
            "findings": [
                "not a dict",
                {"no_rule_id": True},
                {"rule_id": "I001_TODO_COMMENT", "severity": "medium"},
                {"rule_id": 123, "severity": "low"},
            ]
        }
        result = _extract_non_blocking_findings(scan_result)
        assert len(result) == 1
        assert result[0]["rule_id"] == "I001_TODO_COMMENT"


# ---------------------------------------------------------------------------
# --- LLM prompt building ---
# ---------------------------------------------------------------------------

class TestPromptBuilding:

    def test_prompt_contains_rule_id(self):
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Unfinished work comment",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO: fix this",
            "description": "TODO comment found",
            "severity": "medium",
        }
        prompt = _build_llm_prompt(finding)
        assert "I001_TODO_COMMENT" in prompt

    def test_prompt_contains_snippet(self):
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Test",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO: fix this",
            "description": "desc",
            "severity": "medium",
        }
        prompt = _build_llm_prompt(finding)
        assert "# TODO: fix this" in prompt

    def test_prompt_truncates_long_snippet(self):
        """超长 snippet 被截断。"""
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Test",
            "file_path": "src/app.py",
            "snippet_masked": "x" * 1000,
            "description": "desc",
            "severity": "medium",
        }
        prompt = _build_llm_prompt(finding)
        # Should be truncated (500 chars + "...")
        assert "..." in prompt
        assert len(prompt) < 2000


# ---------------------------------------------------------------------------
# --- LLM response parsing ---
# ---------------------------------------------------------------------------

class TestResponseParsing:

    def test_valid_json(self):
        content = '{"explanation": "这是一个问题", "instruction": "这样修复"}'
        result = _parse_llm_response(content)
        assert result is not None
        assert result["explanation"] == "这是一个问题"
        assert result["instruction"] == "这样修复"

    def test_json_with_code_fence(self):
        content = '```json\n{"explanation": "问题", "instruction": "修复"}\n```'
        result = _parse_llm_response(content)
        assert result is not None
        assert result["explanation"] == "问题"
        assert result["instruction"] == "修复"

    def test_json_with_plain_fence(self):
        content = '```\n{"explanation": "问题", "instruction": "修复"}\n```'
        result = _parse_llm_response(content)
        assert result is not None

    def test_invalid_json(self):
        result = _parse_llm_response("not json at all")
        assert result is None

    def test_empty_content(self):
        result = _parse_llm_response("")
        assert result is None

    def test_none_content(self):
        result = _parse_llm_response(None)
        assert result is None

    def test_missing_fields(self):
        content = '{"explanation": "only explanation"}'
        result = _parse_llm_response(content)
        assert result is None

    def test_empty_fields(self):
        content = '{"explanation": "", "instruction": ""}'
        result = _parse_llm_response(content)
        assert result is None

    def test_truncates_long_explanation(self, monkeypatch):
        """超长 explanation 被截断。"""
        monkeypatch.setattr(
            "app.core.config.settings.llm_max_explanation_chars", 10
        )
        content = '{"explanation": "abcdefghijklmnopqrstuvwxyz", "instruction": "fix"}'
        result = _parse_llm_response(content)
        assert result is not None
        assert len(result["explanation"]) == 10


# ---------------------------------------------------------------------------
# --- LLM API call ---
# ---------------------------------------------------------------------------

class TestLLMAPICall:

    def test_disabled_returns_none(self, monkeypatch):
        """LLM 禁用时返回 None。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        result = _call_llm_api("test prompt")
        assert result is None

    def test_no_base_url_returns_none(self, monkeypatch):
        """缺少 base_url 时返回 None。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr("app.core.config.settings.llm_base_url", None)
        result = _call_llm_api("test prompt")
        assert result is None

    def test_no_api_key_returns_none(self, monkeypatch):
        """缺少 api_key 时返回 None。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr(
            "app.core.config.settings.llm_base_url", "https://api.test.com"
        )
        monkeypatch.setattr("app.core.config.settings.llm_api_key", None)
        result = _call_llm_api("test prompt")
        assert result is None

    def test_no_model_returns_none(self, monkeypatch):
        """缺少 model 时返回 None。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr(
            "app.core.config.settings.llm_base_url", "https://api.test.com"
        )
        monkeypatch.setattr(
            "app.core.config.settings.llm_api_key", "test-key"
        )
        monkeypatch.setattr("app.core.config.settings.llm_model", "")
        result = _call_llm_api("test prompt")
        assert result is None


# ---------------------------------------------------------------------------
# --- Analysis item generation ---
# ---------------------------------------------------------------------------

class TestAnalysisItem:

    def test_llm_disabled_uses_fallback(self, monkeypatch):
        """LLM 禁用时使用回退模板。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Unfinished work comment",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO: fix",
            "severity": "medium",
        }
        item = _generate_analysis_item(finding, use_llm=False)
        assert item["source"] == "fallback"
        assert item["rule_id"] == "I001_TODO_COMMENT"
        assert item["explanation"]
        assert item["instruction"]

    def test_llm_success_returns_llm_source(self, monkeypatch):
        """LLM 调用成功时返回 llm 来源。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr(
            "app.services.llm_service._call_llm_api",
            lambda prompt, user_config=None: '{"explanation": "LLM解释", "instruction": "LLM修复"}',
        )
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Test",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO",
            "severity": "medium",
        }
        item = _generate_analysis_item(finding, use_llm=True)
        assert item["source"] == "llm"
        assert item["explanation"] == "LLM解释"
        assert item["instruction"] == "LLM修复"

    def test_llm_failure_falls_back(self, monkeypatch):
        """LLM 调用失败时回退到模板。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr(
            "app.services.llm_service._call_llm_api",
            lambda prompt, user_config=None: None,
        )
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Test",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO",
            "severity": "medium",
        }
        item = _generate_analysis_item(finding, use_llm=True)
        assert item["source"] == "fallback"
        assert item["explanation"]

    def test_llm_invalid_response_falls_back(self, monkeypatch):
        """LLM 返回无效 JSON 时回退到模板。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr(
            "app.services.llm_service._call_llm_api",
            lambda prompt, user_config=None: "not json",
        )
        finding = {
            "rule_id": "I001_TODO_COMMENT",
            "rule_name": "Test",
            "file_path": "src/app.py",
            "snippet_masked": "# TODO",
            "severity": "medium",
        }
        item = _generate_analysis_item(finding, use_llm=True)
        assert item["source"] == "fallback"

    def test_unknown_rule_uses_generic_fallback(self, monkeypatch):
        """未知规则使用通用回退模板。"""
        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        finding = {
            "rule_id": "UNKNOWN_RULE_X",
            "rule_name": "Unknown",
            "file_path": "src/app.py",
            "snippet_masked": "code",
            "severity": "low",
        }
        item = _generate_analysis_item(finding, use_llm=False)
        assert item["source"] == "fallback"
        assert item["explanation"] == GENERIC_FALLBACK.explanation


# ---------------------------------------------------------------------------
# --- Persistence and retrieval ---
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_available_false_when_no_result(self, test_db):
        """无结果时可用性检查返回 False。"""
        from app.services.task_manager import create_task
        task = create_task("https://github.com/test/repo", "test", "repo")
        assert get_llm_analysis_available(task.id) is False

    def test_persist_and_retrieve(self, test_db):
        """持久化后能检索到结果。"""
        from app.services.task_manager import create_task
        from app.db.database import _get_connection, now_iso

        task = create_task("https://github.com/test/repo", "test", "repo")

        # Directly insert a scan result with one non-blocking finding
        scan_result_json = json.dumps({
            "findings": [
                {
                    "rule_id": "I001_TODO_COMMENT",
                    "rule_name": "Unfinished work comment",
                    "severity": "medium",
                    "confidence": "high",
                    "file_path": "src/app.py",
                    "line_start": 1,
                    "line_end": 1,
                    "column_start": 0,
                    "column_end": 10,
                    "snippet_masked": "# TODO: fix this",
                    "is_blocking": False,
                    "finding_type": "content",
                    "description": "TODO comment found",
                    "category": "incomplete",
                    "secret_type": "",
                    "message": "TODO comment",
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
                (task.id, 2, scan_result_json, summary_json,
                 1, 0, 0, 0, 0, 1, 1, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        # Generate LLM analysis (LLM disabled → fallback only)
        result = generate_and_save_llm_analysis(task.id)

        assert result is not None
        assert result["total_analyzed"] == 1
        assert result["total_fallback"] == 1
        assert result["total_llm"] == 0
        assert result["source"] == "fallback"
        assert len(result["items"]) == 1
        assert result["items"][0]["source"] == "fallback"
        assert result["items"][0]["rule_id"] == "I001_TODO_COMMENT"

        # Check availability
        assert get_llm_analysis_available(task.id) is True

        # Check retrieval
        retrieved = get_llm_analysis(task.id)
        assert retrieved is not None
        assert retrieved["total_analyzed"] == 1
        assert len(retrieved["items"]) == 1

        # Check summary
        summary = get_llm_analysis_summary(task.id)
        assert summary is not None
        assert summary["total_analyzed"] == 1
        assert summary["total_fallback"] == 1
        assert summary["source"] == "fallback"

    def test_empty_findings_persists_empty_result(self, test_db):
        """无非阻断 finding 时持久化空结果。"""
        from app.services.task_manager import create_task
        from app.db.database import _get_connection, now_iso

        task = create_task("https://github.com/test/repo", "test", "repo")
        scan_result_json = json.dumps({
            "findings": [], "notices": [],
            "skipped_files": [], "scan_errors": [],
        })
        summary_json = json.dumps({
            "total_findings": 0, "blocking_findings": 0,
            "total_notices": 0, "total_skipped_files": 0,
            "total_scan_errors": 0, "total_files_scanned": 0,
            "total_lines_scanned": 0,
            "returned_findings": 0, "findings_truncated": False,
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
                (task.id, 2, scan_result_json, summary_json,
                 0, 0, 0, 0, 0, 0, 0, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        result = generate_and_save_llm_analysis(task.id)
        assert result["total_analyzed"] == 0
        assert result["items"] == []
        assert get_llm_analysis_available(task.id) is True


# ---------------------------------------------------------------------------
# --- Non-blocking contract ---
# ---------------------------------------------------------------------------

class TestNonBlockingContract:

    def test_no_scan_result_returns_empty(self, test_db):
        """无扫描结果时返回空 dict，不抛出异常。"""
        from app.services.task_manager import create_task
        task = create_task("https://github.com/test/repo", "test", "repo")
        result = generate_and_save_llm_analysis(task.id)
        assert result == {}

    def test_internal_failure_returns_empty(self, test_db, monkeypatch):
        """内部错误时返回空 dict，不抛出异常。"""
        from app.services.task_manager import create_task
        task = create_task("https://github.com/test/repo", "test", "repo")

        # Mock get_scan_result to raise
        def _raise(task_id):
            raise RuntimeError("internal error")

        monkeypatch.setattr(
            "app.services.scan_result_service.get_scan_result", _raise
        )
        result = generate_and_save_llm_analysis(task.id)
        # Should not raise — returns empty dict or fallback result
        assert isinstance(result, dict)

    def test_persistence_failure_returns_empty(self, test_db, monkeypatch):
        """持久化失败时返回空 dict，不抛出异常。"""
        from app.services.task_manager import create_task
        from app.db.database import _get_connection, now_iso

        task = create_task("https://github.com/test/repo", "test", "repo")

        # Directly insert scan result into DB (bypassing serialize_scan_result
        # which expects a ScanResult object, not a dict).
        scan_result_json = json.dumps({
            "findings": [
                {
                    "rule_id": "I001_TODO_COMMENT",
                    "rule_name": "Test",
                    "severity": "medium",
                    "confidence": "high",
                    "file_path": "src/app.py",
                    "line_start": 1, "line_end": 1,
                    "column_start": 0, "column_end": 10,
                    "snippet_masked": "# TODO",
                    "is_blocking": False,
                    "finding_type": "content",
                    "description": "desc",
                    "category": "incomplete",
                    "secret_type": "",
                    "message": "msg",
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
                (task.id, 2, scan_result_json, summary_json,
                 1, 0, 0, 0, 0, 1, 1, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        # Mock _save_llm_analysis to raise
        def _raise_save(*args, **kwargs):
            raise RuntimeError("DB error")

        monkeypatch.setattr(
            "app.services.llm_service._save_llm_analysis", _raise_save
        )
        result = generate_and_save_llm_analysis(task.id)
        # Should not raise — returns empty dict
        assert isinstance(result, dict)
