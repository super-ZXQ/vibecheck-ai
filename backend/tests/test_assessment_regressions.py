r"""P0-6 安全评估引擎回归测试。

覆盖以下边界情况和安全回归测试：

1. SQL 注入文本在发现项字段中不影响评估
2. assessment_json 不包含原始密钥模式（ghp_, AKIA 等）
3. assessment_json 不包含临时路径（/tmp/, C:\）
4. 大量发现项（100+）不会崩溃
5. 同一 rule_id 混合严重级别使用正确的 rule_cap（最高严重级别）
6. blocking_reasons 只包含允许的字段
7. blocking_reasons 不包含 snippet_masked, secret_type, message 等
8. score 永远不低于 0 且不高于 100
9. verdict 只能是 pass/warning/blocked 之一
"""

import copy
import json

import pytest

from app.db import database
from app.services.assessment_service import assess_scan_result

# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """设置临时测试数据库。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_finding_dict(**kwargs):
    """创建一个发现项字典（持久化格式，非 Finding 数据类）。"""
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


# 运行时构造的格式正确但非真实的合成密钥（与 conftest.py 一致）
_MIXED_CHARS = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_RAW_GITHUB_TOKEN = "ghp_" + _MIXED_CHARS[:36]
_RAW_AWS_KEY = "AKIA" + "ABCDEF1234567890GHIJKLMNOP"[:16]
_RAW_GOOGLE_KEY = "AIza" + _MIXED_CHARS[:35]


# ============================================================
# 1. SQL 注入测试
# ============================================================

class TestSqlInjectionRegression:
    """SQL 注入文本在发现项字段中不影响评估。"""

    def test_sql_injection_in_file_path(self):
        """file_path 中的 SQL 注入文本不影响评估。"""
        malicious = "'; DROP TABLE assessment_results; --"
        finding = _make_finding_dict(
            rule_id="R_SQL_PATH",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path=malicious,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        # 评估应正常完成
        assert result["score"] is not None
        assert result["verdict"] == "blocked"
        # 恶意文本原样保留在 blocking_reasons 中（未被执行）
        assert any(malicious in r["file_path"] for r in result["blocking_reasons"])

    def test_sql_injection_in_description(self):
        """description 中的 SQL 注入文本不影响评估。"""
        malicious = "'); DELETE FROM scan_results; SELECT '"
        finding = _make_finding_dict(
            rule_id="R_SQL_DESC",
            severity="critical",
            confidence="high",
            is_blocking=True,
            description=malicious,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert any(malicious in r["description"] for r in result["blocking_reasons"])

    def test_sql_injection_in_rule_id(self):
        """rule_id 中的 SQL 注入文本不影响评估。"""
        malicious = "R001' OR '1'='1"
        finding = _make_finding_dict(
            rule_id=malicious,
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        # rule_id 出现在 score_breakdown 和 blocking_reasons 中
        assert any(e["rule_id"] == malicious for e in result["score_breakdown"])

    def test_sql_injection_in_rule_name(self):
        """rule_name 中的 SQL 注入文本不影响评估。"""
        malicious = "'; UPDATE tasks SET status='hacked'; --"
        finding = _make_finding_dict(
            rule_id="R_SQL_NAME",
            rule_name=malicious,
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert any(malicious in r["rule_name"] for r in result["blocking_reasons"])

    def test_sql_injection_json_serializable(self):
        """包含 SQL 注入文本的评估结果可正确 JSON 序列化。"""
        malicious = "'; DROP TABLE x; --"
        finding = _make_finding_dict(
            rule_id="R_SQL_JSON",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path=malicious,
            description=malicious,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        # 应该能序列化为 JSON 而不报错
        json_str = json.dumps(result, ensure_ascii=False, sort_keys=True)
        parsed = json.loads(json_str)
        assert parsed == result


# ============================================================
# 2. 密钥泄露测试
# ============================================================

class TestNoSecretLeakage:
    """assessment_json 不包含原始密钥模式。"""

    def test_no_raw_github_token_in_assessment(self):
        """assessment_json 不包含原始 GitHub Token。

        即使输入的 snippet_masked 包含原始 token，
        评估引擎不使用 snippet_masked 字段，
        所以原始 token 不应出现在评估结果中。
        """
        finding = _make_finding_dict(
            rule_id="R_TOKEN",
            severity="critical",
            confidence="high",
            is_blocking=True,
            snippet_masked=_RAW_GITHUB_TOKEN,  # 原始 token 在 snippet 中
            description="GitHub token found",  # 干净的 description
            secret_type="github_token",
            message=f"Remove {_RAW_GITHUB_TOKEN} now",  # 原始 token 在 message 中
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result, ensure_ascii=False)
        assert _RAW_GITHUB_TOKEN not in json_str

    def test_no_raw_aws_key_in_assessment(self):
        """assessment_json 不包含原始 AWS 密钥。"""
        finding = _make_finding_dict(
            rule_id="R_AWS",
            severity="critical",
            confidence="high",
            is_blocking=True,
            snippet_masked=_RAW_AWS_KEY,
            secret_type="aws_access_key",
            description="AWS key found",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result, ensure_ascii=False)
        assert _RAW_AWS_KEY not in json_str

    def test_no_raw_google_key_in_assessment(self):
        """assessment_json 不包含原始 Google API 密钥。"""
        finding = _make_finding_dict(
            rule_id="R_GOOGLE",
            severity="critical",
            confidence="high",
            is_blocking=True,
            snippet_masked=_RAW_GOOGLE_KEY,
            secret_type="google_api_key",
            description="Google key found",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result, ensure_ascii=False)
        assert _RAW_GOOGLE_KEY not in json_str

    def test_no_secret_in_score_breakdown(self):
        """score_breakdown 中不包含原始密钥。

        score_breakdown 包含 description 字段（引擎生成的），
        但不应包含来自发现项的 snippet_masked 或 secret_type。
        """
        finding = _make_finding_dict(
            rule_id="R_SECRET_BREAKDOWN",
            severity="critical",
            confidence="high",
            is_blocking=False,
            snippet_masked=_RAW_GITHUB_TOKEN,
            secret_type="github_token",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result["score_breakdown"], ensure_ascii=False)
        assert _RAW_GITHUB_TOKEN not in json_str
        assert "github_token" not in json_str  # secret_type 不在 breakdown 中

    def test_no_secret_in_coverage(self):
        """coverage 中不包含原始密钥。"""
        finding = _make_finding_dict(
            rule_id="R_SECRET_COV",
            severity="critical",
            confidence="high",
            is_blocking=True,
            snippet_masked=_RAW_GITHUB_TOKEN,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result["coverage"], ensure_ascii=False)
        assert _RAW_GITHUB_TOKEN not in json_str

    def test_no_secret_in_score_caps(self):
        """score_caps 中不包含原始密钥。"""
        finding = _make_finding_dict(
            rule_id="R_SECRET_CAPS",
            severity="critical",
            confidence="high",
            is_blocking=True,
            snippet_masked=_RAW_GITHUB_TOKEN,
        )
        scan_result = _make_scan_result([finding])
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result["score_caps"], ensure_ascii=False)
        assert _RAW_GITHUB_TOKEN not in json_str


# ============================================================
# 3. 临时路径泄露测试
# ============================================================

class TestNoTempPathLeakage:
    r"""assessment_json 不包含临时路径（/tmp/, C:\）。"""

    def test_no_temp_path_in_clean_assessment(self):
        """干净输入的评估结果不包含临时路径。"""
        finding = _make_finding_dict(
            rule_id="R_CLEAN",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="src/config.py",  # 干净路径
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result, ensure_ascii=False)
        assert "/tmp/" not in json_str
        assert "C:\\" not in json_str
        assert "C:/" not in json_str
        assert "/var/" not in json_str

    def test_engine_generated_text_no_temp_path(self):
        """引擎生成的描述文本不包含临时路径。

        score_breakdown 的 description 和 coverage 的 reasons
        是引擎内部生成的，不应包含任何文件系统路径。
        """
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        scan_result["summary"]["total_scan_errors"] = 1
        result = assess_scan_result("test-task", scan_result)

        # 检查 score_breakdown 描述
        for entry in result["score_breakdown"]:
            assert "/tmp/" not in entry.get("description", "")
            assert "C:\\" not in entry.get("description", "")

        # 检查 coverage reasons
        for reason in result["coverage"]["reasons"]:
            assert "/tmp/" not in reason
            assert "C:\\" not in reason

        # 检查 score_caps 描述
        for cap in result["score_caps"]:
            assert "/tmp/" not in cap.get("description", "")
            assert "C:\\" not in cap.get("description", "")


# ============================================================
# 4. 大规模发现项测试
# ============================================================

class TestLargeScaleFindings:
    """大量发现项（100+）不会导致崩溃。"""

    def test_150_findings_no_crash(self):
        """150 个发现项不会导致崩溃。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i % 20:02d}",  # 20 个不同规则
                severity=["critical", "high", "medium", "low"][i % 4],
                confidence="high",
                is_blocking=(i % 10 == 0),  # 部分阻断
                file_path=f"file_{i}.py",
                line_start=i + 1,
            )
            for i in range(150)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        # 应正常完成
        assert 0 <= result["score"] <= 100
        assert result["verdict"] in ("pass", "warning", "blocked")

    def test_200_findings_all_same_rule(self):
        """200 个同一规则的发现项不会崩溃，且 rule_cap 正确生效。"""
        findings = [
            _make_finding_dict(
                rule_id="R_SAME_RULE",
                severity="critical",
                confidence="high",
                is_blocking=False,
                file_path=f"file_{i}.py",
                line_start=i + 1,
            )
            for i in range(200)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        # 200 个 critical 在同一规则 → cap 50
        entry = result["score_breakdown"][0]
        assert entry["rule_cap"] == 50
        assert entry["applied_deduction"] == 50
        assert result["score"] == 50  # 100 - 50 = 50

    def test_100_findings_mixed_blocking(self):
        """100 个混合阻断/非阻断发现项不会崩溃。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i % 5}",
                severity="critical" if i % 2 == 0 else "high",
                confidence="high",
                is_blocking=(i < 50),  # 前 50 个阻断
                file_path=f"file_{i}.py",
                line_start=i + 1,
            )
            for i in range(100)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49

    def test_large_findings_json_serializable(self):
        """大量发现项的评估结果可正确 JSON 序列化。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i % 10}",
                severity="low",
                confidence="high",
                is_blocking=False,
                file_path=f"f{i}.py",
                line_start=i + 1,
            )
            for i in range(100)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        json_str = json.dumps(result, ensure_ascii=False, sort_keys=True)
        parsed = json.loads(json_str)
        assert parsed == result


# ============================================================
# 5. 混合严重级别 rule_cap 测试
# ============================================================

class TestMixedSeverityRuleCap:
    """同一 rule_id 混合严重级别使用正确的 rule_cap（最高严重级别）。"""

    def test_critical_plus_low_uses_critical_cap(self):
        """1 个 critical + 3 个 low → rule_cap 基于 critical(50)。"""
        findings = [
            _make_finding_dict(
                rule_id="R_MIXED", severity="critical", confidence="high",
                is_blocking=False, file_path="c.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_MIXED", severity="low", confidence="high",
                is_blocking=False, file_path="l1.py", line_start=2,
            ),
            _make_finding_dict(
                rule_id="R_MIXED", severity="low", confidence="high",
                is_blocking=False, file_path="l2.py", line_start=3,
            ),
            _make_finding_dict(
                rule_id="R_MIXED", severity="low", confidence="high",
                is_blocking=False, file_path="l3.py", line_start=4,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        # 最高严重级别 = critical → cap = 50
        assert entry["severity"] == "critical"
        assert entry["rule_cap"] == 50
        # 扣分: critical(1st)=25, low(2nd)=2, low(3rd)=2, low(4th)=1 = 30
        # 30 < 50 → applied = 30
        assert entry["occurrence_deductions"] == [25, 2, 2, 1]
        assert entry["deduction_before_rule_cap"] == 30
        assert entry["applied_deduction"] == 30

    def test_high_plus_low_uses_high_cap(self):
        """1 个 high + 多个 low → rule_cap 基于 high(40)，而非 low(10)。"""
        findings = [
            _make_finding_dict(
                rule_id="R_HL", severity="high", confidence="high",
                is_blocking=False, file_path="h.py", line_start=1,
            ),
        ] + [
            _make_finding_dict(
                rule_id="R_HL", severity="low", confidence="high",
                is_blocking=False, file_path=f"l{i}.py", line_start=i + 2,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        # 最高严重级别 = high → cap = 40
        assert entry["severity"] == "high"
        assert entry["rule_cap"] == 40
        # 如果错误地使用了 low cap(10)，applied 会是 10
        # 正确应该是基于 high cap(40)
        assert entry["applied_deduction"] <= 40
        assert entry["applied_deduction"] > 10  # 超过 low cap

    def test_medium_plus_info_uses_medium_cap(self):
        """1 个 medium + 多个 info → rule_cap 基于 medium(24)。"""
        findings = [
            _make_finding_dict(
                rule_id="R_MI", severity="medium", confidence="high",
                is_blocking=False, file_path="m.py", line_start=1,
            ),
        ] + [
            _make_finding_dict(
                rule_id="R_MI", severity="info", confidence="high",
                is_blocking=False, file_path=f"i{i}.py", line_start=i + 2,
            )
            for i in range(5)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        # 最高严重级别 = medium → cap = 24
        assert entry["severity"] == "medium"
        assert entry["rule_cap"] == 24
        # medium(1st)=8, info items=0 → total=8
        assert entry["applied_deduction"] == 8

    def test_all_severities_in_one_rule(self):
        """一个规则包含所有严重级别 → rule_cap 基于 critical(50)。"""
        findings = [
            _make_finding_dict(
                rule_id="R_ALL", severity="critical", confidence="high",
                is_blocking=False, file_path="c.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_ALL", severity="high", confidence="high",
                is_blocking=False, file_path="h.py", line_start=2,
            ),
            _make_finding_dict(
                rule_id="R_ALL", severity="medium", confidence="high",
                is_blocking=False, file_path="m.py", line_start=3,
            ),
            _make_finding_dict(
                rule_id="R_ALL", severity="low", confidence="high",
                is_blocking=False, file_path="l.py", line_start=4,
            ),
            _make_finding_dict(
                rule_id="R_ALL", severity="info", confidence="high",
                is_blocking=False, file_path="i.py", line_start=5,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        assert entry["severity"] == "critical"
        assert entry["rule_cap"] == 50


# ============================================================
# 6. blocking_reasons 字段白名单测试
# ============================================================

class TestBlockingReasonsFields:
    """blocking_reasons 字段白名单测试。"""

    def test_blocking_reasons_only_allowed_fields(self):
        """blocking_reasons 只包含允许的字段。

        允许字段：rule_id, rule_name, severity, file_path, description
        """
        finding = _make_finding_dict(
            rule_id="R_BLOCK",
            rule_name="GitHub Token",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="src/config.py",
            line_start=10, line_end=10,
            column_start=5, column_end=25,
            snippet_masked="ghp_****",
            finding_type="content",
            description="GitHub token found",
            category="token",
            secret_type="github_token",
            message="Remove the token",
            repair_template_key="remove_secret",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert len(result["blocking_reasons"]) == 1
        reason = result["blocking_reasons"][0]
        allowed_fields = {
            "rule_id", "rule_name", "severity", "file_path", "description"
        }
        assert set(reason.keys()) == allowed_fields

    def test_blocking_reasons_no_snippet_masked(self):
        """blocking_reasons 不包含 snippet_masked 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_SNIPPET",
            severity="critical",
            is_blocking=True,
            snippet_masked="ghp_****",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "snippet_masked" not in reason

    def test_blocking_reasons_no_secret_type(self):
        """blocking_reasons 不包含 secret_type 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_SECRET_TYPE",
            severity="critical",
            is_blocking=True,
            secret_type="github_token",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "secret_type" not in reason

    def test_blocking_reasons_no_message(self):
        """blocking_reasons 不包含 message 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_MESSAGE",
            severity="critical",
            is_blocking=True,
            message="Remove the token immediately",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "message" not in reason

    def test_blocking_reasons_no_repair_template_key(self):
        """blocking_reasons 不包含 repair_template_key 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_REPAIR",
            severity="critical",
            is_blocking=True,
            repair_template_key="remove_secret",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "repair_template_key" not in reason

    def test_blocking_reasons_no_confidence(self):
        """blocking_reasons 不包含 confidence 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_CONF",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "confidence" not in reason

    def test_blocking_reasons_no_is_blocking(self):
        """blocking_reasons 不包含 is_blocking 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_ISBLOCK",
            severity="critical",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "is_blocking" not in reason

    def test_blocking_reasons_no_finding_type(self):
        """blocking_reasons 不包含 finding_type 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_FTYPE",
            severity="critical",
            is_blocking=True,
            finding_type="content",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "finding_type" not in reason

    def test_blocking_reasons_no_category(self):
        """blocking_reasons 不包含 category 字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_CAT",
            severity="critical",
            is_blocking=True,
            category="token",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "category" not in reason

    def test_blocking_reasons_no_line_column_fields(self):
        """blocking_reasons 不包含行号/列号字段。"""
        finding = _make_finding_dict(
            rule_id="R_NO_LINES",
            severity="critical",
            is_blocking=True,
            line_start=10, line_end=10,
            column_start=5, column_end=25,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert "line_start" not in reason
        assert "line_end" not in reason
        assert "column_start" not in reason
        assert "column_end" not in reason

    def test_blocking_reasons_field_values_correct(self):
        """blocking_reasons 中各字段的值与原始发现项一致。"""
        finding = _make_finding_dict(
            rule_id="R_VALUES",
            rule_name="Test Rule Name",
            severity="high",
            is_blocking=True,
            file_path="path/to/file.py",
            description="A test description",
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        reason = result["blocking_reasons"][0]
        assert reason["rule_id"] == "R_VALUES"
        assert reason["rule_name"] == "Test Rule Name"
        assert reason["severity"] == "high"
        assert reason["file_path"] == "path/to/file.py"
        assert reason["description"] == "A test description"


# ============================================================
# 7. 分数边界测试
# ============================================================

class TestScoreBounds:
    """score 永远不低于 0 且不高于 100。"""

    def test_empty_result_score_100(self):
        """空结果 score=100。"""
        scan_result = _make_scan_result()
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 100
        assert result["score_before_caps"] == 100

    def test_many_findings_score_not_below_zero(self):
        """大量发现项 score 不低于 0。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i}", severity="critical", confidence="high",
                is_blocking=False, file_path=f"f{i}.py", line_start=1,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] >= 0
        assert result["score_before_caps"] >= 0

    def test_blocking_finding_score_not_below_zero(self):
        """阻断项 score 不低于 0。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i}", severity="critical", confidence="high",
                is_blocking=True, file_path=f"b{i}.py", line_start=i + 1,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] >= 0

    def test_score_never_exceeds_100(self):
        """score 永远不超过 100。"""
        test_cases = [
            _make_scan_result(),  # 空结果
            _make_scan_result([
                _make_finding_dict(
                    rule_id="R1", severity="info", is_blocking=False,
                    file_path="a.py", line_start=1,
                ),
            ]),  # info 发现项（0 扣分）
            _make_scan_result([
                _make_finding_dict(
                    rule_id="R1", severity="low", confidence="low",
                    is_blocking=False, file_path="a.py", line_start=1,
                ),
            ]),  # low/low 发现项（最小扣分）
        ]
        for scan_result in test_cases:
            result = assess_scan_result("test-task", scan_result)
            assert result["score"] <= 100
            assert result["score_before_caps"] <= 100

    def test_score_before_caps_never_below_zero(self):
        """score_before_caps 永远不低于 0。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i % 5}", severity="critical", confidence="high",
                is_blocking=False, file_path=f"f{i}.py", line_start=i + 1,
            )
            for i in range(20)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score_before_caps"] >= 0

    def test_score_bounds_with_all_caps(self):
        """所有 cap 同时触发时 score 仍在 [0, 100] 范围内。"""
        finding = _make_finding_dict(
            rule_id="R_ALL_CAPS",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        scan_result["summary"]["findings_truncated"] = True
        scan_result["summary"]["total_scan_errors"] = 5
        scan_result["summary"]["total_files_scanned"] = 0
        result = assess_scan_result("test-task", scan_result)
        assert 0 <= result["score"] <= 100
        assert 0 <= result["score_before_caps"] <= 100


# ============================================================
# 8. Verdict 合法性测试
# ============================================================

class TestVerdictValidity:
    """verdict 只能是 pass/warning/blocked 之一。"""

    def test_empty_result_verdict_pass(self):
        """空结果 verdict=pass。"""
        scan_result = _make_scan_result()
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "pass"

    def test_low_finding_verdict_pass(self):
        """单个 low 发现项（扣 3 分）→ score=97 → pass。"""
        finding = _make_finding_dict(
            rule_id="R_LOW", severity="low", confidence="high",
            is_blocking=False, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 97
        assert result["verdict"] == "pass"

    def test_medium_finding_verdict_pass(self):
        """单个 medium 发现项（扣 8 分）→ score=92 → pass。"""
        finding = _make_finding_dict(
            rule_id="R_MED", severity="medium", confidence="high",
            is_blocking=False, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 92
        assert result["verdict"] == "pass"

    def test_critical_finding_verdict_warning(self):
        """单个 critical 非阻断发现项（扣 25 分）→ score=75 → pass。

        注意：75 >= 75 → pass（边界值）。
        """
        finding = _make_finding_dict(
            rule_id="R_CRIT", severity="critical", confidence="high",
            is_blocking=False, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 75
        assert result["verdict"] == "pass"

    def test_two_critical_findings_verdict_warning(self):
        """两个 critical 非阻断发现项（不同规则）→ score=50 → warning。"""
        findings = [
            _make_finding_dict(
                rule_id="R_C1", severity="critical", confidence="high",
                is_blocking=False, file_path="a.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_C2", severity="critical", confidence="high",
                is_blocking=False, file_path="b.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 50
        assert result["verdict"] == "warning"

    def test_findings_truncated_verdict_warning(self):
        """findings_truncated → cap 74 → warning。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 74
        assert result["verdict"] == "warning"

    def test_blocking_finding_verdict_blocked(self):
        """阻断发现项 → blocked。"""
        finding = _make_finding_dict(
            rule_id="R_BLOCK", severity="critical", confidence="high",
            is_blocking=True, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"

    def test_verdict_always_valid_across_scenarios(self):
        """所有场景下 verdict 都是合法值。"""
        test_cases = [
            # (描述, scan_result)
            ("空结果", _make_scan_result()),
            ("单个 info", _make_scan_result([
                _make_finding_dict(rule_id="R1", severity="info",
                                   is_blocking=False, file_path="a.py"),
            ])),
            ("单个 low", _make_scan_result([
                _make_finding_dict(rule_id="R1", severity="low",
                                   is_blocking=False, file_path="a.py"),
            ])),
            ("单个 critical 非阻断", _make_scan_result([
                _make_finding_dict(rule_id="R1", severity="critical",
                                   is_blocking=False, file_path="a.py"),
            ])),
            ("单个 critical 阻断", _make_scan_result([
                _make_finding_dict(rule_id="R1", severity="critical",
                                   is_blocking=True, file_path="a.py"),
            ])),
            ("多个 critical 非阻断", _make_scan_result([
                _make_finding_dict(rule_id=f"R{i}", severity="critical",
                                   is_blocking=False, file_path=f"f{i}.py")
                for i in range(5)
            ])),
            ("findings_truncated", _make_scan_result(
                summary={
                    "total_findings": 0, "blocking_findings": 0,
                    "total_notices": 0, "total_skipped_files": 0,
                    "total_scan_errors": 0, "total_files_scanned": 10,
                    "total_lines_scanned": 100, "returned_findings": 0,
                    "findings_truncated": True,
                    "returned_notices": 0, "notices_truncated": False,
                    "returned_skipped_files": 0, "skipped_files_truncated": False,
                    "returned_scan_errors": 0, "scan_errors_truncated": False,
                }
            )),
            ("scan_errors", _make_scan_result(
                summary={
                    "total_findings": 0, "blocking_findings": 0,
                    "total_notices": 0, "total_skipped_files": 0,
                    "total_scan_errors": 3, "total_files_scanned": 10,
                    "total_lines_scanned": 100, "returned_findings": 0,
                    "findings_truncated": False,
                    "returned_notices": 0, "notices_truncated": False,
                    "returned_skipped_files": 0, "skipped_files_truncated": False,
                    "returned_scan_errors": 3, "scan_errors_truncated": False,
                }
            )),
        ]
        for desc, scan_result in test_cases:
            result = assess_scan_result("test-task", scan_result)
            assert result["verdict"] in ("pass", "warning", "blocked"), (
                f"Scenario '{desc}': invalid verdict '{result['verdict']}'"
            )


# ============================================================
# 9. 综合边界回归测试
# ============================================================

class TestBoundaryRegressions:
    """综合边界情况回归测试。"""

    def test_score_exactly_75_is_pass(self):
        """score=75 → pass（边界值：>= 75 为 pass）。"""
        # 1 个 critical(25) 非阻断 → score = 75
        finding = _make_finding_dict(
            rule_id="R_BOUNDARY_75", severity="critical", confidence="high",
            is_blocking=False, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 75
        assert result["verdict"] == "pass"

    def test_score_exactly_74_is_warning(self):
        """score=74 → warning（边界值：<= 74 为 warning）。"""
        # findings_truncated → cap 74
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 74
        assert result["verdict"] == "warning"

    def test_score_exactly_50_is_warning(self):
        """score=50 → warning（边界值：>= 50 为 warning）。"""
        # 2 个 critical(不同规则) → 25+25=50 → score=50
        findings = [
            _make_finding_dict(
                rule_id="R_50_A", severity="critical", confidence="high",
                is_blocking=False, file_path="a.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_50_B", severity="critical", confidence="high",
                is_blocking=False, file_path="b.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 50
        assert result["verdict"] == "warning"

    def test_score_exactly_49_is_blocked(self):
        """score=49 → blocked（边界值：<= 49 为 blocked）。"""
        # 阻断项 → cap 49
        finding = _make_finding_dict(
            rule_id="R_49", severity="critical", confidence="high",
            is_blocking=True, file_path="a.py", line_start=1,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 49
        assert result["verdict"] == "blocked"

    def test_score_0_is_blocked(self):
        """score=0 → blocked。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_ZERO_{i}", severity="critical", confidence="high",
                is_blocking=False, file_path=f"f{i}.py", line_start=1,
            )
            for i in range(4)  # 4 * 25 = 100 → score = 0
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 0
        assert result["verdict"] == "blocked"

    def test_info_finding_zero_deduction(self):
        """info 级别发现项不产生任何扣分。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_INFO_{i}", severity="info", confidence="high",
                is_blocking=False, file_path=f"f{i}.py", line_start=1,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 100
        assert result["verdict"] == "pass"
        # 所有 info 规则的扣分为 0
        for entry in result["score_breakdown"]:
            assert entry["applied_deduction"] == 0
            assert entry["rule_cap"] == 0

    def test_assessment_does_not_mutate_input(self):
        """评估函数不修改输入的 scan_result。"""
        findings = [
            _make_finding_dict(
                rule_id="R1", severity="critical", confidence="high",
                is_blocking=True, file_path="a.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        original = copy.deepcopy(scan_result)
        assess_scan_result("test-task", scan_result)
        assert scan_result == original

    def test_missing_summary_fields_handled_gracefully(self):
        """summary 缺少部分字段时不崩溃（使用默认值）。"""
        scan_result = {
            "schema_version": 1,
            "findings": [],
            "notices": [],
            "skipped_files": [],
            "scan_errors": [],
            "summary": {},  # 空 summary
        }
        result = assess_scan_result("test-task", scan_result)
        # 应使用默认值，不崩溃
        assert 0 <= result["score"] <= 100
        assert result["verdict"] in ("pass", "warning", "blocked")

    def test_empty_findings_list_with_summary_totals(self):
        """findings 列表为空但 summary 有 total_findings > 0。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["total_findings"] = 100
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        # score_breakdown 为空（无发现项可评分）
        assert result["score_breakdown"] == []
        # 但 coverage 记录了 total_findings
        assert result["coverage"]["total_findings"] == 100
        assert result["coverage"]["scored_findings"] == 0
        # findings_truncated 触发 cap 74
        assert result["score"] <= 74
