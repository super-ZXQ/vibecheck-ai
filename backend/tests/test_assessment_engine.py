"""P0-6 安全评估引擎综合测试。

覆盖以下测试类别：

A. 评分单元测试（TestScoringUnit）：
   - 空结果 = 100 分，verdict=pass，coverage=complete
   - 每种严重级别单项扣分
   - 每种置信度乘数
   - 阻断级发现强制 100% 置信度
   - 同一 rule_id 内重复违规乘数
   - 纯整数四舍五入公式验证
   - 按严重级别的规则扣分上限
   - 全局最低分 = 0
   - score_breakdown 按 rule_id 字母排序

B. 阻断测试（TestBlocking）：
   - summary.blocking_findings > 0 → blocked
   - 列表中无阻断项但 summary 有 → 仍 blocked
   - 低置信度阻断项仍强制 100%
   - score <= 49 无阻断项 → 仍 blocked
   - 多个阻断项 → 仍 blocked

C. 覆盖率和上限测试（TestCoverageAndCaps）：
   - findings_truncated → cap 74
   - total_scan_errors > 0 → cap 74
   - total_files_scanned=0 → cap 74
   - 多个 cap 取最小值
   - partial coverage 不能 pass
   - skipped_files 不触发 cap
   - score_caps 排序

D. 截断测试（TestTruncation）：
   - total_findings > scored_findings
   - blocking_reasons 最多 N 项
   - blocking_reasons_truncated 标志
   - summary.blocking_findings 是权威值
   - 低风险发现不能掩盖阻断项

H. 确定性测试（TestDeterminism）：
   - 相同输入 3 次评估结果一致
   - 打乱输入顺序结果一致
   - 不同 task_id 结果一致
"""

import copy
import json
import random

import pytest

from app.services.assessment_service import assess_scan_result
from app.services.assessment_policy import (
    MIN_SCORE,
    compute_single_deduction,
    get_repeat_percent,
)
from app.db import database


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """设置临时测试数据库。

    大多数引擎测试不需要数据库，直接调用 assess_scan_result 即可。
    此 fixture 供需要 DB 访问的测试使用。
    """
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


# ============================================================
# A. 评分单元测试
# ============================================================

class TestScoringUnit:
    """评分核心逻辑单元测试。"""

    def test_empty_result_perfect_score(self):
        """空结果应得满分 100 分，verdict=pass，coverage=complete。"""
        scan_result = _make_scan_result()
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 100
        assert result["score_before_caps"] == 100
        assert result["verdict"] == "pass"
        assert result["coverage"]["status"] == "complete"
        assert result["score_breakdown"] == []
        assert result["score_caps"] == []

    def test_each_severity_single_deduction(self):
        """每种严重级别的单项扣分：critical=25, high=15, medium=8, low=3, info=0。"""
        test_cases = [
            ("critical", 25),
            ("high", 15),
            ("medium", 8),
            ("low", 3),
            ("info", 0),
        ]
        for severity, expected_deduction in test_cases:
            finding = _make_finding_dict(
                rule_id=f"R_{severity.upper()}",
                severity=severity,
                confidence="high",
                is_blocking=False,
            )
            scan_result = _make_scan_result([finding])
            result = assess_scan_result("test-task", scan_result)
            assert result["score"] == 100 - expected_deduction, (
                f"severity={severity}: expected score {100 - expected_deduction}, "
                f"got {result['score']}"
            )
            entry = next(
                e for e in result["score_breakdown"]
                if e["rule_id"] == f"R_{severity.upper()}"
            )
            assert entry["occurrence_deductions"] == [expected_deduction]
            assert entry["applied_deduction"] == expected_deduction

    def test_each_confidence_multiplier(self):
        """每种置信度乘数：high=100%, medium=75%, low=50%。

        使用 critical 严重级别（base=25）以清晰区分差异：
        - high(100%):  25*100*100 = 250000 → 25
        - medium(75%): 25*75*100  = 187500 → 19
        - low(50%):    25*50*100  = 125000 → 13
        """
        test_cases = [
            ("high", 100, 25),
            ("medium", 75, 19),
            ("low", 50, 13),
        ]
        for confidence, pct, expected_deduction in test_cases:
            finding = _make_finding_dict(
                rule_id=f"R_CONF_{confidence.upper()}",
                severity="critical",
                confidence=confidence,
                is_blocking=False,
            )
            scan_result = _make_scan_result([finding])
            result = assess_scan_result("test-task", scan_result)
            entry = next(
                e for e in result["score_breakdown"]
                if e["rule_id"] == f"R_CONF_{confidence.upper()}"
            )
            assert entry["occurrence_deductions"] == [expected_deduction], (
                f"confidence={confidence}: expected deduction {expected_deduction}, "
                f"got {entry['occurrence_deductions']}"
            )
            assert entry["applied_deduction"] == expected_deduction

    def test_blocking_forced_100_percent_confidence(self):
        """阻断级发现即使 confidence=low 也强制按 100% 置信度扣分。

        验证 BLOCKING_CONFIDENCE_OVERRIDE = 100 的效果：
        - 低置信度阻断项扣分 = 25*100*100 = 25（与高置信度相同）
        - 而非 25*50*100 = 13
        """
        finding = _make_finding_dict(
            rule_id="R_BLOCK_LOW_CONF",
            severity="critical",
            confidence="low",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        # 阻断项强制 100% 置信度 → 25*100*100 = 25
        assert entry["occurrence_deductions"] == [25]
        # 对比：如果按 low(50%) 置信度计算应为 13
        assert entry["occurrence_deductions"][0] != 13

    def test_repeat_multipliers_within_same_rule(self):
        """同一 rule_id 内的重复违规乘数：1st=100%, 2nd=75%, 3rd=50%, 4th+=25%。

        使用 critical + high confidence：
        - 1st(100%): 25*100*100 = 250000 → 25
        - 2nd(75%):  25*100*75  = 187500 → 19
        - 3rd(50%):  25*100*50  = 125000 → 13
        - 4th(25%):  25*100*25  = 62500  → 6
        """
        findings = [
            _make_finding_dict(
                rule_id="R_REPEAT",
                severity="critical",
                confidence="high",
                is_blocking=False,
                file_path=f"file_{i}.py",
                line_start=i + 1,
            )
            for i in range(4)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        expected_deductions = [25, 19, 13, 6]
        assert entry["occurrence_deductions"] == expected_deductions
        assert entry["deduction_before_rule_cap"] == sum(expected_deductions)
        # 63 > 50 (critical cap) → applied = 50
        assert entry["rule_cap"] == 50
        assert entry["applied_deduction"] == 50

    def test_repeat_multipliers_beyond_fourth(self):
        """第 4 次及以后的重复违规均使用 25% 乘数。"""
        findings = [
            _make_finding_dict(
                rule_id="R_REPEAT_FLOOR",
                severity="critical",
                confidence="high",
                is_blocking=False,
                file_path=f"file_{i}.py",
                line_start=i + 1,
            )
            for i in range(6)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        # 1st=25, 2nd=19, 3rd=13, 4th=6, 5th=6, 6th=6
        assert entry["occurrence_deductions"] == [25, 19, 13, 6, 6, 6]

    def test_pure_integer_rounding_formula(self):
        """验证纯整数四舍五入公式：(base*conf*repeat+5000)//10000。

        使用 compute_single_deduction 直接验证。
        """
        test_cases = [
            # (base, conf_pct, repeat_pct, expected)
            # 用户指定的示例
            (25, 100, 100, 25),   # 250000+5000=255000 → 25
            (8, 75, 100, 6),      # 60000+5000=65000 → 6
            (3, 50, 75, 1),       # 11250+5000=16250 → 1
            # 补充边界用例
            (25, 100, 75, 19),    # 187500+5000=192500 → 19
            (25, 100, 50, 13),    # 125000+5000=130000 → 13
            (25, 100, 25, 6),     # 62500+5000=67500 → 6
            (15, 100, 100, 15),   # 150000+5000=155000 → 15
            (15, 100, 75, 11),    # 112500+5000=117500 → 11
            (15, 100, 50, 8),     # 75000+5000=80000 → 8
            (15, 100, 25, 4),     # 37500+5000=42500 → 4
            (8, 100, 100, 8),     # 80000+5000=85000 → 8
            (8, 100, 75, 6),      # 60000+5000=65000 → 6
            (3, 100, 100, 3),     # 30000+5000=35000 → 3
            (3, 100, 75, 2),      # 22500+5000=27500 → 2
            (0, 100, 100, 0),     # info 永远为 0
        ]
        for base, conf, repeat, expected in test_cases:
            actual = compute_single_deduction(base, conf, repeat)
            assert actual == expected, (
                f"compute_single_deduction({base}, {conf}, {repeat}): "
                f"expected {expected}, got {actual}"
            )

    def test_integer_rounding_through_engine(self):
        """通过引擎端到端验证整数四舍五入公式。

        medium(8) * medium(75) * 1st(100) = 60000 → (60000+5000)//10000 = 6
        """
        finding = _make_finding_dict(
            rule_id="R_ROUNDING",
            severity="medium",
            confidence="medium",
            is_blocking=False,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        entry = result["score_breakdown"][0]
        assert entry["occurrence_deductions"] == [6]
        assert result["score"] == 94  # 100 - 6

    def test_rule_cap_by_severity(self):
        """按严重级别的规则扣分上限：critical=50, high=40, medium=24, low=10, info=0。

        每种严重级别创建足够多的发现项以超过上限。
        """
        # critical(25): 3 项 → 25+19+13=57, cap=50
        crit_findings = [
            _make_finding_dict(
                rule_id="R_CRIT", severity="critical", confidence="high",
                is_blocking=False, file_path=f"c{i}.py", line_start=i + 1,
            )
            for i in range(3)
        ]
        # high(15): 5 项 → 15+11+8+4+4=42, cap=40
        high_findings = [
            _make_finding_dict(
                rule_id="R_HIGH", severity="high", confidence="high",
                is_blocking=False, file_path=f"h{i}.py", line_start=i + 1,
            )
            for i in range(5)
        ]
        # medium(8): 7 项 → 8+6+4+2+2+2+2=26, cap=24
        med_findings = [
            _make_finding_dict(
                rule_id="R_MED", severity="medium", confidence="high",
                is_blocking=False, file_path=f"m{i}.py", line_start=i + 1,
            )
            for i in range(7)
        ]
        # low(3): 7 项 → 3+2+2+1+1+1+1=11, cap=10
        low_findings = [
            _make_finding_dict(
                rule_id="R_LOW", severity="low", confidence="high",
                is_blocking=False, file_path=f"l{i}.py", line_start=i + 1,
            )
            for i in range(7)
        ]
        # info(0): 3 项 → 0+0+0=0, cap=0
        info_findings = [
            _make_finding_dict(
                rule_id="R_INFO", severity="info", confidence="high",
                is_blocking=False, file_path=f"i{i}.py", line_start=i + 1,
            )
            for i in range(3)
        ]

        all_findings = (
            crit_findings + high_findings + med_findings
            + low_findings + info_findings
        )
        scan_result = _make_scan_result(all_findings)
        result = assess_scan_result("test-task", scan_result)

        breakdown_by_rule = {e["rule_id"]: e for e in result["score_breakdown"]}

        # critical: 57 → cap 50
        assert breakdown_by_rule["R_CRIT"]["rule_cap"] == 50
        assert breakdown_by_rule["R_CRIT"]["deduction_before_rule_cap"] == 57
        assert breakdown_by_rule["R_CRIT"]["applied_deduction"] == 50

        # high: 42 → cap 40
        assert breakdown_by_rule["R_HIGH"]["rule_cap"] == 40
        assert breakdown_by_rule["R_HIGH"]["deduction_before_rule_cap"] == 42
        assert breakdown_by_rule["R_HIGH"]["applied_deduction"] == 40

        # medium: 26 → cap 24
        assert breakdown_by_rule["R_MED"]["rule_cap"] == 24
        assert breakdown_by_rule["R_MED"]["deduction_before_rule_cap"] == 26
        assert breakdown_by_rule["R_MED"]["applied_deduction"] == 24

        # low: 11 → cap 10
        assert breakdown_by_rule["R_LOW"]["rule_cap"] == 10
        assert breakdown_by_rule["R_LOW"]["deduction_before_rule_cap"] == 11
        assert breakdown_by_rule["R_LOW"]["applied_deduction"] == 10

        # info: 0 → cap 0
        assert breakdown_by_rule["R_INFO"]["rule_cap"] == 0
        assert breakdown_by_rule["R_INFO"]["deduction_before_rule_cap"] == 0
        assert breakdown_by_rule["R_INFO"]["applied_deduction"] == 0

    def test_global_minimum_score_zero(self):
        """全局最低分为 0（大量发现项不能使分数低于 0）。

        3 个规则各有 3 个 critical 发现项，每个规则扣分 50（cap），
        总扣分 150 → 100-150=-50 → max(0, -50) = 0。
        """
        findings = []
        for rule_idx in range(3):
            for i in range(3):
                findings.append(_make_finding_dict(
                    rule_id=f"R_RULE_{rule_idx}",
                    severity="critical",
                    confidence="high",
                    is_blocking=False,
                    file_path=f"r{rule_idx}_f{i}.py",
                    line_start=i + 1,
                ))
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 0
        assert result["score_before_caps"] == 0
        assert result["score"] >= MIN_SCORE

    def test_score_breakdown_sorted_by_rule_id(self):
        """score_breakdown 按 rule_id 字母顺序排序。"""
        findings = [
            _make_finding_dict(
                rule_id="R_ZEBRA", severity="low", is_blocking=False,
                file_path="z.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_ALPHA", severity="low", is_blocking=False,
                file_path="a.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_MIKE", severity="low", is_blocking=False,
                file_path="m.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        rule_ids = [e["rule_id"] for e in result["score_breakdown"]]
        assert rule_ids == ["R_ALPHA", "R_MIKE", "R_ZEBRA"]

    def test_get_repeat_percent_directly(self):
        """直接验证 get_repeat_percent 函数的返回值。"""
        assert get_repeat_percent(0) == 100  # 1st
        assert get_repeat_percent(1) == 75   # 2nd
        assert get_repeat_percent(2) == 50   # 3rd
        assert get_repeat_percent(3) == 25   # 4th
        assert get_repeat_percent(4) == 25   # 5th (floor)
        assert get_repeat_percent(99) == 25  # far beyond


# ============================================================
# B. 阻断测试
# ============================================================

class TestBlocking:
    """阻断级发现项测试。"""

    def test_blocking_findings_cause_blocked(self):
        """summary.blocking_findings > 0 → verdict=blocked，score<=49。"""
        finding = _make_finding_dict(
            rule_id="R_BLOCK",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49
        # 验证阻断 cap 被触发
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "BLOCKING_FINDING_PRESENT" in cap_codes

    def test_no_blocking_in_list_but_summary_has_blocking(self):
        """持久化发现项列表中无阻断项，但 summary.blocking_findings > 0 → 仍 blocked。

        这模拟了 findings 列表被截断、阻断项不在保留列表中的场景。
        summary.blocking_findings 是权威值。
        """
        finding = _make_finding_dict(
            rule_id="R_NONBLOCK",
            severity="low",
            confidence="high",
            is_blocking=False,
        )
        scan_result = _make_scan_result([finding])
        # 覆盖 summary，声明存在阻断项（尽管列表中没有）
        scan_result["summary"]["blocking_findings"] = 1
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49
        assert result["coverage"]["total_blocking_findings"] == 1
        # 列表中无阻断项，所以 blocking_reasons 为空
        assert len(result["blocking_reasons"]) == 0
        # 但截断标志为 True（total > returned）
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_low_confidence_blocking_forces_100_percent(self):
        """低置信度阻断项仍强制 100% 置信度，并触发 cap 49。

        验证：
        1. 扣分按 100% 置信度计算（25 而非 13）
        2. score 被 cap 到 49
        3. verdict = blocked
        """
        finding = _make_finding_dict(
            rule_id="R_LOW_CONF_BLOCK",
            severity="critical",
            confidence="low",  # 低置信度
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        # 阻断强制 100% 置信度 → 扣分 = 25*100*100 = 25
        entry = result["score_breakdown"][0]
        assert entry["occurrence_deductions"] == [25]
        # score 被 cap 到 49
        assert result["score"] <= 49
        assert result["verdict"] == "blocked"

    def test_score_below_49_no_blocking_still_blocked(self):
        """score <= 49 但无阻断项 → 仍为 blocked。

        使用足够多的发现项使分数降到 49 以下，但不设置任何阻断项。
        验证 verdict 由分数阈值决定（而非阻断项）。
        """
        # 2 critical(不同规则) + 1 high = 25+25+15 = 65, score = 35
        findings = [
            _make_finding_dict(
                rule_id="R_C1", severity="critical", confidence="high",
                is_blocking=False, file_path="c1.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_C2", severity="critical", confidence="high",
                is_blocking=False, file_path="c2.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_H1", severity="high", confidence="high",
                is_blocking=False, file_path="h1.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] == 35
        assert result["score"] <= 49
        assert result["verdict"] == "blocked"
        # 验证没有阻断 cap 被触发
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "BLOCKING_FINDING_PRESENT" not in cap_codes

    def test_multiple_blocking_findings_still_blocked(self):
        """多个阻断项 → 仍为 blocked，score<=49。"""
        findings = [
            _make_finding_dict(
                rule_id="R_B1", severity="critical", confidence="high",
                is_blocking=True, file_path="b1.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_B2", severity="high", confidence="high",
                is_blocking=True, file_path="b2.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_B3", severity="medium", confidence="high",
                is_blocking=True, file_path="b3.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49
        # 多个阻断项都在 blocking_reasons 中
        assert len(result["blocking_reasons"]) == 3

    def test_blocking_cap_49_applied_even_if_deduction_small(self):
        """即使扣分很小，阻断项仍将分数 cap 到 49。

        一个 low 级别的阻断项：扣分仅 3，但 cap 49 生效。
        """
        finding = _make_finding_dict(
            rule_id="R_LOW_BLOCK",
            severity="low",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        result = assess_scan_result("test-task", scan_result)
        # 扣分 = 3*100*100 = 3, score_before_caps = 97
        # 但阻断 cap 49 生效 → score = 49
        assert result["score_before_caps"] == 97
        assert result["score"] == 49
        assert result["verdict"] == "blocked"


# ============================================================
# C. 覆盖率和上限测试
# ============================================================

class TestCoverageAndCaps:
    """覆盖率和分数上限测试。"""

    def test_findings_truncated_caps_74(self):
        """findings_truncated=True → cap 74，coverage=partial。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] <= 74
        assert result["coverage"]["status"] == "partial"
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "FINDINGS_TRUNCATED" in cap_codes
        # 验证 cap 记录的值
        trunc_cap = next(c for c in result["score_caps"]
                         if c["reason_code"] == "FINDINGS_TRUNCATED")
        assert trunc_cap["cap_value"] == 74

    def test_scan_errors_caps_74(self):
        """total_scan_errors > 0 → cap 74，coverage=partial。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["total_scan_errors"] = 3
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] <= 74
        assert result["coverage"]["status"] == "partial"
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "SCAN_ERRORS_PRESENT" in cap_codes

    def test_no_files_scanned_caps_74(self):
        """total_files_scanned=0 → cap 74，coverage=partial。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["total_files_scanned"] = 0
        result = assess_scan_result("test-task", scan_result)
        assert result["score"] <= 74
        assert result["coverage"]["status"] == "partial"
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "NO_FILES_SCANNED" in cap_codes

    def test_multiple_caps_take_minimum(self):
        """多个 cap 同时触发时，取最小 cap_value。

        同时触发 BLOCKING_FINDING_PRESENT(49) 和 FINDINGS_TRUNCATED(74)。
        最终分数应 <= 49（最小值）。
        """
        finding = _make_finding_dict(
            rule_id="R_BLOCK",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        # 最小 cap = 49
        assert result["score"] <= 49
        # 两个 cap 都应存在
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "BLOCKING_FINDING_PRESENT" in cap_codes
        assert "FINDINGS_TRUNCATED" in cap_codes
        # 49 < 74，所以 BLOCKING_FINDING_PRESENT 应该排在前面
        assert cap_codes.index("BLOCKING_FINDING_PRESENT") < \
               cap_codes.index("FINDINGS_TRUNCATED")

    def test_multiple_74_caps_all_present(self):
        """多个 cap_value=74 的 cap 同时触发时，全部保留。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        scan_result["summary"]["total_scan_errors"] = 2
        scan_result["summary"]["total_files_scanned"] = 0
        result = assess_scan_result("test-task", scan_result)
        cap_codes = [c["reason_code"] for c in result["score_caps"]]
        assert "FINDINGS_TRUNCATED" in cap_codes
        assert "SCAN_ERRORS_PRESENT" in cap_codes
        assert "NO_FILES_SCANNED" in cap_codes
        assert result["score"] <= 74

    def test_partial_coverage_cannot_pass(self):
        """partial coverage 时，verdict 不能为 pass（最高为 warning）。

        空结果（score=100）+ findings_truncated → cap 74 → warning。
        """
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        assert result["coverage"]["status"] == "partial"
        assert result["verdict"] != "pass"
        assert result["verdict"] == "warning"
        assert result["score"] == 74

    def test_skipped_files_no_cap_no_partial(self):
        """skipped_files > 0 不触发任何 cap，不导致 coverage=partial。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["total_skipped_files"] = 10
        result = assess_scan_result("test-task", scan_result)
        assert result["coverage"]["status"] == "complete"
        assert len(result["score_caps"]) == 0
        assert result["score"] == 100
        assert result["verdict"] == "pass"
        # coverage 中 skipped 信息保留
        assert result["coverage"]["total_skipped_files"] == 10

    def test_score_caps_sorted_by_value_then_code(self):
        """score_caps 按 (cap_value ASC, reason_code ASC) 排序。"""
        finding = _make_finding_dict(
            rule_id="R_BLOCK",
            severity="critical",
            confidence="high",
            is_blocking=True,
        )
        scan_result = _make_scan_result([finding])
        scan_result["summary"]["findings_truncated"] = True
        scan_result["summary"]["total_scan_errors"] = 2
        scan_result["summary"]["total_files_scanned"] = 0
        result = assess_scan_result("test-task", scan_result)
        caps = result["score_caps"]
        # 验证排序
        for i in range(len(caps) - 1):
            key_i = (caps[i]["cap_value"], caps[i]["reason_code"])
            key_j = (caps[i + 1]["cap_value"], caps[i + 1]["reason_code"])
            assert key_i <= key_j, (
                f"caps not sorted: {key_i} > {key_j} at index {i}"
            )
        # 验证预期顺序：49(BLOCKING) < 74(FINDINGS_TRUNCATED) < 74(NO_FILES_SCANNED) < 74(SCAN_ERRORS_PRESENT)
        expected_codes = [
            "BLOCKING_FINDING_PRESENT",
            "FINDINGS_TRUNCATED",
            "NO_FILES_SCANNED",
            "SCAN_ERRORS_PRESENT",
        ]
        actual_codes = [c["reason_code"] for c in caps]
        assert actual_codes == expected_codes

    def test_cap_applied_flag_correctness(self):
        """cap 的 applied 标志正确反映是否实际降低了分数。"""
        scan_result = _make_scan_result()
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        # score_before_caps = 100, cap = 74 → applied = True
        trunc_cap = next(c for c in result["score_caps"]
                         if c["reason_code"] == "FINDINGS_TRUNCATED")
        assert trunc_cap["applied"] is True
        assert trunc_cap["score_before_cap"] == 100
        assert trunc_cap["score_after_cap"] == 74

    def test_cap_not_applied_when_score_already_lower(self):
        """当分数已经低于 cap_value 时，cap 的 applied=False。"""
        # 创建足够多的发现项使分数低于 74
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i}", severity="critical", confidence="high",
                is_blocking=False, file_path=f"f{i}.py", line_start=1,
            )
            for i in range(3)  # 3 * 25 = 75, score = 25
        ]
        scan_result = _make_scan_result(findings)
        scan_result["summary"]["findings_truncated"] = True
        result = assess_scan_result("test-task", scan_result)
        # score_before_caps = 25 < 74 → cap 不生效
        trunc_cap = next(c for c in result["score_caps"]
                         if c["reason_code"] == "FINDINGS_TRUNCATED")
        assert trunc_cap["applied"] is False
        assert trunc_cap["score_before_cap"] == 25
        assert trunc_cap["score_after_cap"] == 25


# ============================================================
# D. 截断测试
# ============================================================

class TestTruncation:
    """截断相关测试。"""

    def test_total_findings_exceeds_scored_findings(self):
        """total_findings > scored_findings（findings 列表长度）。

        模拟 findings 列表被截断的场景：summary.total_findings=10，
        但实际 findings 列表只有 3 项。
        """
        findings = [
            _make_finding_dict(
                rule_id=f"R_{i}", severity="low", is_blocking=False,
                file_path=f"f{i}.py", line_start=1,
            )
            for i in range(3)
        ]
        scan_result = _make_scan_result(findings)
        scan_result["summary"]["total_findings"] = 10
        result = assess_scan_result("test-task", scan_result)
        assert result["coverage"]["total_findings"] == 10
        assert result["coverage"]["scored_findings"] == 3
        assert result["coverage"]["total_findings"] > \
               result["coverage"]["scored_findings"]

    def test_blocking_reasons_max_items(self, monkeypatch):
        """blocking_reasons 最多 N 项（测试中用 monkeypatch 设置为 5）。

        默认 assessment_max_blocking_reasons=100，
        测试中设为 5 以验证截断行为。
        """
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 5
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"block_{i}.py",
                line_start=i + 1,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert len(result["blocking_reasons"]) == 5

    def test_blocking_reasons_default_max_100(self):
        """默认 assessment_max_blocking_reasons=100 时不截断少量阻断项。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"block_{i}.py",
                line_start=i + 1,
            )
            for i in range(10)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert len(result["blocking_reasons"]) == 10

    def test_blocking_reasons_truncated_flag(self, monkeypatch):
        """total_blocking_findings > returned_blocking_reasons 时，
        blocking_reasons_truncated=True。
        """
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 3
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"block_{i}.py",
                line_start=i + 1,
            )
            for i in range(5)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["coverage"]["blocking_reasons_truncated"] is True
        assert result["coverage"]["total_blocking_findings"] == 5
        assert result["coverage"]["returned_blocking_reasons"] == 3

    def test_blocking_reasons_not_truncated_when_under_limit(
        self, monkeypatch
    ):
        """total_blocking_findings <= returned_blocking_reasons 时，
        blocking_reasons_truncated=False。
        """
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 10
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"block_{i}.py",
                line_start=i + 1,
            )
            for i in range(3)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["coverage"]["blocking_reasons_truncated"] is False
        assert result["coverage"]["total_blocking_findings"] == 3
        assert result["coverage"]["returned_blocking_reasons"] == 3

    def test_summary_blocking_findings_is_authority(self):
        """summary.blocking_findings 是权威值（不是列表中阻断项的长度）。

        findings 列表中有 0 个阻断项，但 summary.blocking_findings=2。
        verdict 应为 blocked，score 应 <= 49。
        """
        finding = _make_finding_dict(
            rule_id="R_NONBLOCK",
            severity="low",
            confidence="high",
            is_blocking=False,
        )
        scan_result = _make_scan_result([finding])
        scan_result["summary"]["blocking_findings"] = 2
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49
        assert result["coverage"]["total_blocking_findings"] == 2
        # 列表中无阻断项，blocking_reasons 为空
        assert len(result["blocking_reasons"]) == 0
        # 但截断标志为 True
        assert result["coverage"]["blocking_reasons_truncated"] is True

    def test_many_low_risk_cannot_mask_blocking(self):
        """大量低风险发现项不能掩盖阻断项（阻断项仍触发 blocked）。

        20 个 low 级别非阻断发现项 + 1 个 critical 阻断项。
        即使低风险项很多，verdict 仍为 blocked。
        """
        findings = [
            _make_finding_dict(
                rule_id=f"R_LOW_{i:03d}",
                severity="low",
                confidence="high",
                is_blocking=False,
                file_path=f"low_{i}.py",
                line_start=1,
            )
            for i in range(20)
        ]
        findings.append(_make_finding_dict(
            rule_id="R_BLOCK",
            severity="critical",
            confidence="high",
            is_blocking=True,
            file_path="block.py",
            line_start=1,
        ))
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        assert result["verdict"] == "blocked"
        assert result["score"] <= 49
        # 阻断项在 blocking_reasons 中
        assert len(result["blocking_reasons"]) == 1
        assert result["blocking_reasons"][0]["rule_id"] == "R_BLOCK"

    def test_blocking_reasons_sorted_deterministically(self, monkeypatch):
        """blocking_reasons 按确定性顺序排序（截断后保留最高优先级）。"""
        monkeypatch.setattr(
            "app.core.config.settings.assessment_max_blocking_reasons", 3
        )
        findings = [
            _make_finding_dict(
                rule_id=f"R_Z{i}",
                severity="low",
                confidence="high",
                is_blocking=True,
                file_path=f"z{i}.py",
                line_start=1,
            )
            for i in range(3)
        ]
        findings += [
            _make_finding_dict(
                rule_id=f"R_A{i}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"a{i}.py",
                line_start=1,
            )
            for i in range(3)
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)
        # 3 个 critical 应优先于 3 个 low
        assert len(result["blocking_reasons"]) == 3
        for reason in result["blocking_reasons"]:
            assert reason["severity"] == "critical"


# ============================================================
# H. 确定性测试
# ============================================================

class TestDeterminism:
    """确定性测试：相同输入必须产生相同输出。"""

    def test_same_input_three_times_identical(self):
        """相同输入评估 3 次 → 相同的 score, verdict, breakdown, caps,
        coverage, blocking_reasons。

        只有 created_at, updated_at, task_id 可能不同。
        """
        findings = [
            _make_finding_dict(
                rule_id="R1", severity="critical", confidence="high",
                is_blocking=True, file_path="a.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R2", severity="high", confidence="medium",
                is_blocking=False, file_path="b.py", line_start=2,
            ),
            _make_finding_dict(
                rule_id="R3", severity="low", confidence="low",
                is_blocking=False, file_path="c.py", line_start=3,
            ),
        ]
        scan_result = _make_scan_result(findings)

        results = [
            assess_scan_result("test-task", copy.deepcopy(scan_result))
            for _ in range(3)
        ]

        # 比较所有确定性字段（排除 created_at, updated_at, task_id）
        deterministic_keys = [
            "score", "score_before_caps", "verdict",
            "score_breakdown", "score_caps", "blocking_reasons",
            "coverage", "schema_version", "policy_version",
            "assessment_scope",
        ]
        for key in deterministic_keys:
            assert results[0][key] == results[1][key] == results[2][key], (
                f"Key '{key}' differs between runs"
            )

    def test_shuffled_input_same_result(self):
        """打乱发现项输入顺序 → 结果相同。

        发现项分组后按 _finding_sort_key 排序，
        所以输入顺序不影响最终结果。
        """
        findings = [
            _make_finding_dict(
                rule_id="R_B", severity="critical", confidence="high",
                is_blocking=False, file_path="b1.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R_A", severity="high", confidence="medium",
                is_blocking=False, file_path="a1.py", line_start=2,
            ),
            _make_finding_dict(
                rule_id="R_B", severity="medium", confidence="low",
                is_blocking=False, file_path="b2.py", line_start=3,
            ),
            _make_finding_dict(
                rule_id="R_A", severity="low", confidence="high",
                is_blocking=False, file_path="a2.py", line_start=4,
            ),
            _make_finding_dict(
                rule_id="R_C", severity="info", confidence="medium",
                is_blocking=False, file_path="c1.py", line_start=5,
            ),
        ]

        scan_result_1 = _make_scan_result(copy.deepcopy(findings))

        rng = random.Random(42)
        shuffled = copy.deepcopy(findings)
        rng.shuffle(shuffled)
        # 验证打乱确实改变了顺序
        original_order = [f["file_path"] for f in findings]
        shuffled_order = [f["file_path"] for f in shuffled]
        assert original_order != shuffled_order

        scan_result_2 = _make_scan_result(shuffled)

        result_1 = assess_scan_result("test-task", scan_result_1)
        result_2 = assess_scan_result("test-task", scan_result_2)

        assert result_1["score"] == result_2["score"]
        assert result_1["verdict"] == result_2["verdict"]
        assert result_1["score_breakdown"] == result_2["score_breakdown"]
        assert result_1["score_caps"] == result_2["score_caps"]
        assert result_1["blocking_reasons"] == result_2["blocking_reasons"]
        assert result_1["coverage"] == result_2["coverage"]

    def test_shuffled_blocking_findings_same_reasons(self):
        """打乱阻断项顺序 → blocking_reasons 相同（确定性截断）。"""
        findings = [
            _make_finding_dict(
                rule_id=f"R_B{i:03d}",
                severity="critical",
                confidence="high",
                is_blocking=True,
                file_path=f"block_{i}.py",
                line_start=i + 1,
            )
            for i in range(10)
        ]

        scan_result_1 = _make_scan_result(copy.deepcopy(findings))

        rng = random.Random(99)
        shuffled = copy.deepcopy(findings)
        rng.shuffle(shuffled)
        scan_result_2 = _make_scan_result(shuffled)

        result_1 = assess_scan_result("test-task", scan_result_1)
        result_2 = assess_scan_result("test-task", scan_result_2)

        assert result_1["blocking_reasons"] == result_2["blocking_reasons"]

    def test_different_task_id_same_score(self):
        """不同 task_id → 相同 score/verdict/breakdown（仅 task_id 和时间戳不同）。"""
        findings = [
            _make_finding_dict(
                rule_id="R1", severity="critical", confidence="high",
                is_blocking=True, file_path="a.py", line_start=1,
            ),
            _make_finding_dict(
                rule_id="R2", severity="high", confidence="medium",
                is_blocking=False, file_path="b.py", line_start=2,
            ),
        ]
        scan_result = _make_scan_result(findings)

        result_1 = assess_scan_result("task-aaa", scan_result)
        result_2 = assess_scan_result("task-bbb", scan_result)

        # task_id 不同
        assert result_1["task_id"] == "task-aaa"
        assert result_2["task_id"] == "task-bbb"
        assert result_1["task_id"] != result_2["task_id"]

        # 所有评分相关字段相同
        for key in ["score", "score_before_caps", "verdict",
                     "score_breakdown", "score_caps", "blocking_reasons",
                     "coverage", "schema_version", "policy_version",
                     "assessment_scope"]:
            assert result_1[key] == result_2[key], (
                f"Key '{key}' differs between task_ids"
            )

    def test_assessment_json_serializable(self):
        """评估结果可正确 JSON 序列化（确定性输出）。"""
        findings = [
            _make_finding_dict(
                rule_id="R1", severity="critical", confidence="high",
                is_blocking=True, file_path="a.py", line_start=1,
            ),
        ]
        scan_result = _make_scan_result(findings)
        result = assess_scan_result("test-task", scan_result)

        # 应该能序列化为 JSON
        json_str = json.dumps(result, ensure_ascii=False, sort_keys=True)
        parsed = json.loads(json_str)
        assert parsed == result

        # 两次序列化结果相同
        json_str_2 = json.dumps(result, ensure_ascii=False, sort_keys=True)
        assert json_str == json_str_2
