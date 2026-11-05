"""Bounded Node subprocess wrapper for the frontend dead-code analyzer.

The Node process only parses files with ts-morph/postcss. It never imports,
requires or executes repository code, and never runs the scanned repository's
npm scripts. Timeout, heap size and output size are enforced here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.quality.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DIMENSION_FRONTEND_DEAD_CODE,
    REASON_ANALYZER_ERROR,
    REASON_ANALYZER_TIMEOUT,
    REASON_ANALYZER_UNAVAILABLE,
    REASON_INPUT_MISSING,
    REASON_PARTIAL_ENUMERATION,
    STATUS_COMPLETED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_COMPLETED,
    STATUS_PARTIAL,
    QualityBlock,
    QualityEvidence,
    QualityItem,
)
from app.quality.repository_index import RepositoryIndex

_ANALYZER_DIR = Path(__file__).resolve().parent / "frontend_analyzer"
_SCRIPT = _ANALYZER_DIR / "analyzer.mjs"
_REQUIRED_MODULE = _ANALYZER_DIR / "node_modules" / "ts-morph"
_ALLOWED_CONFIDENCE = {CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW}


def _block(
    status: str,
    reason_code: str,
    message: str,
    *,
    limitations: list[str] | None = None,
) -> QualityBlock:
    return QualityBlock(
        dimension=DIMENSION_FRONTEND_DEAD_CODE,
        status=status,
        reason_code=reason_code,
        reason_message=message,
        conclusion={"headline": message, "counts": {}},
        verification={"checks_run": [], "uncovered_risks": [message]},
        coverage={"inputs_missing": ["node_runtime"]},
        details={"limitations": limitations or []},
    )


def _node_binary() -> str | None:
    configured = settings.frontend_analyzer_node_bin
    return shutil.which(configured)


def _run_node(root: Path, node: str) -> tuple[int, str, str, bool]:
    """Run the analyzer with bounded stdout/stderr and wall-clock timeout."""
    max_output = settings.frontend_analyzer_max_output_bytes
    timeout = max(5, settings.quality_analyzer_timeout - 2)
    env = {
        "PATH": f"{Path(node).parent}:/usr/local/bin:/usr/bin:/bin",
        "NODE_OPTIONS": f"--max-old-space-size={settings.frontend_analyzer_memory_mb}",
        "HOME": tempfile.gettempdir(),
    }
    with tempfile.TemporaryDirectory(prefix="frontend-analyzer-") as tmp:
        stdout_path = Path(tmp) / "stdout.json"
        stderr_path = Path(tmp) / "stderr.log"
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(
                [
                    node,
                    f"--max-old-space-size={settings.frontend_analyzer_memory_mb}",
                    str(_SCRIPT),
                    str(root),
                ],
                cwd=str(_ANALYZER_DIR),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=env,
            )
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return -1, "", "", True
        stdout_size = stdout_path.stat().st_size if stdout_path.exists() else 0
        if stdout_size > max_output:
            return -2, "", "", False
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_size else ""
        stderr = (
            stderr_path.read_text(encoding="utf-8", errors="replace")[:600]
            if stderr_path.exists()
            else ""
        )
        return returncode, stdout, stderr, False


def _item_from_payload(payload: dict[str, Any]) -> QualityItem | None:
    category = str(payload.get("category") or "")
    if category not in {
        "frontend_zero_call_export",
        "frontend_unused_css_class",
        "frontend_reflection_reference",
    }:
        return None
    name = str(payload.get("name") or payload.get("class_name") or "")
    if not name:
        return None
    file_path = str(payload.get("file") or "")
    line = payload.get("line")
    confidence = str(payload.get("confidence") or CONFIDENCE_MEDIUM)
    if confidence not in _ALLOWED_CONFIDENCE:
        confidence = CONFIDENCE_MEDIUM
    if category == "frontend_unused_css_class":
        title = f"未引用 CSS 类：.{name}"
        impact = "该选择器在已覆盖源码中无引用；不会自动删除。"
        suggestion = "人工确认后删除该规则或补充使用位置。"
        rule_id = "FE-DEAD-CSS-001"
        method = "postcss CSS/SCSS"
    elif category == "frontend_reflection_reference":
        title = f"疑似反射引用导出函数：{name}"
        impact = "符号名仅以字符串出现，可能存在运行时注册；不会自动删除。"
        suggestion = "人工确认反射/注册链路后再处理。"
        rule_id = "FE-DEAD-REFLECT-001"
        method = "ts-morph AST / string reference scan"
    else:
        title = f"零调用导出函数：{name}"
        impact = "该导出函数没有导入或调用；不会自动删除。"
        suggestion = "人工确认是否为测试辅助或预留 API 后再删除。"
        rule_id = "FE-DEAD-EXPORT-001"
        method = "ts-morph AST"
    evidence = QualityEvidence(
        method=method,
        detail=str(payload.get("selector") or payload.get("reason") or "")[:300],
        file_path=file_path or None,
        line_start=line if isinstance(line, int) else None,
        line_end=line if isinstance(line, int) else None,
    )
    item_id = f"frontend-{category}-{line or 0}-{name}"
    return QualityItem(
        item_id=item_id,
        dimension=DIMENSION_FRONTEND_DEAD_CODE,
        category=category,
        conclusion=title,
        confidence=confidence,
        title=title,
        impact=impact,
        suggestion=suggestion,
        fixability="report_only",
        manual_decision_required=False,
        limitation=str(payload.get("reason") or "")[:300],
        rule_id=rule_id,
        evidence=[evidence],
        details={
            "name": name,
            "selector": payload.get("selector"),
            "file": file_path,
            "line": line,
            "confidence": confidence,
            "reason": payload.get("reason"),
            "minified_css_checked": payload.get("minified_css_checked"),
            "present_in_minified_css": payload.get("present_in_minified_css"),
        },
    )


def analyze_frontend_dead_code(index: RepositoryIndex) -> QualityBlock:
    """Run the pinned Node analyzer and normalize its output."""
    if not _SCRIPT.exists() or not _REQUIRED_MODULE.exists():
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_UNAVAILABLE,
            "前端分析器运行时或依赖缺失；该块未执行。",
        )
    node = _node_binary()
    if node is None:
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_UNAVAILABLE,
            "未找到 Node 运行时；该块未执行。",
        )
    returncode, stdout, stderr, timed_out = _run_node(index.root, node)
    if timed_out:
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_TIMEOUT,
            "前端分析器超时，未完成。",
        )
    if returncode == -2:
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_ERROR,
            "前端分析器输出超出上限，未完成。",
        )
    if returncode != 0:
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_ERROR,
            f"前端分析器退出异常（{returncode}）：{stderr[:200]}",
        )
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_ERROR,
            "前端分析器返回非法 JSON，未完成。",
        )
    if not isinstance(payload, dict):
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_ERROR,
            "前端分析器返回结构非法，未完成。",
        )

    status = str(payload.get("status") or "")
    if status == STATUS_NOT_APPLICABLE:
        message = str(payload.get("message") or "未发现 Next.js 前端工程。")
        block = _block(STATUS_NOT_APPLICABLE, REASON_INPUT_MISSING, message)
        block.coverage = {"inputs_missing": ["next_frontend"]}
        block.details = {"limitations": []}
        return block
    if status not in {STATUS_COMPLETED, STATUS_PARTIAL}:
        message = str(payload.get("message") or "前端分析器未完成。")
        return _block(
            STATUS_NOT_COMPLETED,
            REASON_ANALYZER_ERROR,
            message,
            limitations=[message],
        )

    raw_items = payload.get("items")
    raw_items = raw_items if isinstance(raw_items, list) else []
    items = [item for raw in raw_items if isinstance(raw, dict) and (item := _item_from_payload(raw))]
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    limitations = [str(row)[:300] for row in payload.get("limitations") or []]
    build = payload.get("build_output") if isinstance(payload.get("build_output"), dict) else {}
    confidence_counts = {level: 0 for level in _ALLOWED_CONFIDENCE}
    for item in items:
        confidence_counts[item.confidence] += 1
    headline = (
        f"前端死代码静态分析：{len(items)} 条只读报告"
        f"（零调用函数 {counts.get('zero_call_functions', 0)}，"
        f"未引用 CSS 类 {counts.get('css_classes', 0)}）。"
    )
    status = STATUS_PARTIAL if status == STATUS_PARTIAL or not build.get("available") else STATUS_COMPLETED
    reason_code = (
        REASON_PARTIAL_ENUMERATION if status == STATUS_PARTIAL else None
    )
    block = QualityBlock(
        dimension=DIMENSION_FRONTEND_DEAD_CODE,
        status=status,
        reason_code=reason_code,
        reason_message=(
            "构建产物缺失，置信度已降级。" if status == STATUS_PARTIAL else "前端死代码静态分析完成。"
        ),
        conclusion={
            "headline": headline,
            "counts": {
                "findings": len(items),
                "zero_call_functions": sum(
                    1 for item in items if item.category == "frontend_zero_call_export"
                ),
                "css_classes": sum(
                    1 for item in items if item.category == "frontend_unused_css_class"
                ),
                "confidence": confidence_counts,
                "source_files": counts.get("source_files", 0),
                "next_entries": counts.get("next_entries", 0),
            },
        },
        items=items,
        verification={
            "checks_run": [
                "tsconfig paths/include/exclude 由 ts-morph 读取",
                "Next 约定入口清单排除",
                "ts-morph 导入/导出符号图",
                "postcss CSS/SCSS 解析",
                "模板字符串类名前缀族匹配",
                "构建产物命中检查",
            ],
            "uncovered_risks": limitations,
            "build_output_checked": bool(build.get("available")),
            "build_output_dirs": build.get("directories") or [],
            "minified_css_files": build.get("minified_css_files", 0),
            "next_entries": payload.get("next_entries") or [],
        },
        coverage={
            "frontend_root": payload.get("frontend_root"),
            "source_files": counts.get("source_files", 0),
            "next_entries": counts.get("next_entries", 0),
            "used_class_tokens": counts.get("used_class_tokens", 0),
            "family_prefixes": counts.get("family_prefixes", 0),
            "public_assets": payload.get("public_assets") or {},
            "inputs_missing": [] if build.get("available") else ["build_output"],
        },
        details={
            "limitations": limitations,
            "build_output": build,
        },
    )
    return block
