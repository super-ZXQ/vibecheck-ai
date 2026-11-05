"""Backend comment-quality audit.

Deterministic checks (no model required):

- missing docstrings for route handlers, stage services, core/tool modules,
  and state-write functions
- Google/Sphinx/NumPy Args/Returns/Raises structure
- stale documented parameters versus the real signature
- invalid patterns: line-by-line translation, function-name restatement,
  change-history comments, commented-out code, owner-less TODO/FIXME
- state-write functions must explain fencing token / idempotency / transaction
- route handlers and retry paths must state status codes and ``error_code``

The language policy is "match the file's existing dominant language". The
analyzer reports missing/invalid comments only; it never scores language
ratios and never penalises English-dominant files.

Semantic judgement (does the comment explain *why*, are params and failure
modes clear, has the comment drifted) runs only when the user supplied a
BYOK LLM config. Without it the block is ``partial`` with ``LLM_DISABLED``
and a manual-confirmation item. In both modes model text may only land in
``QualityItem.suggestion``; it is never evidence and never affects status
codes or the font tri-state.
"""

from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings
from app.core.security.desensitize import mask_snippet
from app.quality.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    DIMENSION_BACKEND_COMMENTS,
    FIXABILITY_REPORT,
    REASON_LLM_DISABLED,
    REASON_NO_BACKEND,
    REASON_PARTIAL_ENUMERATION,
    STATUS_COMPLETED,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
    QualityBlock,
    QualityEvidence,
    QualityItem,
)
from app.quality.repository_index import RepositoryIndex

_COVERED_DIR_TOKENS = {
    "api",
    "services",
    "service",
    "core",
    "utils",
    "tools",
    "quality",
    "scanner",
    "db",
    "worker",
}
_EXCLUDED_DIR_TOKENS = {
    "tests",
    "test",
    "fixtures",
    "examples",
    "samples",
    "testdata",
    "migrations",
    "node_modules",
    ".venv",
    "venv",
    "build",
    "dist",
    "__pycache__",
}
_ROUTE_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "route",
    "api_route",
    "websocket",
}
_STATE_WRITE_CALLS = {
    "mark_running_owned",
    "mark_running_async",
    "mark_completed_async",
    "mark_cancelled_async",
    "fail_or_retry_async",
    "claim_next_pending_async",
    "recover_expired_tasks_async",
    "complete_as_reused_async",
    "admit_repo_task_async",
    "session.commit",
    "session.flush",
    "session.add",
}
_GENERIC_STATE_NAME_RE = re.compile(
    r"^(?:mark|claim|fail_or_retry|recover|cancel|complete|save|persist|store|admit)_",
)
_LIFECYCLE_NAMES = {"lifespan", "startup", "shutdown", "on_startup", "on_shutdown"}
_FENCE_NAMES = {"claim", "mark_running", "mark_completed", "mark_cancelled", "recover"}
_RETRY_NAMES = {"fail_or_retry", "retry"}

_FENCE_KEYWORDS = (
    "claim_token",
    "worker_id",
    "fencing",
    "fence",
    "ownership",
    "owner",
    "围栏",
    "归属",
    "令牌",
)
_IDEMPOTENCY_KEYWORDS = ("idempot", "幂等", "重复执行", "at-least-once")
_TRANSACTION_KEYWORDS = (
    "transaction",
    "atomic",
    "commit",
    "rollback",
    "事务",
    "原子",
    "回滚",
)

_GOOGLE_ARGS_RE = re.compile(r"^\s*Args\s*:\s*$", re.MULTILINE)
_GOOGLE_RETURNS_RE = re.compile(r"^\s*Returns?\s*:\s*$", re.MULTILINE)
_GOOGLE_RAISES_RE = re.compile(r"^\s*Raises?\s*:\s*$", re.MULTILINE)
_SPHINX_ARGS_RE = re.compile(r"^\s*:param\s+", re.MULTILINE)
_SPHINX_RETURNS_RE = re.compile(r"^\s*:returns?:", re.MULTILINE)
_SPHINX_RAISES_RE = re.compile(r"^\s*:raises\s+", re.MULTILINE)
_NUMPY_PARAMS_RE = re.compile(
    r"^\s*Parameters\s*\n\s*[-=]{3,}", re.MULTILINE
)
_GOOGLE_ARG_NAME_RE = re.compile(
    r"^\s{2,}([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:", re.MULTILINE
)
_SPHINX_ARG_NAME_RE = re.compile(
    r"^\s*:param\s+(?:[^:]+:)?\s*([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)

_SKIP_COMMENT_PREFIXES = (
    "type:",
    "noqa",
    "pragma",
    "pylint:",
    "mypy:",
    "fmt:",
    "isort:",
    "ruff:",
    "nosec",
    "coverage:",
    "region",
    "endregion",
)
_DIVIDER_RE = re.compile(r"^[-=_*#~]{3,}$")
_COPYRIGHT_RE = re.compile(r"copyright|spdx-license|licensed under|license", re.IGNORECASE)
_TODO_OWNER_RE = re.compile(
    r"@[A-Za-z0-9_.-]+|(?:owner|by)\s*[:=]\s*[A-Za-z0-9_.-]+|#\d+"
)
_TODO_BRACKET_OWNER_RE = re.compile(
    r"^(?:TODO|FIXME)[({][A-Za-z0-9_.-]{2,}[)}]", re.IGNORECASE
)
_CHANGE_HISTORY_RE = re.compile(
    r"\b(?:changed|modified|updated|added|removed)\s+(?:by|on|at|in)\b"
    r"|\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\b"
    r"|\bv\d+\.\d+\.\d+\b"
    r"|修改记录|变更历史|历史版本|更新于|修改人|author\s*:",
    re.IGNORECASE,
)
# Section labels ("Step 3: ...", "2. ...", "E. ...", "--- ... ---") and
# inline annotations ("policy_version: must be ...") are structural markers,
# not line-by-line translations of the next statement.
_SECTION_LABEL_RE = re.compile(
    r"^(?:[-=*#~_]{2,}|\d+[.)、]|[A-Z][.)]|Step\s+\d+|Phase\s+\d+)\b",
    re.IGNORECASE,
)
_ANNOTATION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\s*:")
# Common English words that carry no discriminating signal when measuring
# overlap between a comment and the statement below it.
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "the",
        "then",
        "this",
        "to",
        "with",
    }
)
_CODE_OPENERS = re.compile(
    r"^(?:async\s+def|def|class|if|elif|else|for|while|try|except|finally|"
    r"with|return|yield|raise|break|continue|import|from)\b"
)
_ACTION_VERBS = (
    "初始化",
    "设置",
    "获取",
    "返回",
    "创建",
    "删除",
    "更新",
    "遍历",
    "判断",
    "检查",
    "调用",
    "打印",
    "定义",
    "导入",
    "加载",
    "保存",
    "读取",
    "写入",
    "执行",
    "处理",
    "构建",
    "生成",
    "开始",
    "结束",
    "initialize",
    "set",
    "get",
    "return",
    "create",
    "delete",
    "update",
    "iterate",
    "check",
    "call",
    "print",
    "define",
    "import",
    "load",
    "save",
    "read",
    "write",
    "execute",
    "handle",
    "build",
    "generate",
)
_RATIONALE_MARKERS = (
    "because",
    "since",
    "why",
    "reason",
    "unless",
    "otherwise",
    "edge case",
    "fallback",
    "workaround",
    "avoid",
    "prevent",
    "for safety",
    "note",
    "warning",
    "todo",
    "fixme",
    "hack",
    "为了",
    "因为",
    "原因",
    "避免",
    "防止",
    "否则",
    "注意",
    "警告",
    "必须",
    "不要",
    "禁止",
    "兼容",
    "边界",
    "only",
    "etc",
    "default",
    "fallback",
)
_PYTHON_KEYWORDS = {
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
    "self",
    "cls",
    "None",
    "True",
    "False",
}
_ALLOWED_CODE_STMTS = (
    ast.Assign,
    ast.AnnAssign,
    ast.AugAssign,
    ast.Import,
    ast.ImportFrom,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Return,
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.Expr,
    ast.Raise,
    ast.Delete,
)

_SEMANTIC_CANDIDATE_LIMIT = 8
_LLM_TIMEOUT_SECONDS = 15.0


@dataclass(slots=True)
class _FunctionInfo:
    name: str
    file_path: str
    line: int
    end_line: int
    docstring: str | None
    params: list[str]
    is_route: bool
    is_state_write: bool
    covered: bool
    body: list[ast.stmt] = field(default_factory=list)
    node: ast.AST | None = None


def analyze_backend_comments(
    index: RepositoryIndex,
    llm_user_config: dict[str, Any] | None = None,
) -> QualityBlock:
    """Build the comment-quality block for a repository index."""
    py_files = [
        item
        for item in index.by_suffix(".py")
        if _is_backend_python(item.rel_path)
    ]
    if not py_files:
        return _not_applicable_block()

    items: list[QualityItem] = []
    functions: list[_FunctionInfo] = []
    parse_errors = 0
    files_analyzed = 0
    language_counts = {"cjk_chars": 0, "latin_words": 0}

    for item in py_files:
        source = index.read_text(item.rel_path)
        if source is None:
            parse_errors += 1
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            parse_errors += 1
            continue
        files_analyzed += 1
        module_doc = ast.get_docstring(tree, clean=False)
        file_functions = _collect_functions(tree, item.rel_path)
        covered = [info for info in file_functions if info.covered]
        functions.extend(covered)

        if covered and module_doc is None and _has_meaningful_content(source):
            items.append(
                _item(
                    "comment-module-docstring",
                    item.rel_path,
                    1,
                    "module_docstring_missing",
                    "P3",
                    f"模块缺少文档串：{item.rel_path}",
                    "模块职责、输入输出与副作用没有集中说明。",
                    "在文件顶部补充模块级文档串，说明职责与关键约束。",
                    evidence=[
                        QualityEvidence(
                            method="ast 模块文档串",
                            detail="module.__doc__ 为空",
                            file_path=item.rel_path,
                            line_start=1,
                            line_end=1,
                        )
                    ],
                )
            )

        for info in covered:
            items.extend(_check_function(info, source))
        items.extend(_check_comment_patterns(item.rel_path, source, file_functions))
        cjk, latin = _comment_language_counts(source)
        language_counts["cjk_chars"] += cjk
        language_counts["latin_words"] += latin

    llm_enabled = _llm_ready(llm_user_config)
    candidates = _select_semantic_candidates(functions)
    llm_state = "not_required"
    if candidates:
        if not llm_enabled:
            items.append(_semantic_pending_item(candidates, "未配置 BYOK 模型"))
            llm_state = "disabled"
        else:
            suggestions, llm_error = _run_semantic_llm(candidates, llm_user_config)
            if llm_error or not suggestions:
                items.append(
                    _semantic_pending_item(
                        candidates,
                        "BYOK 模型调用失败或未返回可解析结果",
                    )
                )
                llm_state = "failed"
            else:
                items.extend(_semantic_suggestion_items(candidates, suggestions))
                llm_state = "completed"

    if not functions:
        return _not_applicable_block(
            message="未检测到路由 handler、阶段服务、工具/核心模块或状态写入函数，注释规范检查不适用。"
        )

    items = _aggregate_report_items(_dedupe_items(items))
    counts_by_rule: dict[str, int] = {}
    for quality_item in items:
        counts_by_rule[quality_item.category] = counts_by_rule.get(quality_item.category, 0) + 1
    risk_counts: dict[str, int] = {}
    for quality_item in items:
        risk_counts[quality_item.severity] = risk_counts.get(quality_item.severity, 0) + 1

    deterministic_items = [
        item
        for item in items
        if item.category not in {"semantic_review_pending", "semantic_comment_suggestion"}
    ]
    llm_note = {
        "completed": "语义判断已完成（BYOK 模型仅提供 suggestion）。",
        "disabled": "语义判断未执行（LLM_DISABLED），需人工确认。",
        "failed": "语义判断调用失败（LLM_DISABLED），需人工确认。",
        "not_required": "未发现需要语义判断的候选函数。",
    }[llm_state]

    status = STATUS_COMPLETED
    reason_code: str | None = None
    reason_message = ""
    if parse_errors:
        status = STATUS_PARTIAL
        reason_code = REASON_PARTIAL_ENUMERATION
        reason_message = f"{parse_errors} 个 Python 文件无法解析，相关函数未纳入检查。"
    elif llm_state in {"disabled", "failed"}:
        status = STATUS_PARTIAL
        reason_code = REASON_LLM_DISABLED
        reason_message = (
            "确定性注释检查已完成；语义判断依赖用户配置的 BYOK 模型，当前未执行。"
            if llm_state == "disabled"
            else "确定性注释检查已完成；BYOK 模型调用失败，语义判断未完成。"
        )

    docstring_present = len([info for info in functions if info.docstring])
    coverage_pct = (
        round(docstring_present * 100 / len(functions), 1) if functions else 0.0
    )
    if deterministic_items:
        headline = (
            f"覆盖 {len(functions)} 个函数，发现 {len(deterministic_items)} 项确定性问题"
            f"（P2 {risk_counts.get('P2', 0)} / P3 {risk_counts.get('P3', 0)}）；{llm_note}"
        )
    else:
        headline = (
            f"在已覆盖输入范围内未发现确定性问题（覆盖 {len(functions)} 个函数）；"
            f"{llm_note}"
        )

    checks = [
        {
            "name": "function_docstring_presence",
            "status": "passed",
            "detail": f"检查 {len(functions)} 个覆盖范围内的函数",
        },
        {
            "name": "args_returns_raises_structure",
            "status": "passed",
            "detail": "Google/Sphinx/NumPy 结构识别完成",
        },
        {
            "name": "invalid_comment_patterns",
            "status": "passed",
            "detail": "逐行翻译、复述函数名、变更历史、注释旧代码、无 owner TODO",
        },
        {
            "name": "state_write_contract",
            "status": "passed",
            "detail": "围栏令牌/幂等/事务边界关键词检查完成",
        },
        {
            "name": "error_contract",
            "status": "passed",
            "detail": "状态码与 error_code 说明检查完成",
        },
        {
            "name": "semantic_llm",
            "status": "skipped" if llm_state != "completed" else "passed",
            "detail": llm_note,
        },
    ]

    uncovered = [
        "语言策略只判断缺失/无效，不按语言占比扣分（中英文均可）。",
        "模型仅能写入 suggestion 字段，不能作为证据或改变确定性结论。",
        "注释与实现的语义漂移、是否解释「为什么」需人工或 BYOK 模型复核。",
    ]
    if parse_errors:
        uncovered.append(f"{parse_errors} 个 Python 文件解析失败，未纳入覆盖。")

    return QualityBlock(
        dimension=DIMENSION_BACKEND_COMMENTS,
        status=status,
        reason_code=reason_code,
        reason_message=reason_message,
        conclusion={
            "headline": headline,
            "counts": {
                "covered_functions": len(functions),
                "docstrings_present": docstring_present,
                "docstring_coverage_pct": coverage_pct,
                "route_handlers": len([info for info in functions if info.is_route]),
                "state_write_functions": len(
                    [info for info in functions if info.is_state_write]
                ),
                "findings": len(deterministic_items),
                "manual_items": len(
                    [item for item in items if item.manual_decision_required]
                ),
                "by_rule": counts_by_rule,
                "risk_p0": risk_counts.get("P0", 0),
                "risk_p1": risk_counts.get("P1", 0),
                "risk_p2": risk_counts.get("P2", 0),
                "risk_p3": risk_counts.get("P3", 0),
            },
            "llm": {"state": llm_state, "byok_configured": llm_enabled},
        },
        evidence=[
            QualityEvidence(
                method="Python ast + tokenize",
                detail=(
                    f"{files_analyzed} 个文件，{len(functions)} 个函数，"
                    f"模块文档串与注释模式检查完成"
                ),
            )
        ],
        items=items,
        verification={
            "checks_run": checks,
            "uncovered_risks": uncovered,
            "llm_policy": (
                "模型只能写 suggestion；不参与确定性规则、状态码与字体三态"
            ),
        },
        coverage={
            "files_analyzed": files_analyzed,
            "files_excluded": len(index.by_suffix(".py")) - len(py_files),
            "parse_errors": parse_errors,
            "functions_covered": len(functions),
            "language_policy": "match_file_majority_no_ratio_penalty",
            "comment_language": language_counts,
        },
        details={
            "invalid_pattern_files": sorted(
                {
                    item.evidence[0].file_path
                    for item in items
                    if item.category
                    in {
                        "trivial_line_comment",
                        "comment_restates_function_name",
                        "change_history_comment",
                        "commented_out_code",
                        "todo_without_owner",
                    }
                    and item.evidence
                    and item.evidence[0].file_path
                }
            ),
            "semantic_candidates": [
                {"function": info.name, "file": info.file_path, "line": info.line}
                for info in candidates
            ],
            "limitations": uncovered,
        },
    )


def _not_applicable_block(
    message: str = "未检测到后端 Python 源码，注释规范检查不适用。",
) -> QualityBlock:
    return QualityBlock(
        dimension=DIMENSION_BACKEND_COMMENTS,
        status=STATUS_NOT_APPLICABLE,
        reason_code=REASON_NO_BACKEND,
        reason_message=message,
        conclusion={"headline": message, "counts": {}},
        coverage={"inputs_missing": ["backend python sources"]},
        verification={"checks_run": [], "uncovered_risks": [message]},
    )


def _is_backend_python(rel_path: str) -> bool:
    parts = [part.lower() for part in rel_path.split("/")[:-1]]
    if any(part in _EXCLUDED_DIR_TOKENS for part in parts):
        return False
    basename = rel_path.rsplit("/", 1)[-1]
    return basename != "conftest.py"


def _has_meaningful_content(source: str) -> bool:
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return True
    return False


def _collect_functions(tree: ast.Module, file_path: str) -> list[_FunctionInfo]:
    result: list[_FunctionInfo] = []
    scope_reasons = _scope_reasons(file_path)

    def _visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = _function_info(child, file_path, scope_reasons)
                result.append(info)
            elif isinstance(child, ast.ClassDef):
                _visit_class(child)

    def _visit_class(node: ast.ClassDef) -> None:
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result.append(_function_info(child, file_path, scope_reasons))
            elif isinstance(child, ast.ClassDef):
                _visit_class(child)

    _visit(tree)
    return result


def _scope_reasons(file_path: str) -> set[str]:
    parts = [part.lower() for part in file_path.split("/")[:-1]]
    return {part for part in parts if part in _COVERED_DIR_TOKENS}


def _function_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    scope_reasons: set[str],
) -> _FunctionInfo:
    name = node.name
    is_route = _is_route_handler(node)
    calls = _shallow_call_names(node)
    is_state_write = name not in _LIFECYCLE_NAMES and (
        bool(_GENERIC_STATE_NAME_RE.match(name)) or bool(calls & _STATE_WRITE_CALLS)
    )
    public = not name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
    covered = is_route or is_state_write or bool(scope_reasons)
    if not is_route and not is_state_write and not public:
        covered = False
    return _FunctionInfo(
        name=name,
        file_path=file_path,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        docstring=ast.get_docstring(node, clean=False),
        params=_function_params(node),
        is_route=is_route,
        is_state_write=is_state_write,
        covered=covered,
        body=node.body,
        node=node,
    )


def _is_route_handler(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _dotted_name(target)
        if name and name.rsplit(".", 1)[-1] in _ROUTE_METHODS:
            return True
    return False


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    names = [arg.arg for arg in args.posonlyargs + args.args]
    names.extend(arg.arg for arg in args.kwonlyargs)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return [name for name in names if name not in {"self", "cls"}]


def _shallow_call_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in _shallow_walk(node):
        if isinstance(child, ast.Call):
            name = _dotted_name(child.func)
            if name:
                names.add(name)
                names.add(name.rsplit(".", 1)[-1])
    return names


def _shallow_walk(node: ast.AST) -> list[ast.AST]:
    result: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        result.append(current)
        stack.extend(ast.iter_child_nodes(current))
    return result


def _check_function(info: _FunctionInfo, source: str) -> list[QualityItem]:
    items: list[QualityItem] = []
    if not info.docstring:
        severity = "P2" if (info.is_route or info.is_state_write) else "P3"
        category = (
            "missing_route_handler_docstring"
            if info.is_route
            else "missing_state_write_docstring"
            if info.is_state_write
            else "docstring_missing"
        )
        items.append(
            _item(
                f"comment-docstring-{info.name}",
                info.file_path,
                info.line,
                category,
                severity,
                f"函数缺少文档串：{info.name}",
                (
                    "路由/状态写入函数的输入、错误契约与并发约束没有说明。"
                    if severity == "P2"
                    else "函数职责与参数含义需要阅读实现才能理解。"
                ),
                "补充说明职责、参数、返回值与失败模式的文档串。",
                evidence=[_function_evidence(info, source)],
                details={"function": info.name, "params": info.params},
            )
        )
        return items

    items.extend(_docstring_structure_items(info, source))
    restates = _docstring_restates_name(info)
    if restates:
        items.append(
            _item(
                f"comment-restates-{info.name}",
                info.file_path,
                info.line,
                "comment_restates_function_name",
                "P3",
                f"文档串复述函数名：{info.name}",
                "文档串首个句子只是函数名的自然语言重复，没有补充职责或约束。",
                "改写文档串，说明为什么存在、边界条件与失败模式。",
                evidence=[_function_evidence(info, source)],
                details={"function": info.name},
            )
        )

    if info.is_state_write:
        missing = _missing_state_write_groups(info, info.docstring)
        if missing:
            items.append(_state_write_item(info, source, missing_groups=missing))
    if info.is_route or info.is_state_write:
        error_item = _error_contract_item(info, source)
        if error_item is not None:
            items.append(error_item)
    return items


def _docstring_structure_items(
    info: _FunctionInfo, source: str
) -> list[QualityItem]:
    if not (
        info.is_route
        or info.is_state_write
        or len(info.params) >= 3
        or _statement_count(info) >= 6
    ):
        return []
    doc = info.docstring or ""
    items: list[QualityItem] = []
    has_args_section = bool(
        _GOOGLE_ARGS_RE.search(doc)
        or _SPHINX_ARGS_RE.search(doc)
        or _NUMPY_PARAMS_RE.search(doc)
    )
    if len(info.params) >= 2 and not has_args_section:
        items.append(
            _item(
                f"comment-args-{info.name}",
                info.file_path,
                info.line,
                "docstring_args_missing",
                "P3",
                f"文档串缺少 Args/Parameters 段：{info.name}",
                f"函数有 {len(info.params)} 个参数，但文档串未逐个说明。",
                "补充 Args 段（或 Sphinx :param:），说明每个参数的语义与约束。",
                evidence=[_function_evidence(info, source)],
                details={
                    "function": info.name,
                    "params": info.params,
                    "missing_sections": ["Args"],
                },
            )
        )
    if has_args_section:
        documented, missing, extra = _parse_documented_params(doc, info.params)
        if documented and (missing or extra):
            items.append(
                _item(
                    f"comment-stale-params-{info.name}",
                    info.file_path,
                    info.line,
                    "docstring_stale_params",
                    "P3",
                    f"文档串参数与签名不一致：{info.name}",
                    "Args 段与实际参数漂移，读者会被过期文档误导。",
                    "按当前签名更新 Args 段，删除已移除参数并补充新增参数。",
                    evidence=[_function_evidence(info, source)],
                    details={
                        "function": info.name,
                        "missing": missing,
                        "extra": extra,
                        "missing_sections": ["Args (stale)"],
                    },
                )
            )
    if _returns_value(info) and not (
        _GOOGLE_RETURNS_RE.search(doc) or _SPHINX_RETURNS_RE.search(doc)
    ):
        items.append(
            _item(
                f"comment-returns-{info.name}",
                info.file_path,
                info.line,
                "docstring_returns_missing",
                "P3",
                f"文档串缺少 Returns 段：{info.name}",
                "函数返回非 None 值，但文档串未说明返回含义与失败时的返回。",
                "补充 Returns 段，写清返回值的语义与边界。",
                evidence=[_function_evidence(info, source)],
                details={"function": info.name, "missing_sections": ["Returns"]},
            )
        )
    if _raises_exception(info) and not (
        _GOOGLE_RAISES_RE.search(doc) or _SPHINX_RAISES_RE.search(doc)
    ):
        items.append(
            _item(
                f"comment-raises-{info.name}",
                info.file_path,
                info.line,
                "docstring_raises_missing",
                "P3",
                f"文档串缺少 Raises 段：{info.name}",
                "函数会显式抛出异常，但文档串未说明失败模式。",
                "补充 Raises 段，说明异常类型、触发条件与调用方处理方式。",
                evidence=[_function_evidence(info, source)],
                details={"function": info.name, "missing_sections": ["Raises"]},
            )
        )
    return items


def _statement_count(info: _FunctionInfo) -> int:
    count = 0
    for statement in info.body:
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Constant
        ) and isinstance(statement.value.value, str):
            continue
        count += 1
    return count


def _returns_value(info: _FunctionInfo) -> bool:
    for node in _shallow_walk(info.node) if info.node is not None else []:
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Constant) and node.value.value is None:
                continue
            return True
    return False


def _raises_exception(info: _FunctionInfo) -> bool:
    for node in _shallow_walk(info.node) if info.node is not None else []:
        if isinstance(node, ast.Raise):
            return True
    return False


def _google_args_section(doc: str) -> str:
    """Return only the body of a Google-style ``Args:`` section.

    Scanning the whole docstring also matches ``Returns:`` / ``Raises:``
    headers and their entries, which then look like stale parameters.
    """
    lines = doc.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:Args?|Arguments|Parameters)\s*:\s*$", line)
        if not match:
            continue
        header_indent = len(match.group(1))
        body: list[str] = []
        for follow in lines[index + 1 :]:
            stripped = follow.strip()
            if not stripped:
                body.append(follow)
                continue
            if len(follow) - len(follow.lstrip()) <= header_indent:
                break
            if re.match(r"^[A-Z][A-Za-z ]{1,20}:\s*$", stripped):
                break
            body.append(follow)
        return "\n".join(body)
    return ""


def _parse_documented_params(
    doc: str, params: list[str]
) -> tuple[set[str], list[str], list[str]]:
    documented: set[str] = set()
    if _GOOGLE_ARGS_RE.search(doc) or _NUMPY_PARAMS_RE.search(doc):
        documented.update(_GOOGLE_ARG_NAME_RE.findall(_google_args_section(doc)))
    if _SPHINX_ARGS_RE.search(doc):
        documented.update(_SPHINX_ARG_NAME_RE.findall(doc))
    documented.discard("Args")
    missing = [name for name in params if name not in documented]
    extra = sorted(name for name in documented if name not in params)
    return documented, missing, extra


def _docstring_restates_name(info: _FunctionInfo) -> bool:
    doc = (info.docstring or "").strip()
    if not doc:
        return False
    first_line = doc.splitlines()[0].strip()
    words = re.findall(r"[a-z0-9]+", first_line.lower())
    name_words = re.findall(r"[a-z0-9]+", info.name.lower())
    if not words or not name_words:
        return False
    filler = {"the", "a", "an", "this", "that", "to", "of", "and", "or"}
    return set(words) <= set(name_words) | filler and len(words) <= len(name_words) + 2


def _required_groups(info: _FunctionInfo) -> list[str]:
    calls = _shallow_call_names(info.node) if info.node is not None else set()
    name = info.name.lower()
    groups: list[str] = []
    if any(token in name for token in _FENCE_NAMES) or calls & {
        "mark_running_owned",
        "mark_running_async",
        "claim_next_pending_async",
        "recover_expired_tasks_async",
        "mark_completed_async",
        "mark_cancelled_async",
    }:
        groups.append("fence")
    if any(token in name for token in _RETRY_NAMES) or "fail_or_retry_async" in calls:
        groups.append("idempotency")
    if (
        any(token in name for token in ("save", "persist", "store", "update", "delete", "write"))
        or calls & {"session.commit", "session.flush", "session.add", "session.execute"}
    ):
        groups.append("transaction")
    return groups


def _missing_state_write_groups(info: _FunctionInfo, doc: str) -> list[str]:
    required = _required_groups(info)
    if not required:
        return []
    lower = doc.lower()
    present = {
        "fence": any(keyword in lower for keyword in _FENCE_KEYWORDS),
        "idempotency": any(keyword in lower for keyword in _IDEMPOTENCY_KEYWORDS),
        "transaction": any(keyword in lower for keyword in _TRANSACTION_KEYWORDS),
    }
    return [group for group in required if not present[group]]


def _state_write_item(
    info: _FunctionInfo, source: str, *, missing_groups: list[str]
) -> QualityItem:
    labels = {
        "fence": "围栏令牌/归属校验",
        "idempotency": "幂等/重复执行",
        "transaction": "事务边界",
    }
    missing_text = "、".join(labels.get(group, group) for group in missing_groups)
    return _item(
        f"comment-state-write-{info.name}",
        info.file_path,
        info.line,
        "state_write_contract_missing",
        "P2",
        f"状态写入函数未说明并发安全约束：{info.name}",
        f"文档串缺少 {missing_text} 说明，调用方难以判断重试与并发行为。",
        f"补充 {missing_text} 的说明，写清失败重试与并发写入的边界。",
        evidence=[_function_evidence(info, source)],
        details={"missing_groups": missing_groups},
    )


def _error_contract_item(
    info: _FunctionInfo, source: str
) -> QualityItem | None:
    if not info.docstring or info.node is None:
        return None
    doc = info.docstring
    calls = _shallow_call_names(info.node)
    status_codes = set(re.findall(r"\b(?:4|5)\d{2}\b", doc))
    error_tokens = set(re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", doc))
    needs_status = False
    needs_error_code = False
    if info.is_route and _has_http_exception(info.node):
        needs_status = not bool(status_codes)
        needs_error_code = not bool(error_tokens)
    if "fail_or_retry_async" in calls:
        needs_error_code = needs_error_code or not (
            "error_code" in doc.lower()
            or bool(_GOOGLE_RAISES_RE.search(doc))
            or bool(_SPHINX_RAISES_RE.search(doc))
            or bool(error_tokens)
        )
    if not needs_status and not needs_error_code:
        return None
    missing = []
    if needs_status:
        missing.append("状态码")
    if needs_error_code:
        missing.append("error_code")
    return _item(
        f"comment-error-contract-{info.name}",
        info.file_path,
        info.line,
        "error_contract_undocumented",
        "P2",
        f"错误契约说明不完整：{info.name}",
        f"文档串未写清 {'、'.join(missing)}，调用方无法稳定处理失败。",
        "补充失败路径的状态码与稳定 error_code（或 Raises 段）。",
        evidence=[_function_evidence(info, source)],
        details={"missing": missing},
    )


def _has_http_exception(node: ast.AST) -> bool:
    for child in _shallow_walk(node):
        if isinstance(child, ast.Raise) and isinstance(child.exc, ast.Call):
            if _dotted_name(child.exc.func).rsplit(".", 1)[-1] == "HTTPException":
                return True
    return False


def _check_comment_patterns(
    file_path: str, source: str, functions: list[_FunctionInfo]
) -> list[QualityItem]:
    del functions
    comments = _iter_comments(source)
    if not comments:
        return []
    lines = source.splitlines()
    items: list[QualityItem] = []

    todo_lines: list[int] = []
    history_lines: list[int] = []
    code_lines: list[int] = []
    trivial_lines: list[tuple[int, str]] = []

    for line_no, text in comments:
        stripped = _clean_comment(text)
        if not stripped:
            continue
        if _skip_comment(stripped, line_no):
            continue
        if re.search(r"\b(?:TODO|FIXME|XXX|HACK)\b", stripped, re.IGNORECASE):
            if not _todo_has_owner(stripped):
                todo_lines.append(line_no)
        if _CHANGE_HISTORY_RE.search(stripped):
            history_lines.append(line_no)
        if _looks_like_commented_code(stripped):
            code_lines.append(line_no)
        if _looks_like_trivial_translation(stripped, lines, line_no):
            trivial_lines.append((line_no, stripped))

    if todo_lines:
        items.append(
            _aggregate_item(
                file_path,
                todo_lines,
                "todo_without_owner",
                "P3",
                f"无 owner 的 TODO/FIXME：{len(todo_lines)} 处",
                "待办没有负责人或跟踪编号，容易长期滞留。",
                "补充 owner（@user / #issue）或转为可跟踪任务。",
            )
        )
    if history_lines:
        items.append(
            _aggregate_item(
                file_path,
                history_lines,
                "change_history_comment",
                "P3",
                f"变更历史式注释：{len(history_lines)} 处",
                "变更历史应由版本控制承载，注释会随代码漂移。",
                "删除变更历史注释，保留解释「为什么」的约束说明。",
            )
        )
    if code_lines:
        items.append(
            _aggregate_item(
                file_path,
                code_lines,
                "commented_out_code",
                "P3",
                f"注释掉的旧代码：{len(code_lines)} 处",
                "旧代码会被误读为当前逻辑，也可能掩盖真实分支。",
                "删除旧代码；需要保留时放入版本控制或独立说明。",
            )
        )
    if trivial_lines:
        items.append(
            _aggregate_item(
                file_path,
                [line for line, _text in trivial_lines],
                "trivial_line_comment",
                "P3",
                f"逐行翻译/复述式注释：{len(trivial_lines)} 处",
                "注释只是重复下一行代码，不解释原因，增加维护成本。",
                "删除复述式注释，仅在需要说明原因、边界或风险时保留。",
            )
        )
    return items


def _iter_comments(source: str) -> list[tuple[int, str]]:
    comments: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], token.string))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return comments
    return comments


def _clean_comment(text: str) -> str:
    stripped = text.lstrip("#").strip()
    while stripped.startswith("#"):
        stripped = stripped[1:].strip()
    return stripped


def _skip_comment(text: str, line_no: int) -> bool:
    lower = text.lower()
    if lower.startswith(_SKIP_COMMENT_PREFIXES):
        return True
    if _DIVIDER_RE.match(text.strip("# ").strip()):
        return True
    return line_no <= 15 and bool(_COPYRIGHT_RE.search(text.lower()))


def _todo_has_owner(text: str) -> bool:
    return bool(_TODO_OWNER_RE.search(text)) or bool(
        _TODO_BRACKET_OWNER_RE.search(text.strip())
    )


def _looks_like_commented_code(text: str) -> bool:
    candidate = text.strip()
    if not candidate or candidate.startswith(("TODO", "FIXME", "XXX", "HACK")):
        return False
    if _CODE_OPENERS.match(candidate) and candidate.endswith(":"):
        return True
    if not any(marker in candidate.lower() for marker in _RATIONALE_MARKERS):
        if re.match(r"^(?:return|yield|raise)\s+[A-Za-z_(]", candidate) or re.match(
            r"^(?:break|continue|pass)\s*$", candidate
        ):
            return True
    try:
        tree = ast.parse(candidate)
    except (SyntaxError, ValueError):
        return False
    for statement in tree.body:
        if not isinstance(statement, _ALLOWED_CODE_STMTS):
            continue
        if isinstance(statement, ast.Expr):
            value = statement.value
            if isinstance(value, (ast.Call, ast.Attribute, ast.Subscript)) or (
                isinstance(value, ast.Constant) and isinstance(value.value, (int, float))
            ):
                return True
            continue
        return True
    return False


def _english_words(text: str) -> set[str]:
    """Lowercase English word tokens, splitting identifiers on underscores."""
    return {
        word
        for word in re.findall(r"[a-z][a-z0-9]*", text.lower())
        if word not in _STOPWORDS
    }


def _looks_like_trivial_translation(
    text: str, lines: list[str], line_no: int
) -> bool:
    candidate = text.strip()
    if len(candidate) > 48:
        return False
    if _SECTION_LABEL_RE.match(candidate) or _ANNOTATION_RE.match(candidate):
        return False
    lower = candidate.lower()
    if any(marker in lower for marker in _RATIONALE_MARKERS):
        return False
    next_line = _next_code_line(lines, line_no)
    if next_line is None:
        return False
    code = next_line.strip()
    if code.startswith(("@", "def ", "class ", "async def ", "#")):
        return False
    first_word = re.split(r"[\s:，,。.]", candidate.lstrip("# ").strip(), maxsplit=1)[0]
    starts_action = first_word.lower() in _ACTION_VERBS or first_word in _ACTION_VERBS
    has_cjk = bool(re.search(r"[\u4e00-\u9fff]", candidate))
    if not starts_action and not has_cjk:
        return False
    identifiers = {
        word for word in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", code)
        if word not in _PYTHON_KEYWORDS
    }
    mentions_identifier = any(
        word.lower() in lower for word in identifiers
    )
    simple_statement = bool(
        re.match(r"^(?:[A-Za-z_][\w.]*\s*=|return\b|[A-Za-z_][\w.]*\()", code)
    )
    if has_cjk:
        return simple_statement and (mentions_identifier or starts_action)
    # English comments: require a real lexical overlap with the next
    # statement, not merely an imperative opening verb. This keeps
    # English-dominant repositories from producing a flood of false
    # "line-by-line translation" findings.
    comment_words = _english_words(candidate)
    if not comment_words:
        return False
    overlap_ratio = len(comment_words & _english_words(code)) / len(comment_words)
    if overlap_ratio >= 0.5:
        return simple_statement
    return bool(
        simple_statement
        and (mentions_identifier or len(comment_words) <= 3)
    )


def _next_code_line(lines: list[str], line_no: int) -> str | None:
    index = line_no
    while index < len(lines):
        candidate = lines[index]
        stripped = candidate.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        return candidate
    return None


def _aggregate_item(
    file_path: str,
    line_numbers: list[int],
    category: str,
    severity: str,
    title: str,
    impact: str,
    suggestion: str,
) -> QualityItem:
    unique = sorted(set(line_numbers))
    evidence = [
        QualityEvidence(
            method="注释模式扫描",
            detail=f"{file_path}:{line}",
            file_path=file_path,
            line_start=line,
            line_end=line,
        )
        for line in unique[:5]
    ]
    return _item(
        f"comment-{category}",
        file_path,
        unique[0] if unique else 1,
        category,
        severity,
        f"{title}（{file_path}）",
        impact,
        suggestion,
        evidence=evidence,
        details={
            "file_path": file_path,
            "occurrences": len(unique),
            "lines": unique[:20],
        },
    )


def _comment_language_counts(source: str) -> tuple[int, int]:
    comments = "\n".join(text for _line, text in _iter_comments(source))
    cjk = len(re.findall(r"[\u4e00-\u9fff]", comments))
    latin = len(re.findall(r"[A-Za-z]{2,}", comments))
    return cjk, latin


def _function_evidence(info: _FunctionInfo, source: str) -> QualityEvidence:
    del source
    return QualityEvidence(
        method="函数定义位置",
        detail=f"{info.file_path}:{info.line}",
        file_path=info.file_path,
        line_start=info.line,
        line_end=info.end_line,
    )


def _llm_ready(user_config: dict[str, Any] | None) -> bool:
    if not isinstance(user_config, dict):
        return False
    for key in ("api_key", "base_url", "model"):
        value = user_config.get(key)
        if not isinstance(value, str) or not value.strip():
            return False
    return True


def _select_semantic_candidates(
    functions: list[_FunctionInfo],
) -> list[_FunctionInfo]:
    candidates = [
        info
        for info in functions
        if info.docstring and (info.is_route or info.is_state_write or len(info.params) >= 2)
    ]
    candidates.sort(
        key=lambda info: (
            0 if info.is_route else 1,
            0 if info.is_state_write else 1,
            info.file_path,
            info.line,
        )
    )
    return candidates[:_SEMANTIC_CANDIDATE_LIMIT]


def _run_semantic_llm(
    candidates: list[_FunctionInfo],
    llm_user_config: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], str | None]:
    prompt = _semantic_prompt(candidates)
    try:
        from app.services.llm_service import _call_llm_api

        response = _call_llm_api(
            prompt,
            user_config=llm_user_config,
            max_attempts=1,
            timeout_seconds=min(_LLM_TIMEOUT_SECONDS, settings.llm_timeout),
        )
    except Exception as exc:
        return [], type(exc).__name__
    if not response:
        return [], "empty_response"
    parsed = _parse_semantic_response(response)
    if not parsed:
        return [], "unparseable_response"
    return parsed, None


def _semantic_prompt(candidates: list[_FunctionInfo]) -> str:
    lines = [
        "你是代码注释审查助手。只判断语义层面，不要改写代码，不要编造事实。",
        (
            "对每个函数判断：1) 注释是否解释「为什么」而不只是复述实现；"
            "2) 参数与失败模式是否说清；3) 注释与实现是否明显漂移。"
        ),
        (
            "只输出 JSON 数组，元素形如 "
            '{"function": "name", "why_clear": true/false, '
            '"failure_modes_clear": true/false, "drift": true/false, '
            '"suggestion": "不超过 80 字"}。'
        ),
        "没有问题的函数可以省略。函数清单：",
    ]
    for info in candidates:
        doc = mask_snippet((info.docstring or "").strip())[:300]
        lines.append(
            f"- function={info.name}; file={info.file_path}; line={info.line}; "
            f"params={','.join(info.params) or '-'}; doc={doc}"
        )
    return "\n".join(lines)


def _parse_semantic_response(response: str) -> list[dict[str, Any]]:
    start = response.find("[")
    end = response.rfind("]")
    if start < 0 or end <= start:
        return []
    try:
        payload = json.loads(response[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(payload, list):
        return []
    results: list[dict[str, Any]] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        name = row.get("function")
        if not isinstance(name, str) or not name.strip():
            continue
        results.append(
            {
                "function": name.strip(),
                "why_clear": bool(row.get("why_clear")),
                "failure_modes_clear": bool(row.get("failure_modes_clear")),
                "drift": bool(row.get("drift")),
                "suggestion": str(row.get("suggestion", ""))[:300],
            }
        )
    return results


def _semantic_pending_item(
    candidates: list[_FunctionInfo], reason: str
) -> QualityItem:
    return QualityItem(
        item_id="comment-semantic-review-pending",
        dimension=DIMENSION_BACKEND_COMMENTS,
        category="semantic_review_pending",
        conclusion="manual_confirm",
        confidence=CONFIDENCE_LOW,
        severity="P3",
        title="注释语义判断未执行，需人工确认",
        impact="是否解释「为什么」、参数与失败模式是否说清、注释是否漂移未被自动判定。",
        suggestion="配置 BYOK 模型以获得建议，或人工抽查以下候选函数的注释。",
        fixability=FIXABILITY_REPORT,
        manual_decision_required=True,
        limitation=f"LLM_DISABLED：{reason}；语义判断需人工决策。",
        rule_id="comment-quality-v1",
        evidence=[
            QualityEvidence(
                method="语义检查状态",
                detail=reason,
                file_path=candidates[0].file_path if candidates else None,
            )
        ],
        details={
            "reason": reason,
            "candidates": [
                {
                    "function": info.name,
                    "file": info.file_path,
                    "line": info.line,
                }
                for info in candidates
            ],
        },
    )


def _semantic_suggestion_items(
    candidates: list[_FunctionInfo], suggestions: list[dict[str, Any]]
) -> list[QualityItem]:
    by_name = {info.name: info for info in candidates}
    items: list[QualityItem] = []
    for suggestion in suggestions:
        info = by_name.get(suggestion["function"])
        if info is None or not suggestion["suggestion"]:
            continue
        signals = []
        if not suggestion["why_clear"]:
            signals.append("未说明为什么")
        if not suggestion["failure_modes_clear"]:
            signals.append("失败模式不清")
        if suggestion["drift"]:
            signals.append("疑似与实现漂移")
        if not signals:
            continue
        items.append(
            _item(
                f"comment-semantic-{info.name}",
                info.file_path,
                info.line,
                "semantic_comment_suggestion",
                "P3",
                f"注释语义建议（模型）：{info.name}",
                "；".join(signals),
                suggestion["suggestion"],
                evidence=[
                    QualityEvidence(
                        method="确定性位置证据",
                        detail=f"{info.file_path}:{info.line}",
                        file_path=info.file_path,
                        line_start=info.line,
                        line_end=info.end_line,
                    )
                ],
                details={
                    "suggestion_source": "llm",
                    "signals": signals,
                },
                confidence=CONFIDENCE_LOW,
                manual=False,
            )
        )
    return items


def _item(
    item_id: str,
    file_path: str,
    line: int,
    category: str,
    severity: str,
    title: str,
    impact: str,
    suggestion: str,
    *,
    evidence: list[QualityEvidence] | None = None,
    details: dict[str, Any] | None = None,
    confidence: str = CONFIDENCE_HIGH,
    manual: bool = False,
) -> QualityItem:
    return QualityItem(
        item_id=_finalize_id(f"{item_id}-{file_path}-{line}"),
        dimension=DIMENSION_BACKEND_COMMENTS,
        category=category,
        conclusion=category,
        confidence=confidence,
        severity=severity,
        title=title,
        impact=impact,
        suggestion=suggestion,
        fixability=FIXABILITY_REPORT,
        manual_decision_required=manual,
        rule_id="comment-quality-v1",
        evidence=evidence or [],
        details=details or {},
    )


def _finalize_id(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug[:160] or "comment-item"


def _dedupe_items(items: list[QualityItem]) -> list[QualityItem]:
    seen: set[str] = set()
    result: list[QualityItem] = []
    for item in items:
        if item.item_id in seen:
            continue
        seen.add(item.item_id)
        result.append(item)
    return result


_STRUCTURAL_CATEGORIES = {
    "docstring_args_missing",
    "docstring_returns_missing",
    "docstring_raises_missing",
    "docstring_stale_params",
    "comment_restates_function_name",
}
_DOCSTRING_FILE_CATEGORIES = {"docstring_missing", "missing_state_write_docstring"}


def _aggregate_report_items(items: list[QualityItem]) -> list[QualityItem]:
    """Collapse high-volume per-function findings to one item per file.

    A large backend legitimately has hundreds of small helpers; emitting one
    item per helper would bury the P2 findings. Structural gaps and missing
    docstrings are therefore grouped per file with explicit function lists.
    """
    groups: dict[tuple[str, str], list[QualityItem]] = {}
    passthrough: list[QualityItem] = []
    for item in items:
        file_path = item.evidence[0].file_path if item.evidence else None
        if not file_path:
            passthrough.append(item)
            continue
        if item.category in _STRUCTURAL_CATEGORIES:
            groups.setdefault((file_path, "structure"), []).append(item)
        elif item.category in _DOCSTRING_FILE_CATEGORIES:
            groups.setdefault((file_path, item.category), []).append(item)
        else:
            passthrough.append(item)

    result = list(passthrough)
    for (file_path, group), rows in groups.items():
        rows.sort(key=lambda row: (row.evidence[0].line_start or 0) if row.evidence else 0)
        result.append(_build_aggregate_item(file_path, group, rows))
    return result


def _build_aggregate_item(
    file_path: str, group: str, rows: list[QualityItem]
) -> QualityItem:
    functions: list[dict[str, Any]] = []
    evidence: list[QualityEvidence] = []
    seen_lines: set[int] = set()
    for row in rows:
        line = row.evidence[0].line_start if row.evidence else None
        if line and line not in seen_lines and len(evidence) < 5:
            seen_lines.add(line)
            evidence.append(
                QualityEvidence(
                    method="函数定义位置",
                    detail=f"{file_path}:{line}",
                    file_path=file_path,
                    line_start=line,
                    line_end=row.evidence[0].line_end if row.evidence else line,
                )
            )
        if len(functions) < 20:
            functions.append(
                {
                    "function": row.details.get("function", row.title),
                    "line": line,
                    "missing": row.details.get("missing_sections", [row.category]),
                }
            )

    if group == "structure":
        category = "docstring_structure_incomplete"
        severity = "P3"
        title = f"文档串结构不完整：{file_path}（{len(rows)} 个函数）"
        impact = "多个函数的文档串缺少 Args/Returns/Raises 或参数已漂移。"
        suggestion = "按函数补充缺失的文档串段落，优先处理路由与状态写入函数。"
    elif group == "missing_state_write_docstring":
        category = group
        severity = "P2"
        title = f"状态写入函数缺少文档串：{file_path}（{len(rows)} 个函数）"
        impact = "并发写入、围栏令牌与事务边界没有文档说明。"
        suggestion = "为每个状态写入函数补充职责、围栏/幂等与事务边界说明。"
    else:
        category = group
        severity = "P3"
        title = f"函数缺少文档串：{file_path}（{len(rows)} 个函数）"
        impact = "函数职责、参数与边界需要阅读实现才能理解。"
        suggestion = "按函数补充简要文档串；优先处理公开 API 与核心路径。"

    return QualityItem(
        item_id=_finalize_id(f"comment-{category}-{file_path}"),
        dimension=DIMENSION_BACKEND_COMMENTS,
        category=category,
        conclusion=category,
        confidence=CONFIDENCE_HIGH,
        severity=severity,
        title=title,
        impact=impact,
        suggestion=suggestion,
        fixability=FIXABILITY_REPORT,
        manual_decision_required=False,
        rule_id="comment-quality-v1",
        evidence=evidence,
        details={
            "file_path": file_path,
            "count": len(rows),
            "functions": functions,
        },
    )
