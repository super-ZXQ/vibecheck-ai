"""Deterministic backend route audit.

The analyzer enumerates FastAPI registrations with ``ast`` (never executing
repository code), resolves ``APIRouter`` prefixes, searches repository-local
call evidence, and grades exposure risks. Runtime instantiation is intentionally
excluded: running an untrusted repository's application inside the worker would
cross the execution trust boundary.
"""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.quality.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DIMENSION_BACKEND_ROUTES,
    FIXABILITY_DIFF,
    FIXABILITY_REPORT,
    REASON_NO_BACKEND,
    REASON_PARTIAL_ENUMERATION,
    REASON_RUNTIME_UNVERIFIED,
    REASON_UNSUPPORTED_FRAMEWORK,
    STATUS_COMPLETED,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
    QualityBlock,
    QualityEvidence,
    QualityItem,
)
from app.quality.repository_index import RepoFile, RepositoryIndex

_METHOD_ATTRS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "options": "OPTIONS",
    "head": "HEAD",
}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PATH = re.compile(
    r"/(admin|internal|debug|metrics|config|secret|token|user|account|cleanup|purge|shutdown|reload)(/|$)",
    re.IGNORECASE,
)
_OPS_PATH = re.compile(
    r"^/(metrics|health|healthz|ready|readyz|livez|healthcheck|status)$",
    re.IGNORECASE,
)
_SCHEMA_PATH = re.compile(r"^/(docs|redoc|openapi\.json|swagger\.json)", re.IGNORECASE)
_EXTERNAL_PATH = re.compile(
    r"(webhook|callback|event|hook|cron|schedule|job)", re.IGNORECASE
)
_DEPRECATED_VERSION = re.compile(r"/v1(/|$)", re.IGNORECASE)
_ACCESS_GUARD = re.compile(
    r"(ensure|require|verify|check|assert|validate|authorize|authenticate)"
    r".*(access|auth|owner|submitter|permission|token|key|user|admin)",
    re.IGNORECASE,
)
_DEFINITION_LINE = re.compile(
    r"^\s*(@(?:app|router|api)\.|.*\b(include_router|add_api_route|app\.mount)\s*\()"
)
_EXCLUDED_EVIDENCE_DIRS = {
    "fixtures",
    "fixture",
    "examples",
    "example",
    "samples",
    "sample",
    "testdata",
    "node_modules",
    ".git",
    ".venv",
    "vendor",
}
_EXCLUDED_SOURCE_DIRS = _EXCLUDED_EVIDENCE_DIRS | {
    "tests",
    "test",
    "__tests__",
    "e2e",
}
_BACKEND_DIR_TOKENS = {
    "backend",
    "server",
    "api",
    "service",
    "services",
    "cmd",
    "internal",
}
_OPS_FILENAMES = (
    "dockerfile",
    "docker-compose",
    "compose.yaml",
    "compose.yml",
    "makefile",
    "procfile",
    "prometheus",
    "nginx.conf",
)
_OPS_PATH_PARTS = (
    ".github/workflows/",
    "/k8s/",
    "/kubernetes/",
    "/helm/",
    "/charts/",
    "/deploy/",
    "/deployment/",
    "/terraform/",
    "/ansible/",
)
_CLI_PATH_PARTS = (
    "/scripts/",
    "/script/",
    "/tools/",
    "/benchmark/",
    "/benchmarks/",
    "/loadtest/",
    "/loadtests/",
)
_FRONTEND_PATH_PARTS = (
    "frontend/",
    "frontend\\",
    "/web/",
    "/client/",
    "/ui/",
    "/apps/",
)
_SOURCE_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"}


@dataclass(frozen=True, slots=True)
class _RouterInfo:
    prefix: str
    dependencies: tuple[str, ...]
    file_path: str
    line: int


@dataclass(frozen=True, slots=True)
class _IncludeEdge:
    child: tuple[str, str]
    parent: tuple[str, str] | None
    prefix: str
    file_path: str
    line: int
    conditional: bool
    condition: str
    unresolved: bool = False


@dataclass(slots=True)
class _RouteDecl:
    methods: tuple[str, ...]
    path: str
    router: tuple[str, str] | None
    file_path: str
    line: int
    endpoint: str
    include_in_schema: bool = True
    auth_guard: str | None = None
    body_guard: str | None = None
    conditional: bool = False
    condition: str = ""
    unresolved: bool = False
    framework_generated: bool = False


@dataclass(frozen=True, slots=True)
class _Chain:
    prefix: str
    reachable: bool
    conditional: bool
    condition: str
    unresolved: bool


@dataclass(slots=True)
class _RouteRecord:
    method: str
    path: str
    file_path: str
    line: int
    endpoint: str
    include_in_schema: bool
    conditional: bool
    condition: str
    auth_guard: str | None
    body_guard: str | None
    unresolved: bool
    framework_generated: bool
    reachable: bool
    call_evidence: list[dict[str, Any]] = field(default_factory=list)
    verdict: str = ""
    confidence: str = CONFIDENCE_MEDIUM
    risk_priority: str | None = None


@dataclass(slots=True)
class _SpecRoutes:
    file_path: str
    methods: set[tuple[str, str]]


class _RouteFileAnalyzer:
    """Parse one Python file into router definitions, edges and route declarations."""

    def __init__(
        self,
        rel_path: str,
        source: str,
        module_lookup: dict[str, str],
        router_infos: dict[tuple[str, str], _RouterInfo],
        app_infos: dict[tuple[str, str], dict[str, Any]],
        function_guards: dict[tuple[str, str], str],
        edges: list[_IncludeEdge],
        declarations: list[_RouteDecl],
        mounts: list[dict[str, Any]],
    ) -> None:
        self.rel_path = rel_path
        self.source = source
        self.module_lookup = module_lookup
        self.router_infos = router_infos
        self.app_infos = app_infos
        self.function_guards = function_guards
        self.edges = edges
        self.declarations = declarations
        self.mounts = mounts
        self._imported_names: dict[str, tuple[str, str]] = {}
        self._module_aliases: dict[str, str] = {}
        self._name_bindings: dict[str, tuple[str, str]] = {}
        self._conditional: list[str] = []
        self._factory_depth = 0
        self._scope_names: list[str] = []

    # -- resolution ---------------------------------------------------------

    def _resolve_name(self, name: str) -> tuple[str, str]:
        if name in self._name_bindings:
            return self._name_bindings[name]
        if name in self._imported_names:
            return self._imported_names[name]
        return (self.rel_path, name)

    def _resolve_expr(self, node: ast.AST | None) -> tuple[str, str] | None:
        if isinstance(node, ast.Name):
            if node.id in self._module_aliases:
                return None
            return self._resolve_name(node.id)
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted:
                resolved = self._resolve_dotted(dotted)
                if resolved is not None:
                    return resolved
            return None
        return None

    def _resolve_dotted(self, dotted: str) -> tuple[str, str] | None:
        parts = dotted.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            module = ".".join(parts[:cut])
            target = self.module_lookup.get(module)
            if target is not None:
                attr = parts[cut]
                return (target, attr)
        if parts[0] in self._module_aliases:
            module = self._module_aliases[parts[0]]
            if len(parts) == 2:
                target = self.module_lookup.get(module)
                if target is not None:
                    return (target, parts[1])
        # `from app.api import users` binds `users` to a *module*, so
        # `users.router` resolves to (users.py, "router").
        imported = self._imported_names.get(parts[0])
        if imported is not None and len(parts) == 2:
            target, name = imported
            if name == parts[0]:
                return (target, parts[1])
        return None

    def _resolve_router(self, node: ast.AST | None) -> tuple[str, str] | None:
        return self._resolve_expr(node)

    # -- pass A: imports, router/app assignments, guards -------------------

    def collect_definitions(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    module = node.module
                    if alias.name != "*":
                        child_module = f"{module}.{alias.name}"
                        if child_module in self.module_lookup:
                            module = child_module
                    target = self.module_lookup.get(module)
                    if target is None:
                        continue
                    local = alias.asname or alias.name
                    self._imported_names[local] = (target, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self._module_aliases[local] = alias.name

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                assign_target = node.targets[0]
                if not isinstance(assign_target, ast.Name):
                    continue
                value = node.value
                if isinstance(value, (ast.Name, ast.Attribute)):
                    resolved = self._resolve_expr(value)
                    if resolved is not None:
                        self._name_bindings[assign_target.id] = resolved
                    continue
                if not isinstance(value, ast.Call):
                    continue
                func_name = _call_name(value.func)
                if func_name not in {"APIRouter", "FastAPI", "fastapi.APIRouter", "fastapi.FastAPI"}:
                    continue
                key = (self.rel_path, assign_target.id)
                if func_name.endswith("APIRouter"):
                    prefix = _kw_const(value, "prefix") or ""
                    dependencies = _dependency_names(_kw(value, "dependencies"))
                    self.router_infos[key] = _RouterInfo(
                        prefix=prefix,
                        dependencies=dependencies,
                        file_path=self.rel_path,
                        line=node.lineno,
                    )
                else:
                    docs = {
                        "docs_url": _kw(value, "docs_url"),
                        "redoc_url": _kw(value, "redoc_url"),
                        "openapi_url": _kw(value, "openapi_url"),
                    }
                    self.app_infos[key] = {
                        "file_path": self.rel_path,
                        "line": node.lineno,
                        "docs": docs,
                    }

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                guard = _body_guard(node)
                if guard:
                    self.function_guards[(self.rel_path, node.name)] = guard

    # -- pass B: declarations and include edges -----------------------------

    def collect_routes(self, tree: ast.AST) -> None:
        self._visit(tree)

    def _visit(self, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self._handle_decorator(decorator, node.name)
            is_factory = _is_factory_name(node.name) or self._factory_depth > 0
            if is_factory:
                self._factory_depth += 1
            else:
                self._scope_names.append(node.name)
            for child in node.body:
                self._visit(child)
            if is_factory:
                self._factory_depth -= 1
            else:
                self._scope_names.pop()
            return
        if isinstance(node, ast.ClassDef):
            self._scope_names.append(node.name)
            for child in node.body:
                self._visit(child)
            self._scope_names.pop()
            return
        if isinstance(node, ast.If):
            reason = f"if {_source_snippet(self.source, node.test)}"
            self._conditional.append(reason)
            for child in node.body + node.orelse:
                self._visit(child)
            self._conditional.pop()
            return
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            self._conditional.append("loop registration")
            for child in node.body + node.orelse:
                self._visit(child)
            self._conditional.pop()
            return
        if isinstance(node, ast.Call):
            self._handle_call(node)
        for subnode in ast.iter_child_nodes(node):
            self._visit(subnode)

    def _handle_decorator(self, node: ast.AST, endpoint_name: str) -> None:
        if not isinstance(node, ast.Call):
            return
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        owner = self._resolve_router(func.value)
        if owner is None:
            return
        attr = func.attr
        if attr not in _METHOD_ATTRS and attr not in {"api_route", "websocket"}:
            return
        methods: tuple[str, ...]
        if attr == "websocket":
            methods = ("WEBSOCKET",)
        elif attr == "api_route":
            methods = _methods_kw(node) or ("GET",)
        else:
            methods = (_METHOD_ATTRS[attr],)
        path_node = node.args[0] if node.args else _kw(node, "path")
        path = _const_str(path_node)
        self.declarations.append(
            _RouteDecl(
                methods=methods,
                path=path or "",
                router=owner,
                file_path=self.rel_path,
                line=node.lineno,
                endpoint=endpoint_name,
                include_in_schema=_kw_const_bool(node, "include_in_schema", True),
                auth_guard=_decorator_guard(node)
                or self.function_guards.get((self.rel_path, endpoint_name)),
                conditional=bool(self._conditional),
                condition="; ".join(self._conditional),
                unresolved=path is None,
            )
        )

    def _handle_call(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        attr = func.attr
        owner = self._resolve_router(func.value)
        if attr == "include_router" and node.args:
            child = self._resolve_router(node.args[0])
            prefix = _kw_const(node, "prefix") or ""
            unresolved = child is None
            self.edges.append(
                _IncludeEdge(
                    child=child or ("", ""),
                    parent=owner,
                    prefix=prefix,
                    file_path=self.rel_path,
                    line=node.lineno,
                    conditional=bool(self._conditional),
                    condition="; ".join(self._conditional),
                    unresolved=unresolved,
                )
            )
            return
        if attr in {"add_api_route", "add_websocket_route"} and node.args:
            path = _const_str(node.args[0])
            methods = (
                ("WEBSOCKET",)
                if attr == "add_websocket_route"
                else _methods_kw(node) or ("GET",)
            )
            endpoint_name = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Name):
                endpoint_name = node.args[1].id
            self.declarations.append(
                _RouteDecl(
                    methods=methods,
                    path=path or "",
                    router=owner,
                    file_path=self.rel_path,
                    line=node.lineno,
                    endpoint=endpoint_name,
                    include_in_schema=_kw_const_bool(node, "include_in_schema", True),
                    auth_guard=_decorator_guard(node)
                    or self.function_guards.get((self.rel_path, endpoint_name)),
                    conditional=bool(self._conditional),
                    condition="; ".join(self._conditional),
                    unresolved=path is None,
                )
            )
            return
        if attr == "mount" and node.args:
            path = _const_str(node.args[0])
            self.mounts.append(
                {
                    "file_path": self.rel_path,
                    "line": node.lineno,
                    "path": path,
                    "conditional": bool(self._conditional),
                    "condition": "; ".join(self._conditional),
                }
            )


def _collect_framework_routes(
    app_infos: dict[tuple[str, str], dict[str, Any]],
    declarations: list[_RouteDecl],
    sources: dict[str, str],
) -> None:
    """Emit the docs/redoc/openapi pseudo-routes once for all app instances."""
    for key, info in app_infos.items():
        source = sources.get(info["file_path"], "")
        for mode, default in (
            ("docs_url", "/docs"),
            ("redoc_url", "/redoc"),
            ("openapi_url", "/openapi.json"),
        ):
            expression = info["docs"][mode]
            if isinstance(expression, ast.Constant) and expression.value is None:
                continue
            const_path = _const_str(expression) if expression is not None else default
            conditional = expression is not None and const_path is None
            path = const_path or default
            declarations.append(
                _RouteDecl(
                    methods=("GET",),
                    path=path,
                    router=key,
                    file_path=info["file_path"],
                    line=info["line"],
                    endpoint=f"framework:{mode}",
                    conditional=conditional,
                    condition=(
                        f"{mode}={_source_snippet(source, expression)}"
                        if conditional
                        else ""
                    ),
                    unresolved=False,
                    framework_generated=True,
                )
            )


def _is_backend_source(item: RepoFile) -> bool:
    """Heuristic: does this file plausibly belong to a server-side app?

    Frontend-only repositories are common; counting every .ts/.tsx file as a
    backend would turn "no backend" into a false unsupported-framework state.
    Non-Python server files therefore need a backend-ish directory or a
    root-level entry point.
    """
    if item.suffix == ".py":
        return True
    if item.suffix in {".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs"}:
        parts = item.rel_path.lower().split("/")
        return len(parts) == 1 or any(
            part in _BACKEND_DIR_TOKENS for part in parts[:-1]
        )
    if item.suffix in {".ts", ".js", ".mjs", ".cjs"}:
        parts = item.rel_path.lower().split("/")
        return any(part in _BACKEND_DIR_TOKENS for part in parts[:-1])
    return False


def analyze_backend_routes(index: RepositoryIndex) -> QualityBlock:
    """Build the backend route audit block for a repository index."""
    py_files = index.by_suffix(".py")
    backend_files = [item for item in index.files if _is_backend_source(item)]
    if not backend_files:
        return _not_applicable_block()
    if not py_files:
        return _unsupported_framework_block(["non-python backend"], len(backend_files))

    module_lookup = _build_module_lookup(py_files)
    router_infos: dict[tuple[str, str], _RouterInfo] = {}
    app_infos: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[_IncludeEdge] = []
    declarations: list[_RouteDecl] = []
    mounts: list[dict[str, Any]] = []
    function_guards: dict[tuple[str, str], str] = {}
    parse_errors = 0
    fastapi_files = 0
    framework_hints: set[str] = set()
    analyzed_files = 0

    source_py_files = [
        item for item in py_files if not _excluded_source_path(item.rel_path)
    ]
    file_sources: dict[str, str] = {}

    for file_item in source_py_files:
        source = index.read_text(file_item.rel_path)
        if source is None:
            continue
        file_sources[file_item.rel_path] = source
        analyzed_files += 1
        if _mentions_fastapi(source):
            fastapi_files += 1
        hint = _framework_hint(source, file_item.rel_path)
        if hint:
            framework_hints.add(hint)
        try:
            tree = ast.parse(source, filename=file_item.rel_path)
        except (SyntaxError, ValueError):
            parse_errors += 1
            continue
        analyzer = _RouteFileAnalyzer(
            rel_path=file_item.rel_path,
            source=source,
            module_lookup=module_lookup,
            router_infos=router_infos,
            app_infos=app_infos,
            function_guards=function_guards,
            edges=edges,
            declarations=declarations,
            mounts=mounts,
        )
        analyzer.collect_definitions(tree)
        analyzer.collect_routes(tree)

    _collect_framework_routes(app_infos, declarations, file_sources)

    if fastapi_files == 0:
        hints = sorted(framework_hints) or ["python (no FastAPI)"]
        return _unsupported_framework_block(hints, analyzed_files)

    records, unresolved_routes = _resolve_route_records(
        declarations=declarations,
        router_infos=router_infos,
        app_infos=app_infos,
        edges=edges,
    )
    spec = _load_openapi_specs(index)
    _attach_evidence(index, records)
    _apply_verdicts(records, spec)
    spec_verification = _spec_verification(records, spec)
    conditional_count = len([record for record in records if record.conditional])
    has_conditional = conditional_count > 0

    items = _build_items(records)
    risk_counts: dict[str, int] = defaultdict(int)
    for item in items:
        risk_counts[item.severity] += 1

    inventory = [_inventory_row(record) for record in records]
    counts = {
        "routes_enumerated": len(records),
        "routes_reachable": len([row for row in records if row.reachable]),
        "routes_used": len([row for row in records if row.verdict == "used"]),
        "routes_public_contract": len(
            [row for row in records if row.verdict == "public_contract"]
        ),
        "routes_unused_candidates": len(
            [row for row in records if row.verdict == "unused_candidate"]
        ),
        "routes_manual_confirm": len(
            [row for row in records if row.verdict == "manual_confirm"]
        ),
        "risk_p0": risk_counts.get("P0", 0),
        "risk_p1": risk_counts.get("P1", 0),
        "risk_p2": risk_counts.get("P2", 0),
        "risk_p3": risk_counts.get("P3", 0),
    }

    status = STATUS_COMPLETED
    reason_code: str | None = None
    reason_message = ""
    if unresolved_routes or parse_errors or mounts:
        status = STATUS_PARTIAL
        reason_code = REASON_PARTIAL_ENUMERATION
        reason_message = (
            "部分路由无法完整枚举：存在无法解析的前缀/路径、挂载子应用或语法错误，"
            "相关条目已进入人工确认。"
        )
    elif has_conditional:
        status = STATUS_PARTIAL
        reason_code = REASON_RUNTIME_UNVERIFIED
        reason_message = (
            "存在条件注册或 feature flag 包裹的路由；本版本不实例化被检应用，"
            "静态枚举结果需人工确认。"
        )

    if items:
        headline = (
            f"枚举 {len(records)} 条路由；发现 {len(items)} 项问题/需人工确认项"
            f"（P0 {risk_counts.get('P0', 0)} / P1 {risk_counts.get('P1', 0)} / "
            f"P2 {risk_counts.get('P2', 0)} / P3 {risk_counts.get('P3', 0)}）。"
        )
    else:
        headline = f"在已覆盖输入范围内未发现问题（枚举 {len(records)} 条路由）。"

    checks = [
        {
            "name": "static_route_enumeration",
            "status": "passed" if not unresolved_routes else "partial",
            "detail": f"FastAPI AST 枚举 {len(records)} 条路由",
        },
        {
            "name": "call_evidence_search",
            "status": "passed",
            "detail": "仓库内调用证据检索完成",
        },
    ]
    if spec:
        checks.append(
            {
                "name": "openapi_cross_validation",
                "status": "passed",
                "detail": spec_verification["summary"],
            }
        )
    else:
        checks.append(
            {
                "name": "openapi_cross_validation",
                "status": "skipped",
                "detail": "未找到 openapi/swagger JSON；未能交叉验证",
            }
        )
    checks.append(
        {
            "name": "runtime_registration_diff",
            "status": "skipped",
            "detail": "不实例化被检应用（执行不可信代码属于 RCE 边界）",
        }
    )

    uncovered = [
        "仓库外调用方、网关暴露面需结合网关/APM 日志人工确认",
        "运行时条件注册与 feature flag 实际生效分支未执行",
        "模板字符串拼接的 URL 仅按静态前缀命中，无法证明具体目标",
        "路由注册文件被排除在调用证据语料，避免声明行自匹配",
    ]
    if mounts:
        uncovered.append("Mount 挂载的子应用未展开")
    if not spec:
        uncovered.append("缺少 OpenAPI/Swagger JSON，无法交叉验证注册与契约")
    if parse_errors:
        uncovered.append(f"{parse_errors} 个 Python 文件存在语法错误，未纳入枚举")

    return QualityBlock(
        dimension=DIMENSION_BACKEND_ROUTES,
        status=status,
        reason_code=reason_code,
        reason_message=reason_message,
        conclusion={"headline": headline, "counts": counts},
        evidence=[
            QualityEvidence(
                method="静态 AST 路由台账",
                detail=f"{len(records)} 条路由，证据表见 details.routes",
            )
        ],
        items=items,
        verification={
            "checks_run": checks,
            "uncovered_risks": uncovered,
            "openapi": spec_verification,
        },
        coverage={
            "files_considered": len(py_files),
            "files_analyzed": analyzed_files,
            "frameworks": ["fastapi"],
            "conditional_routes": conditional_count,
            "unresolved_routes": unresolved_routes,
            "mounts": len(mounts),
            "parse_errors": parse_errors,
            "inputs_missing": [] if spec else ["openapi/swagger JSON"],
        },
        details={"routes": inventory, "mounts": mounts},
    )


def _resolve_route_records(
    declarations: list[_RouteDecl],
    router_infos: dict[tuple[str, str], _RouterInfo],
    app_infos: dict[tuple[str, str], dict[str, Any]],
    edges: list[_IncludeEdge],
) -> tuple[list[_RouteRecord], int]:
    edges_by_child: dict[tuple[str, str], list[_IncludeEdge]] = defaultdict(list)
    for edge in edges:
        if edge.parent is not None:
            edges_by_child[edge.child].append(edge)

    unresolved_routes = 0
    records: list[_RouteRecord] = []

    def chains(
        key: tuple[str, str], visited: set[tuple[str, str]]
    ) -> list[_Chain]:
        if key in visited:
            return [_Chain("", False, False, "cycle", True)]
        base = router_infos[key].prefix if key in router_infos else ""
        if key in app_infos:
            return [_Chain(base, True, False, "", False)]
        outgoing = edges_by_child.get(key, [])
        if not outgoing:
            return [_Chain(base, False, False, "", key not in router_infos)]
        result: list[_Chain] = []
        for edge in outgoing:
            if edge.parent is None:
                result.append(_Chain(base, False, edge.conditional, edge.condition, True))
                continue
            parent_chain = chains(edge.parent, visited | {key})
            for chain in parent_chain[:8]:
                result.append(
                    _Chain(
                        prefix=_join_path(chain.prefix, edge.prefix, base),
                        reachable=chain.reachable,
                        conditional=chain.conditional or edge.conditional,
                        condition="; ".join(
                            part for part in (edge.condition, chain.condition) if part
                        ),
                        unresolved=chain.unresolved or edge.unresolved,
                    )
                )
        return result or [_Chain(base, False, False, "", True)]

    for decl in declarations:
        if decl.router is None:
            unresolved_routes += 1
            continue
        route_chains = chains(decl.router, set())
        for chain in route_chains:
            path = _join_path(chain.prefix, decl.path) if not decl.unresolved else ""
            unresolved = decl.unresolved or chain.unresolved
            if unresolved:
                unresolved_routes += 1
            for method in decl.methods:
                records.append(
                    _RouteRecord(
                        method=method,
                        path=path or "<unresolved>",
                        file_path=decl.file_path,
                        line=decl.line,
                        endpoint=decl.endpoint,
                        include_in_schema=decl.include_in_schema,
                        conditional=decl.conditional or chain.conditional,
                        condition="; ".join(
                            part for part in (decl.condition, chain.condition) if part
                        ),
                        auth_guard=decl.auth_guard,
                        body_guard=decl.body_guard,
                        unresolved=unresolved,
                        framework_generated=decl.framework_generated,
                        reachable=chain.reachable,
                    )
                )

    deduped: dict[tuple[str, str, str, int, str], _RouteRecord] = {}
    for record in records:
        key = (
            record.method,
            record.path,
            record.file_path,
            record.line,
            record.endpoint,
        )
        deduped.setdefault(key, record)
    ordered = sorted(
        deduped.values(), key=lambda row: (row.path, row.method, row.file_path, row.line)
    )
    return ordered, unresolved_routes


def _attach_evidence(index: RepositoryIndex, records: list[_RouteRecord]) -> None:
    if not records:
        return
    registration_files = {record.file_path for record in records}
    spec_files = {
        item.rel_path for item in index.files if _is_openapi_spec(item.rel_path)
    }
    matchers = [(record, _path_matcher(record.path)) for record in records]
    for file_item in index.files:
        if file_item.rel_path in registration_files or file_item.rel_path in spec_files:
            continue
        if _excluded_evidence_path(file_item.rel_path):
            continue
        category = _evidence_category(file_item)
        if category is None:
            continue
        text = index.read_text(file_item.rel_path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _DEFINITION_LINE.match(line):
                continue
            for record, matcher in matchers:
                if len(record.call_evidence) >= 8:
                    continue
                kind = matcher(line)
                if kind is None:
                    continue
                record.call_evidence.append(
                    {
                        "category": category,
                        "file_path": file_item.rel_path,
                        "line": line_number,
                        "match_kind": kind,
                        "snippet": line.strip()[:200],
                    }
                )


def _path_matcher(path: str) -> Any:
    if not path or path == "<unresolved>" or not path.startswith("/"):
        return lambda _line: None
    prefix, suffix = _static_path_bounds(path)
    if "{" not in path:
        needle = path.rstrip("/")
        if len(needle) < 4:
            return lambda _line: None
        return lambda line: "exact" if needle in line else None
    if len(prefix) < 4 or prefix == "/":
        return lambda _line: None
    if suffix:
        return (
            lambda line: "exact"
            if prefix in line and suffix in line
            else ("prefix_weak" if prefix in line else None)
        )
    return lambda line: "prefix" if prefix in line else None


def _static_path_bounds(path: str) -> tuple[str, str]:
    first = path.find("{")
    last = path.rfind("}")
    prefix = path[:first] if first >= 0 else path
    suffix = path[last + 1 :] if last >= 0 else ""
    if suffix == "/":
        suffix = ""
    return prefix, suffix


def _apply_verdicts(
    records: list[_RouteRecord], spec: list[_SpecRoutes]
) -> None:
    spec_methods = {
        (method, path) for spec_route in spec for method, path in spec_route.methods
    }
    v2_paths = {record.path for record in records if "/v2" in record.path.lower()}
    for record in records:
        strong_hits = [
            row
            for row in record.call_evidence
            if row.get("match_kind") in {"exact", "prefix"}
        ]
        categories = {row["category"] for row in strong_hits}
        strong_usage = bool(
            categories
            & {"frontend_client", "backend_call", "cli_script", "code_reference"}
        )
        contract = bool(categories & {"docs", "tests", "ops_probe"})
        prefix_only = bool(record.call_evidence) and not strong_hits
        risk, priority, confidence = _route_risk(record, v2_paths)
        record.risk_priority = priority
        record.confidence = confidence
        if record.framework_generated:
            record.verdict = "manual_confirm"
            record.confidence = CONFIDENCE_LOW
            continue
        if not record.reachable:
            record.verdict = "defined_not_registered"
            record.confidence = CONFIDENCE_LOW
            continue
        if (record.method, record.path) in spec_methods:
            contract = True
        if strong_usage:
            record.verdict = "used"
            record.confidence = CONFIDENCE_HIGH
        elif contract:
            record.verdict = "public_contract"
            record.confidence = CONFIDENCE_HIGH
        elif risk is not None:
            record.verdict = "manual_confirm"
        elif prefix_only:
            record.verdict = "manual_confirm"
            record.confidence = CONFIDENCE_MEDIUM
        else:
            record.verdict = "unused_candidate"
            record.confidence = CONFIDENCE_MEDIUM


def _route_risk(
    record: _RouteRecord, v2_paths: set[str]
) -> tuple[str | None, str | None, str]:
    path = record.path
    if _is_docs_route(record):
        return "schema_endpoint", "P2", CONFIDENCE_LOW
    if _OPS_PATH.match(path) or (record.include_in_schema is False and "metric" in path):
        return "ops_endpoint", "P1", CONFIDENCE_HIGH
    if _SENSITIVE_PATH.search(path):
        return "internal_endpoint", "P1", CONFIDENCE_MEDIUM
    if record.conditional:
        return "conditional_registration", "P2", CONFIDENCE_LOW
    if _DEPRECATED_VERSION.search(path) and path.replace("/v1", "/v2") in v2_paths:
        return "deprecated_version", "P3", CONFIDENCE_MEDIUM
    if record.method in _WRITE_METHODS and not _has_guard(record):
        if _SENSITIVE_PATH.search(path):
            return "unauthenticated_sensitive_write", "P1", CONFIDENCE_LOW
        return "public_write_unverified", "P3", CONFIDENCE_LOW
    if record.include_in_schema is False:
        return "hidden_route", "P2", CONFIDENCE_MEDIUM
    return None, None, record.confidence


def _has_guard(record: _RouteRecord) -> bool:
    return bool(record.auth_guard or record.body_guard)


def _is_docs_route(record: _RouteRecord) -> bool:
    return record.framework_generated or bool(_SCHEMA_PATH.match(record.path))


def _build_items(records: list[_RouteRecord]) -> list[QualityItem]:
    items: list[QualityItem] = []
    for record in records:
        if (
            record.verdict in {"used", "public_contract"}
            and record.risk_priority is None
        ):
            continue
        if record.verdict == "defined_not_registered":
            category = "defined_not_registered"
            title = (
                "路由已定义但未挂载到任何 FastAPI 应用："
                f"{record.method} {record.path}"
            )
            conclusion = "unused_candidate"
            priority = "P3"
            fixability = FIXABILITY_REPORT
            confidence = CONFIDENCE_MEDIUM
        elif record.unresolved:
            category = "unresolved_route"
            title = "路由路径/前缀无法静态解析"
            conclusion = "manual_confirm"
            priority = "P2"
            fixability = FIXABILITY_REPORT
            confidence = CONFIDENCE_LOW
        elif record.risk_priority is not None:
            category = _risk_category(record)
            title, conclusion, fixability = _risk_text(record, category)
            priority = record.risk_priority
            confidence = record.confidence
        elif record.verdict == "unused_candidate":
            category = "unused_route_candidate"
            title = f"仓库内未发现调用方：{record.method} {record.path}"
            conclusion = "unused_candidate"
            priority = "P3"
            fixability = FIXABILITY_DIFF
            confidence = CONFIDENCE_MEDIUM
        else:
            category = "dynamic_reference_or_unknown"
            title = f"仅存在前缀/动态引用，需人工确认：{record.method} {record.path}"
            conclusion = "manual_confirm"
            priority = "P3"
            fixability = FIXABILITY_REPORT
            confidence = CONFIDENCE_MEDIUM

        evidence = _route_item_evidence(record)
        limitation = "仓库外调用方无法在仓库内证明；网关实际暴露面需人工确认。"
        manual = True
        items.append(
            QualityItem(
                item_id=f"route-{record.method.lower()}-{_slug(record.path)}-{record.line}",
                dimension=DIMENSION_BACKEND_ROUTES,
                category=category,
                conclusion=conclusion,
                confidence=confidence,
                severity=priority,
                title=title,
                impact="该路由可能缺少调用方、鉴权设计或契约说明，需结合部署与网关确认。",
                suggestion=(
                    "补充调用方/契约说明，或增加鉴权与限流；删除前必须确认仓库外调用方。"
                ),
                fixability=fixability,
                manual_decision_required=manual,
                limitation=limitation,
                rule_id="route-audit-v1",
                evidence=evidence,
                details={
                    "method": record.method,
                    "path": record.path,
                    "registration": {
                        "file_path": record.file_path,
                        "line": record.line,
                    },
                    "include_in_schema": record.include_in_schema,
                    "conditional": record.conditional,
                    "condition": record.condition,
                    "auth_guard": record.auth_guard or record.body_guard,
                    "call_evidence": record.call_evidence,
                    "reachable": record.reachable,
                },
            )
        )
    return items


def _risk_category(record: _RouteRecord) -> str:
    path = record.path
    if record.framework_generated or _SCHEMA_PATH.match(path):
        return "schema_endpoint"
    if _OPS_PATH.match(path) or (record.include_in_schema is False and "metric" in path):
        return "ops_endpoint"
    if _SENSITIVE_PATH.search(path):
        return "internal_endpoint"
    if record.conditional:
        return "conditional_registration"
    if record.method in _WRITE_METHODS and not _has_guard(record):
        return "public_write_unverified"
    if record.include_in_schema is False:
        return "hidden_route"
    return "route_risk"


def _risk_text(record: _RouteRecord, category: str) -> tuple[str, str, str]:
    if category == "schema_endpoint":
        return (
            f"框架文档/Schema 端点：{record.method} {record.path}",
            "schema_exposure",
            FIXABILITY_REPORT,
        )
    if category == "ops_endpoint":
        return (
            f"运维/指标端点公网可达性需确认：{record.method} {record.path}",
            "ops_exposure",
            FIXABILITY_REPORT,
        )
    if category == "internal_endpoint":
        return (
            f"内部/敏感路由未发现鉴权守卫：{record.method} {record.path}",
            "unverified_auth",
            FIXABILITY_REPORT,
        )
    if category == "conditional_registration":
        return (
            f"条件注册/feature flag 路由：{record.method} {record.path}",
            "conditional_registration",
            FIXABILITY_REPORT,
        )
    if category == "public_write_unverified":
        return (
            f"写操作未发现鉴权守卫：{record.method} {record.path}",
            "unverified_write_auth",
            FIXABILITY_REPORT,
        )
    if category == "hidden_route":
        return (
            f"隐藏于 Schema 的可达路由：{record.method} {record.path}",
            "hidden_route",
            FIXABILITY_REPORT,
        )
    return (
        f"路由风险需人工确认：{record.method} {record.path}",
        "manual_confirm",
        FIXABILITY_REPORT,
    )


def _route_item_evidence(record: _RouteRecord) -> list[QualityEvidence]:
    evidence = [
        QualityEvidence(
            method="静态注册",
            file_path=record.file_path,
            line_start=record.line,
            detail=f"{record.method} {record.path}",
        )
    ]
    for hit in record.call_evidence[:5]:
        evidence.append(
            QualityEvidence(
                method=f"调用证据·{hit['category']}",
                file_path=hit["file_path"],
                line_start=hit["line"],
                snippet=hit["snippet"],
                detail=str(hit.get("match_kind", "")),
            )
        )
    return evidence


def _inventory_row(record: _RouteRecord) -> dict[str, Any]:
    return {
        "method": record.method,
        "path": record.path,
        "registration": {"file_path": record.file_path, "line": record.line},
        "endpoint": record.endpoint,
        "include_in_schema": record.include_in_schema,
        "conditional": record.conditional,
        "condition": record.condition,
        "reachable": record.reachable,
        "auth_guard": record.auth_guard or record.body_guard,
        "call_evidence": record.call_evidence[:6],
        "verdict": record.verdict,
        "risk_priority": record.risk_priority,
        "confidence": record.confidence,
    }


def _spec_verification(
    records: list[_RouteRecord], specs: list[_SpecRoutes]
) -> dict[str, Any]:
    if not specs:
        return {
            "status": "skipped",
            "summary": "未找到 OpenAPI/Swagger JSON",
            "static_only": 0,
            "spec_only": 0,
            "matched": 0,
        }
    spec_methods = {
        (method, path) for spec_route in specs for method, path in spec_route.methods
    }
    static_methods = {
        (record.method, record.path)
        for record in records
        if not record.framework_generated and record.reachable
    }
    matched = static_methods & spec_methods
    static_only = static_methods - spec_methods
    spec_only = spec_methods - static_methods
    return {
        "status": "passed",
        "summary": (
            f"OpenAPI 命中 {len(matched)} 条，静态独有 {len(static_only)} 条，"
            f"规格独有 {len(spec_only)} 条"
        ),
        "files": [spec.file_path for spec in specs],
        "matched": len(matched),
        "static_only": len(static_only),
        "spec_only": len(spec_only),
    }


def _load_openapi_specs(index: RepositoryIndex) -> list[_SpecRoutes]:
    specs: list[_SpecRoutes] = []
    for file_item in index.files:
        if not _is_openapi_spec(file_item.rel_path) or file_item.suffix != ".json":
            continue
        text = index.read_text(file_item.rel_path)
        if text is None:
            continue
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        paths = payload.get("paths")
        if not isinstance(paths, dict):
            continue
        methods: set[tuple[str, str]] = set()
        for path, operations in paths.items():
            if not isinstance(path, str) or not isinstance(operations, dict):
                continue
            for method in operations:
                upper = str(method).upper()
                if upper in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                    methods.add((upper, path))
        if methods:
            specs.append(_SpecRoutes(file_path=file_item.rel_path, methods=methods))
    return specs


def _is_openapi_spec(rel_path: str) -> bool:
    lowered = rel_path.lower()
    name = lowered.rsplit("/", 1)[-1]
    return name in {
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
    }


def _evidence_category(file_item: RepoFile) -> str | None:
    rel = file_item.rel_path.lower()
    suffix = file_item.suffix
    if any(part in rel for part in _OPS_PATH_PARTS):
        return "ops_probe"
    name = rel.rsplit("/", 1)[-1]
    if any(name.startswith(prefix) for prefix in _OPS_FILENAMES):
        return "ops_probe"
    if any(part in rel for part in _CLI_PATH_PARTS) or name == "makefile":
        return "cli_script"
    if suffix in {".md", ".mdx", ".rst"} or name.startswith("readme"):
        return "docs"
    if (
        "/tests/" in rel
        or "/test/" in rel
        or ".test." in name
        or ".spec." in name
        or "/e2e/" in rel
    ):
        return "tests"
    if suffix in _SOURCE_SUFFIXES and any(part in rel for part in _FRONTEND_PATH_PARTS):
        return "frontend_client"
    if suffix in _SOURCE_SUFFIXES | {".py", ".go", ".java", ".kt", ".rb", ".php", ".cs"}:
        return "code_reference"
    if name == "package.json":
        return "cli_script"
    return None


def _excluded_source_path(rel_path: str) -> bool:
    """Test/fixture trees often build throwaway FastAPI apps.

    They are useful as call evidence but must never contribute route
    declarations, otherwise the inventory fills with duplicate apps and
    conditional test wrappers.
    """
    parts = rel_path.lower().split("/")
    name = parts[-1] if parts else ""
    if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return True
    return any(part in _EXCLUDED_SOURCE_DIRS for part in parts)


def _excluded_evidence_path(rel_path: str) -> bool:
    parts = rel_path.lower().split("/")
    return any(part in _EXCLUDED_EVIDENCE_DIRS for part in parts)


def _build_module_lookup(py_files: list[RepoFile]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for file_item in py_files:
        rel = file_item.rel_path
        if not rel.endswith(".py"):
            continue
        parts = rel[:-3].split("/")
        for cut in range(max(1, len(parts) - 1)):
            module = ".".join(parts[cut:])
            if module:
                lookup.setdefault(module, rel)
    return lookup


def _framework_hint(source: str, rel_path: str) -> str | None:
    lowered = source.lower()
    if "from flask" in lowered or "import flask" in lowered:
        return "flask"
    if "django" in lowered and ("urls" in rel_path.lower() or "settings" in rel_path.lower()):
        return "django"
    if "fastapi" in lowered:
        return "fastapi"
    return None


def _mentions_fastapi(source: str) -> bool:
    return "fastapi" in source.lower()


def _not_applicable_block() -> QualityBlock:
    return QualityBlock(
        dimension=DIMENSION_BACKEND_ROUTES,
        status=STATUS_NOT_APPLICABLE,
        reason_code=REASON_NO_BACKEND,
        reason_message="未检测到后端源码，未执行路由审计。",
        conclusion={
            "headline": "未检测到后端源码，该项不适用。",
            "counts": {},
        },
        coverage={"inputs_missing": ["backend source"]},
        verification={
            "checks_run": [],
            "uncovered_risks": ["未检测到后端源码"],
        },
    )


def _unsupported_framework_block(frameworks: list[str], files: int) -> QualityBlock:
    return QualityBlock(
        dimension=DIMENSION_BACKEND_ROUTES,
        status=STATUS_PARTIAL,
        reason_code=REASON_UNSUPPORTED_FRAMEWORK,
        reason_message=(
            f"检测到后端框架 {', '.join(frameworks)}，本版本仅支持 FastAPI AST 枚举，"
            "未完成路由审计。"
        ),
        conclusion={
            "headline": "检测到非 FastAPI 后端，本版本未完成路由枚举。",
            "counts": {"frameworks": frameworks},
        },
        coverage={"files_considered": files, "frameworks": frameworks},
        verification={
            "checks_run": [],
            "uncovered_risks": ["非 FastAPI 框架未覆盖", "运行时注册未校验"],
        },
    )


def _call_name(node: ast.AST) -> str:
    return _dotted_name(node)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _kw_const(call: ast.Call, name: str) -> str | None:
    return _const_str(_kw(call, name))


def _kw_const_bool(call: ast.Call, name: str, default: bool) -> bool:
    value = _kw(call, name)
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return value.value
    return default


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    return None


def _methods_kw(call: ast.Call) -> tuple[str, ...]:
    value = _kw(call, "methods")
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        result = []
        for element in value.elts:
            constant = _const_str(element)
            if constant:
                result.append(constant.upper())
        return tuple(result)
    return ()


def _dependency_names(node: ast.AST | None) -> tuple[str, ...]:
    names: list[str] = []
    if isinstance(node, (ast.List, ast.Tuple)):
        for element in node.elts:
            name = _dependency_name(element)
            if name:
                names.append(name)
    return tuple(names)


def _dependency_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        target = node.args[0] if node.args else None
        if target is not None:
            return _dotted_name(target)
    if isinstance(node, ast.Subscript):
        for value in ast.walk(node.slice):
            name = _dependency_name(value)
            if name:
                return name
    return None


def _decorator_guard(call: ast.Call) -> str | None:
    names = list(_dependency_names(_kw(call, "dependencies")))
    if names and any(_ACCESS_GUARD.search(name) or "auth" in name.lower() for name in names):
        return names[0]
    return None


def _body_guard(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted_name(child.func)
            if name and _ACCESS_GUARD.search(name):
                return name
    return None


def _is_factory_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(
        ("create_app", "build_app", "make_app", "create_", "build_", "make_")
    )


def _source_snippet(source: str, node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        value = ast.get_source_segment(source, node) or ""
    except (ValueError, TypeError, IndexError):
        value = ""
    return re.sub(r"\s+", " ", value).strip()[:80]


def _join_path(*parts: str) -> str:
    cleaned = [part.strip("/") for part in parts if part and part.strip("/")]
    if not cleaned:
        return "/"
    return "/" + "/".join(cleaned)


def _slug(path: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", path).strip("-").lower()[:60] or "root"
