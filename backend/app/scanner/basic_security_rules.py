"""High-confidence static checks for the basic-security dimension."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.core.config import settings
from app.core.security.desensitize import mask_snippet
from app.scanner.base import (
    BASIC_SECURITY_DIMENSION,
    Confidence,
    Finding,
    FindingType,
    RepositoryProbe,
    Rule,
    Severity,
)
from app.scanner.incomplete_rules import (
    EXCLUDED_PATH_PARTS,
    _analyze_source_lines,
    _code_without_comments,
    _code_without_strings,
    is_incomplete_source_file,
)

_REPOSITORY_SNIPPET = "<repository-basic-security-check>"
_HEALTH_ROUTE_RE = re.compile(
    r"(?:/|['\"])(?:health|ready|readiness|liveness|metrics|docs|openapi)(?:/|['\"]|$)",
    re.IGNORECASE,
)
_ROUTE_PATTERNS = (
    re.compile(
        r"^\s*@[A-Za-z_][\w.]*\."
        r"(?:get|post|put|patch|delete|route|api_route)\s*\(\s*['\"]/",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(?:[A-Za-z_$][\w$]*\.)*"
        r"(?:app|server|router|api|"
        r"[A-Za-z_$][\w$]*(?:app|server|router|api)|"
        r"(?:app|server|router|api)[A-Za-z_$][\w$]+)\."
        r"(?:get|post|put|patch|delete)\s*\(\s*['\"`]/",
        re.IGNORECASE,
    ),
    re.compile(r"^\s*@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b"),
    re.compile(r"^\s*@(?:Get|Post|Put|Patch|Delete)\s*\("),
    re.compile(r"^\s*\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:app|group|router|r)\.(?:GET|POST|PUT|PATCH|DELETE|HandleFunc)\s*\("),
    re.compile(r"^\s*http\.HandleFunc\s*\("),
    re.compile(r"^\s*(?:Route|Router)::(?:get|post|put|patch|delete)\s*\(", re.IGNORECASE),
    re.compile(r"^\s*(?:get|post|put|patch|delete)\s+['\"]", re.IGNORECASE),
    re.compile(r"^\s*app\.Map(?:Get|Post|Put|Patch|Delete)\s*\(", re.IGNORECASE),
)
_DJANGO_ROUTE_RE = re.compile(r"^\s*(?:path|re_path)\s*\(")
_NEXT_ROUTE_RE = re.compile(
    r"^\s*export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\("
)

_AUTH_SOURCE_RE = re.compile(
    r"OAuth2PasswordBearer|HTTPBearer|passport\.authenticate|jwt_required|"
    r"login_required|permission_classes|authentication_classes|"
    r"@Authorize\b|\bAddAuthentication\s*\(|\bUseAuthentication\s*\(|"
    r"SecurityFilterChain|@PreAuthorize\b|"
    r"Depends\s*\([^)]*(?:current_user|authenticate)|"
    r"Auth::guard|authenticate!",
    re.IGNORECASE,
)
_VALIDATION_SOURCE_RE = re.compile(
    r"\bBaseModel\b|\bField\s*\(|@Valid\b|@Validated\b|"
    r"\bzod\b|\bjoi\b|express-validator|class-validator|"
    r"validateOrReject|\.safeParse\s*\(|\.parse\s*\(\s*(?:req|request)\.|"
    r"serializer\.is_valid\s*\(|\bSchema\b|validator\.Struct\s*\(|"
    r"ShouldBind(?:JSON|Query)?\s*\(|ModelState\.IsValid|"
    r"\[(?:Required|StringLength|Range)\b|FluentValidation|\bFormRequest\b",
    re.IGNORECASE,
)
_RAW_INPUT_RE = re.compile(
    r"\brequest\.(?:body|json|data|args|form|POST|GET|query_params)\b|"
    r"\brequest\.get_json\s*\(|\brequest\.json\s*\(|"
    r"\breq\.(?:body|query|params)\b|\brequest\.getParameter\s*\(|"
    r"\bRequest\.(?:Body|Query|Form)\b|\bparams\s*\[|"
    r"\$_(?:GET|POST|REQUEST)\s*\[|\br\.(?:Body|FormValue)\b|"
    r"\br\.URL\.Query\s*\(",
    re.IGNORECASE,
)
_RATE_LIMIT_USE_RE = re.compile(
    r"@(?:limiter\.)?(?:limit|rate_limit)\b|\bLimiter\s*\(|"
    r"@Throttle\b|\bthrottle\s*[:(]|Rack::Attack|UseRateLimiter|"
    r"AddRateLimiter|AspNetCoreRateLimit|golang\.org/x/time/rate|"
    r"rate\.NewLimiter|resilience4j-ratelimiter|Bucket4j",
    re.IGNORECASE,
)
_NODE_RATE_LIMIT_IMPORT_RE = re.compile(
    r"^\s*(?:import\s+([A-Za-z_$][\w$]*)\s+from\s+"
    r"['\"]express-rate-limit['\"]|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"require\s*\(\s*['\"]express-rate-limit['\"]\s*\))",
    re.IGNORECASE | re.MULTILINE,
)
_CORS_EXPLICIT_PATTERNS = (
    re.compile(r"allow_origins\s*=\s*[\[(]\s*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"(?:setHeader|header|add_header)\s*\([^)]*Access-Control-Allow-Origin[^)]*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"(?:^|[{,])\s*['\"]Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"@CrossOrigin\s*\([^)]*['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"\.AllowAnyOrigin\s*\(", re.IGNORECASE),
    re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True\b", re.IGNORECASE),
    re.compile(r"\borigins\s+['\"]\*['\"]", re.IGNORECASE),
    re.compile(r"allowed-origins\s*[=:]\s*\*", re.IGNORECASE),
)
_NODE_CORS_IMPORT_RE = re.compile(
    r"^\s*(?:import\s+.+?\s+from\s+['\"]cors['\"]|"
    r"(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*"
    r"require\s*\(\s*['\"]cors['\"]\s*\))",
    re.IGNORECASE | re.MULTILINE,
)
_FLASK_CORS_IMPORT_RE = re.compile(r"\bflask_cors\b", re.IGNORECASE)
_SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
_SQL_SINK_RE = re.compile(
    r"\b(?:execute|executemany|query|raw|rawQuery|execSQL)\s*\(",
    re.IGNORECASE,
)
_SQL_INPUT_RE = re.compile(
    r"\brequest\.(?:body|json|data|args|form|POST|GET|query_params)\b|"
    r"\brequest\.get_json\s*\(|\breq\.(?:body|query|params)\b|"
    r"\brequest\.getParameter\s*\(|\bRequest\.(?:Body|Query|Form)\b|"
    r"\bparams\s*\[|\$_(?:GET|POST|REQUEST)\s*\[|"
    r"\br\.(?:FormValue|URL\.Query)\b",
    re.IGNORECASE,
)
_FORMAT_WRAPPER_RE = re.compile(
    r"(?:fmt\.Sprintf|String\.format)\s*\(\s*$", re.IGNORECASE
)
_CONFIG_SUFFIXES = frozenset({".yml", ".yaml", ".properties", ".toml", ".env"})

_RULE_METADATA: dict[str, tuple[str, Severity, str, str, str]] = {
    "B001_API_AUTHENTICATION": (
        "API authentication not detected", Severity.HIGH,
        "Application API routes were detected without a recognized authentication control.",
        "Add and enforce authentication on non-public API routes, then document intentional public endpoints.",
        "add_api_authentication",
    ),
    "B002_INPUT_VALIDATION": (
        "Request input validation not detected", Severity.MEDIUM,
        "Raw request input is read by an API project without a recognized validation boundary.",
        "Validate request bodies, query values, and path parameters with the framework's schema facilities.",
        "validate_request_input",
    ),
    "B003_RATE_LIMITING": (
        "API rate limiting not detected", Severity.LOW,
        "Application API routes were detected without a recognized rate-limiting control.",
        "Add a documented rate limit at the application or trusted gateway boundary.",
        "add_rate_limiting",
    ),
    "B004_PERMISSIVE_CORS": (
        "Permissive CORS configuration", Severity.HIGH,
        "An explicit all-origins CORS configuration was detected.",
        "Replace the wildcard with the minimum trusted production origins.",
        "restrict_cors_origins",
    ),
    "B005_SQL_INJECTION": (
        "Request data interpolated into SQL", Severity.HIGH,
        "A SQL statement dynamically incorporates request-derived input on the same source line.",
        "Use parameterized queries or a safe query builder and keep request values out of SQL text.",
        "parameterize_sql_query",
    ),
}


def _is_excluded_path(file_path: str) -> bool:
    parts = {part.lower() for part in PurePosixPath(file_path).parts[:-1]}
    return bool(parts & EXCLUDED_PATH_PARTS)


def _finding(
    rule_id: str,
    file_path: str,
    *,
    line_number: int | None = None,
    snippet: str = _REPOSITORY_SNIPPET,
) -> Finding:
    name, severity, description, message, template = _RULE_METADATA[rule_id]
    return Finding(
        rule_id=rule_id,
        rule_name=name,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        column_start=None,
        column_end=None,
        snippet_masked=snippet,
        is_blocking=False,
        finding_type=(
            FindingType.CONTENT if line_number is not None else FindingType.FILE
        ),
        description=description,
        category="basic_security",
        secret_type="",
        message=message,
        repair_template_key=template,
        dimension=BASIC_SECURITY_DIMENSION,
    )


def _is_route(file_path: str, line: str) -> bool:
    if _HEALTH_ROUTE_RE.search(line):
        return False
    if any(pattern.search(line) for pattern in _ROUTE_PATTERNS):
        return True
    lowered = file_path.lower()
    if PurePosixPath(file_path).name.lower() in {"urls.py", "routes.py"}:
        return bool(_DJANGO_ROUTE_RE.search(line))
    if "/app/api/" in f"/{lowered}" and PurePosixPath(file_path).name.lower().startswith("route."):
        return bool(_NEXT_ROUTE_RE.search(line))
    return False


def _outside_string(position: int, spans: list[tuple[int, int]]) -> bool:
    return not any(start <= position < end for start, end in spans)


def _node_rate_limit_aliases(text: str) -> set[str]:
    aliases: set[str] = set()
    for match in _NODE_RATE_LIMIT_IMPORT_RE.finditer(text):
        alias = match.group(1) or match.group(2)
        aliases.add(alias)
    return aliases


def _call_expression_end(
    line: str,
    open_parenthesis: int,
    spans: list[tuple[int, int]],
) -> int:
    depth = 0
    for index in range(open_parenthesis, len(line)):
        if not _outside_string(index, spans):
            continue
        if line[index] == "(":
            depth += 1
        elif line[index] == ")":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(line)


def _has_dynamic_sql(
    line: str,
    spans: list[tuple[int, int]],
    expression_start: int,
    expression_end: int,
) -> bool:
    relevant_spans = [
        (start, end) for start, end in spans
        if expression_start <= start < end <= expression_end
    ]
    sql_spans = [
        (start, end) for start, end in relevant_spans
        if _SQL_KEYWORD_RE.search(line[start:end])
    ]
    input_matches = [
        (expression_start + match.start(), expression_start + match.end())
        for match in _SQL_INPUT_RE.finditer(
            line[expression_start:expression_end]
        )
    ]
    if not sql_spans or not input_matches:
        return False

    for sql_start, sql_end in sql_spans:
        literal = line[sql_start:sql_end]
        prefix = line[max(expression_start, sql_start - 2):sql_start].lower()
        input_in_literal = any(
            sql_start <= input_start < sql_end
            for input_start, _ in input_matches
        )
        if input_in_literal and (
            "${" in literal
            or "#{" in literal
            or "{$_" in literal
            or bool(re.search(r"(?:[rubf]{1,2}|\$)$", prefix))
        ):
            return True

        after_literal = line[sql_end:expression_end]
        before_literal = line[expression_start:sql_start]
        if any(input_start >= sql_end for input_start, _ in input_matches):
            if re.match(r"\s*\.format\s*\(", after_literal):
                return True
            if _FORMAT_WRAPPER_RE.search(before_literal):
                return True

        for input_start, input_end in input_matches:
            if sql_end <= input_start:
                between = line[sql_end:input_start]
            elif input_end <= sql_start:
                between = line[input_end:sql_start]
            else:
                continue
            if "+" in between and "," not in between:
                return True
    return False


class BasicSecurityProbe(RepositoryProbe):
    """Per-scan, bounded evidence for B001-B005."""

    def __init__(self) -> None:
        self.route_paths: set[str] = set()
        self.raw_input_paths: set[str] = set()
        self.auth_detected = False
        self.validation_detected = False
        self.rate_limit_detected = False
        self.cors_findings: list[Finding] = []
        self.sql_findings: list[Finding] = []

    def observe_file(self, file_path: str, lines: list[str]) -> None:
        if _is_excluded_path(file_path):
            return
        path = PurePosixPath(file_path)

        if is_incomplete_source_file(file_path):
            self._observe_source(file_path, lines)
        elif path.suffix.lower() in _CONFIG_SUFFIXES:
            self._observe_cors(file_path, lines, node_cors=False, flask_cors=False)

    def _observe_source(self, file_path: str, lines: list[str]) -> None:
        comments, strings = _analyze_source_lines(file_path, lines)
        uncommented = [
            _code_without_comments(line, comments[index])
            for index, line in enumerate(lines)
        ]
        bare = [
            _code_without_strings(line, strings[index])
            for index, line in enumerate(uncommented)
        ]
        raw_text = "\n".join(uncommented)
        bare_text = "\n".join(bare)

        self.auth_detected = self.auth_detected or bool(
            _AUTH_SOURCE_RE.search(bare_text)
        )
        self.validation_detected = self.validation_detected or bool(
            _VALIDATION_SOURCE_RE.search(bare_text)
        )
        rate_aliases = _node_rate_limit_aliases(raw_text)
        rate_alias_used = any(
            re.search(rf"\b{re.escape(alias)}\s*\(", bare_text)
            for alias in rate_aliases
        )
        self.rate_limit_detected = self.rate_limit_detected or bool(
            _RATE_LIMIT_USE_RE.search(bare_text) or rate_alias_used
        )

        for line in uncommented:
            if _is_route(file_path, line):
                self.route_paths.add(file_path)
        if _RAW_INPUT_RE.search(bare_text):
            self.raw_input_paths.add(file_path)

        node_cors = bool(_NODE_CORS_IMPORT_RE.search(raw_text))
        flask_cors = bool(_FLASK_CORS_IMPORT_RE.search(bare_text))
        self._observe_cors(
            file_path,
            uncommented,
            node_cors,
            flask_cors,
            code_lines=bare,
            string_spans=strings,
        )

        limit = settings.scan_max_findings_per_rule_per_file
        added = 0
        for index, line in enumerate(uncommented):
            if added >= limit:
                break
            dynamic_sql = False
            for sink in _SQL_SINK_RE.finditer(line):
                if not _outside_string(sink.start(), strings[index]):
                    continue
                expression_end = _call_expression_end(
                    line, sink.end() - 1, strings[index]
                )
                if _has_dynamic_sql(
                    line,
                    strings[index],
                    sink.start(),
                    expression_end,
                ):
                    dynamic_sql = True
                    break
            if not dynamic_sql:
                continue
            self.sql_findings.append(_finding(
                "B005_SQL_INJECTION",
                file_path,
                line_number=index + 1,
                snippet=mask_snippet(line),
            ))
            added += 1

    def _observe_cors(
        self,
        file_path: str,
        lines: list[str],
        node_cors: bool,
        flask_cors: bool,
        code_lines: list[str] | None = None,
        string_spans: list[list[tuple[int, int]]] | None = None,
    ) -> None:
        limit = settings.scan_max_findings_per_rule_per_file
        added = 0
        for index, line in enumerate(lines):
            if added >= limit:
                break
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            spans = string_spans[index] if string_spans is not None else []
            explicit = any(
                (match := pattern.search(line)) is not None
                and _outside_string(match.start(), spans)
                for pattern in _CORS_EXPLICIT_PATTERNS
            )
            origin_match = re.search(
                r"\borigin\s*:\s*['\"]\*['\"]", line, re.IGNORECASE
            )
            node_origin = bool(
                node_cors
                and origin_match is not None
                and _outside_string(origin_match.start(), spans)
            )
            code_line = code_lines[index] if code_lines is not None else line
            bare_node = node_cors and bool(
                re.search(r"\bcors\s*\(\s*\)", code_line)
            )
            bare_flask = flask_cors and bool(
                re.search(r"\bCORS\s*\(\s*\w+\s*\)", code_line)
            )
            if not (explicit or node_origin or bare_node or bare_flask):
                continue
            self.cors_findings.append(_finding(
                "B004_PERMISSIVE_CORS",
                file_path,
                line_number=index + 1,
                snippet=mask_snippet(line),
            ))
            added += 1

    def finalize(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.route_paths and not self.auth_detected:
            findings.append(_finding(
                "B001_API_AUTHENTICATION", min(self.route_paths)
            ))
        if (
            self.route_paths
            and self.raw_input_paths
            and not self.validation_detected
        ):
            findings.append(_finding(
                "B002_INPUT_VALIDATION", min(self.raw_input_paths)
            ))
        if self.route_paths and not self.rate_limit_detected:
            findings.append(_finding(
                "B003_RATE_LIMITING", min(self.route_paths)
            ))
        findings.extend(self.cors_findings)
        findings.extend(self.sql_findings)
        return findings


class BasicSecurityRule(Rule):
    """Registry rule that creates isolated basic-security probes."""

    rule_id = "B000_BASIC_SECURITY_REPOSITORY"
    rule_name = "Basic security checks"
    finding_type = FindingType.FILE
    dimension = BASIC_SECURITY_DIMENSION

    def create_repository_probe(self) -> RepositoryProbe:
        return BasicSecurityProbe()
