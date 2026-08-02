"""High-confidence incomplete-content rules.

The rules in this module only inspect text. They never import, parse, or
execute code from the target repository. Each rule filters its own input to
common production source files so the existing sensitive-data scan remains
unchanged for tests, fixtures, documentation, lock files, and generated code.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.core.config import settings
from app.core.security.desensitize import mask_snippet
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    INCOMPLETE_CONTENT_DIMENSION,
    Rule,
    Severity,
)
from app.scanner.rules import BoundedFindingCollector


SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".swift", ".vue", ".svelte",
    ".sh", ".bash", ".zsh", ".ps1",
})

EXCLUDED_PATH_PARTS = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures",
    "mock", "mocks", "docs", "doc", "documentation", "examples",
    "generated", "gen", "dist", "build", "coverage", "vendor",
})

_HASH_COMMENT_EXTENSIONS = frozenset({
    ".py", ".rb", ".sh", ".bash", ".zsh", ".ps1",
})
_SLASH_COMMENT_EXTENSIONS = SOURCE_EXTENSIONS - _HASH_COMMENT_EXTENSIONS
_MARKER_RE = re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)
_PLACEHOLDER_COMMENT_RE = re.compile(
    r"\b(?:TODO|FIXME|HACK|XXX|placeholder|not\s+implemented)\b",
    re.IGNORECASE,
)
_PLACEHOLDER_RETURN_RE = re.compile(
    r"^\s*return\s+(?:\[\]|\{\}|None|null|nil|undefined)\s*;?\s*$",
    re.IGNORECASE,
)
_UNIMPLEMENTED_PATTERNS = (
    re.compile(r"^\s*raise\s+NotImplementedError\b"),
    re.compile(r"^\s*throw\s+new\s+NotImplementedException\s*\("),
    re.compile(
        r"^\s*raise\s+[A-Za-z_][\w.]*\s*\("
        r"\s*(['\"])\s*not\s+implemented\b.*?\1\s*\)",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:todo|unimplemented)!\s*\("),
    re.compile(
        r"^\s*throw\s+(?:new\s+)?[A-Za-z_$][\w$]*\s*\("
        r"\s*(['\"])\s*not\s+implemented\b.*?\1\s*\)",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(?:return\s+)?panic\s*\(\s*(['\"])\s*not\s+implemented\b.*?\1\s*\)",
        re.IGNORECASE,
    ),
)
_DEBUG_BREAKPOINT_PATTERNS = (
    re.compile(r"\bdebugger\b\s*;?"),
    re.compile(r"\bbreakpoint\s*\(\s*\)"),
    re.compile(r"\b(?:pdb|ipdb)\.set_trace\s*\(\s*\)"),
)
_DEBUG_OUTPUT_PATTERNS = (
    re.compile(r"\bconsole\.log\s*\("),
    re.compile(r"\bSystem\.(?:out|err)\.println\s*\("),
    re.compile(r"(?<![.\w])print\s*\("),
    re.compile(r"(?<![.\w])println!?\s*\("),
)

_PYTHON_TRIPLE_QUOTE_EXTENSIONS = frozenset({".py"})
_BACKTICK_STRING_EXTENSIONS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
})
_ABSTRACT_CLASS_RE = re.compile(
    r"\b(?:abc\.)?ABC\b|\bmetaclass\s*=\s*(?:abc\.)?ABCMeta\b"
)
_PYTHON_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(")
_PYTHON_CLASS_RE = re.compile(r"^(\s*)class\s+[A-Za-z_]\w*\s*\(([^)]*)\)\s*:")


def is_incomplete_source_file(file_path: str) -> bool:
    """Return whether a path is an eligible production source file."""
    path = PurePosixPath(file_path)
    lowered_parts = {part.lower() for part in path.parts[:-1]}
    if lowered_parts & EXCLUDED_PATH_PARTS:
        return False
    name = path.name.lower()
    if name.endswith((".min.js", ".min.css", ".lock")):
        return False
    stem = path.stem.lower()
    if (
        name in {"conftest.py", "fixtures.py", "mocks.py"}
        or stem.startswith("test_")
        or stem.endswith("_test")
        or stem.endswith("_spec")
        or ".test" in stem
        or ".spec" in stem
    ):
        return False
    return path.suffix.lower() in SOURCE_EXTENSIONS


def _find_unescaped(line: str, delimiter: str, start: int) -> int:
    """Find a delimiter whose first character is not backslash-escaped."""
    position = line.find(delimiter, start)
    while position >= 0:
        backslashes = 0
        cursor = position - 1
        while cursor >= 0 and line[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return position
        position = line.find(delimiter, position + 1)
    return -1


def _analyze_source_lines(
    file_path: str, lines: list[str]
) -> tuple[list[list[tuple[int, int, str]]], list[list[tuple[int, int]]]]:
    """Return comment and string spans using deterministic lexical state."""
    ext = PurePosixPath(file_path).suffix.lower()
    comments: list[list[tuple[int, int, str]]] = [[] for _ in lines]
    strings: list[list[tuple[int, int]]] = [[] for _ in lines]
    block_comment_end: str | None = None
    multiline_string_end: str | None = None

    if ext in _HASH_COMMENT_EXTENSIONS:
        single_comment_tokens = ("#",)
    elif ext == ".php":
        single_comment_tokens = ("//", "#")
    else:
        single_comment_tokens = ("//",)
    block_comment_tokens = (("/*", "*/"),)
    if ext in {".vue", ".svelte"}:
        block_comment_tokens += (("<!--", "-->"),)

    for index, line in enumerate(lines):
        pos = 0
        while pos < len(line):
            if block_comment_end is not None:
                end = line.find(block_comment_end, pos)
                if end < 0:
                    comments[index].append((pos, len(line), line[pos:]))
                    break
                span_end = end + len(block_comment_end)
                comments[index].append((pos, span_end, line[pos:span_end]))
                block_comment_end = None
                pos = span_end
                continue

            if multiline_string_end is not None:
                end = _find_unescaped(line, multiline_string_end, pos)
                if end < 0:
                    strings[index].append((pos, len(line)))
                    break
                span_end = end + len(multiline_string_end)
                strings[index].append((pos, span_end))
                multiline_string_end = None
                pos = span_end
                continue

            triple_quote = next(
                (
                    delimiter for delimiter in ('"""', "'''")
                    if ext in _PYTHON_TRIPLE_QUOTE_EXTENSIONS
                    and line.startswith(delimiter, pos)
                ),
                None,
            )
            if triple_quote is not None:
                end = _find_unescaped(line, triple_quote, pos + len(triple_quote))
                if end < 0:
                    strings[index].append((pos, len(line)))
                    multiline_string_end = triple_quote
                    break
                span_end = end + len(triple_quote)
                strings[index].append((pos, span_end))
                pos = span_end
                continue

            if ext in _BACKTICK_STRING_EXTENSIONS and line[pos] == "`":
                end = _find_unescaped(line, "`", pos + 1)
                if end < 0:
                    strings[index].append((pos, len(line)))
                    multiline_string_end = "`"
                    break
                strings[index].append((pos, end + 1))
                pos = end + 1
                continue

            if line[pos] in ("'", '"'):
                end = _find_unescaped(line, line[pos], pos + 1)
                span_end = len(line) if end < 0 else end + 1
                strings[index].append((pos, span_end))
                pos = span_end
                continue

            matched_block = next(
                (
                    (start_token, end_token)
                    for start_token, end_token in block_comment_tokens
                    if line.startswith(start_token, pos)
                ),
                None,
            )
            if matched_block is not None:
                start_token, end_token = matched_block
                end = line.find(end_token, pos + len(start_token))
                if end < 0:
                    comments[index].append((pos, len(line), line[pos:]))
                    block_comment_end = end_token
                    break
                span_end = end + len(end_token)
                comments[index].append((pos, span_end, line[pos:span_end]))
                pos = span_end
                continue

            if any(line.startswith(token, pos) for token in single_comment_tokens):
                comments[index].append((pos, len(line), line[pos:]))
                break
            pos += 1
    return comments, strings


def _comment_segments(file_path: str, lines: list[str]) -> list[list[tuple[int, int, str]]]:
    """Extract conservative comment segments with their source columns."""
    return _analyze_source_lines(file_path, lines)[0]


def _code_without_comments(line: str, comments: list[tuple[int, int, str]]) -> str:
    chars = list(line)
    for start, end, _ in comments:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _code_without_strings(line: str, spans: list[tuple[int, int]]) -> str:
    """Replace lexer-provided string spans while retaining source columns."""
    chars = list(line)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _position_in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def _indent_width(value: str) -> int:
    return len(value.expandtabs(8))


def _is_explicit_abstract_python_context(lines: list[str], line_index: int) -> bool:
    """Recognize explicit abstract methods/classes without importing target code."""
    current_indent = _indent_width(lines[line_index]) - _indent_width(lines[line_index].lstrip())
    method_index: int | None = None
    method_indent = -1
    for previous in range(line_index - 1, -1, -1):
        match = _PYTHON_DEF_RE.match(lines[previous])
        if match and _indent_width(match.group(1)) < current_indent:
            method_index = previous
            method_indent = _indent_width(match.group(1))
            break
    if method_index is None:
        return False

    decorator_index = method_index - 1
    while decorator_index >= 0 and lines[decorator_index].lstrip().startswith("@"):
        if re.search(r"@(?:abc\.)?abstractmethod\b", lines[decorator_index]):
            return True
        decorator_index -= 1

    for previous in range(method_index - 1, -1, -1):
        match = _PYTHON_CLASS_RE.match(lines[previous])
        if match and _indent_width(match.group(1)) < method_indent:
            return bool(_ABSTRACT_CLASS_RE.search(match.group(2)))
    return False


def _content_finding(
    *, rule: Rule, file_path: str, line_number: int, column_start: int,
    column_end: int, line: str, description: str, category: str,
    message: str, repair_template_key: str,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        rule_name=rule.rule_name,
        severity=rule.severity,
        confidence=rule.confidence,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        column_start=column_start,
        column_end=column_end,
        snippet_masked=mask_snippet(line)[:200],
        is_blocking=False,
        finding_type=FindingType.CONTENT,
        description=description,
        category=category,
        secret_type="",
        message=message,
        repair_template_key=repair_template_key,
        dimension=INCOMPLETE_CONTENT_DIMENSION,
    )


class TodoCommentRule(Rule):
    rule_id = "I001_TODO_COMMENT"
    rule_name = "Unfinished work comment"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    dimension = INCOMPLETE_CONTENT_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        if not is_incomplete_source_file(file_path):
            return []
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, segments in enumerate(_comment_segments(file_path, lines)):
            for start, _, segment in segments:
                for match in _MARKER_RE.finditer(segment):
                    column = start + match.start()
                    if not collector.should_accept(False, self.severity, self.confidence,
                                                   line_index + 1, column, self.rule_id):
                        continue
                    collector.add(_content_finding(
                        rule=self, file_path=file_path, line_number=line_index + 1,
                        column_start=column, column_end=start + match.end(),
                        line=lines[line_index],
                        description="An unfinished-work marker remains in production source code.",
                        category="unfinished_comment",
                        message="Complete the referenced work or remove the stale marker.",
                        repair_template_key="complete_or_remove_todo_comment",
                    ))
        return collector.finalize()


class UnimplementedCodeRule(Rule):
    rule_id = "I002_UNIMPLEMENTED_CODE"
    rule_name = "Explicit unimplemented code"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    dimension = INCOMPLETE_CONTENT_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        if not is_incomplete_source_file(file_path):
            return []
        comments, strings = _analyze_source_lines(file_path, lines)
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, line in enumerate(lines):
            code = _code_without_comments(line, comments[line_index])
            for pattern in _UNIMPLEMENTED_PATTERNS:
                for match in pattern.finditer(code):
                    if _position_in_spans(match.start(), strings[line_index]):
                        continue
                    if (
                        PurePosixPath(file_path).suffix.lower() == ".py"
                        and "NotImplementedError" in match.group(0)
                        and _is_explicit_abstract_python_context(lines, line_index)
                    ):
                        continue
                    if not collector.should_accept(False, self.severity, self.confidence,
                                                   line_index + 1, match.start(), self.rule_id):
                        continue
                    collector.add(_content_finding(
                        rule=self, file_path=file_path, line_number=line_index + 1,
                        column_start=match.start(), column_end=match.end(), line=line,
                        description="An explicit unimplemented-code construct can fail at runtime.",
                        category="unimplemented_code",
                        message="Implement this code path and replace the unimplemented construct.",
                        repair_template_key="implement_code_path",
                    ))
        return collector.finalize()


class PlaceholderReturnRule(Rule):
    rule_id = "I003_PLACEHOLDER_RETURN"
    rule_name = "Marked placeholder return"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    dimension = INCOMPLETE_CONTENT_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        if not is_incomplete_source_file(file_path):
            return []
        comments = _comment_segments(file_path, lines)
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, line in enumerate(lines):
            code = _code_without_comments(line, comments[line_index])
            match = _PLACEHOLDER_RETURN_RE.match(code)
            if not match:
                continue
            adjacent_comments = list(comments[line_index])
            if line_index > 0 and not _code_without_comments(
                lines[line_index - 1], comments[line_index - 1]
            ).strip():
                adjacent_comments.extend(comments[line_index - 1])
            if not any(_PLACEHOLDER_COMMENT_RE.search(segment) for _, _, segment in adjacent_comments):
                continue
            column = len(line) - len(line.lstrip())
            if not collector.should_accept(False, self.severity, self.confidence,
                                           line_index + 1, column, self.rule_id):
                continue
            collector.add(_content_finding(
                rule=self, file_path=file_path, line_number=line_index + 1,
                column_start=column, column_end=len(line.rstrip()), line=line,
                description="A return value is explicitly marked as a placeholder.",
                category="placeholder_return",
                message="Replace the placeholder return with the completed implementation.",
                repair_template_key="replace_placeholder_return",
            ))
        return collector.finalize()


class DebugBreakpointRule(Rule):
    rule_id = "I004_DEBUG_BREAKPOINT"
    rule_name = "Debug breakpoint"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    dimension = INCOMPLETE_CONTENT_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        if not is_incomplete_source_file(file_path):
            return []
        comments, strings = _analyze_source_lines(file_path, lines)
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, line in enumerate(lines):
            code = _code_without_strings(
                _code_without_comments(line, comments[line_index]),
                strings[line_index],
            )
            for pattern in _DEBUG_BREAKPOINT_PATTERNS:
                for match in pattern.finditer(code):
                    if not collector.should_accept(False, self.severity, self.confidence,
                                                   line_index + 1, match.start(), self.rule_id):
                        continue
                    collector.add(_content_finding(
                        rule=self, file_path=file_path, line_number=line_index + 1,
                        column_start=match.start(), column_end=match.end(), line=line,
                        description="An interactive debug breakpoint remains in production source code.",
                        category="debug_breakpoint",
                        message="Remove the breakpoint before shipping this code.",
                        repair_template_key="remove_debug_breakpoint",
                    ))
        return collector.finalize()


class ExcessiveDebugOutputRule(Rule):
    rule_id = "I005_EXCESSIVE_DEBUG_OUTPUT"
    rule_name = "Excessive debug output"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    finding_type = FindingType.CONTENT
    dimension = INCOMPLETE_CONTENT_DIMENSION

    def scan_content(self, file_path: str, lines: list[str]) -> list[Finding]:
        if not is_incomplete_source_file(file_path):
            return []
        comments, strings = _analyze_source_lines(file_path, lines)
        count = 0
        first_line = 0
        for line_index, line in enumerate(lines):
            code = _code_without_strings(
                _code_without_comments(line, comments[line_index]),
                strings[line_index],
            )
            line_count = sum(len(pattern.findall(code)) for pattern in _DEBUG_OUTPUT_PATTERNS)
            if line_count and not first_line:
                first_line = line_index + 1
            count += line_count
        if count <= 5:
            return []
        return [Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            confidence=self.confidence,
            file_path=file_path,
            line_start=first_line,
            line_end=first_line,
            column_start=0,
            column_end=0,
            snippet_masked=f"<debug-output-count:{count}>",
            is_blocking=False,
            finding_type=FindingType.FILE,
            description="This production source file contains more than five debug output calls.",
            category="excessive_debug_output",
            secret_type="",
            message="Remove debug output or replace necessary diagnostics with structured logging.",
            repair_template_key="reduce_debug_output",
            dimension=INCOMPLETE_CONTENT_DIMENSION,
        )]
