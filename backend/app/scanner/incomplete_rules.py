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
    re.compile(r"^\s*(?:return\s+)?(?:todo|unimplemented)!\s*\("),
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
    re.compile(r"^\s*debugger\s*;?\s*$"),
    re.compile(r"\bbreakpoint\s*\(\s*\)"),
    re.compile(r"\b(?:pdb|ipdb)\.set_trace\s*\(\s*\)"),
)
_DEBUG_OUTPUT_PATTERNS = (
    re.compile(r"\bconsole\.log\s*\("),
    re.compile(r"(?<![.\w])print\s*\("),
    re.compile(r"(?<![.\w])println\s*\("),
)


def is_incomplete_source_file(file_path: str) -> bool:
    """Return whether a path is an eligible production source file."""
    path = PurePosixPath(file_path)
    lowered_parts = {part.lower() for part in path.parts[:-1]}
    if lowered_parts & EXCLUDED_PATH_PARTS:
        return False
    name = path.name.lower()
    if name.endswith((".min.js", ".min.css", ".lock")):
        return False
    return path.suffix.lower() in SOURCE_EXTENSIONS


def _find_comment_token(line: str, start: int, tokens: tuple[str, ...]) -> tuple[int, str] | None:
    """Find a comment token outside single-line string literals."""
    quote: str | None = None
    escaped = False
    index = start
    while index < len(line):
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            index += 1
            continue
        for token in tokens:
            if line.startswith(token, index):
                return index, token
        index += 1
    return None


def _comment_segments(file_path: str, lines: list[str]) -> list[list[tuple[int, int, str]]]:
    """Extract conservative comment segments with their source columns."""
    ext = PurePosixPath(file_path).suffix.lower()
    result: list[list[tuple[int, int, str]]] = [[] for _ in lines]
    in_block = False
    for index, line in enumerate(lines):
        pos = 0
        while pos < len(line):
            if in_block:
                end = line.find("*/", pos)
                if end < 0:
                    result[index].append((pos, len(line), line[pos:]))
                    break
                result[index].append((pos, end + 2, line[pos:end + 2]))
                in_block = False
                pos = end + 2
                continue

            tokens = ("#",) if ext in _HASH_COMMENT_EXTENSIONS else ("//", "/*")
            located = _find_comment_token(line, pos, tokens)
            if located is None:
                break
            start, token = located
            if token != "/*":
                result[index].append((start, len(line), line[start:]))
                break
            end = line.find("*/", start + 2)
            if end < 0:
                result[index].append((start, len(line), line[start:]))
                in_block = True
                break
            result[index].append((start, end + 2, line[start:end + 2]))
            pos = end + 2
    return result


def _code_without_comments(line: str, comments: list[tuple[int, int, str]]) -> str:
    chars = list(line)
    for start, end, _ in comments:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _code_without_strings(line: str) -> str:
    """Replace quoted string contents so code-like text is not executed as a rule."""
    chars = list(line)
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if quote is None:
            if char in ("'", '"', "`"):
                quote = char
            continue
        if escaped:
            chars[index] = " "
            escaped = False
        elif char == "\\":
            chars[index] = " "
            escaped = True
        elif char == quote:
            quote = None
        else:
            chars[index] = " "
    return "".join(chars)


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
        comments = _comment_segments(file_path, lines)
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, line in enumerate(lines):
            code = _code_without_comments(line, comments[line_index])
            for pattern in _UNIMPLEMENTED_PATTERNS:
                for match in pattern.finditer(code):
                    if (
                        PurePosixPath(file_path).suffix.lower() == ".py"
                        and "NotImplementedError" in match.group(0)
                        and any(
                            "@abstractmethod" in lines[previous]
                            for previous in range(max(0, line_index - 6), line_index)
                        )
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
        comments = _comment_segments(file_path, lines)
        collector = BoundedFindingCollector(settings.scan_max_findings_per_rule_per_file)
        for line_index, line in enumerate(lines):
            code = _code_without_strings(
                _code_without_comments(line, comments[line_index])
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
        comments = _comment_segments(file_path, lines)
        count = 0
        first_line = 0
        for line_index, line in enumerate(lines):
            code = _code_without_strings(
                _code_without_comments(line, comments[line_index])
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
