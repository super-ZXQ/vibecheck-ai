"""Deterministic repository-level documentation consistency checks."""

from __future__ import annotations

import json
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.scanner.base import (
    Confidence,
    DOCUMENTATION_CONSISTENCY_DIMENSION,
    Finding,
    FindingType,
    RepositoryProbe,
    Rule,
    Severity,
)


_REPOSITORY_PATH = "<repository>"
_README_PRIORITY = {
    "readme.md": 0,
    "readme.rst": 1,
    "readme.txt": 2,
    "readme": 3,
}
_COMPOSE_NAMES = (
    "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml",
)
_TECH_SECTION_RE = re.compile(
    r"(?:tech(?:nology)?\s+stack|built\s+with|technologies|技术栈|技术选型)",
    re.IGNORECASE,
)
_COMMAND_SECTION_RE = re.compile(
    r"(?:\b(?:getting\s+started|quick\s*start|installation|usage|run(?:ning)?|"
    r"start(?:ing)?|development|deployment)\b|安装|使用|启动|运行|部署|快速开始)",
    re.IGNORECASE,
)
_STRUCTURE_SECTION_RE = re.compile(
    r"(?:project|directory|repository)\s+structure|项目结构|目录结构",
    re.IGNORECASE,
)
_MARKDOWN_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_RST_UNDERLINE_RE = re.compile(r"^\s*([=\-~^])\1{2,}\s*$")
_FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
_RST_CODE_DIRECTIVE_RE = re.compile(
    r"^\s*\.\.\s+(?:code-block|code)::(?:\s+\S+)?\s*$",
    re.IGNORECASE,
)
_INLINE_COMMAND_RE = re.compile(
    r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?`([^`]+)`\s*[.!。]?[\s]*$"
)
_TREE_RE = re.compile(r"^(?P<prefix>(?:│   |    )*)(?:├──|└──)\s*(?P<name>.+?)\s*$")
_DIRECT_TREE_PATH_RE = re.compile(
    r"^\s*(?:\./)?([A-Za-z0-9._@+\-]+(?:/[A-Za-z0-9._@+\-]+)*/?)\s*$"
)
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@+\-]+/?$")
_ARCHIVE_ROOT_RE = re.compile(
    r"^[A-Za-z0-9_.-]+-(?:main|master|[0-9a-f]{7,40}|"
    r"v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?)$",
    re.IGNORECASE,
)
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?")
_REQUIREMENT_INCLUDE_RE = re.compile(
    r"^(?:-r(?:\s+|=)?|--requirement(?:\s+|=))([^\s]+)",
    re.IGNORECASE,
)
_DANGEROUS_COMMAND_RE = re.compile(r"[|;<>`]|\$\(|\$\{|%[^%]+%")
_NODE_BUILTIN_COMMANDS = {
    "yarn": frozenset({
        "add", "audit", "autoclean", "bin", "cache", "config", "create",
        "dlx", "exec", "global", "help", "import", "info", "init",
        "install", "licenses", "link", "list", "login", "logout", "node",
        "npm", "outdated", "owner", "pack", "patch", "plugin", "policies",
        "publish", "remove", "run", "set", "stage", "tag", "team",
        "unlink", "unplug", "up", "upgrade", "version", "why", "workspace",
        "workspaces",
    }),
    "pnpm": frozenset({
        "add", "audit", "bin", "config", "create", "deploy", "dlx", "env",
        "exec", "fetch", "help", "import", "init", "install", "link",
        "list", "login", "logout", "ls", "outdated", "pack", "patch",
        "patch-commit", "prune", "publish", "rebuild", "remove", "root",
        "run", "server", "setup", "store", "uninstall", "unlink", "update",
        "why",
    }),
    "bun": frozenset({
        "add", "build", "create", "help", "init", "install", "link",
        "outdated", "pm", "publish", "remove", "repl", "run", "test",
        "unlink", "update", "upgrade", "x",
    }),
}
_MAX_REQUIREMENT_INCLUDE_DEPTH = 8
_KNOWN_PYTHON_TOOL_MODULES = frozenset({
    "django", "flask", "gunicorn", "hypercorn", "jupyter", "pip",
    "pytest", "streamlit", "uvicorn", "venv",
})
_IGNORED_DOCUMENTED_PARTS = frozenset({
    ".git", ".next", ".venv", "venv", "node_modules", "dist", "build",
    "coverage", "vendor", "generated", "__pycache__",
})

_TECH_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("react", "node", re.compile(r"(?<![\w.-])React(?![\w.-])", re.IGNORECASE)),
    ("vue", "node", re.compile(r"(?<![\w.-])Vue(?:\.js)?(?![\w.-])", re.IGNORECASE)),
    ("next", "node", re.compile(r"(?<![\w.-])Next(?:\.js|JS)(?![\w.-])", re.IGNORECASE)),
    ("fastapi", "python", re.compile(r"(?<![\w.-])FastAPI(?![\w.-])", re.IGNORECASE)),
    ("flask", "python", re.compile(r"(?<![\w.-])Flask(?![\w.-])", re.IGNORECASE)),
    ("django", "python", re.compile(r"(?<![\w.-])Django(?![\w.-])", re.IGNORECASE)),
)

_RULE_METADATA: dict[str, tuple[str, str, str]] = {
    "C001_README_COMPLETENESS": (
        "README is missing or incomplete",
        "The repository does not contain a sufficiently complete root README.",
        "Add a root README with at least 100 characters of useful project documentation.",
    ),
    "C002_TECH_STACK_MISMATCH": (
        "Documented technology is not confirmed",
        "A technology declared in the README is not present in the corresponding dependency manifest.",
        "Add the documented dependency or correct the README technology stack.",
    ),
    "C003_START_COMMAND_MISMATCH": (
        "Documented command does not match the repository",
        "A documented run or start command references a missing script, manifest, or entry path.",
        "Correct the documented command or add the referenced script or entry point.",
    ),
    "C004_PROJECT_STRUCTURE_MISMATCH": (
        "Documented project path does not exist",
        "A path shown in the README project structure is not present in the repository.",
        "Update the documented project structure or restore the referenced path.",
    ),
}


@dataclass(frozen=True)
class _TechnologyReference:
    line: int
    package: str
    ecosystem: str


@dataclass(frozen=True)
class _CommandReference:
    line: int
    kind: str
    base_dir: str
    target: str
    targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class _StructureReference:
    line: int
    path: str
    is_directory: bool


@dataclass(frozen=True)
class _ReadmeFacts:
    path: str
    prose_characters: int
    technologies: tuple[_TechnologyReference, ...]
    commands: tuple[_CommandReference, ...]
    structure: tuple[_StructureReference, ...]


def _finding(rule_id: str, file_path: str, line: int | None = None) -> Finding:
    name, description, message = _RULE_METADATA[rule_id]
    is_content = line is not None
    return Finding(
        rule_id=rule_id,
        rule_name=name,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line_start=line,
        line_end=line,
        column_start=0 if is_content else None,
        column_end=1 if is_content else None,
        snippet_masked=f"<{rule_id.lower()}>",
        is_blocking=False,
        finding_type=FindingType.CONTENT if is_content else FindingType.FILE,
        description=description,
        category="documentation",
        secret_type="",
        message=message,
        repair_template_key=rule_id.lower(),
        dimension=DOCUMENTATION_CONSISTENCY_DIMENSION,
    )


def _normalize_title(value: str) -> str:
    return re.sub(r"[`*_\[\]()]+", " ", value).strip()


def _headings(lines: list[str]) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        markdown = _MARKDOWN_HEADING_RE.match(line)
        if markdown:
            result.append((index, len(markdown.group(1)), _normalize_title(markdown.group(2))))
            continue
        if index + 1 >= len(lines) or not line.strip():
            continue
        underline = _RST_UNDERLINE_RE.match(lines[index + 1])
        if underline:
            level = 1 if underline.group(1) == "=" else 2
            result.append((index, level, _normalize_title(line)))
    return result


def _section_ranges(
    lines: list[str], matcher: re.Pattern[str]
) -> list[tuple[int, int]]:
    headings = _headings(lines)
    ranges: list[tuple[int, int]] = []
    for position, (index, level, title) in enumerate(headings):
        if not matcher.search(title):
            continue
        end = len(lines)
        for next_index, next_level, _ in headings[position + 1:]:
            if next_level <= level:
                end = next_index
                break
        ranges.append((index + 1, end))
    return ranges


def _document_code_lines(lines: list[str]) -> tuple[set[int], set[int]]:
    """Return code-content lines and all lines excluded from prose."""
    content: set[int] = set()
    excluded: set[int] = set()
    in_fence = False
    for index, line in enumerate(lines):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            excluded.add(index)
        elif in_fence:
            content.add(index)
            excluded.add(index)

    index = 0
    while index < len(lines):
        if index in excluded:
            index += 1
            continue
        stripped = lines[index].rstrip()
        is_directive = bool(_RST_CODE_DIRECTIVE_RE.match(stripped))
        is_literal = stripped.endswith("::") and not is_directive
        if not (is_directive or is_literal):
            index += 1
            continue

        marker_indent = len(lines[index]) - len(lines[index].lstrip())
        cursor = index + 1
        if is_directive:
            excluded.add(index)
        while cursor < len(lines):
            current = lines[cursor]
            if not current.strip():
                excluded.add(cursor)
                cursor += 1
                continue
            current_indent = len(current) - len(current.lstrip())
            if is_directive and current_indent > marker_indent and current.lstrip().startswith(":"):
                excluded.add(cursor)
                cursor += 1
                continue
            break
        if cursor >= len(lines):
            break
        block_indent = len(lines[cursor]) - len(lines[cursor].lstrip())
        if block_indent <= marker_indent:
            index += 1
            continue
        while cursor < len(lines):
            current = lines[cursor]
            if not current.strip():
                content.add(cursor)
                excluded.add(cursor)
                cursor += 1
                continue
            current_indent = len(current) - len(current.lstrip())
            if current_indent < block_indent:
                break
            content.add(cursor)
            excluded.add(cursor)
            cursor += 1
        index = cursor
    return content, excluded


def _prose_character_count(lines: list[str], excluded_lines: set[int]) -> int:
    visible: list[str] = []
    in_comment = False
    for index, line in enumerate(lines):
        if index in excluded_lines:
            continue
        current = line
        if in_comment:
            if "-->" not in current:
                continue
            current = current.split("-->", 1)[1]
            in_comment = False
        while "<!--" in current:
            before, after = current.split("<!--", 1)
            if "-->" in after:
                current = before + after.split("-->", 1)[1]
            else:
                current = before
                in_comment = True
                break
        current = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", current)
        current = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", current)
        current = re.sub(r"https?://\S+", " ", current)
        visible.append(current)
    return sum(1 for char in "\n".join(visible) if char.isalnum())


def _safe_relative_path(base_dir: str, value: str) -> str | None:
    raw = value.strip().strip('"\'').replace("\\", "/")
    if not raw or raw.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", raw):
        return None
    parts = [] if base_dir in {"", "."} else list(PurePosixPath(base_dir).parts)
    for part in PurePosixPath(raw).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    normalized = "/".join(parts) or "."
    return mask_untrusted_text(normalized)


def _parse_workspace_command(
    command: str,
    line_number: int,
    base_dir: str,
) -> _CommandReference | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) < 3:
        return None
    manager = tokens[0].lower()
    workspace: str | None = None
    remainder: list[str] = []
    if manager == "npm" and tokens[1] in {"--workspace", "-w"}:
        workspace, remainder = tokens[2], tokens[3:]
    elif manager == "npm" and tokens[1].startswith("--workspace="):
        workspace, remainder = tokens[1].split("=", 1)[1], tokens[2:]
    elif manager == "pnpm" and tokens[1] in {"--filter", "-C", "--dir"}:
        workspace, remainder = tokens[2], tokens[3:]
    elif manager == "pnpm" and tokens[1].startswith(("--filter=", "--dir=")):
        workspace, remainder = tokens[1].split("=", 1)[1], tokens[2:]
    elif manager in {"yarn", "bun"} and tokens[1] == "--cwd":
        workspace, remainder = tokens[2], tokens[3:]
    elif manager == "yarn" and tokens[1] == "workspace":
        workspace, remainder = tokens[2], tokens[3:]
    if workspace is None:
        return None
    if remainder and remainder[0].lower() == "run":
        remainder = remainder[1:]
    if not remainder or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_-]*", remainder[0]):
        return None
    normalized = _safe_relative_path(base_dir, workspace)
    if normalized is None:
        return None
    return _CommandReference(
        line_number, "node_script", normalized, remainder[0]
    )


def _parse_python_server_command(
    command: str,
    line_number: int,
    base_dir: str,
) -> _CommandReference | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None
    server = tokens[0].lower()
    arguments = tokens[1:]
    if server in {"python", "python3"}:
        if len(tokens) < 3 or tokens[1] != "-m":
            return None
        server = tokens[2].lower()
        arguments = tokens[3:]
    if server not in {"uvicorn", "gunicorn", "hypercorn"}:
        return None

    directory_option = "--chdir" if server == "gunicorn" else "--app-dir"
    command_base = base_dir
    target: str | None = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == directory_option:
            if index + 1 >= len(arguments):
                return None
            normalized = _safe_relative_path(base_dir, arguments[index + 1])
            if normalized is None:
                return None
            command_base = normalized
            index += 2
            continue
        if token.startswith(f"{directory_option}="):
            normalized = _safe_relative_path(base_dir, token.split("=", 1)[1])
            if normalized is None:
                return None
            command_base = normalized
        elif re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", token
        ):
            target = token.split(":", 1)[0]
        index += 1
    if target is None:
        return None
    return _CommandReference(
        line_number, "python_import_module", command_base, target
    )


def _parse_command(
    line: str,
    line_number: int,
    initial_base_dir: str = ".",
) -> _CommandReference | None:
    command = line.strip()
    command = re.sub(r"^(?:\$|>)\s+", "", command)
    if not command or _DANGEROUS_COMMAND_RE.search(command):
        return None
    base_dir = initial_base_dir
    cd_match = re.match(r"^cd\s+([^\s]+)\s*&&\s*(.+)$", command, re.IGNORECASE)
    if cd_match:
        normalized = _safe_relative_path(base_dir, cd_match.group(1))
        if normalized is None:
            return None
        base_dir = normalized
        command = cd_match.group(2).strip()
    if "&" in command:
        return None

    server = _parse_python_server_command(command, line_number, base_dir)
    if server is not None:
        return server

    workspace = _parse_workspace_command(command, line_number, base_dir)
    if workspace is not None:
        return workspace
    if re.match(r"^(?:npm|pnpm|yarn|bun)\s+(?:-|workspace\b)", command, re.IGNORECASE):
        return None

    node = re.match(
        r"^(npm|pnpm|yarn|bun)\s+run\s+([A-Za-z0-9][A-Za-z0-9:_-]*)(?:\s|$)",
        command, re.IGNORECASE,
    )
    if node:
        return _CommandReference(line_number, "node_script", base_dir, node.group(2))

    node_shorthand = re.match(
        r"^(npm|pnpm|yarn|bun)\s+([A-Za-z0-9][A-Za-z0-9:_-]*)(?:\s|$)",
        command,
        re.IGNORECASE,
    )
    if node_shorthand:
        manager = node_shorthand.group(1).lower()
        script = node_shorthand.group(2)
        lowered = script.lower()
        if manager == "npm":
            if lowered not in {"restart", "start", "stop", "test"}:
                return None
            return _CommandReference(line_number, "npm_lifecycle", base_dir, lowered)
        elif lowered in _NODE_BUILTIN_COMMANDS[manager]:
            return None
        return _CommandReference(line_number, "node_script", base_dir, script)
    python_module = re.match(
        r"^python(?:3)?\s+-m\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        command,
    )
    if python_module:
        return _CommandReference(
            line_number, "python_runnable_module", base_dir, python_module.group(1)
        )
    python_file = re.match(r"^python(?:3)?\s+([^\s]+\.py)(?:\s|$)", command)
    if python_file:
        target = _safe_relative_path(base_dir, python_file.group(1))
        return _CommandReference(line_number, "path", ".", target) if target else None
    node_file = re.match(r"^(?:node|tsx|ts-node)\s+([^\s]+\.(?:js|mjs|cjs|ts|tsx))(?:\s|$)", command)
    if node_file:
        target = _safe_relative_path(base_dir, node_file.group(1))
        return _CommandReference(line_number, "path", ".", target) if target else None

    compose = re.match(r"^(?:docker\s+compose|docker-compose)\b(.*)$", command, re.IGNORECASE)
    if compose:
        file_options = re.finditer(
            r"(?:^|\s)(?:-f|--file)(?:\s+|=)([^\s]+)",
            compose.group(1),
            re.IGNORECASE,
        )
        targets: list[str] = []
        for file_option in file_options:
            normalized = _safe_relative_path(base_dir, file_option.group(1))
            if normalized is None:
                return None
            targets.append(normalized)
        return _CommandReference(
            line_number, "compose", base_dir, "", tuple(targets)
        )

    make = re.match(r"^make\s+([A-Za-z0-9_.-]+)(?:\s|$)", command)
    if make:
        return _CommandReference(line_number, "make", base_dir, make.group(1))
    go = re.match(r"^go\s+(?:run|build)\s+([^\s]+)", command)
    if go:
        target = _safe_relative_path(base_dir, go.group(1))
        return _CommandReference(line_number, "go", base_dir, target) if target else None
    if re.match(r"^cargo\s+(?:run|build)\b", command):
        return _CommandReference(line_number, "cargo", base_dir, "")
    if re.match(r"^(?:\./)?mvnw?(?:\.cmd)?\s+", command):
        return _CommandReference(line_number, "maven", base_dir, "")
    if re.match(r"^(?:\./)?gradlew?(?:\.bat)?\s+", command):
        return _CommandReference(line_number, "gradle", base_dir, "")
    dotnet = re.match(r"^dotnet\s+run\b(.*)$", command, re.IGNORECASE)
    if dotnet:
        project = re.search(r"--project\s+([^\s]+)", dotnet.group(1))
        target = ""
        if project:
            normalized = _safe_relative_path(base_dir, project.group(1))
            if normalized is None:
                return None
            target = normalized
        return _CommandReference(line_number, "dotnet", base_dir, target)
    if re.match(r"^bundle\s+exec\s+(?:rails|rackup|puma)\b", command):
        return _CommandReference(line_number, "ruby", base_dir, "")
    php = re.match(r"^php\s+(artisan|bin/console)(?:\s|$)", command, re.IGNORECASE)
    if php:
        target = _safe_relative_path(base_dir, php.group(1))
        return _CommandReference(line_number, "path", ".", target) if target else None
    return None


def _technology_references(lines: list[str]) -> tuple[_TechnologyReference, ...]:
    references: list[_TechnologyReference] = []
    seen: set[str] = set()
    for start, end in _section_ranges(lines, _TECH_SECTION_RE):
        for index in range(start, end):
            for package, ecosystem, pattern in _TECH_PATTERNS:
                if package not in seen and pattern.search(lines[index]):
                    references.append(_TechnologyReference(index + 1, package, ecosystem))
                    seen.add(package)
    return tuple(references)


def _command_references(
    lines: list[str], code_lines: set[int]
) -> tuple[_CommandReference, ...]:
    references: list[_CommandReference] = []
    for start, end in _section_ranges(lines, _COMMAND_SECTION_RE):
        in_code_block = False
        pending_parts: list[str] = []
        pending_line = 0
        working_directory: str | None = "."
        for index in range(start, end):
            line = lines[index]
            is_code = index in code_lines
            if is_code != in_code_block:
                in_code_block = is_code
                pending_parts.clear()
                working_directory = "."
            candidate: str | None = None
            candidate_line = index + 1
            if is_code:
                stripped = line.strip()
                if pending_parts:
                    pending_parts.append(
                        stripped[:-1].rstrip() if stripped.endswith("\\") else stripped
                    )
                    if stripped.endswith("\\"):
                        continue
                    candidate = " ".join(part for part in pending_parts if part)
                    candidate_line = pending_line
                    pending_parts.clear()
                elif stripped.endswith("\\"):
                    pending_parts.append(stripped[:-1].rstrip())
                    pending_line = index + 1
                    continue
                else:
                    candidate = line
            else:
                inline = _INLINE_COMMAND_RE.match(line)
                candidate = inline.group(1) if inline else None
            if candidate:
                normalized_candidate = re.sub(
                    r"^(?:\$|>)\s+", "", candidate.strip()
                )
                directory_change = re.fullmatch(
                    r"cd\s+([^\s]+)", normalized_candidate, re.IGNORECASE
                )
                if is_code and directory_change:
                    if working_directory is not None:
                        working_directory = _safe_relative_path(
                            working_directory, directory_change.group(1)
                        )
                    continue
                if is_code and working_directory is None:
                    continue
                parsed = _parse_command(
                    candidate,
                    candidate_line,
                    working_directory if is_code else ".",
                )
                if parsed is not None:
                    references.append(parsed)
    return tuple(references)


def _structure_references(
    lines: list[str], code_lines: set[int]
) -> tuple[_StructureReference, ...]:
    references: list[_StructureReference] = []
    seen: set[str] = set()
    for start, end in _section_ranges(lines, _STRUCTURE_SECTION_RE):
        in_code_block = False
        stack: dict[int, str] = {}
        for index in range(start, end):
            line = lines[index]
            is_code = index in code_lines
            if is_code != in_code_block:
                in_code_block = is_code
                stack.clear()
            if not is_code:
                continue
            match = _TREE_RE.match(line)
            path_value: str | None = None
            is_directory = False
            if match:
                depth = len(match.group("prefix")) // 4
                name = re.split(r"\s{2,}|\s+#", match.group("name"), maxsplit=1)[0].strip()
                stack = {key: value for key, value in stack.items() if key < depth}
                next_depth: int | None = None
                next_index = index + 1
                while next_index < end and not lines[next_index].strip():
                    next_index += 1
                if next_index < end and next_index in code_lines:
                    next_match = _TREE_RE.match(lines[next_index])
                    if next_match:
                        next_depth = len(next_match.group("prefix")) // 4
                is_directory = name.endswith("/") or (
                    next_depth is not None and next_depth > depth
                )
                if not _SAFE_SEGMENT_RE.fullmatch(name):
                    if is_directory:
                        stack[depth] = ""
                    continue
                segment = name.rstrip("/")
                parent = stack.get(depth - 1, "") if depth > 0 else ""
                if depth > 0 and not parent:
                    if is_directory:
                        stack[depth] = ""
                    continue
                path_value = f"{parent}/{segment}" if parent else segment
                if is_directory:
                    stack[depth] = path_value
            else:
                direct = _DIRECT_TREE_PATH_RE.match(line)
                if direct:
                    if direct.group(1) == "...":
                        continue
                    is_directory = direct.group(1).endswith("/")
                    path_value = direct.group(1).rstrip("/")
            if not path_value:
                continue
            normalized = _safe_relative_path(".", path_value)
            if normalized in {None, "."}:
                continue
            parts = PurePosixPath(normalized).parts
            if any(part.lower() in _IGNORED_DOCUMENTED_PARTS for part in parts):
                continue
            if normalized not in seen:
                references.append(_StructureReference(index + 1, normalized, is_directory))
                seen.add(normalized)
    return tuple(references)


def _readme_facts(file_path: str, lines: list[str]) -> _ReadmeFacts:
    code_lines, excluded_lines = _document_code_lines(lines)
    return _ReadmeFacts(
        path=file_path,
        prose_characters=_prose_character_count(lines, excluded_lines),
        technologies=_technology_references(lines),
        commands=_command_references(lines, code_lines),
        structure=_structure_references(lines, code_lines),
    )


class DocumentationConsistencyProbe(RepositoryProbe):
    """Bounded per-scan state for C001-C004."""

    def __init__(self) -> None:
        self.limit = max(1, int(settings.scan_max_findings_per_rule_per_file))
        self.paths: set[str] = set()
        self.directories: set[str] = set()
        self.readmes: dict[str, _ReadmeFacts] = {}
        self.top_level_parts: set[str] = set()
        self.node_packages: set[str] = set()
        self.python_packages: set[str] = set()
        self.valid_node_manifest = False
        self.valid_python_manifest = False
        self.node_scripts: dict[str, set[str]] = {}
        self.make_targets: dict[str, set[str]] = {}
        self.requirement_roots: set[str] = set()
        self.requirement_packages: dict[str, set[str]] = {}
        self.requirement_includes: dict[str, set[str]] = {}

    def observe_path(self, file_path: str) -> None:
        path = PurePosixPath(file_path)
        normalized = path.as_posix()
        self.paths.add(normalized)
        if path.parts:
            self.top_level_parts.add(path.parts[0])
        for parent in path.parents:
            value = parent.as_posix()
            if value != ".":
                self.directories.add(value)

    def observe_file(self, file_path: str, lines: list[str]) -> None:
        path = PurePosixPath(file_path)
        normalized = path.as_posix()

        name = path.name.lower()
        directory = path.parent.as_posix()
        if len(path.parts) <= 2 and name in _README_PRIORITY:
            self.readmes[normalized] = _readme_facts(normalized, lines)
        text = "\n".join(lines)
        if name == "package.json":
            self._observe_package_json(directory, text)
        elif name in {"makefile", "gnumakefile"}:
            targets = self.make_targets.setdefault(directory, set())
            for line in lines:
                target = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", line)
                if target:
                    targets.add(target.group(1))
        elif name.endswith((".txt", ".in")) or not path.suffix:
            self._observe_requirements(normalized, directory, name, lines)
        elif name == "pyproject.toml":
            self._observe_pyproject(text)
        elif name == "pipfile":
            self._observe_pipfile(text)

    def _observe_package_json(self, directory: str, text: str) -> None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeError):
            return
        if not isinstance(data, dict):
            return
        self.valid_node_manifest = True
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            dependencies = data.get(key)
            if isinstance(dependencies, dict):
                self.node_packages.update(str(name).lower() for name in dependencies)
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            self.node_scripts.setdefault(directory, set()).update(
                str(name) for name, command in scripts.items()
                if isinstance(command, str) and command.strip()
            )

    def _observe_requirements(
        self,
        file_path: str,
        directory: str,
        name: str,
        lines: list[str],
    ) -> None:
        packages: set[str] = set()
        includes: set[str] = set()
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            include = _REQUIREMENT_INCLUDE_RE.match(stripped)
            if include:
                target = _safe_relative_path(directory, include.group(1))
                if target not in {None, "."}:
                    includes.add(target)
                continue
            if stripped.startswith("-"):
                continue
            match = _REQUIREMENT_NAME_RE.match(stripped)
            if match:
                packages.add(match.group(1).lower().replace("_", "-"))
        self.requirement_packages[file_path] = packages
        self.requirement_includes[file_path] = includes
        if name.startswith("requirements"):
            self.valid_python_manifest = True
            self.requirement_roots.add(file_path)

    def _resolved_requirement_packages(self) -> set[str]:
        packages: set[str] = set()
        visited: set[str] = set()
        pending = [(root, 0) for root in sorted(self.requirement_roots)]
        while pending:
            file_path, depth = pending.pop()
            if file_path in visited or depth > _MAX_REQUIREMENT_INCLUDE_DEPTH:
                continue
            visited.add(file_path)
            packages.update(self.requirement_packages.get(file_path, set()))
            pending.extend(
                (target, depth + 1)
                for target in sorted(self.requirement_includes.get(file_path, set()))
            )
        return packages

    def _observe_pyproject(self, text: str) -> None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        self.valid_python_manifest = True
        project = data.get("project")
        if isinstance(project, dict):
            dependencies = project.get("dependencies")
            if isinstance(dependencies, list):
                for dependency in dependencies:
                    if isinstance(dependency, str):
                        match = _REQUIREMENT_NAME_RE.match(dependency)
                        if match:
                            self.python_packages.add(match.group(1).lower().replace("_", "-"))
        tool = data.get("tool")
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        dependencies = poetry.get("dependencies") if isinstance(poetry, dict) else None
        if isinstance(dependencies, dict):
            self.python_packages.update(
                str(name).lower().replace("_", "-")
                for name in dependencies if str(name).lower() != "python"
            )

    def _observe_pipfile(self, text: str) -> None:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        self.valid_python_manifest = True
        for key in ("packages", "dev-packages"):
            dependencies = data.get(key)
            if isinstance(dependencies, dict):
                self.python_packages.update(
                    str(name).lower().replace("_", "-") for name in dependencies
                )

    def _primary_readme(self) -> tuple[_ReadmeFacts | None, str]:
        if not self.readmes:
            return None, ""
        root_readmes = [
            facts for facts in self.readmes.values()
            if PurePosixPath(facts.path).parent.as_posix() == "."
        ]
        root_prefix = ""
        candidates = root_readmes
        if not candidates and len(self.top_level_parts) == 1:
            possible_root = next(iter(self.top_level_parts))
            if _ARCHIVE_ROOT_RE.fullmatch(possible_root):
                candidates = [
                    facts for facts in self.readmes.values()
                    if PurePosixPath(facts.path).parent.as_posix() == possible_root
                ]
                if candidates:
                    root_prefix = possible_root
        if not candidates:
            return None, ""
        return min(
            candidates,
            key=lambda facts: (
                _README_PRIORITY[PurePosixPath(facts.path).name.lower()],
                facts.path.casefold(),
                facts.path,
            ),
        ), root_prefix

    def _path_exists(self, path: str, *, directory: bool = False) -> bool:
        return path in (self.directories if directory else self.paths | self.directories)

    def _command_is_valid(
        self, reference: _CommandReference, root_prefix: str
    ) -> bool:
        relative_base = "" if reference.base_dir == "." else reference.base_dir
        base = "/".join(part for part in (root_prefix, relative_base) if part)
        def joined(name: str) -> str:
            return f"{base}/{name}" if base else name
        def rooted(name: str) -> str:
            return f"{root_prefix}/{name}" if root_prefix else name

        if reference.kind == "node_script":
            manifest_dir = base or "."
            return reference.target in self.node_scripts.get(manifest_dir, set())
        if reference.kind == "npm_lifecycle":
            scripts = self.node_scripts.get(base or ".", set())
            if joined("package.json") not in self.paths:
                return False
            if reference.target == "start":
                return "start" in scripts or joined("server.js") in self.paths
            if reference.target == "restart":
                return "restart" in scripts or (
                    "stop" in scripts
                    and ("start" in scripts or joined("server.js") in self.paths)
                )
            return reference.target in scripts
        if reference.kind == "path":
            return self._path_exists(rooted(reference.target))
        if reference.kind == "python_runnable_module":
            top_level = reference.target.split(".", 1)[0].lower()
            dependency = top_level.replace("_", "-")
            declared_packages = (
                self.python_packages | self._resolved_requirement_packages()
            )
            if (
                top_level in sys.stdlib_module_names
                or top_level in _KNOWN_PYTHON_TOOL_MODULES
                or dependency in declared_packages
            ):
                return True
            module = reference.target.replace(".", "/")
            return self._path_exists(joined(f"{module}.py")) or self._path_exists(
                joined(f"{module}/__main__.py")
            )
        if reference.kind == "python_import_module":
            module = reference.target.replace(".", "/")
            return self._path_exists(joined(f"{module}.py")) or self._path_exists(
                joined(f"{module}/__init__.py")
            )
        if reference.kind == "compose":
            if reference.targets:
                return all(rooted(target) in self.paths for target in reference.targets)
            if reference.target:
                return rooted(reference.target) in self.paths
            return any(joined(name) in self.paths for name in _COMPOSE_NAMES)
        if reference.kind == "make":
            return reference.target in self.make_targets.get(base or ".", set())
        if reference.kind == "go":
            if reference.target in {reference.base_dir, "."}:
                return joined("go.mod") in self.paths
            return self._path_exists(rooted(reference.target))
        if reference.kind == "cargo":
            return joined("Cargo.toml") in self.paths
        if reference.kind == "maven":
            return joined("pom.xml") in self.paths
        if reference.kind == "gradle":
            return joined("build.gradle") in self.paths or joined("build.gradle.kts") in self.paths
        if reference.kind == "dotnet":
            if reference.target:
                return self._path_exists(rooted(reference.target))
            prefix = f"{base}/" if base else ""
            return any(
                path.startswith(prefix) and path.endswith((".csproj", ".fsproj", ".vbproj"))
                and "/" not in path[len(prefix):]
                for path in self.paths
            )
        if reference.kind == "ruby":
            return joined("Gemfile") in self.paths
        return True

    def finalize(self) -> list[Finding]:
        readme, root_prefix = self._primary_readme()
        if readme is None:
            return [_finding("C001_README_COMPLETENESS", _REPOSITORY_PATH)]

        findings: list[Finding] = []
        if readme.prose_characters < 100:
            findings.append(_finding("C001_README_COMPLETENESS", readme.path))

        packages_by_ecosystem: dict[str, tuple[bool, set[str]]] = {
            "node": (self.valid_node_manifest, self.node_packages),
            "python": (
                self.valid_python_manifest,
                self.python_packages | self._resolved_requirement_packages(),
            ),
        }
        tech_count = 0
        for reference in readme.technologies:
            valid_manifest, packages = packages_by_ecosystem[reference.ecosystem]
            if valid_manifest and reference.package not in packages:
                findings.append(_finding("C002_TECH_STACK_MISMATCH", readme.path, reference.line))
                tech_count += 1
                if tech_count >= self.limit:
                    break

        command_count = 0
        for reference in readme.commands:
            if not self._command_is_valid(reference, root_prefix):
                findings.append(_finding("C003_START_COMMAND_MISMATCH", readme.path, reference.line))
                command_count += 1
                if command_count >= self.limit:
                    break

        structure_count = 0
        for reference in readme.structure:
            repository_path = (
                f"{root_prefix}/{reference.path}" if root_prefix else reference.path
            )
            if not self._path_exists(
                repository_path, directory=reference.is_directory
            ):
                findings.append(_finding("C004_PROJECT_STRUCTURE_MISMATCH", readme.path, reference.line))
                structure_count += 1
                if structure_count >= self.limit:
                    break
        return findings


class DocumentationConsistencyRule(Rule):
    """Registry entry that creates isolated documentation probes."""

    rule_id = "C000_DOCUMENTATION_REPOSITORY"
    rule_name = "Documentation consistency repository checks"
    finding_type = FindingType.FILE
    dimension = DOCUMENTATION_CONSISTENCY_DIMENSION

    def create_repository_probe(self) -> RepositoryProbe:
        return DocumentationConsistencyProbe()
