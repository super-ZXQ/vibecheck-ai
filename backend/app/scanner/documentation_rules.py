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
_SIMPLE_PACKAGE_NAME_RE = re.compile(
    r"^(@[A-Za-z0-9][A-Za-z0-9-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$"
)
_STREAMLIT_FLASK_TOOLS = frozenset({"streamlit", "flask"})
_SERVER_VALUE_OPTIONS = frozenset({
    "--header", "--host", "--port", "--workers", "--reload-dir",
    "--reload-include", "--reload-exclude", "--env-file",
    "--log-config", "--log-level", "--ssl-keyfile", "--ssl-certfile",
    "--ssl-keyfile-password", "--ssl-version", "--ssl-cert-reqs",
    "--ssl-ca-certs", "--limit-concurrency", "--backlog",
    "--limit-max-requests", "--timeout-keep-alive",
    "--timeout-graceful-shutdown", "--uds", "--fd", "--loop",
    "--http", "--interface", "--ws", "--ws-ping-interval",
    "--ws-ping-timeout", "--ws-max-size", "--ws-max-queue",
    "--forwarded-allow-ips", "--keyfile", "--certfile",
    "--ca-certs", "--ciphers", "--insecure-bind",
    "--bind", "-b", "--config", "-c", "--pid", "--error-logfile",
    "--access-logfile", "--logger-class", "--logformat",
    "--access-logformat", "--worker-class", "-k", "--worker-tmp-dir",
    "--worker-connections", "--max-requests", "--max-requests-jitter",
    "--graceful-timeout", "--keepalive", "--threads", "--paste",
    "--limit-request-line", "--limit-request-fields",
    "--limit-request-field-size", "--name", "--umask",
})
_IGNORED_DOCUMENTED_PARTS = frozenset({
    ".git", ".next", ".venv", "venv", "node_modules", "dist", "build",
    "coverage", "vendor", "generated", "__pycache__",
})
_NPM_LIFECYCLE_COMMANDS = frozenset({"start", "stop", "restart", "test"})
_NPM_RUN_KEYWORDS = frozenset({"run", "run-script"})
_COMPLEX_SELECTOR_CHARS = frozenset("*!?[]{}")
# ---- Go flag sets (split by subcommand) ----
# Global flags that can appear before the subcommand.
_GO_GLOBAL_VALUE_OPTIONS = frozenset({"-C"})

# Build-specific boolean flags.
_GO_BUILD_BOOLEAN_OPTIONS = frozenset({
    "-v", "-race", "-cover", "-a", "-n", "-x", "-work",
    "-modcacherw", "-trimpath", "-buildvcs", "-linkshared",
    "-msan", "-asan",
})
# Build-specific value-taking flags.
_GO_BUILD_VALUE_OPTIONS = frozenset({
    "-o", "-ldflags", "-tags", "-mod", "-compiler",
    "-gccgoflags", "-gcflags", "-asmflags",
    "-p", "-covermode", "-coverpkg", "-buildmode",
    "-installsuffix", "-modfile", "-overlay", "-pkgdir", "-toolexec",
    "-pgo",
})
# Run-specific boolean flags.
_GO_RUN_BOOLEAN_OPTIONS = frozenset({
    "-v", "-race", "-cover", "-a", "-n", "-x", "-work",
    "-modcacherw", "-trimpath", "-buildvcs", "-linkshared",
    "-msan", "-asan",
})
# Run-specific value-taking flags.
_GO_RUN_VALUE_OPTIONS = frozenset({
    "-ldflags", "-tags", "-mod", "-compiler",
    "-gccgoflags", "-gcflags", "-asmflags",
    "-exec", "-p", "-covermode", "-coverpkg",
    "-installsuffix", "-modfile", "-overlay", "-pkgdir", "-toolexec",
    "-pgo",
})
# Known Go flags that are NOT valid for build/run subcommands.
_GO_UNSUPPORTED_KNOWN_OPTIONS = frozenset({"-u", "-d", "-fix", "-json", "-e"})
# All known Go boolean flags (for detecting "known but wrong subcommand").
_GO_ALL_KNOWN_BOOLEAN = (
    _GO_BUILD_BOOLEAN_OPTIONS
    | _GO_RUN_BOOLEAN_OPTIONS
    | _GO_UNSUPPORTED_KNOWN_OPTIONS
)
# All known Go value-taking flags.
_GO_ALL_KNOWN_VALUE = (
    _GO_BUILD_VALUE_OPTIONS
    | _GO_RUN_VALUE_OPTIONS
    | _GO_GLOBAL_VALUE_OPTIONS
)

# Go boolean flag valid values (Go cmd accepts these for -flag=value).
_GO_BOOLEAN_VALID_VALUES = frozenset({
    "1", "0", "t", "f", "T", "F",
    "true", "false", "True", "False", "TRUE", "FALSE",
})
_GO_BUILDVCS_VALID_VALUES = frozenset({
    "1", "0", "t", "f", "T", "F",
    "true", "false", "True", "False", "TRUE", "FALSE",
    "auto",
})
_SKIP_COMMAND = object()
_NPM_IF_PRESENT = "--if-present"

# ---- P0-13 Support Boundary Freeze ----
# npm: run/run-script, start/stop/restart/test, --if-present[=true|false],
#   single/multiple --workspace/-w, root workspaces array/object form,
#   declared workspace package name or directory selection.
# pnpm: single simple name filter, single ./directory filter,
#   complex or multiple filters → SKIP_UNSUPPORTED.
# Go: local relative paths, .go files, ... pattern,
#   import/module path (no local check), declared build/run param sets,
#   unknown params → SKIP_UNSUPPORTED.
# -----------------------------------------------------------------

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
    workspace: str = ""
    manager: str = ""
    selector_type: str = ""
    workspaces: tuple[str, ...] = ()
    # None: --if-present not specified; True: allow missing script;
    # False: --if-present=false, do NOT allow missing script.
    if_present: bool | None = None
    invalid: bool = False


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


def _is_complex_pnpm_selector(selector: str) -> bool:
    """Return True for glob, negation, or dependency-graph selectors."""
    if "..." in selector:
        return True
    return any(c in _COMPLEX_SELECTOR_CHARS for c in selector)


def _is_go_import_path(token: str) -> bool:
    """Return True if token is a Go import/module path, not a local path."""
    if "@" in token:
        return True
    if token.startswith((".", "..")):
        return False
    if token.endswith(".go"):
        return False
    return True


def _npm_glob_to_regex(pattern: str) -> str:
    """Convert an npm workspace glob pattern to a regex string.

    ``*`` matches within a single path segment (``[^/]*``).
    ``**`` matches across path separators (``.*``).
    """
    result: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                result.append(".*")
                i += 2
            else:
                result.append("[^/]*")
                i += 1
        elif ch in ".+(){}|^$\\":
            result.append("\\")
            result.append(ch)
            i += 1
        else:
            result.append(ch)
            i += 1
    return "^" + "".join(result) + "$"


_NPM_GLOB_CACHE: dict[str, "re.Pattern[str]"] = {}


def _npm_glob_match(path: str, pattern: str) -> bool:
    """Match a relative directory path against an npm workspace glob."""
    if pattern not in _NPM_GLOB_CACHE:
        _NPM_GLOB_CACHE[pattern] = re.compile(_npm_glob_to_regex(pattern))
    return bool(_NPM_GLOB_CACHE[pattern].fullmatch(path))


def _npm_workspace_glob_match(directory: str, patterns: list[str]) -> bool:
    """Check if *directory* matches npm workspace *patterns*.

    Supports positive patterns and negation (``!`` prefix).  A directory
    must match at least one positive pattern and must not match any
    negative pattern.
    """
    positive: list[str] = []
    negative: list[str] = []
    for pattern in patterns:
        if pattern.startswith("!"):
            negative.append(pattern[1:])
        else:
            positive.append(pattern)
    if not any(_npm_glob_match(directory, p) for p in positive):
        return False
    return not any(_npm_glob_match(directory, p) for p in negative)


def _parse_workspace_command(
    command: str,
    line_number: int,
    base_dir: str,
) -> _CommandReference | object | None:
    """Parse a workspace command.

    Returns:
        _CommandReference: a valid command reference.
        _SKIP_COMMAND: the command was identified as a package-manager
            workspace command but is conservatively skipped (e.g. ``--workspaces``).
            Callers must NOT fall back to other parsers.
        None: the command is not a workspace command.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) < 3:
        return None
    manager = tokens[0].lower()
    if manager not in {"npm", "yarn", "pnpm", "bun"}:
        return None

    workspaces: list[str] = []
    selector_type = ""
    remainder: list[str] = []
    if_present: bool | None = None
    filter_count = 0
    index = 1

    while index < len(tokens):
        token = tokens[index]

        # -- separator stops package-manager option parsing
        if token == "--":
            remainder.extend(tokens[index + 1:])
            break

        # --workspaces / --no-workspaces → conservatively skip
        if manager == "npm" and token in {"--workspaces", "--no-workspaces"}:
            return _SKIP_COMMAND

        # --if-present: npm flag (bare or =true/=false)
        if manager == "npm" and (
            token == _NPM_IF_PRESENT
            or token.startswith(_NPM_IF_PRESENT + "=")
        ):
            if "=" in token:
                value = token.split("=", 1)[1].lower()
                if value in ("true", "1", "t"):
                    if_present = True
                elif value in ("false", "0", "f"):
                    if_present = False
                else:
                    return _SKIP_COMMAND
            else:
                if_present = True
            index += 1
            continue

        # Name-based selectors (workspace can appear before or after script)
        if manager == "npm" and token in {"--workspace", "-w"}:
            if index + 1 < len(tokens):
                workspaces.append(tokens[index + 1])
                selector_type = "npm_workspace"
                index += 2
                continue
        elif manager == "npm" and token.startswith("--workspace="):
            workspaces.append(token.split("=", 1)[1])
            selector_type = "npm_workspace"
            index += 1
            continue
        elif manager == "npm" and token.startswith("-w="):
            workspaces.append(token.split("=", 1)[1])
            selector_type = "npm_workspace"
            index += 1
            continue
        elif manager == "yarn" and token == "workspace":
            if index + 1 < len(tokens):
                workspaces.append(tokens[index + 1])
                selector_type = "name"
                index += 2
                continue
        elif manager == "pnpm" and token == "--filter":
            if index + 1 < len(tokens):
                filter_value = tokens[index + 1]
                if _is_complex_pnpm_selector(filter_value):
                    return _SKIP_COMMAND
                if filter_value.startswith(("./", "../")):
                    selector_type = "dir"
                else:
                    if not _SIMPLE_PACKAGE_NAME_RE.fullmatch(filter_value):
                        return _SKIP_COMMAND
                    selector_type = "name"
                workspaces.append(filter_value)
                filter_count += 1
                index += 2
                continue
        elif manager == "pnpm" and token.startswith("--filter="):
            filter_value = token.split("=", 1)[1]
            if _is_complex_pnpm_selector(filter_value):
                return _SKIP_COMMAND
            if filter_value.startswith(("./", "../")):
                selector_type = "dir"
            else:
                if not _SIMPLE_PACKAGE_NAME_RE.fullmatch(filter_value):
                    return _SKIP_COMMAND
                selector_type = "name"
            workspaces.append(filter_value)
            filter_count += 1
            index += 1
            continue
        # Directory-based selectors: pnpm -C/--dir, yarn/bun --cwd
        elif manager == "pnpm" and token in {"-C", "--dir"}:
            if index + 1 < len(tokens):
                workspaces.append(tokens[index + 1])
                selector_type = "dir"
                index += 2
                continue
        elif manager == "pnpm" and token.startswith("--dir="):
            workspaces.append(token.split("=", 1)[1])
            selector_type = "dir"
            index += 1
            continue
        elif manager in {"yarn", "bun"} and token == "--cwd":
            if index + 1 < len(tokens):
                workspaces.append(tokens[index + 1])
                selector_type = "dir"
                index += 2
                continue

        remainder.append(token)
        index += 1

    # Multiple pnpm --filter (before --) → conservative skip
    if manager == "pnpm" and filter_count > 1:
        return _SKIP_COMMAND

    if not workspaces and if_present is None:
        return None

    # strip optional "run"/"run-script" and check for built-in commands
    has_run = False
    if remainder and remainder[0].lower() in _NPM_RUN_KEYWORDS:
        has_run = True
        remainder = remainder[1:]
    if not remainder or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_-]*", remainder[0]):
        return _SKIP_COMMAND if has_run else None

    command_name = remainder[0]
    lowered_command = command_name.lower()

    # skip package-manager built-in commands
    if has_run:
        pass
    elif manager == "npm":
        if lowered_command not in _NPM_LIFECYCLE_COMMANDS:
            return None
    elif lowered_command in _NODE_BUILTIN_COMMANDS.get(manager, frozenset()):
        return None

    # Determine if this is a lifecycle command for workspace validation
    is_lifecycle = (
        manager == "npm"
        and lowered_command in _NPM_LIFECYCLE_COMMANDS
    )

    # Root-level --if-present without workspaces
    if not workspaces:
        return _CommandReference(
            line_number,
            "npm_lifecycle" if is_lifecycle else "node_script",
            base_dir, command_name,
            manager=manager,
            if_present=if_present,
        )

    # Create reference based on selector type
    if selector_type in ("name", "npm_workspace"):
        return _CommandReference(
            line_number,
            "node_workspace_lifecycle" if is_lifecycle else "node_workspace_name",
            base_dir, command_name,
            workspace=workspaces[0],
            workspaces=tuple(workspaces),
            manager=manager,
            selector_type=selector_type,
            if_present=if_present,
        )
    # Directory-based selector: single workspace only
    if len(workspaces) > 1:
        return None
    normalized = _safe_relative_path(base_dir, workspaces[0])
    if normalized is None:
        return None
    return _CommandReference(
        line_number,
        "npm_lifecycle" if is_lifecycle else "node_script",
        normalized, command_name,
        manager=manager,
        selector_type=selector_type,
        if_present=if_present,
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

        # Handle directory option (--app-dir / --chdir)
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
            index += 1
            continue

        # Skip options (flags and value-taking options)
        if token.startswith("-"):
            if "=" in token and not token.startswith("---"):
                index += 1
                continue
            if token in _SERVER_VALUE_OPTIONS and index + 1 < len(arguments):
                index += 2
                continue
            index += 1
            continue

        # Positional argument: only first match becomes the target
        if target is None and re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", token
        ):
            target = token.split(":", 1)[0]
        index += 1

    if target is None:
        return None
    return _CommandReference(
        line_number, "python_import_module", command_base, target
    )


def _parse_go_command(
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
    if tokens[0].lower() != "go":
        return None

    go_base_dir = base_dir
    index = 1

    # Parse leading -C <dir> or -C=<dir> (global flag before subcommand)
    while index < len(tokens):
        token = tokens[index]
        if token in _GO_GLOBAL_VALUE_OPTIONS:
            if index + 1 < len(tokens):
                normalized = _safe_relative_path(go_base_dir, tokens[index + 1])
                if normalized is None:
                    return None
                go_base_dir = normalized
                index += 2
                continue
            return None  # -C without value
        if token.startswith("-C="):
            value = token.split("=", 1)[1]
            normalized = _safe_relative_path(go_base_dir, value)
            if normalized is None:
                return None
            go_base_dir = normalized
            index += 1
            continue
        break

    if index >= len(tokens):
        return None
    subcommand = tokens[index].lower()
    if subcommand not in {"run", "build"}:
        return None
    index += 1

    # Parse -C <dir> or -C=<dir> as first argument of build/run
    if index < len(tokens):
        token = tokens[index]
        if token in _GO_GLOBAL_VALUE_OPTIONS:
            if index + 1 < len(tokens):
                normalized = _safe_relative_path(go_base_dir, tokens[index + 1])
                if normalized is None:
                    return None
                go_base_dir = normalized
                index += 2
            else:
                return None  # -C without value
        elif token.startswith("-C="):
            value = token.split("=", 1)[1]
            normalized = _safe_relative_path(go_base_dir, value)
            if normalized is None:
                return None
            go_base_dir = normalized
            index += 1

    go_packages: list[str] = []
    package_found = False
    go_file_mode = False
    invalid = False

    # Select subcommand-specific flag sets.
    sub_boolean = (
        _GO_BUILD_BOOLEAN_OPTIONS if subcommand == "build"
        else _GO_RUN_BOOLEAN_OPTIONS
    )
    sub_value = (
        _GO_BUILD_VALUE_OPTIONS if subcommand == "build"
        else _GO_RUN_VALUE_OPTIONS
    )

    while index < len(tokens):
        token = tokens[index]
        # For "go run", after finding the first target:
        if subcommand == "run" and package_found:
            if go_file_mode:
                if token.endswith(".go"):
                    normalized = _safe_relative_path(go_base_dir, token)
                    if normalized is None:
                        return None
                    go_packages.append(normalized)
                    index += 1
                    continue
                break
            break
        if token.startswith("-") and token != "-":
            # Handle -flag=value form
            if "=" in token:
                flag, value = token.split("=", 1)
                if flag in sub_value:
                    index += 1
                    continue
                if flag in sub_boolean:
                    valid_values = (
                        _GO_BUILDVCS_VALID_VALUES
                        if flag == "-buildvcs"
                        else _GO_BOOLEAN_VALID_VALUES
                    )
                    if value not in valid_values:
                        invalid = True
                    index += 1
                    continue
                # Known Go flag but not valid for this subcommand → INVALID
                if (
                    flag in _GO_ALL_KNOWN_BOOLEAN
                    or flag in _GO_ALL_KNOWN_VALUE
                ):
                    invalid = True
                    index += 1
                    continue
                # Completely unknown flag: conservative skip
                return None
            # Handle -flag (boolean) form
            if token in sub_boolean:
                index += 1
                continue
            # Handle -flag value (value option) form
            if token in sub_value and index + 1 < len(tokens):
                index += 2
                continue
            # Known Go flag but not valid for this subcommand → INVALID
            if (
                token in _GO_ALL_KNOWN_BOOLEAN
                or token in _GO_ALL_KNOWN_VALUE
            ):
                invalid = True
                index += 1
                continue
            # Unknown flag: conservative skip
            return None
        # Positional argument: package/path/file
        package_found = True
        if _is_go_import_path(token):
            # Import/module path: skip local validation
            index += 1
            continue
        if token.endswith(".go"):
            go_file_mode = True
        normalized = _safe_relative_path(go_base_dir, token)
        if normalized is None:
            return None
        go_packages.append(normalized)
        index += 1

    if not go_packages:
        if invalid:
            return _CommandReference(
                line_number, "go", go_base_dir, "", invalid=True,
            )
        return None
    if len(go_packages) == 1:
        return _CommandReference(
            line_number, "go", go_base_dir, go_packages[0], invalid=invalid,
        )
    return _CommandReference(
        line_number, "go", go_base_dir, go_packages[0],
        targets=tuple(go_packages), invalid=invalid,
    )


def _parse_streamlit_flask_command(
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
    tool = tokens[0].lower()
    arguments = tokens[1:]
    if tool in {"python", "python3"}:
        if len(tokens) < 3 or tokens[1] != "-m":
            return None
        tool = tokens[2].lower()
        arguments = tokens[3:]
    if tool not in _STREAMLIT_FLASK_TOOLS:
        return None

    if tool == "streamlit":
        if len(arguments) >= 2 and arguments[0].lower() == "run":
            path = arguments[1]
            if path.lower().startswith(("http://", "https://")):
                return None
            target = _safe_relative_path(base_dir, path)
            if target is None:
                return None
            return _CommandReference(line_number, "path", ".", target)
        return None

    app_target: str | None = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--app":
            if index + 1 >= len(arguments):
                return None
            app_target = arguments[index + 1]
            index += 2
            continue
        if token.startswith("--app="):
            app_target = token.split("=", 1)[1]
            index += 1
            continue
        index += 1
    if app_target is None:
        return None

    if ":" in app_target:
        app_target = app_target.split(":", 1)[0]

    if app_target.endswith(".py") or "/" in app_target or "\\" in app_target:
        target = _safe_relative_path(base_dir, app_target)
        if target is None:
            return None
        return _CommandReference(line_number, "path", ".", target)
    return _CommandReference(
        line_number, "python_import_module", base_dir, app_target
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

    streamlit_flask = _parse_streamlit_flask_command(command, line_number, base_dir)
    if streamlit_flask is not None:
        return streamlit_flask

    workspace = _parse_workspace_command(command, line_number, base_dir)
    if workspace is _SKIP_COMMAND:
        return None
    if workspace is not None:
        return workspace
    if re.match(r"^(?:npm|pnpm|yarn|bun)\s+(?:-|workspace\b)", command, re.IGNORECASE):
        return None

    node = re.match(
        r"^(npm|pnpm|yarn|bun)\s+(?:run|run-script)\s+([A-Za-z0-9][A-Za-z0-9:_-]*)(?:\s|$)",
        command, re.IGNORECASE,
    )
    if node:
        manager = node.group(1).lower()
        script_name = node.group(2)
        lowered_script = script_name.lower()
        if manager == "npm" and lowered_script in _NPM_LIFECYCLE_COMMANDS:
            return _CommandReference(
                line_number, "npm_lifecycle", base_dir, lowered_script,
            )
        return _CommandReference(line_number, "node_script", base_dir, script_name)

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
    go = _parse_go_command(command, line_number, base_dir)
    if go is not None:
        return go
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
        # package name → list of directories (preserves insertion order)
        self.node_package_names: dict[str, list[str]] = {}
        # directories where package.json parsed successfully to a dict
        self.valid_node_manifest_dirs: set[str] = set()
        self.package_workspaces: dict[str, list[str]] = {}
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
        self.valid_node_manifest_dirs.add(directory)
        package_name = data.get("name")
        if isinstance(package_name, str) and package_name.strip():
            dirs = self.node_package_names.setdefault(package_name, [])
            if directory not in dirs:
                dirs.append(directory)
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
        # Parse workspaces config (npm workspaces)
        workspaces = data.get("workspaces")
        if isinstance(workspaces, list):
            self.package_workspaces[directory] = [
                str(w) for w in workspaces if isinstance(w, str)
            ]
        elif isinstance(workspaces, dict):
            packages = workspaces.get("packages")
            if isinstance(packages, list):
                self.package_workspaces[directory] = [
                    str(p) for p in packages if isinstance(p, str)
                ]

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

    def _npm_lifecycle_is_valid(
        self, target: str, scripts: set[str], package_path: str,
    ) -> bool:
        """Unified npm lifecycle validation shared by root and workspace.

        Args:
            target: the lifecycle command name (start/stop/restart/test).
            scripts: the scripts set for the package directory.
            package_path: the rooted path to the package directory
                (used to check for ``server.js``).
        """
        server_js = "server.js" if package_path == "." else f"{package_path}/server.js"
        if target == "start":
            return "start" in scripts or server_js in self.paths
        if target == "restart":
            return "restart" in scripts or (
                "start" in scripts or server_js in self.paths
            )
        return target in scripts

    def _npm_workspace_is_declared(
        self, directory: str, root_prefix: str,
    ) -> bool:
        """Check that *directory* is a declared npm workspace with valid package.json.

        Uses proper npm workspace glob matching (``*`` for single segment,
        ``**`` for recursive, ``!`` for negation) instead of
        ``PurePosixPath.match()``.
        """
        root_pkg_dir = root_prefix or "."
        patterns = self.package_workspaces.get(root_pkg_dir)
        if not patterns:
            return False
        rel_dir = directory
        if root_prefix and directory.startswith(root_prefix + "/"):
            rel_dir = directory[len(root_prefix) + 1:]
        if not _npm_workspace_glob_match(rel_dir, patterns):
            return False
        # Workspace must have a valid (parseable) package.json
        pkg_json = f"{directory}/package.json"
        if pkg_json not in self.paths:
            return False
        return directory in self.valid_node_manifest_dirs

    def _resolve_npm_workspace_by_name(
        self, name: str, root_prefix: str,
    ) -> str | None:
        """Resolve an npm workspace package name to its directory.

        1. Read root package.json workspaces patterns.
        2. From all valid package manifests, filter those matching patterns.
        3. Match by package name among the filtered candidates.
        """
        root_pkg_dir = root_prefix or "."
        patterns = self.package_workspaces.get(root_pkg_dir)
        if not patterns:
            return None
        candidate_dirs = self.node_package_names.get(name, [])
        for directory in candidate_dirs:
            rel_dir = directory
            if root_prefix and directory.startswith(root_prefix + "/"):
                rel_dir = directory[len(root_prefix) + 1:]
            if _npm_workspace_glob_match(rel_dir, patterns):
                if directory in self.valid_node_manifest_dirs:
                    return directory
        return None

    def _command_is_valid(
        self, reference: _CommandReference, root_prefix: str
    ) -> bool:
        if reference.invalid:
            return False
        relative_base = "" if reference.base_dir == "." else reference.base_dir
        base = "/".join(part for part in (root_prefix, relative_base) if part)
        def joined(name: str) -> str:
            return f"{base}/{name}" if base else name
        def rooted(name: str) -> str:
            return f"{root_prefix}/{name}" if root_prefix else name

        # --if-present only suppresses missing-script errors.
        # It does NOT suppress: missing package.json, corrupt package.json,
        # missing workspace, undeclared workspace.
        if_present_allows_missing = reference.if_present is True

        if reference.kind == "node_workspace_name":
            all_workspaces = reference.workspaces or (
                (reference.workspace,) if reference.workspace else ()
            )
            if not all_workspaces:
                return False
            for ws in all_workspaces:
                if reference.manager == "npm":
                    directory = self._resolve_npm_workspace_by_name(
                        ws, root_prefix,
                    )
                    if directory is None:
                        # Try as directory path
                        normalized = _safe_relative_path(reference.base_dir, ws)
                        if normalized is None:
                            return False
                        rel = normalized if normalized != "." else ""
                        dir_path = "/".join(p for p in (root_prefix, rel) if p) or "."
                        if not self._npm_workspace_is_declared(dir_path, root_prefix):
                            return False
                        directory = dir_path
                    if reference.target not in self.node_scripts.get(directory, set()):
                        if if_present_allows_missing:
                            continue
                        return False
                    continue
                # Non-npm managers: use legacy name→dir map
                dirs = self.node_package_names.get(ws, [])
                if dirs:
                    directory = dirs[0]
                    if reference.target not in self.node_scripts.get(directory, set()):
                        if if_present_allows_missing:
                            continue
                        return False
                    continue
                # Name not found in package registry
                if reference.selector_type == "name":
                    return False
                if reference.selector_type == "npm_workspace":
                    if ws.startswith("@"):
                        return False
                    normalized = _safe_relative_path(reference.base_dir, ws)
                    if normalized is None:
                        return False
                    rel = normalized if normalized != "." else ""
                    dir_path = "/".join(p for p in (root_prefix, rel) if p) or "."
                    if reference.target not in self.node_scripts.get(dir_path, set()):
                        if if_present_allows_missing:
                            continue
                        return False
                    continue
                return False
            return True
        if reference.kind == "node_workspace_lifecycle":
            all_workspaces = reference.workspaces or (
                (reference.workspace,) if reference.workspace else ()
            )
            if not all_workspaces:
                return False
            for ws in all_workspaces:
                if reference.manager == "npm":
                    directory = self._resolve_npm_workspace_by_name(
                        ws, root_prefix,
                    )
                    if directory is None:
                        # Try as directory path
                        normalized = _safe_relative_path(reference.base_dir, ws)
                        if normalized is None:
                            return False
                        rel = normalized if normalized != "." else ""
                        directory = "/".join(p for p in (root_prefix, rel) if p) or "."
                        if not self._npm_workspace_is_declared(directory, root_prefix):
                            return False
                else:
                    dirs = self.node_package_names.get(ws, [])
                    if dirs:
                        directory = dirs[0]
                    elif reference.selector_type == "name":
                        return False
                    elif reference.selector_type == "npm_workspace":
                        if ws.startswith("@"):
                            return False
                        normalized = _safe_relative_path(reference.base_dir, ws)
                        if normalized is None:
                            return False
                        rel = normalized if normalized != "." else ""
                        directory = "/".join(p for p in (root_prefix, rel) if p) or "."
                    else:
                        return False
                scripts = self.node_scripts.get(directory, set())
                pkg_path = directory
                if not self._npm_lifecycle_is_valid(
                    reference.target, scripts, pkg_path,
                ):
                    if if_present_allows_missing:
                        continue
                    return False
            return True
        if reference.kind == "node_script":
            manifest_dir = base or "."
            # Verify package.json exists and is valid before if_present
            if joined("package.json") not in self.paths:
                return False
            if manifest_dir not in self.valid_node_manifest_dirs:
                return False
            if reference.target in self.node_scripts.get(manifest_dir, set()):
                return True
            return if_present_allows_missing
        if reference.kind == "npm_lifecycle":
            manifest_dir = base or "."
            # Step 1: package.json must exist
            if joined("package.json") not in self.paths:
                return False
            # Step 2: package.json must be valid
            if manifest_dir not in self.valid_node_manifest_dirs:
                return False
            # Step 3: validate scripts/server.js
            scripts = self.node_scripts.get(manifest_dir, set())
            if self._npm_lifecycle_is_valid(
                reference.target, scripts, manifest_dir,
            ):
                return True
            # Step 4: apply --if-present (only suppresses missing script)
            return if_present_allows_missing
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
            return (
                self._path_exists(joined(f"{module}.py"))
                or self._path_exists(joined(f"{module}/__main__.py"))
                or self._path_exists(joined(f"src/{module}.py"))
                or self._path_exists(joined(f"src/{module}/__main__.py"))
            )
        if reference.kind == "python_import_module":
            module = reference.target.replace(".", "/")
            return (
                self._path_exists(joined(f"{module}.py"))
                or self._path_exists(joined(f"{module}/__init__.py"))
                or self._path_exists(joined(f"src/{module}.py"))
                or self._path_exists(joined(f"src/{module}/__init__.py"))
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
            all_targets = (reference.target,)
            if reference.targets:
                all_targets = reference.targets
            for target in all_targets:
                if "..." in target:
                    if joined("go.mod") not in self.paths:
                        return False
                    base_path = target.replace("/...", "").replace("...", "")
                    if base_path and base_path != ".":
                        if not self._path_exists(rooted(base_path), directory=True):
                            return False
                elif target in {reference.base_dir, "."}:
                    if joined("go.mod") not in self.paths:
                        return False
                elif not self._path_exists(rooted(target)):
                    return False
            return True
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
