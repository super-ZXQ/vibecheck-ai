"""Deterministic repository-level documentation consistency checks."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable

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
_INLINE_COMMAND_RE = re.compile(
    r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?`([^`]+)`\s*[.!。]?[\s]*$"
)
_TREE_RE = re.compile(r"^(?P<prefix>(?:│   |    )*)(?:├──|└──)\s*(?P<name>.+?)\s*$")
_DIRECT_TREE_PATH_RE = re.compile(
    r"^\s*(?:\./)?([A-Za-z0-9._@+\-]+(?:/[A-Za-z0-9._@+\-]+)+/?)\s*$"
)
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@+\-]+/?$")
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?")
_DANGEROUS_COMMAND_RE = re.compile(r"[|;<>`]|\$\(|\$\{|%[^%]+%")
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


def _prose_character_count(lines: list[str]) -> int:
    visible: list[str] = []
    in_fence = False
    in_comment = False
    for line in lines:
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
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
            return None
        parts.append(part)
    normalized = "/".join(parts) or "."
    return mask_untrusted_text(normalized)


def _parse_command(line: str, line_number: int) -> _CommandReference | None:
    command = line.strip()
    command = re.sub(r"^(?:\$|>)\s+", "", command)
    if not command or _DANGEROUS_COMMAND_RE.search(command):
        return None
    base_dir = "."
    cd_match = re.match(r"^cd\s+([^\s]+)\s*&&\s*(.+)$", command, re.IGNORECASE)
    if cd_match:
        normalized = _safe_relative_path(".", cd_match.group(1))
        if normalized is None:
            return None
        base_dir = normalized
        command = cd_match.group(2).strip()
    if "&" in command:
        return None

    node = re.match(
        r"^(npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)(?:\s|$)",
        command, re.IGNORECASE,
    )
    if node and node.group(2).lower() not in {"install", "add", "ci", "audit"}:
        return _CommandReference(line_number, "node_script", base_dir, node.group(2))

    python_module = re.match(r"^python(?:3)?\s+-m\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", command)
    if python_module:
        return _CommandReference(line_number, "python_module", base_dir, python_module.group(1))
    python_file = re.match(r"^python(?:3)?\s+([^\s]+\.py)(?:\s|$)", command)
    if python_file:
        target = _safe_relative_path(base_dir, python_file.group(1))
        return _CommandReference(line_number, "path", ".", target) if target else None
    python_server = re.match(
        r"^(?:uvicorn|gunicorn|hypercorn)\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):[A-Za-z_]\w*",
        command,
    )
    if python_server:
        return _CommandReference(line_number, "python_module", base_dir, python_server.group(1))
    node_file = re.match(r"^(?:node|tsx|ts-node)\s+([^\s]+\.(?:js|mjs|cjs|ts|tsx))(?:\s|$)", command)
    if node_file:
        target = _safe_relative_path(base_dir, node_file.group(1))
        return _CommandReference(line_number, "path", ".", target) if target else None

    compose = re.match(r"^(?:docker\s+compose|docker-compose)\b(.*)$", command, re.IGNORECASE)
    if compose:
        file_option = re.search(r"(?:^|\s)-f\s+([^\s]+)", compose.group(1))
        target = ""
        if file_option:
            normalized = _safe_relative_path(base_dir, file_option.group(1))
            if normalized is None:
                return None
            target = normalized
        return _CommandReference(line_number, "compose", base_dir, target)

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


def _command_references(lines: list[str], limit: int) -> tuple[_CommandReference, ...]:
    references: list[_CommandReference] = []
    for start, end in _section_ranges(lines, _COMMAND_SECTION_RE):
        in_fence = False
        for index in range(start, end):
            line = lines[index]
            if _FENCE_RE.match(line):
                in_fence = not in_fence
                continue
            candidate: str | None = line if in_fence else None
            if not in_fence:
                inline = _INLINE_COMMAND_RE.match(line)
                candidate = inline.group(1) if inline else None
            if candidate:
                parsed = _parse_command(candidate, index + 1)
                if parsed is not None:
                    references.append(parsed)
                    if len(references) >= limit:
                        return tuple(references)
    return tuple(references)


def _structure_references(lines: list[str], limit: int) -> tuple[_StructureReference, ...]:
    references: list[_StructureReference] = []
    seen: set[str] = set()
    for start, end in _section_ranges(lines, _STRUCTURE_SECTION_RE):
        in_fence = False
        stack: dict[int, str] = {}
        for index in range(start, end):
            line = lines[index]
            if _FENCE_RE.match(line):
                in_fence = not in_fence
                stack.clear()
                continue
            if not in_fence:
                continue
            match = _TREE_RE.match(line)
            path_value: str | None = None
            is_directory = False
            if match:
                depth = len(match.group("prefix")) // 4
                name = re.split(r"\s{2,}|\s+#", match.group("name"), maxsplit=1)[0].strip()
                if not _SAFE_SEGMENT_RE.fullmatch(name):
                    continue
                is_directory = name.endswith("/")
                segment = name.rstrip("/")
                parent = stack.get(depth - 1, "") if depth > 0 else ""
                path_value = f"{parent}/{segment}" if parent else segment
                stack = {key: value for key, value in stack.items() if key < depth}
                if is_directory:
                    stack[depth] = path_value
            else:
                direct = _DIRECT_TREE_PATH_RE.match(line)
                if direct:
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
                if len(references) >= limit:
                    return tuple(references)
    return tuple(references)


def _readme_facts(file_path: str, lines: list[str], limit: int) -> _ReadmeFacts:
    return _ReadmeFacts(
        path=file_path,
        prose_characters=_prose_character_count(lines),
        technologies=_technology_references(lines),
        commands=_command_references(lines, limit),
        structure=_structure_references(lines, limit),
    )


class DocumentationConsistencyProbe(RepositoryProbe):
    """Bounded per-scan state for C001-C004."""

    def __init__(self) -> None:
        self.limit = max(1, int(settings.scan_max_findings_per_rule_per_file))
        self.paths: set[str] = set()
        self.directories: set[str] = set()
        self.readmes: dict[str, _ReadmeFacts] = {}
        self.node_packages: set[str] = set()
        self.python_packages: set[str] = set()
        self.valid_node_manifest = False
        self.valid_python_manifest = False
        self.node_scripts: dict[str, set[str]] = {}
        self.make_targets: dict[str, set[str]] = {}

    def observe_file(self, file_path: str, lines: list[str]) -> None:
        path = PurePosixPath(file_path)
        normalized = path.as_posix()
        self.paths.add(normalized)
        for parent in path.parents:
            value = parent.as_posix()
            if value != ".":
                self.directories.add(value)

        name = path.name.lower()
        directory = path.parent.as_posix()
        if directory == "." and name in _README_PRIORITY:
            self.readmes[normalized] = _readme_facts(normalized, lines, self.limit)
        text = "\n".join(lines)
        if name == "package.json":
            self._observe_package_json(directory, text)
        elif name.startswith("requirements") and name.endswith(".txt"):
            self.valid_python_manifest = True
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-")):
                    continue
                match = _REQUIREMENT_NAME_RE.match(stripped)
                if match:
                    self.python_packages.add(match.group(1).lower().replace("_", "-"))
        elif name == "pyproject.toml":
            self._observe_pyproject(text)
        elif name == "pipfile":
            self._observe_pipfile(text)
        elif name in {"makefile", "gnumakefile"}:
            targets = self.make_targets.setdefault(directory, set())
            for line in lines:
                target = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", line)
                if target:
                    targets.add(target.group(1))

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

    def _primary_readme(self) -> _ReadmeFacts | None:
        if not self.readmes:
            return None
        return min(
            self.readmes.values(),
            key=lambda facts: (
                _README_PRIORITY[PurePosixPath(facts.path).name.lower()],
                facts.path.casefold(),
                facts.path,
            ),
        )

    def _path_exists(self, path: str, *, directory: bool = False) -> bool:
        return path in (self.directories if directory else self.paths | self.directories)

    def _command_is_valid(self, reference: _CommandReference) -> bool:
        base = "" if reference.base_dir == "." else reference.base_dir
        def joined(name: str) -> str:
            return f"{base}/{name}" if base else name

        if reference.kind == "node_script":
            return reference.target in self.node_scripts.get(reference.base_dir, set())
        if reference.kind == "path":
            return self._path_exists(reference.target)
        if reference.kind == "python_module":
            module = reference.target.replace(".", "/")
            return self._path_exists(joined(f"{module}.py")) or self._path_exists(
                joined(f"{module}/__main__.py")
            )
        if reference.kind == "compose":
            if reference.target:
                return reference.target in self.paths
            return any(joined(name) in self.paths for name in _COMPOSE_NAMES)
        if reference.kind == "make":
            return reference.target in self.make_targets.get(reference.base_dir, set())
        if reference.kind == "go":
            if reference.target in {reference.base_dir, "."}:
                return joined("go.mod") in self.paths
            return self._path_exists(reference.target)
        if reference.kind == "cargo":
            return joined("Cargo.toml") in self.paths
        if reference.kind == "maven":
            return joined("pom.xml") in self.paths
        if reference.kind == "gradle":
            return joined("build.gradle") in self.paths or joined("build.gradle.kts") in self.paths
        if reference.kind == "dotnet":
            if reference.target:
                return self._path_exists(reference.target)
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
        readme = self._primary_readme()
        if readme is None:
            return [_finding("C001_README_COMPLETENESS", _REPOSITORY_PATH)]

        findings: list[Finding] = []
        if readme.prose_characters < 100:
            findings.append(_finding("C001_README_COMPLETENESS", readme.path))

        packages_by_ecosystem: dict[str, tuple[bool, set[str]]] = {
            "node": (self.valid_node_manifest, self.node_packages),
            "python": (self.valid_python_manifest, self.python_packages),
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
            if not self._command_is_valid(reference):
                findings.append(_finding("C003_START_COMMAND_MISMATCH", readme.path, reference.line))
                command_count += 1
                if command_count >= self.limit:
                    break

        structure_count = 0
        for reference in readme.structure:
            if not self._path_exists(reference.path, directory=reference.is_directory):
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
