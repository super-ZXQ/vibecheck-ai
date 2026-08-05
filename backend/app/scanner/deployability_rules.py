"""Deterministic repository-level deployability and production checks."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from app.scanner.base import (
    DEPLOYABILITY_PRODUCTION_DIMENSION,
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

_REPOSITORY_PATH = "<repository>"
_ENV_TEMPLATE_NAMES = frozenset({".env.example", ".env.sample", ".env.template"})
_CONFIG_TEMPLATE_DIR_NAMES = frozenset({
    "config.example", "config.sample", "config.template",
    "settings.example", "settings.sample",
    "env.example", "env.sample", "env.template",
})
_COMPOSE_NAMES = frozenset({
    "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml",
})
_COMPOSE_VARIANT_RE = re.compile(
    r"^(?:docker-)?compose(?:[._-][a-z0-9_-]+)?\.ya?ml$",
    re.IGNORECASE,
)
_README_NAMES = frozenset({"readme", "readme.md", "readme.rst", "readme.txt"})
_NODE_LOCKS = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "bun.lockb",
})
_PYTHON_LOCKS = frozenset({"poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock"})

_DEV_START_RE = re.compile(
    r"\b(?:next\s+dev|vite(?:\s|$)|webpack-dev-server|nodemon|"
    r"ts-node-dev|react-scripts\s+start)\b",
    re.IGNORECASE,
)
_PRODUCTION_SERVER_RE = re.compile(
    r"\b(?:gunicorn|uvicorn|hypercorn|waitress-serve|waitress\.serve)\b",
    re.IGNORECASE,
)
_ENV_ASSIGNMENT_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=")
_ENV_DOC_RE = re.compile(
    r"environment\s+variables?|configuration|\.env\b|环境变量|配置变量",
    re.IGNORECASE,
)
_DEPLOY_DOC_RE = re.compile(
    r"deploy(?:ment)?|production|run(?:ning)?|start|部署|生产|启动|运行",
    re.IGNORECASE,
)
_DEPLOY_COMMAND_RE = re.compile(
    r"npm\s+(?:run\s+)?start|pnpm\s+(?:run\s+)?start|yarn\s+start|"
    r"docker\s+compose\s+up|docker-compose\s+up|gunicorn|uvicorn|hypercorn|"
    r"waitress|go\s+(?:run|build)|cargo\s+(?:run|build)|java\s+-jar|"
    r"dotnet\s+(?:run|publish)|bundle\s+exec|php\s+(?:artisan|bin/console)|"
    r"(?:上传|upload).{0,12}(?:部署|deploy)|云端安装依赖|"
    r"serverless\s+deploy|sls\s+deploy|firebase\s+deploy|vercel\s+deploy|"
    r"wrangler\s+(?:deploy|publish)|gcloud\s+functions\s+deploy|"
    r"云函数.*部署|云开发.*部署",
    re.IGNORECASE,
)
_PREREQUISITE_DOC_RE = re.compile(
    r"prerequisites?|requirements?|before\s+you\s+begin|"
    r"install(?:ation)?|requires?\s+(?:node|python|java|go|rust|ruby|php|\.net)|"
    r"\u524d\u7f6e\u6761\u4ef6|\u5b89\u88c5\u8981\u6c42|\u73af\u5883\u8981\u6c42|"
    r"\u5feb\u901f\u5f00\u59cb|\u5feb\u901f\u4e0a\u624b|quick\s+start|"
    r"\u8fd0\u884c\u73af\u5883|\u73af\u5883\u8981\u6c42",
    re.IGNORECASE,
)
_ENV_USAGE_PATTERNS = (
    re.compile(r"\bprocess\.env\.[A-Za-z_][A-Za-z0-9_]*"),
    re.compile(r"\bprocess\.env\s*\["),
    re.compile(r"\bos\.(?:getenv|environ\.get)\s*\("),
    re.compile(r"\bos\.environ\s*\["),
    re.compile(r"\bSystem\.getenv\s*\("),
    re.compile(r"\bEnvironment\.GetEnvironmentVariable\s*\("),
    re.compile(r"\bstd::env::var\s*\("),
    re.compile(r"\bos\.Getenv\s*\("),
    re.compile(r"\bENV\s*\["),
    re.compile(r"(?<![.\w])getenv\s*\("),
    re.compile(r"\$_(?:ENV|SERVER)\s*\["),
)
_GO_MAIN_RE = re.compile(r"\bfunc\s+main\s*\(")
_JAVA_MAIN_RE = re.compile(r"\bstatic\s+void\s+main\s*\(")
_KOTLIN_MAIN_RE = re.compile(r"\bfun\s+main\s*\(")
_REQUIREMENT_PIN_RE = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^*\s]+(?:\s|$)"
)
_EXACT_DOTNET_VERSION_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$"
)


@dataclass
class _DependencyState:
    manifests: set[str] = field(default_factory=set)
    has_dependencies: bool = False
    locked: bool = False
    manifest_deps: dict[str, bool] = field(default_factory=dict)


@dataclass
class _DockerState:
    path: str
    has_from: bool = False
    final_base: str | None = None
    final_has_start: bool = False
    final_user: str | None = None


_RULE_METADATA: dict[str, tuple[str, Severity, str, str, str]] = {
    "D001_PRODUCTION_START": (
        "Missing reproducible production start",
        Severity.MEDIUM,
        "No reproducible production start method was detected.",
        "Add and document a deterministic production start command.",
        "add_production_start",
    ),
    "D002_ENVIRONMENT_DOCUMENTATION": (
        "Missing environment configuration documentation",
        Severity.MEDIUM,
        "The project reads environment variables without a configuration template or documentation.",
        "Add a sanitized environment template or document required configuration in the README.",
        "document_environment",
    ),
    "D003_DEPENDENCY_LOCK": (
        "Missing reproducible dependency lock",
        Severity.MEDIUM,
        "A dependency manifest is present without the expected reproducibility control.",
        "Commit the ecosystem lock file or use exact supported dependency pins.",
        "lock_dependencies",
    ),
    "D004_DEPLOYMENT_DOCUMENTATION": (
        "Missing deployment documentation",
        Severity.LOW,
        "The README does not provide a production deployment command and prerequisites.",
        "Document production prerequisites and the exact deployment or start command.",
        "document_deployment",
    ),
    "D005_DOCKER_MISSING": (
        "Missing container configuration",
        Severity.LOW,
        "No Dockerfile or Compose configuration was detected.",
        "Add a reproducible Docker or Compose packaging path for deployment.",
        "add_container_configuration",
    ),
    "D006_DOCKER_MISSING_FROM": (
        "Dockerfile missing base image",
        Severity.HIGH,
        "A Dockerfile does not contain a valid FROM instruction.",
        "Add a valid, pinned FROM instruction to the Dockerfile.",
        "add_docker_base",
    ),
    "D007_DOCKER_MUTABLE_BASE": (
        "Mutable Docker base image",
        Severity.MEDIUM,
        "The final Docker base image uses an implicit or latest tag.",
        "Pin the final base image to an explicit version tag or digest.",
        "pin_docker_base",
    ),
    "D008_DOCKER_ROOT_USER": (
        "Docker runtime user is root or unspecified",
        Severity.MEDIUM,
        "The final container runtime does not declare a non-root user.",
        "Create and select a non-root runtime user in Dockerfile or Compose.",
        "set_non_root_user",
    ),
    "D009_DOCKER_MISSING_START": (
        "Docker runtime start command missing",
        Severity.MEDIUM,
        "The final container runtime has no explicit start command.",
        "Add CMD, ENTRYPOINT, or a Compose command for the production process.",
        "add_docker_start",
    ),
    "D010_INVALID_DEPLOYMENT_CONFIG": (
        "Invalid deployment configuration",
        Severity.MEDIUM,
        "A supported deployment or dependency manifest could not be parsed.",
        "Correct the manifest syntax and verify it with the ecosystem tooling.",
        "fix_deployment_manifest",
    ),
}


def _finding(rule_id: str, file_path: str) -> Finding:
    name, severity, description, message, template = _RULE_METADATA[rule_id]
    return Finding(
        rule_id=rule_id,
        rule_name=name,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line_start=None,
        line_end=None,
        column_start=None,
        column_end=None,
        snippet_masked="<repository-deployability-check>",
        is_blocking=False,
        finding_type=FindingType.FILE,
        description=description,
        category="deployability",
        secret_type="",
        message=message,
        repair_template_key=template,
        dimension=DEPLOYABILITY_PRODUCTION_DIMENSION,
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _has_mapping_entries(value: Any) -> bool:
    return isinstance(value, dict) and bool(value)


def _code_lines(file_path: str, lines: list[str]) -> list[str]:
    comments, strings = _analyze_source_lines(file_path, lines)
    return [
        _code_without_strings(
            _code_without_comments(line, comments[index]), strings[index]
        )
        for index, line in enumerate(lines)
    ]


def _is_mutable_base(image: str | None) -> bool:
    if not image:
        return False
    lowered = image.lower()
    if lowered == "scratch" or "@sha256:" in lowered:
        return False
    if "$" in image:
        return False
    final_component = image.rsplit("/", 1)[-1]
    if ":" not in final_component:
        return True
    return final_component.rsplit(":", 1)[-1].lower() == "latest"


def _is_non_root_user(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip().strip('"\'').split(":", 1)[0].lower()
    if "$" in normalized:
        return False
    return normalized not in {"root", "0"}


def _is_root_user(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip().strip('"\'').split(":", 1)[0].lower()
    return normalized in {"root", "0"}


def _is_compose_file(name: str) -> bool:
    return name in _COMPOSE_NAMES or bool(_COMPOSE_VARIANT_RE.match(name))


def _is_container_file(name: str) -> bool:
    return (
        name == "dockerfile" or name.startswith(("dockerfile.", "containerfile.")) or name == "containerfile"
    )


def _is_excluded_path(file_path: str) -> bool:
    parts = {part.lower() for part in PurePosixPath(file_path).parts[:-1]}
    return bool(parts & EXCLUDED_PATH_PARTS)


class DeployabilityProbe(RepositoryProbe):
    """Bounded per-scan state for D001-D010."""

    def __init__(self) -> None:
        self.production_start = False
        self.env_usage_paths: set[str] = set()
        self.has_env_docs = False
        self.readme_paths: set[str] = set()
        self.readme_has_deploy_text = False
        self.readme_has_deploy_command = False
        self.readme_has_prerequisites = False
        self.has_compose = False
        self.compose_paths: set[str] = set()
        self.compose_has_start = False
        self.compose_non_root_user = False
        self.compose_root_user = False
        self.dockerfiles: dict[str, _DockerState] = {}
        self.invalid_configs: set[str] = set()
        self.lock_dirs: set[str] = set()
        self.dependencies: dict[str, _DependencyState] = {
            key: _DependencyState()
            for key in (
                "node", "python", "go", "rust", "maven", "gradle",
                "ruby", "php", "dotnet",
            )
        }
        self.python_requirements_all_pinned = True
        self.python_requirements_seen = False
        self.rust_application = False
        self.maven_wrapper_script = False
        self.maven_wrapper_config = False
        self.gradle_wrapper_script = False
        self.gradle_wrapper_config = False
        self.dotnet_all_exact = True

    def observe_file(self, file_path: str, lines: list[str]) -> None:
        if _is_excluded_path(file_path):
            return

        path = PurePosixPath(file_path)
        lowered = file_path.lower()
        name = path.name.lower()
        text = "\n".join(lines)

        if name in _README_NAMES:
            self.readme_paths.add(file_path)
            self.has_env_docs = self.has_env_docs or bool(_ENV_DOC_RE.search(text))
            self.readme_has_deploy_text = (
                self.readme_has_deploy_text or bool(_DEPLOY_DOC_RE.search(text))
            )
            self.readme_has_deploy_command = (
                self.readme_has_deploy_command or bool(_DEPLOY_COMMAND_RE.search(text))
            )
            self.readme_has_prerequisites = (
                self.readme_has_prerequisites
                or bool(_PREREQUISITE_DOC_RE.search(text))
            )
            self.production_start = self.production_start or bool(
                _PRODUCTION_SERVER_RE.search(text)
            )

        if name in _ENV_TEMPLATE_NAMES and any(
            _ENV_ASSIGNMENT_RE.match(line) for line in lines
        ):
            self.has_env_docs = True
        elif any(
            segment in _CONFIG_TEMPLATE_DIR_NAMES for segment in path.parts
        ) and any(line.strip() for line in lines):
            # config.example/ 等样板目录中的非空配置即视为环境文档（无需 KEY= 赋值行）。
            self.has_env_docs = True

        if _is_compose_file(name):
            self.has_compose = True
            self.compose_paths.add(file_path)
            pending_start_indent: int | None = None
            for line in lines:
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())
                if pending_start_indent is not None and stripped and not stripped.startswith("#"):
                    if indent > pending_start_indent:
                        self.compose_has_start = True
                        self.production_start = True
                    pending_start_indent = None
                start_match = re.match(
                    r"^(?:command|entrypoint)\s*:\s*(.*)$", stripped, re.IGNORECASE
                )
                if start_match:
                    value = start_match.group(1).strip()
                    if value and value.lower() not in {"[]", "{}", "null", "~"}:
                        self.compose_has_start = True
                        self.production_start = True
                    elif not value:
                        pending_start_indent = indent
                user_match = re.match(r"^user\s*:\s*(.+)$", stripped, re.IGNORECASE)
                if user_match:
                    self.compose_non_root_user = (
                        self.compose_non_root_user
                        or _is_non_root_user(user_match.group(1))
                    )
                    self.compose_root_user = (
                        self.compose_root_user or _is_root_user(user_match.group(1))
                    )

        if _is_container_file(name):
            state = self._observe_dockerfile(file_path, lines)
            self.dockerfiles[file_path] = state
            self.production_start = self.production_start or state.final_has_start

        if name == "procfile":
            self.production_start = self.production_start or any(
                re.match(r"^\s*web\s*:\s*\S", line, re.IGNORECASE)
                for line in lines
            )

        self._observe_manifest(file_path, name, lowered, lines, text)
        self._observe_source(file_path, lowered, name, lines)

    def _observe_dockerfile(self, file_path: str, lines: list[str]) -> _DockerState:
        state = _DockerState(path=file_path)
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            from_match = re.match(r"^FROM\s+(.+)$", stripped, re.IGNORECASE)
            if from_match:
                remainder = from_match.group(1).strip()
                tokens = [token for token in remainder.split() if not token.startswith("--")]
                state.has_from = bool(tokens)
                state.final_base = tokens[0] if tokens else None
                state.final_has_start = False
                state.final_user = None
                continue
            if re.match(r"^(?:CMD|ENTRYPOINT)\s+", stripped, re.IGNORECASE):
                state.final_has_start = True
            user_match = re.match(r"^USER\s+(.+)$", stripped, re.IGNORECASE)
            if user_match:
                state.final_user = user_match.group(1).strip()
        return state

    def _observe_manifest(
        self, file_path: str, name: str, lowered: str,
        lines: list[str], text: str,
    ) -> None:
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            valid = self._parse_json(file_path, text) is not None
            if valid:
                self.dependencies["node"].locked = True
                self.lock_dirs.add(str(PurePosixPath(file_path).parent))
        elif name in _NODE_LOCKS:
            self.dependencies["node"].locked = True
            self.lock_dirs.add(str(PurePosixPath(file_path).parent))
        if name == "pipfile.lock":
            valid = self._parse_json(file_path, text) is not None
            self.dependencies["python"].locked = self.dependencies["python"].locked or valid
        elif name in {"poetry.lock", "uv.lock", "pdm.lock"}:
            valid = self._parse_toml(file_path, text) is not None
            self.dependencies["python"].locked = self.dependencies["python"].locked or valid
        if name == "go.sum":
            self.dependencies["go"].locked = True
        if name == "cargo.lock":
            valid = self._parse_toml(file_path, text) is not None
            self.dependencies["rust"].locked = self.dependencies["rust"].locked or valid
        if name == "gemfile.lock":
            self.dependencies["ruby"].locked = True
        if name == "composer.lock":
            valid = self._parse_json(file_path, text) is not None
            self.dependencies["php"].locked = self.dependencies["php"].locked or valid
        if name == "packages.lock.json":
            valid = self._parse_json(file_path, text) is not None
            self.dependencies["dotnet"].locked = self.dependencies["dotnet"].locked or valid
        if name in {"mvnw", "mvnw.cmd"}:
            self.maven_wrapper_script = True
        if lowered == ".mvn/wrapper/maven-wrapper.properties" or lowered.endswith(
            "/.mvn/wrapper/maven-wrapper.properties"
        ):
            self.maven_wrapper_config = True
        if name in {"gradlew", "gradlew.bat"}:
            self.gradle_wrapper_script = True
        if lowered == "gradle/wrapper/gradle-wrapper.properties" or lowered.endswith(
            "/gradle/wrapper/gradle-wrapper.properties"
        ):
            self.gradle_wrapper_config = True

        if name == "package.json":
            state = self.dependencies["node"]
            state.manifests.add(file_path)
            data = self._parse_json(file_path, text)
            if data is not None:
                has_deps = any(
                    _has_mapping_entries(data.get(key))
                    for key in ("dependencies", "devDependencies", "peerDependencies")
                )
                state.manifest_deps[file_path] = has_deps
                state.has_dependencies = state.has_dependencies or has_deps
                scripts = data.get("scripts")
                start = scripts.get("start") if isinstance(scripts, dict) else None
                if isinstance(start, str) and start.strip() and not _DEV_START_RE.search(start):
                    self.production_start = True

        if name == "pyproject.toml":
            state = self.dependencies["python"]
            state.manifests.add(file_path)
            data = self._parse_toml(file_path, text)
            if data is not None:
                project = data.get("project")
                poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
                project_deps = project.get("dependencies") if isinstance(project, dict) else None
                poetry_deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
                state.has_dependencies = state.has_dependencies or bool(project_deps) or (
                    isinstance(poetry_deps, dict)
                    and any(key.lower() != "python" for key in poetry_deps)
                )

        if name == "pipfile":
            state = self.dependencies["python"]
            state.manifests.add(file_path)
            data = self._parse_toml(file_path, text)
            if data is not None:
                state.has_dependencies = state.has_dependencies or any(
                    _has_mapping_entries(data.get(key))
                    for key in ("packages", "dev-packages")
                )

        if name.startswith("requirements") and name.endswith(".txt"):
            state = self.dependencies["python"]
            state.manifests.add(file_path)
            active = [
                line.strip() for line in lines
                if line.strip() and not line.lstrip().startswith(("#", "-"))
            ]
            if active:
                self.python_requirements_seen = True
                state.has_dependencies = True
                self.python_requirements_all_pinned = (
                    self.python_requirements_all_pinned
                    and all(_REQUIREMENT_PIN_RE.match(line) for line in active)
                )

        if name == "go.mod":
            state = self.dependencies["go"]
            state.manifests.add(file_path)
            state.has_dependencies = state.has_dependencies or bool(
                re.search(r"(?m)^\s*require(?:\s|\()", text)
            )

        if name == "cargo.toml":
            state = self.dependencies["rust"]
            state.manifests.add(file_path)
            data = self._parse_toml(file_path, text)
            if data is not None:
                state.has_dependencies = state.has_dependencies or any(
                    _has_mapping_entries(data.get(key))
                    for key in ("dependencies", "dev-dependencies", "build-dependencies")
                )
                self.rust_application = self.rust_application or bool(data.get("bin"))

        if name == "gemfile":
            state = self.dependencies["ruby"]
            state.manifests.add(file_path)
            state.has_dependencies = state.has_dependencies or bool(
                re.search(r"(?m)^\s*gem\s+['\"]", text)
            )

        if name == "composer.json":
            state = self.dependencies["php"]
            state.manifests.add(file_path)
            data = self._parse_json(file_path, text)
            if data is not None:
                state.has_dependencies = state.has_dependencies or any(
                    _has_mapping_entries(data.get(key))
                    for key in ("require", "require-dev")
                )

        if name == "pom.xml":
            state = self.dependencies["maven"]
            state.manifests.add(file_path)
            root = self._parse_xml(file_path, text)
            if root is not None:
                state.has_dependencies = state.has_dependencies or any(
                    _local_name(element.tag) == "dependency" for element in root.iter()
                )

        if name in {"build.gradle", "build.gradle.kts"}:
            state = self.dependencies["gradle"]
            state.manifests.add(file_path)
            state.has_dependencies = state.has_dependencies or bool(
                re.search(
                    r"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?",
                    text,
                )
            )

        if name.endswith((".csproj", ".fsproj", ".vbproj")):
            state = self.dependencies["dotnet"]
            state.manifests.add(file_path)
            root = self._parse_xml(file_path, text)
            if root is not None:
                references = [
                    element for element in root.iter()
                    if _local_name(element.tag) == "PackageReference"
                ]
                if references:
                    state.has_dependencies = True
                for reference in references:
                    version = reference.attrib.get("Version")
                    if version is None:
                        version_element = next(
                            (
                                child for child in reference
                                if _local_name(child.tag) == "Version"
                            ),
                            None,
                        )
                        version = version_element.text if version_element is not None else None
                    if not isinstance(version, str) or not _EXACT_DOTNET_VERSION_RE.match(version.strip()):
                        self.dotnet_all_exact = False

    def _observe_source(
        self, file_path: str, lowered: str, name: str, lines: list[str]
    ) -> None:
        if _is_excluded_path(file_path):
            return
        if lowered.endswith("/src/main.rs") or lowered == "src/main.rs":
            self.rust_application = True
            self.production_start = True
        if name == "config.ru" or lowered.endswith("/bin/rails"):
            self.production_start = True
        if (
            name == "artisan" or lowered == "public/index.php" or lowered.endswith(("/public/index.php", "/bin/console")) or lowered == "bin/console"
        ):
            self.production_start = True
        if name.lower() == "program.cs":
            self.production_start = True

        if not is_incomplete_source_file(file_path):
            return
        code = "\n".join(_code_lines(file_path, lines))
        if any(pattern.search(code) for pattern in _ENV_USAGE_PATTERNS):
            self.env_usage_paths.add(file_path)
        suffix = PurePosixPath(file_path).suffix.lower()
        if suffix == ".go" and "package main" in code and _GO_MAIN_RE.search(code):
            self.production_start = True
        if suffix == ".java" and _JAVA_MAIN_RE.search(code):
            self.production_start = True
        if suffix in {".kt", ".kts"} and _KOTLIN_MAIN_RE.search(code):
            self.production_start = True

    def _parse_json(self, file_path: str, text: str) -> dict[str, Any] | None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeError):
            self.invalid_configs.add(file_path)
            return None
        if not isinstance(data, dict):
            self.invalid_configs.add(file_path)
            return None
        return data

    def _parse_toml(self, file_path: str, text: str) -> dict[str, Any] | None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            self.invalid_configs.add(file_path)
            return None

    def _parse_xml(self, file_path: str, text: str) -> ET.Element | None:
        try:
            return ET.fromstring(text)
        except ET.ParseError:
            self.invalid_configs.add(file_path)
            return None

    def finalize(self) -> list[Finding]:
        findings: list[Finding] = []
        docker_start = self.compose_has_start or any(
            state.final_has_start for state in self.dockerfiles.values()
        )
        deployment_documented = (
            self.readme_paths
            and self.readme_has_deploy_text
            and self.readme_has_deploy_command
            and self.readme_has_prerequisites
        )
        # A fully documented deployment procedure IS the reproducible
        # production start for platform-managed projects (serverless,
        # WeChat cloud functions, etc.), where there is no process to
        # launch. Only require an explicit start entrypoint when no
        # deployment documentation exists.
        if not (self.production_start or docker_start or deployment_documented):
            findings.append(_finding("D001_PRODUCTION_START", _REPOSITORY_PATH))
        if self.env_usage_paths and not self.has_env_docs:
            findings.append(_finding(
                "D002_ENVIRONMENT_DOCUMENTATION", min(self.env_usage_paths)
            ))

        self.dependencies["python"].locked = (
            self.dependencies["python"].locked
            or (self.python_requirements_seen and self.python_requirements_all_pinned)
        )
        self.dependencies["rust"].locked = (
            self.dependencies["rust"].locked or not self.rust_application
        )
        self.dependencies["maven"].locked = (
            self.maven_wrapper_script and self.maven_wrapper_config
        )
        self.dependencies["gradle"].locked = (
            self.gradle_wrapper_script and self.gradle_wrapper_config
        )
        self.dependencies["dotnet"].locked = (
            self.dependencies["dotnet"].locked or self.dotnet_all_exact
        )
        for key in sorted(self.dependencies):
            dep_state = self.dependencies[key]
            if key == "node":
                # Per-manifest nearest-lock detection: multi-manifest
                # repos (monorepos, cloud function directories) need a
                # lock next to EACH manifest, so report every unlocked
                # manifest instead of a single min() sample.
                for manifest, has_deps in sorted(dep_state.manifest_deps.items()):
                    if not has_deps:
                        continue
                    if str(PurePosixPath(manifest).parent) in self.lock_dirs:
                        continue
                    findings.append(_finding("D003_DEPENDENCY_LOCK", manifest))
                continue
            if dep_state.has_dependencies and not dep_state.locked:
                findings.append(_finding("D003_DEPENDENCY_LOCK", min(dep_state.manifests)))

        if not (
            self.readme_paths
            and self.readme_has_deploy_text
            and self.readme_has_deploy_command
            and self.readme_has_prerequisites
        ):
            path = min(self.readme_paths) if self.readme_paths else _REPOSITORY_PATH
            findings.append(_finding("D004_DEPLOYMENT_DOCUMENTATION", path))

        if not self.dockerfiles and not self.has_compose:
            findings.append(_finding("D005_DOCKER_MISSING", _REPOSITORY_PATH))

        for path in sorted(self.dockerfiles):
            docker_state = self.dockerfiles[path]
            if not docker_state.has_from:
                findings.append(_finding("D006_DOCKER_MISSING_FROM", path))
                continue
            if _is_mutable_base(docker_state.final_base):
                findings.append(_finding("D007_DOCKER_MUTABLE_BASE", path))
            if (
                _is_root_user(docker_state.final_user)
                or self.compose_root_user
                or not (
                    _is_non_root_user(docker_state.final_user)
                    or self.compose_non_root_user
                )
            ):
                findings.append(_finding("D008_DOCKER_ROOT_USER", path))
            if not (docker_state.final_has_start or self.compose_has_start):
                findings.append(_finding("D009_DOCKER_MISSING_START", path))

        if self.has_compose and not self.dockerfiles:
            compose_path = min(self.compose_paths)
            if self.compose_root_user or not self.compose_non_root_user:
                findings.append(_finding("D008_DOCKER_ROOT_USER", compose_path))
            if not self.compose_has_start:
                findings.append(_finding("D009_DOCKER_MISSING_START", compose_path))

        findings.extend(
            _finding("D010_INVALID_DEPLOYMENT_CONFIG", path)
            for path in sorted(self.invalid_configs)
        )
        return findings


class DeployabilityRule(Rule):
    """Registry entry that creates isolated deployability probes."""

    rule_id = "D000_DEPLOYABILITY_REPOSITORY"
    rule_name = "Deployability repository checks"
    finding_type = FindingType.FILE
    dimension = DEPLOYABILITY_PRODUCTION_DIMENSION

    def create_repository_probe(self) -> RepositoryProbe:
        return DeployabilityProbe()
