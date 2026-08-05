"""Repository-level tests for the deployability production dimension."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.scanner.base import DEPLOYABILITY_PRODUCTION_DIMENSION
from app.scanner.sensitive import scan_directory
from app.services.scan_result_service import serialize_scan_result


def _write_repo(tmp_path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _findings(tmp_path):
    return [
        finding for finding in scan_directory(tmp_path).findings
        if finding.dimension == DEPLOYABILITY_PRODUCTION_DIMENSION
    ]


def _rule_ids(tmp_path):
    return [finding.rule_id for finding in _findings(tmp_path)]


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("package.json", '{"scripts":{"start":"node server.js"}}'),
        ("Procfile", "web: bundle exec puma -C config/puma.rb\n"),
        ("src/main.go", "package main\nfunc main() {}\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("src/App.java", "class App { public static void main(String[] args) {} }\n"),
        ("src/App.kt", "fun main() { println(\"ok\") }\n"),
        ("config.ru", "run App\n"),
        ("public/index.php", "<?php echo 'ok';\n"),
        ("Program.cs", "Console.WriteLine(\"ok\");\n"),
    ),
)
def test_production_start_entrypoints_are_recognized(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    assert "D001_PRODUCTION_START" not in _rule_ids(tmp_path)


def test_dev_only_node_start_is_not_a_production_entrypoint(tmp_path):
    _write_repo(tmp_path, {"package.json": '{"scripts":{"start":"vite"}}'})
    assert "D001_PRODUCTION_START" in _rule_ids(tmp_path)


def test_test_and_fixture_entrypoints_do_not_satisfy_production_start(tmp_path):
    _write_repo(tmp_path, {
        "tests/main.go": "package main\nfunc main() {}\n",
        "fixtures/Program.cs": "Console.WriteLine(\"ok\");\n",
    })
    assert "D001_PRODUCTION_START" in _rule_ids(tmp_path)


def test_environment_usage_requires_template_or_readme_documentation(tmp_path):
    _write_repo(tmp_path, {"src/app.ts": "const port = process.env.PORT;\n"})
    assert "D002_ENVIRONMENT_DOCUMENTATION" in _rule_ids(tmp_path)

    _write_repo(tmp_path, {".env.example": "PORT=\n"})
    assert "D002_ENVIRONMENT_DOCUMENTATION" not in _rule_ids(tmp_path)


def test_environment_strings_comments_and_tests_are_not_usage(tmp_path):
    _write_repo(tmp_path, {
        "src/app.py": "# os.getenv('TOKEN')\ntext = \"process.env.PORT\"\n",
        "tests/app.py": "value = os.getenv('TEST_VALUE')\n",
    })
    assert "D002_ENVIRONMENT_DOCUMENTATION" not in _rule_ids(tmp_path)


def test_config_example_template_directory_satisfies_environment_docs(tmp_path):
    _write_repo(tmp_path, {
        "src/app.ts": "const value = process.env.APP_SECRET;\n",
        "config.example/app-config.json": "{\"key\": \"在此填入\"}\n",
    })
    assert "D002_ENVIRONMENT_DOCUMENTATION" not in _rule_ids(tmp_path)


def test_multiple_node_manifests_each_require_their_own_lock(tmp_path):
    _write_repo(tmp_path, {
        "services/a/package.json": '{"dependencies":{"express":"^5.0.0"}}',
        "services/b/package.json": '{"dependencies":{"lodash":"^4.0.0"}}',
        "services/c/package.json": '{"name":"empty"}',
    })
    d003 = [
        finding.file_path for finding in _findings(tmp_path)
        if finding.rule_id == "D003_DEPENDENCY_LOCK"
    ]
    assert d003 == ["services/a/package.json", "services/b/package.json"]

    _write_repo(tmp_path, {"services/a/package-lock.json": "{}"})
    d003 = [
        finding.file_path for finding in _findings(tmp_path)
        if finding.rule_id == "D003_DEPENDENCY_LOCK"
    ]
    assert d003 == ["services/b/package.json"]


def test_serverless_deployment_readme_counts_as_production_start(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            "# 项目\n## 运行环境\nNode.js 12+。\n"
            "## 环境变量\n见 config.example 目录。\n"
            "## 快速开始\n云函数目录右键「上传并部署：云端安装依赖」。\n"
        ),
        "cloudfunctions/api/index.js": "const port = process.env.PORT;\n",
    })
    ids = _rule_ids(tmp_path)
    assert "D001_PRODUCTION_START" not in ids
    assert "D004_DEPLOYMENT_DOCUMENTATION" not in ids
    assert "D002_ENVIRONMENT_DOCUMENTATION" not in ids


@pytest.mark.parametrize(
    "content",
    (
        'const value = process.env["PORT"];\n',
        'var value = Environment.GetEnvironmentVariable("PORT");\n',
    ),
)
def test_environment_usage_variants_are_recognized(tmp_path, content):
    _write_repo(tmp_path, {"src/app.cs": content})
    assert "D002_ENVIRONMENT_DOCUMENTATION" in _rule_ids(tmp_path)


def test_case_insensitive_configuration_paths_and_crlf_are_supported(tmp_path):
    _write_repo(tmp_path, {
        "README.TXT": (
            "# PRODUCTION\r\nREQUIREMENTS: Node.js 20.\r\n"
            "Run `NPM START`.\r\nEnvironment variables are documented below.\r\n"
        ),
        ".ENV.SAMPLE": "PORT=\r\n",
        "DOCKERFILE.PRODUCTION": (
            "from NODE:20.18.0\r\nuser 10001\r\ncmd [\"node\",\"server.js\"]\r\n"
        ),
        "src/app.js": "const port = process.env.PORT;\r\n",
    })
    ids = _rule_ids(tmp_path)
    assert not ids


@pytest.mark.parametrize(
    ("files", "manifest_path", "lock_files"),
    (
        (
            {"package.json": '{"dependencies":{"express":"^5.0.0"}}'},
            "package.json", {"package-lock.json": "{}"},
        ),
        (
            {"pyproject.toml": '[project]\ndependencies=["fastapi>=1"]\n'},
            "pyproject.toml", {"uv.lock": "version = 1\n"},
        ),
        (
            {"go.mod": "module example\nrequire example.com/lib v1.0.0\n"},
            "go.mod", {"go.sum": "example.com/lib v1.0.0 h1:test\n"},
        ),
        (
            {"Cargo.toml": '[package]\nname="app"\n[[bin]]\nname="app"\n[dependencies]\nserde="1"\n'},
            "Cargo.toml", {"Cargo.lock": "version = 3\n"},
        ),
        (
            {"pom.xml": "<project><dependencies><dependency/></dependencies></project>"},
            "pom.xml", {"mvnw": "", ".mvn/wrapper/maven-wrapper.properties": "distributionUrl=x\n"},
        ),
        (
            {"build.gradle": "dependencies {\n implementation('org.example:lib:1.0')\n}\n"},
            "build.gradle", {"gradlew": "", "gradle/wrapper/gradle-wrapper.properties": "distributionUrl=x\n"},
        ),
        (
            {"Gemfile": "gem 'rack'\n"},
            "Gemfile", {"Gemfile.lock": "GEM\n"},
        ),
        (
            {"composer.json": '{"require":{"php":"^8.3","symfony/console":"^7"}}'},
            "composer.json", {"composer.lock": "{}"},
        ),
        (
            {"App.csproj": '<Project><ItemGroup><PackageReference Include="X" Version="[1,2)" /></ItemGroup></Project>'},
            "App.csproj", {"packages.lock.json": "{}"},
        ),
    ),
)
def test_dependency_ecosystems_require_and_accept_reproducibility_controls(
    tmp_path, files, manifest_path, lock_files
):
    _write_repo(tmp_path, files)
    missing = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "D003_DEPENDENCY_LOCK"
        and finding.file_path == manifest_path
    ]
    assert len(missing) == 1

    _write_repo(tmp_path, lock_files)
    assert not any(
        finding.rule_id == "D003_DEPENDENCY_LOCK"
        and finding.file_path == manifest_path
        for finding in _findings(tmp_path)
    )


def test_exact_python_requirements_and_dotnet_versions_do_not_need_lock(tmp_path):
    _write_repo(tmp_path, {
        "requirements.txt": "fastapi==0.116.1\nuvicorn==0.35.0\n",
        "App.csproj": '<Project><ItemGroup><PackageReference Include="X" Version="1.2.3" /></ItemGroup></Project>',
    })
    assert "D003_DEPENDENCY_LOCK" not in _rule_ids(tmp_path)


def test_library_manifest_is_still_checked_as_deployable_project(tmp_path):
    _write_repo(tmp_path, {"package.json": '{"name":"library","dependencies":{"x":"1"}}'})
    ids = _rule_ids(tmp_path)
    assert "D001_PRODUCTION_START" in ids
    assert "D003_DEPENDENCY_LOCK" in ids
    assert "D005_DOCKER_MISSING" in ids


def test_deployment_readme_requires_context_and_command(tmp_path):
    _write_repo(tmp_path, {
        "README.md": "# Production\nPrerequisites: Node.js 20.\nRun `npm start`.\n"
    })
    assert "D004_DEPLOYMENT_DOCUMENTATION" not in _rule_ids(tmp_path)

    _write_repo(tmp_path, {"README.md": "# Production\nRun `npm start`.\n"})
    assert "D004_DEPLOYMENT_DOCUMENTATION" in _rule_ids(tmp_path)


def test_missing_docker_is_a_low_non_blocking_finding(tmp_path):
    _write_repo(tmp_path, {"README.md": "# Project\n"})
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "D005_DOCKER_MISSING"
    ]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert findings[0].is_blocking is False


def test_valid_multistage_dockerfile_has_no_docker_configuration_findings(tmp_path):
    _write_repo(tmp_path, {
        "Dockerfile": (
            "FROM node:20.18.0 AS build\r\nRUN npm run build\r\n"
            "FROM node:20.18.0\r\nUSER 10001\r\nCMD [\"node\",\"server.js\"]\r\n"
        )
    })
    ids = _rule_ids(tmp_path)
    assert not any(rule_id.startswith("D00") and rule_id in {
        "D006_DOCKER_MISSING_FROM", "D007_DOCKER_MUTABLE_BASE",
        "D008_DOCKER_ROOT_USER", "D009_DOCKER_MISSING_START",
    } for rule_id in ids)
    assert "D005_DOCKER_MISSING" not in ids


def test_containerfile_and_compose_variants_are_recognized(tmp_path):
    _write_repo(tmp_path, {
        "Containerfile.production": "FROM python:3.12.4\nUSER 10001\nCMD [\"app\"]\n",
        "docker-compose.production.yml": "services:\n  app:\n    command:\n      - gunicorn\n      - app:app\n    user: '10001'\n",
    })
    ids = _rule_ids(tmp_path)
    assert "D001_PRODUCTION_START" not in ids
    assert "D005_DOCKER_MISSING" not in ids
    assert "D008_DOCKER_ROOT_USER" not in ids
    assert "D009_DOCKER_MISSING_START" not in ids


def test_deployment_files_in_fixture_directories_are_ignored(tmp_path):
    _write_repo(tmp_path, {
        "fixtures/package.json": "{invalid",
        "examples/Dockerfile": "FROM node:latest\nUSER root\n",
        "docs/README.md": "# Production\nRequirements: Node 20.\nRun npm start.\n",
    })
    ids = _rule_ids(tmp_path)
    assert "D010_INVALID_DEPLOYMENT_CONFIG" not in ids
    assert "D007_DOCKER_MUTABLE_BASE" not in ids
    assert "D004_DEPLOYMENT_DOCUMENTATION" in ids


def test_dockerfile_configuration_failures_are_reported(tmp_path):
    _write_repo(tmp_path, {"Dockerfile.production": "FROM node:latest\nUSER root\n"})
    ids = _rule_ids(tmp_path)
    assert "D007_DOCKER_MUTABLE_BASE" in ids
    assert "D008_DOCKER_ROOT_USER" in ids
    assert "D009_DOCKER_MISSING_START" in ids

    _write_repo(tmp_path, {"Dockerfile.production": "RUN echo invalid\n"})
    assert "D006_DOCKER_MISSING_FROM" in _rule_ids(tmp_path)


@pytest.mark.parametrize("base", ("scratch", "node:20.18.0", "node@sha256:abc", "${BASE_IMAGE}"))
def test_immutable_or_unresolved_docker_bases_are_not_reported(tmp_path, base):
    _write_repo(tmp_path, {
        "Dockerfile": f"FROM {base}\nUSER 10001\nCMD [\"app\"]\n"
    })
    assert "D007_DOCKER_MUTABLE_BASE" not in _rule_ids(tmp_path)


def test_compose_command_and_user_satisfy_docker_runtime_checks(tmp_path):
    _write_repo(tmp_path, {
        "Dockerfile": "FROM python:3.12.4\n",
        "compose.yaml": "services:\n  app:\n    build: .\n    user: '10001'\n    command: gunicorn app:app\n",
    })
    ids = _rule_ids(tmp_path)
    assert "D008_DOCKER_ROOT_USER" not in ids
    assert "D009_DOCKER_MISSING_START" not in ids
    assert "D001_PRODUCTION_START" not in ids


def test_compose_only_configuration_requires_user_and_start(tmp_path):
    _write_repo(tmp_path, {
        "compose.yaml": "services:\n  app:\n    image: example/app:1.0\n",
    })
    ids = _rule_ids(tmp_path)
    assert "D005_DOCKER_MISSING" not in ids
    assert "D008_DOCKER_ROOT_USER" in ids
    assert "D009_DOCKER_MISSING_START" in ids


def test_explicit_root_or_variable_user_is_not_treated_as_non_root(tmp_path):
    _write_repo(tmp_path, {
        "Dockerfile": "FROM python:3.12.4\nUSER root\nCMD [\"app\"]\n",
        "compose.yaml": "services:\n  app:\n    user: '10001'\n    command: app\n",
    })
    assert "D008_DOCKER_ROOT_USER" in _rule_ids(tmp_path)

    _write_repo(tmp_path, {
        "Dockerfile": "FROM python:3.12.4\nUSER ${APP_USER}\nCMD [\"app\"]\n",
        "compose.yaml": "services:\n  app:\n    command: app\n",
    })
    assert "D008_DOCKER_ROOT_USER" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("package.json", "{not-json"),
        ("pyproject.toml", "[project\ninvalid"),
        ("pom.xml", "<project>"),
    ),
)
def test_invalid_supported_manifests_use_fixed_findings(tmp_path, path, content):
    _write_repo(tmp_path, {path: content})
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "D010_INVALID_DEPLOYMENT_CONFIG"
    ]
    assert len(findings) == 1
    assert findings[0].file_path == path
    assert content not in findings[0].description
    assert content not in findings[0].message


@pytest.mark.parametrize(
    "path",
    ("package-lock.json", "Pipfile.lock", "Cargo.lock", "composer.lock", "packages.lock.json"),
)
def test_invalid_supported_lock_files_are_not_accepted(tmp_path, path):
    manifest_files = {
        "package-lock.json": {"package.json": '{"dependencies":{"x":"1"}}'},
        "Pipfile.lock": {"Pipfile": '[packages]\nfastapi="*"\n'},
        "Cargo.lock": {"Cargo.toml": '[package]\nname="app"\n[[bin]]\nname="app"\n[dependencies]\nserde="1"\n'},
        "composer.lock": {"composer.json": '{"require":{"x/y":"1"}}'},
        "packages.lock.json": {"App.csproj": '<Project><ItemGroup><PackageReference Include="X" Version="[1,2)" /></ItemGroup></Project>'},
    }
    _write_repo(tmp_path, {**manifest_files[path], path: "{invalid"})
    ids = _rule_ids(tmp_path)
    assert "D010_INVALID_DEPLOYMENT_CONFIG" in ids
    assert "D003_DEPENDENCY_LOCK" in ids


def test_deployability_results_are_deterministic_non_blocking_and_masked(tmp_path):
    token = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2"
    _write_repo(tmp_path, {f"{token}.json": "{}", "package.json": "{invalid"})
    first = scan_directory(tmp_path)
    second = scan_directory(tmp_path)
    assert first == second
    deployability = [
        finding for finding in first.findings
        if finding.dimension == DEPLOYABILITY_PRODUCTION_DIMENSION
    ]
    assert deployability
    assert all(not finding.is_blocking for finding in deployability)
    serialized = json.dumps(serialize_scan_result(first))
    assert token not in serialized


def test_repository_probe_state_is_isolated_between_concurrent_scans(tmp_path):
    configured = tmp_path / "configured"
    missing = tmp_path / "missing"
    configured.mkdir()
    missing.mkdir()
    _write_repo(configured, {
        "README.md": (
            "# Production\nPrerequisites: Docker 24 or newer.\n"
            "Run `docker compose up`.\n"
        ),
        "Dockerfile": "FROM python:3.12.4\nUSER 10001\nCMD [\"app\"]\n",
    })

    with ThreadPoolExecutor(max_workers=2) as executor:
        configured_future = executor.submit(scan_directory, configured)
        missing_future = executor.submit(scan_directory, missing)
    configured_ids = {
        finding.rule_id for finding in configured_future.result().findings
        if finding.dimension == DEPLOYABILITY_PRODUCTION_DIMENSION
    }
    missing_ids = {
        finding.rule_id for finding in missing_future.result().findings
        if finding.dimension == DEPLOYABILITY_PRODUCTION_DIMENSION
    }
    assert not configured_ids & {
        "D001_PRODUCTION_START",
        "D004_DEPLOYMENT_DOCUMENTATION",
        "D005_DOCKER_MISSING",
    }
    assert {
        "D001_PRODUCTION_START",
        "D004_DEPLOYMENT_DOCUMENTATION",
        "D005_DOCKER_MISSING",
    } <= missing_ids
