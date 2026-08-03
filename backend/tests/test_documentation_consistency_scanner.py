"""High-confidence boundaries for the documentation-consistency dimension."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.scanner.base import DOCUMENTATION_CONSISTENCY_DIMENSION
from app.scanner.sensitive import scan_directory


def _write_repo(tmp_path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _findings(tmp_path):
    return [
        finding for finding in scan_directory(tmp_path).findings
        if finding.dimension == DOCUMENTATION_CONSISTENCY_DIMENSION
    ]


def _rule_ids(tmp_path):
    return [finding.rule_id for finding in _findings(tmp_path)]


def _long_intro() -> str:
    return (
        "This repository contains a production application with documented "
        "installation, configuration, operation, maintenance, and support guidance. "
    )


def test_missing_and_short_readme_are_reported(tmp_path):
    _write_repo(tmp_path, {"app.py": "print('ok')\n"})
    finding = next(
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C001_README_COMPLETENESS"
    )
    assert finding.file_path == "<repository>"

    _write_repo(tmp_path, {"README.md": "# Tiny\n"})
    finding = next(
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C001_README_COMPLETENESS"
    )
    assert finding.file_path == "README.md"


def test_complete_readme_is_accepted(tmp_path):
    _write_repo(tmp_path, {"README.md": f"# Application\n\n{_long_intro()}\n"})
    assert "C001_README_COMPLETENESS" not in _rule_ids(tmp_path)


def test_code_badges_urls_and_markup_do_not_inflate_prose(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            "# App\n![badge](https://example.com/badge.svg)\n"
            "```text\n" + ("generated code " * 40) + "\n```\n"
            "https://example.com/" + ("x" * 200) + "\n"
        ),
    })
    assert "C001_README_COMPLETENESS" in _rule_ids(tmp_path)


def test_rst_code_blocks_do_not_inflate_prose(tmp_path):
    _write_repo(tmp_path, {
        "README.rst": (
            "App\n===\n\nShort.\n\n.. code-block:: text\n\n"
            "   " + ("generated code " * 40) + "\n"
        ),
    })
    assert "C001_README_COMPLETENESS" in _rule_ids(tmp_path)


def test_primary_readme_priority_is_deterministic_and_case_insensitive(tmp_path):
    _write_repo(tmp_path, {
        "README.RST": "Application\n===========\n" + (_long_intro() * 2),
        "ReadMe.MD": "# Short\n",
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C001_README_COMPLETENESS"
    ]
    assert len(findings) == 1
    assert findings[0].file_path == "ReadMe.MD"


@pytest.mark.parametrize(
    "wrapper",
    ("owner-project-7fd1a60", "project-main", "project-v1.0.0"),
)
def test_archive_wrapper_is_treated_as_repository_root(tmp_path, wrapper):
    _write_repo(tmp_path, {
        f"{wrapper}/README.md": (
            f"# App\n\n{_long_intro()}\n"
            "## Quick Start\n```sh\ncd frontend && npm run start\n```\n"
            "## Project Structure\n```text\n"
            "├── backend/\n│   └── app.py\n"
            "└── frontend/\n    └── package.json\n```\n"
        ),
        f"{wrapper}/backend/app.py": "print('ok')\n",
        f"{wrapper}/frontend/package.json": '{"scripts":{"start":"next start"}}',
    })
    ids = _rule_ids(tmp_path)
    assert "C001_README_COMPLETENESS" not in ids
    assert "C003_START_COMMAND_MISMATCH" not in ids
    assert "C004_PROJECT_STRUCTURE_MISMATCH" not in ids


def test_nested_docs_readme_is_not_mistaken_for_repository_root(tmp_path):
    _write_repo(tmp_path, {
        "docs/README.md": f"# Docs\n\n{_long_intro()}\n",
        "docs/guide.md": "Guide\n",
    })
    finding = next(
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C001_README_COMPLETENESS"
    )
    assert finding.file_path == "<repository>"


@pytest.mark.parametrize(
    ("technology", "manifest", "missing"),
    (
        ("React", '{"dependencies":{"react":"19.0.0"}}', False),
        ("Vue.js", '{"dependencies":{"vue":"3.5.0"}}', False),
        ("Next.js", '{"dependencies":{"next":"16.0.0"}}', False),
        ("React", '{"dependencies":{"vue":"3.5.0"}}', True),
    ),
)
def test_node_technology_matches_valid_manifest(
    tmp_path, technology, manifest, missing,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Tech Stack\n- {technology}\n",
        "package.json": manifest,
    })
    assert ("C002_TECH_STACK_MISMATCH" in _rule_ids(tmp_path)) is missing


@pytest.mark.parametrize(
    ("technology", "manifest_path", "manifest"),
    (
        ("FastAPI", "requirements.txt", "fastapi==0.116.1\n"),
        ("Flask", "pyproject.toml", '[project]\ndependencies=["Flask==3.1.0"]\n'),
        ("Django", "Pipfile", '[packages]\nDjango="==5.2"\n'),
    ),
)
def test_python_technology_matches_supported_manifests(
    tmp_path, technology, manifest_path, manifest,
):
    _write_repo(tmp_path, {
        "README.rst": (
            "Application\n===========\n" + _long_intro()
            + "\nTechnology Stack\n----------------\n* " + technology + "\n"
        ),
        manifest_path: manifest,
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_technology_outside_explicit_section_is_not_compared(tmp_path):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\nThis replaced React with another tool.\n",
        "package.json": '{"dependencies":{"vue":"3.5.0"}}',
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_absent_or_invalid_manifest_does_not_create_technology_guess(tmp_path):
    readme = f"# App\n\n{_long_intro()}\n## 技术栈\n- React\n"
    _write_repo(tmp_path, {"README.md": readme})
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)

    _write_repo(tmp_path, {"package.json": "{broken"})
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_monorepo_manifest_can_confirm_documented_technology(tmp_path):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Built With\n- React\n",
        "frontend/package.json": '{"dependencies":{"react":"19.0.0"}}',
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_repeated_technology_declaration_produces_one_finding(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Tech Stack\n- React\n- React frontend\n"
        ),
        "package.json": '{"dependencies":{"vue":"3.5.0"}}',
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C002_TECH_STACK_MISMATCH"
    ]
    assert len(findings) == 1


def test_node_script_and_working_directory_are_validated(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Quick Start\n"
            "```sh\ncd frontend && npm run start\n```\n"
        ),
        "frontend/package.json": '{"scripts":{"start":"next start"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Issue 1: workspace built-in commands are not project scripts ----

@pytest.mark.parametrize(
    "command",
    (
        "npm install --workspace web",
        "npm exec --workspace web vite",
        "yarn workspace web add react",
        "pnpm --filter web install",
    ),
)
def test_workspace_builtin_commands_are_not_treated_as_scripts(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Issue 2: -- separator stops workspace option parsing ----

@pytest.mark.parametrize(
    "command",
    (
        "npm run dev -- --workspace web",
        "npm run dev -- --filter api",
    ),
)
def test_double_dash_separator_stops_workspace_parsing(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": '{"scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Issue 3: yarn/pnpm name selectors must not fall back to directory ----

def test_yarn_workspace_name_not_found_does_not_fall_back_to_directory(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nyarn workspace web dev\n```\n"
        ),
        "web/package.json": '{"name":"different-name","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_pnpm_filter_name_not_found_does_not_fall_back_to_directory(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --filter web dev\n```\n"
        ),
        "web/package.json": '{"name":"different-name","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_pnpm_directory_selector_validates_correctly(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --filter ./packages/web dev\n```\n"
        ),
        "packages/web/package.json": '{"name":"different-name","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    _write_repo(tmp_path, {"packages/web/package.json": '{"name":"different-name","scripts":{}}'})
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Issue 4: Go command parses arguments and all packages ----

@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go build -o bin ./...", {"go.mod": "module app\n"}, False),
        ("go build -o bin ./...", {}, True),
        ("go build ./cmd/a ./cmd/b", {"cmd/a/main.go": "package main\n", "cmd/b/main.go": "package main\n"}, False),
        ("go build ./cmd/a ./cmd/b", {"cmd/a/main.go": "package main\n"}, True),
        ("go build ./cmd/...", {"go.mod": "module app\n", "cmd/main.go": "package main\n"}, False),
        ("go build ./cmd/...", {"go.mod": "module app\n"}, True),
        ("go build ./cmd/...", {"cmd/main.go": "package main\n"}, True),
    ),
)
def test_go_command_parses_arguments_and_all_packages(
    tmp_path, command, files, should_report,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


# ---- Issue 5: pnpm complex selectors must be skipped at parse stage ----

@pytest.mark.parametrize(
    "command",
    (
        'pnpm --filter web... dev',
        'pnpm --filter ...web dev',
        'pnpm --filter web^... dev',
        'pnpm --filter "./packages/*" dev',
    ),
)
def test_pnpm_complex_selectors_are_skipped(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Issue 6: multiple npm workspaces must all be validated ----

_ROOT_WORKSPACES_PKG = '{"workspaces":["packages/*"]}'


def test_multiple_npm_workspaces_all_valid(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web --workspace api\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_multiple_npm_workspaces_second_missing_script(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web --workspace api\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_multiple_npm_workspaces_first_missing_script(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web --workspace api\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_multiple_npm_workspaces_order_independence(tmp_path):
    base_readme = (
        f"# App\n\n{_long_intro()}\n## Running\n"
        "```sh\n{}\n```\n"
    )
    _write_repo(tmp_path, {
        "README.md": base_readme.format("npm run dev --workspace api --workspace web"),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspaces_flag_is_skipped_no_root_script(tmp_path):
    """--workspaces must conservatively skip; no root scripts.dev to prove no fallback."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspaces\n```\n"
        ),
        "package.json": '{"scripts":{}}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspaces_flag_is_skipped_even_with_root_script(tmp_path):
    """--workspaces must skip even when root has scripts.dev (no false positive on workspace)."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspaces\n```\n"
        ),
        "package.json": '{"scripts":{"dev":"vite"}}',
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_cd_and_npm_run_missing_reports_c003(tmp_path):
    """Separate test: cd into directory and run missing script."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Quick Start\n"
            "```sh\ncd frontend && npm run missing\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_no_workspaces_flag_is_skipped(tmp_path):
    """--no-workspaces must also conservatively skip."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --no-workspaces\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_multiline_working_directory_is_applied_to_following_commands(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Quick Start\n"
            "```sh\ncd frontend\nnpm install\nnpm run dev\n```\n"
        ),
        "frontend/package.json": '{"scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "python -m venv .venv",
        "python -m pip install -r requirements.txt",
        "python -m pytest",
        "python -m flask run",
        "python -m http.server 8000",
        "npm create vite@latest",
    ),
)
def test_installation_and_tool_commands_are_not_treated_as_project_entries(
    tmp_path, command,
):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Installation\n"
            f"```sh\n{command}\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_python_module_server_resolves_the_application_module(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npython -m uvicorn app.main:app\n```\n"
        ),
        "app/main.py": "app = object()\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_python_runnable_module_is_validated(tmp_path):
    readme = (
        f"# App\n\n{_long_intro()}\n## Running\n"
        "```sh\npython -m service\n```\n"
    )
    _write_repo(tmp_path, {
        "README.md": readme,
        "service/__main__.py": "print('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    (tmp_path / "service" / "__main__.py").unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_declared_python_tool_module_is_not_treated_as_project_entry(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npython -m customtool\n```\n"
        ),
        "requirements.txt": "customtool==1.0.0\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "npm --workspace web run dev",
        "npm --workspace=web run dev",
        "pnpm --filter web dev",
        "pnpm --filter=web dev",
        "pnpm -C web dev",
        "yarn --cwd web dev",
        "yarn workspace web dev",
        "bun --cwd web run dev",
    ),
)
def test_workspace_commands_validate_the_workspace_script(tmp_path, command):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n"
    _write_repo(tmp_path, {
        "README.md": readme,
        "package.json": '{"workspaces":["web"]}',
        "web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    _write_repo(tmp_path, {"web/package.json": '{"name":"web","scripts":{}}'})
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_unsupported_workspace_option_combination_is_skipped(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --recursive --filter web dev\n```\n"
        ),
        "web/package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_start_accepts_default_server_js_entry(tmp_path):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\nnpm start\n```\n"
    _write_repo(tmp_path, {
        "README.md": readme,
        "package.json": "{}",
        "server.js": "console.info('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    (tmp_path / "server.js").unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_restart_accepts_restart_or_start_scripts(tmp_path):
    # scripts.restart exists
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n```sh\nnpm restart\n```\n"
        ),
        "package.json": '{"scripts":{"restart":"echo restart"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    # scripts.start exists but stop does not
    _write_repo(tmp_path, {
        "package.json": '{"scripts":{"start":"node app.js"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    # server.js exists with empty package.json
    _write_repo(tmp_path, {
        "package.json": "{}",
        "server.js": "console.info('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    # No restart, no start, no server.js
    (tmp_path / "server.js").unlink(missing_ok=True)
    _write_repo(tmp_path, {
        "package.json": '{"scripts":{"stop":"echo stop"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("uvicorn --reload app.main:app", {"app/main.py": "app = object()\n"}),
        ("python -m uvicorn --reload app.main:app", {"app/main.py": "app = object()\n"}),
        ("uvicorn --app-dir src app.main:app", {"src/app/main.py": "app = object()\n"}),
        ("uvicorn app.main:app --app-dir src", {"src/app/main.py": "app = object()\n"}),
        ("gunicorn --chdir src app.main:app", {"src/app/main.py": "app = object()\n"}),
        ("uvicorn service.api:app", {"service/api/__init__.py": "app = object()\n"}),
    ),
)
def test_python_server_options_and_import_packages_resolve(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    for path in files:
        (tmp_path / path).unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "script"),
    (
        ("npm start", "start"),
        ("npm test", "test"),
        ("yarn dev", "dev"),
        ("yarn start", "start"),
        ("pnpm dev", "dev"),
        ("bun start", "start"),
    ),
)
def test_package_manager_shorthand_validates_scripts(tmp_path, command, script):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n"
    _write_repo(tmp_path, {
        "README.md": readme,
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)

    _write_repo(tmp_path, {
        "package.json": f'{{"scripts":{{"{script}":"echo ok"}}}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "yarn config set npmRegistryServer https://registry.npmjs.org",
        "yarn cache clean",
        "pnpm list",
        "pnpm store prune",
        "bun pm cache",
    ),
)
def test_package_manager_builtin_commands_are_not_treated_as_scripts(
    tmp_path, command,
):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Installation\n"
            f"```sh\n{command}\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_multiline_compose_command_resolves_explicit_file(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ndocker compose \\\n  -f deploy/production.yml up\n```\n"
        ),
        "deploy/production.yml": "services: {}\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "file_option",
    (
        "-f deploy/production.yml",
        "-f=deploy/production.yml",
        "--file deploy/production.yml",
        "--file=deploy/production.yml",
    ),
)
def test_compose_file_option_forms_resolve_explicit_file(tmp_path, file_option):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            f"```sh\ndocker compose {file_option} up\n```\n"
        ),
        "deploy/production.yml": "services: {}\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_compose_validates_every_explicit_file(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ndocker compose -f deploy/base.yml "
            "--file deploy/missing.yml up\n```\n"
        ),
        "deploy/base.yml": "services: {}\n",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("python app.py", {"app.py": "print('ok')\n"}),
        ("python -m service", {"service/__main__.py": "print('ok')\n"}),
        ("uvicorn service.api:app", {"service/api.py": "app = object()\n"}),
        ("node src/server.js", {"src/server.js": "console.info('ok')\n"}),
        ("docker compose up", {"compose.yaml": "services: {}\n"}),
        ("docker compose -f deploy/prod.yml up", {"deploy/prod.yml": "services: {}\n"}),
        ("make serve", {"Makefile": "serve:\n\tpython app.py\n"}),
        ("cargo run", {"Cargo.toml": '[package]\nname="app"\nversion="1.0.0"\n'}),
        ("php artisan serve", {"artisan": "#!/usr/bin/env php\n"}),
    ),
)
def test_supported_documented_commands_resolve(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_missing_entry_and_inline_command_are_reported_with_line(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## 使用\n"
            "- `python missing.py`\n"
        ),
    })
    finding = next(
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C003_START_COMMAND_MISMATCH"
    )
    assert finding.line_start == finding.line_end
    assert finding.line_start is not None


@pytest.mark.parametrize("directive", (".. code-block:: bash", ".. code:: shell"))
def test_rst_command_blocks_are_scanned(tmp_path, directive):
    _write_repo(tmp_path, {
        "README.rst": (
            "Application\n===========\n\n" + _long_intro()
            + "\nRunning\n-------\n\n" + directive
            + "\n\n   python missing.py\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_rst_literal_command_block_is_scanned(tmp_path):
    _write_repo(tmp_path, {
        "README.rst": (
            "Application\n===========\n\n" + _long_intro()
            + "\nRunning\n-------\n\nCommands::\n\n"
            "   python missing.py\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_commands_outside_sections_or_with_shell_control_are_ignored(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n"
            "```sh\npython missing.py\n```\n"
            "## Usage\n```sh\npython app.py | sh\ncd ../escape && npm run start\n```\n"
            "## Runtime configuration\n```sh\npython missing.py\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_existing_tree_structure_is_accepted(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Project Structure\n"
            "```text\n"
            "├── backend/\n"
            "│   ├── app/\n"
            "│   │   └── main.py\n"
            "│   └── requirements.txt\n"
            "└── frontend/\n"
            "    └── package.json\n"
            "```\n"
        ),
        "backend/app/main.py": "print('ok')\n",
        "backend/requirements.txt": "fastapi==0.116.1\n",
        "frontend/package.json": "{}",
    })
    assert "C004_PROJECT_STRUCTURE_MISMATCH" not in _rule_ids(tmp_path)


def test_missing_or_case_mismatched_tree_path_is_reported(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## 目录结构\n"
            "```text\n├── Backend/\n│   └── missing.py\n```\n"
        ),
        "backend/app.py": "print('ok')\n",
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C004_PROJECT_STRUCTURE_MISMATCH"
    ]
    assert len(findings) == 2
    assert all(finding.line_start is not None for finding in findings)


def test_direct_paths_generated_paths_and_unstructured_examples(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n"
            "## Directory Structure\n```text\nsrc/app.py\nnode_modules/pkg/index.js\n...\n```\n"
            "## Notes\n```text\nmissing/example.py\n```\n"
        ),
        "src/app.py": "print('ok')\n",
    })
    assert "C004_PROJECT_STRUCTURE_MISMATCH" not in _rule_ids(tmp_path)


def test_top_level_paths_in_structure_block_are_validated(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n"
            "## Project Structure\n```text\nmissing.py\nsrc/\n...\n```\n"
        ),
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C004_PROJECT_STRUCTURE_MISMATCH"
    ]
    assert len(findings) == 2


def test_rst_literal_structure_block_is_scanned(tmp_path):
    _write_repo(tmp_path, {
        "README.rst": (
            "Application\n===========\n\n" + _long_intro()
            + "\nProject Structure\n-----------------\n\n::\n\n"
            "   src/\n   missing.py\n"
        ),
        "src/app.py": "print('ok')\n",
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C004_PROJECT_STRUCTURE_MISMATCH"
    ]
    assert len(findings) == 1


def test_unparseable_tree_parent_does_not_reuse_previous_sibling(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Project Structure\n"
            "```text\n"
            "├── alpha/\n"
            "│   └── x.py\n"
            "├── beta dir/\n"
            "    └── y.py\n"
            "```\n"
        ),
        "alpha/x.py": "print('ok')\n",
    })
    assert "C004_PROJECT_STRUCTURE_MISMATCH" not in _rule_ids(tmp_path)


def test_standard_tree_output_infers_directory_from_child_depth(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Project Structure\n"
            "```text\n"
            "├── backend\n"
            "│   └── missing.py\n"
            "```\n"
        ),
        "backend/other.py": "print('ok')\n",
    })
    findings = [
        finding for finding in _findings(tmp_path)
        if finding.rule_id == "C004_PROJECT_STRUCTURE_MISMATCH"
    ]
    assert len(findings) == 1
    assert findings[0].line_start is not None


def test_binary_tree_paths_are_observed_without_reading_content(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Project Structure\n"
            "```text\n"
            "└── assets/\n"
            "    └── logo.png\n"
            "```\n"
        ),
    })
    logo = tmp_path / "assets" / "logo.png"
    logo.parent.mkdir(parents=True, exist_ok=True)
    logo.write_bytes(b"\x89PNG\r\n\x1a\n\x00binary")
    assert "C004_PROJECT_STRUCTURE_MISMATCH" not in _rule_ids(tmp_path)


def test_referenced_requirements_file_confirms_documented_technology(tmp_path):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Tech Stack\n- FastAPI\n",
        "requirements.txt": "-r requirements/prod.txt\n",
        "requirements/prod.txt": "fastapi==0.116.1\n",
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize("included", ("requirements/base.in", "requirements/base"))
def test_referenced_requirements_files_are_parsed_regardless_of_suffix(
    tmp_path, included,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Tech Stack\n- FastAPI\n",
        "requirements.txt": f"-r {included}\n",
        included: "fastapi==0.116.1\n",
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_safe_parent_requirements_reference_stays_inside_repository(tmp_path):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Tech Stack\n- FastAPI\n",
        "service/requirements.txt": "-r ../requirements/common.txt\n",
        "requirements/common.txt": "fastapi==0.116.1\n",
    })
    assert "C002_TECH_STACK_MISMATCH" not in _rule_ids(tmp_path)


def test_finding_limit_does_not_limit_command_or_structure_checks(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "app.scanner.documentation_rules.settings.scan_max_findings_per_rule_per_file",
        1,
    )
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n"
            "## Running\n```sh\npython app.py\npython missing.py\n```\n"
            "## Project Structure\n```text\nsrc/app.py\nmissing/path.py\n```\n"
        ),
        "app.py": "print('ok')\n",
        "src/app.py": "print('ok')\n",
    })
    ids = _rule_ids(tmp_path)
    assert ids.count("C003_START_COMMAND_MISMATCH") == 1
    assert ids.count("C004_PROJECT_STRUCTURE_MISMATCH") == 1


def test_findings_are_bounded_deterministic_and_non_blocking(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.scanner.documentation_rules.settings.scan_max_findings_per_rule_per_file",
        1,
    )
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\r\n\r\n{_long_intro()}\r\n## Project Structure\r\n"
            "```text\r\n├── missing-a/\r\n└── missing-b/\r\n```\r\n"
        ),
    })
    first = _findings(tmp_path)
    second = _findings(tmp_path)
    assert first == second
    assert sum(f.rule_id == "C004_PROJECT_STRUCTURE_MISMATCH" for f in first) == 1
    assert all(f.severity.value == "low" for f in first)
    assert all(f.confidence.value == "high" for f in first)
    assert all(not f.is_blocking for f in first)


def test_parallel_scans_do_not_share_probe_state(tmp_path):
    valid = tmp_path / "valid"
    invalid = tmp_path / "invalid"
    _write_repo(valid, {"README.md": f"# App\n\n{_long_intro()}\n"})
    _write_repo(invalid, {"app.py": "print('ok')\n"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        valid_future = executor.submit(_rule_ids, valid)
        invalid_future = executor.submit(_rule_ids, invalid)

    assert "C001_README_COMPLETENESS" not in valid_future.result()
    assert "C001_README_COMPLETENESS" in invalid_future.result()


def test_repository_derived_text_never_enters_finding_payload(tmp_path):
    marker = "private-documentation-marker-1234567890"
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Project Structure\n"
            f"```text\n└── {marker}/\n```\n"
        ),
    })
    findings = _findings(tmp_path)
    assert "C004_PROJECT_STRUCTURE_MISMATCH" in [f.rule_id for f in findings]
    for finding in findings:
        payload = " ".join(
            str(value) for value in (
                finding.file_path, finding.snippet_masked, finding.description,
                finding.message, finding.category, finding.repair_template_key,
            )
        )
        assert marker not in payload


@pytest.mark.parametrize(
    ("command", "package_dir", "package_json"),
    (
        ("pnpm --filter web dev", "packages/web", '{"name":"web","scripts":{"dev":"vite"}}'),
        ("yarn workspace @acme/web dev", "packages/web", '{"name":"@acme/web","scripts":{"dev":"vite"}}'),
        ("npm --workspace web run dev", "packages/web", '{"name":"web","scripts":{"dev":"vite"}}'),
        ("npm --workspace @acme/web run dev", "packages/web", '{"name":"@acme/web","scripts":{"dev":"vite"}}'),
        ("pnpm --filter @acme/web dev", "packages/web", '{"name":"@acme/web","scripts":{"dev":"vite"}}'),
        ("pnpm -C packages/web dev", "packages/web", '{"name":"web","scripts":{"dev":"vite"}}'),
    ),
)
def test_workspace_name_resolves_to_package_directory(
    tmp_path, command, package_dir, package_json,
):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n"
    _write_repo(tmp_path, {
        "README.md": readme,
        "package.json": _ROOT_WORKSPACES_PKG,
        f"{package_dir}/package.json": package_json,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_workspace_name_with_missing_script_reports_c003(tmp_path):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\npnpm --filter web dev\n```\n"
    _write_repo(tmp_path, {
        "README.md": readme,
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_complex_pnpm_filter_selector_is_skipped(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --filter \"./packages/*\" dev\n```\n"
        ),
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("python -m streamlit run app.py", {"app.py": "print('ok')\n"}),
        ("streamlit run app.py", {"app.py": "print('ok')\n"}),
        ("flask --app app.py run", {"app.py": "print('ok')\n"}),
        ("python -m flask --app app.py run", {"app.py": "print('ok')\n"}),
        ("python -m flask --app myapp run", {"myapp.py": "app = object()\n"}),
        ("python -m flask --app myapp run", {"myapp/__init__.py": "app = object()\n"}),
    ),
)
def test_streamlit_and_flask_entries_are_validated(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    for path in files:
        (tmp_path / path).unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("python -m streamlit run missing.py", {}),
        ("streamlit run missing.py", {}),
        ("python -m flask --app missing run", {}),
        ("flask --app missing.py run", {}),
    ),
)
def test_streamlit_and_flask_missing_entries_report_c003(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("uvicorn app.main:app --header X:Y", {"app/main.py": "app = object()\n"}),
        ("uvicorn --header X:Y app.main:app", {"app/main.py": "app = object()\n"}),
        ("python -m uvicorn --header X:Y app.main:app", {"app/main.py": "app = object()\n"}),
        ("uvicorn --header X:Y --port 8000 app.main:app", {"app/main.py": "app = object()\n"}),
        ("uvicorn app.main:app --host 0.0.0.0 --port 8000", {"app/main.py": "app = object()\n"}),
    ),
)
def test_uvicorn_option_values_do_not_override_entry(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    for path in files:
        (tmp_path / path).unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("uvicorn app.main:app --header X:Y", {}),
        ("uvicorn --header X:Y app.main:app", {}),
        ("python -m uvicorn --header X:Y app.main:app", {}),
    ),
)
def test_uvicorn_missing_module_with_option_values_reports_c003(
    tmp_path, command, files,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("python -m myapp", {"src/myapp/__main__.py": "print('ok')\n"}),
        ("python -m myapp", {"src/myapp.py": "print('ok')\n"}),
        ("python -m pkg.svc", {"src/pkg/svc/__main__.py": "print('ok')\n"}),
        ("python -m pkg.svc", {"src/pkg/svc.py": "print('ok')\n"}),
    ),
)
def test_src_layout_runnable_module_is_validated(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    for path in files:
        (tmp_path / path).unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files"),
    (
        ("uvicorn myapp.api:app", {"src/myapp/api.py": "app = object()\n"}),
        ("uvicorn myapp.api:app", {"src/myapp/api/__init__.py": "app = object()\n"}),
    ),
)
def test_src_layout_import_module_is_validated(tmp_path, command, files):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    for path in files:
        (tmp_path / path).unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("uvicorn --factory app.main:create_app", {"app/main.py": "app = object()\n"}, False),
        ("uvicorn --factory missing:create_app", {}, True),
        ("python -m uvicorn --factory missing:create_app", {}, True),
    ),
)
def test_uvicorn_factory_is_boolean_flag_not_value_option(
    tmp_path, command, files, should_report,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


@pytest.mark.parametrize(
    ("command", "script"),
    (
        ("npm run dev --workspace web", "dev"),
        ("npm run dev --workspace=web", "dev"),
        ("npm run dev -w web", "dev"),
        ("npm test --workspace web", "test"),
    ),
)
def test_npm_workspace_after_script_validates_workspace_package(
    tmp_path, command, script,
):
    readme = f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n"
    root_pkg = '{"workspaces":["packages/*"]}'
    _write_repo(tmp_path, {
        "README.md": readme,
        "package.json": root_pkg,
        "packages/web/package.json": (
            f'{{"name":"web","scripts":{{"{script}":"echo ok"}}}}'
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    _write_repo(tmp_path, {
        "package.json": root_pkg,
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_scoped_workspace_with_missing_script_reports_c003(tmp_path):
    readme = (
        f"# App\n\n{_long_intro()}\n## Running\n"
        "```sh\nyarn workspace @acme/web dev\n```\n"
    )
    _write_repo(tmp_path, {
        "README.md": readme,
        "packages/web/package.json": '{"name":"@acme/web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_scoped_workspace_not_found_reports_c003(tmp_path):
    readme = (
        f"# App\n\n{_long_intro()}\n## Running\n"
        "```sh\nyarn workspace @acme/missing dev\n```\n"
    )
    _write_repo(tmp_path, {"README.md": readme})
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go build ./...", {"go.mod": "module app\n"}, False),
        ("go build ./...", {}, True),
        ("go build ./cmd/...", {"go.mod": "module app\n", "cmd/main.go": "package main\n"}, False),
        ("go build ./cmd/...", {"go.mod": "module app\n"}, True),
    ),
)
def test_go_package_pattern_with_ellipsis(tmp_path, command, files, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


@pytest.mark.parametrize(
    "command",
    (
        "streamlit run https://example.com/app.py",
        "python -m streamlit run https://example.com/app.py",
    ),
)
def test_streamlit_remote_url_is_skipped(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Issue 2: workspace npm lifecycle supports default server.js ----

def test_workspace_npm_start_accepts_default_server_js(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","version":"1.0.0"}',
        "packages/web/server.js": "console.info('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_workspace_npm_restart_accepts_default_server_js(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm restart --workspace web\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","version":"1.0.0"}',
        "packages/web/server.js": "console.info('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_workspace_npm_start_missing_script_and_server_js_reports_c003(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","version":"1.0.0"}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_workspace_npm_restart_missing_script_and_server_js_reports_c003(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm restart --workspace web\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","version":"1.0.0"}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_workspace_npm_start_one_fails_in_multiple_workspaces(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web --workspace api\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{"start":"node app.js"}}',
        "packages/api/package.json": '{"name":"api","version":"1.0.0"}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Issue 3: Go extended value options and -C global flag ----

@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go build -p 4 ./...", {"go.mod": "module app\n"}, False),
        ("go build -p 4 ./...", {}, True),
        ("go run -exec wrapper ./cmd/app", {"cmd/app/main.go": "package main\n"}, False),
        ("go run -exec wrapper ./cmd/missing", {}, True),
        ("go build -coverpkg ./... ./cmd/app", {"go.mod": "module app\n", "cmd/app/main.go": "package main\n"}, False),
    ),
)
def test_go_extended_value_options(tmp_path, command, files, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go -C service build ./...", {"service/go.mod": "module app\n"}, False),
        ("go -C service build ./...", {}, True),
    ),
)
def test_go_global_c_flag_changes_directory(tmp_path, command, files, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


# ---- Issue 4: go run validates multiple .go files ----

@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go run main.go helper.go", {"main.go": "package main\n", "helper.go": "package main\n"}, False),
        ("go run main.go missing.go", {"main.go": "package main\n"}, True),
        ("go run main.go helper.go arg1", {"main.go": "package main\n", "helper.go": "package main\n"}, False),
        ("go run ./cmd/app arg1", {"cmd/app/main.go": "package main\n"}, False),
    ),
)
def test_go_run_multiple_go_files(tmp_path, command, files, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) is should_report


# ---- Issue 5: npm run-script formal syntax ----

@pytest.mark.parametrize(
    ("command", "script_present"),
    (
        ("npm run-script dev --workspace web", True),
        ("npm run-script dev --workspace web", False),
        ("npm --workspace web run-script dev", True),
        ("npm --workspace web run-script dev", False),
        ("npm run-script dev", True),
        ("npm run-script dev", False),
    ),
)
def test_npm_run_script_workspace_and_root(tmp_path, command, script_present):
    script_json = '{"dev":"vite"}' if script_present else '{}'
    if "--workspace" in command:
        files = {
            "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
            "package.json": _ROOT_WORKSPACES_PKG,
            "packages/web/package.json": f'{{"name":"web","scripts":{script_json}}}',
        }
    else:
        files = {
            "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
            "package.json": f'{{"scripts":{script_json}}}',
        }
    _write_repo(tmp_path, files)
    if script_present:
        assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)
    else:
        assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Round 6 Issue 1: npm run/run-script lifecycle supports server.js ----

@pytest.mark.parametrize(
    ("command", "script_present", "server_js_present", "should_report"),
    (
        ("npm run start", False, True, False),
        ("npm run-script start", False, True, False),
        ("npm run restart", False, True, False),
        ("npm run start", False, False, True),
        ("npm run-script restart", False, False, True),
        ("npm run start", True, False, False),
        ("npm run-script start", True, False, False),
    ),
)
def test_npm_run_lifecycle_supports_server_js(
    tmp_path, command, script_present, server_js_present, should_report,
):
    scripts = {"start": "node app.js"} if script_present else {}
    files = {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": '{"scripts":' + json.dumps(scripts) + '}',
    }
    if server_js_present:
        files["server.js"] = "console.log('ok')"
    _write_repo(tmp_path, files)
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


@pytest.mark.parametrize(
    ("command", "script_present", "server_js_present", "should_report"),
    (
        ("npm run start --workspace web", False, True, False),
        ("npm run-script start --workspace web", False, True, False),
        ("npm run restart --workspace web", False, True, False),
        ("npm run start --workspace web", False, False, True),
        ("npm run-script restart --workspace web", False, False, True),
        ("npm run start --workspace web", True, False, False),
    ),
)
def test_npm_run_lifecycle_workspace_supports_server_js(
    tmp_path, command, script_present, server_js_present, should_report,
):
    scripts = {"start": "node app.js"} if script_present else {}
    files = {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":' + json.dumps(scripts) + '}',
    }
    if server_js_present:
        files["packages/web/server.js"] = "console.log('ok')"
    _write_repo(tmp_path, files)
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


# ---- Round 6 Issue 2: archive wrapper workspace path duplication ----

def test_archive_wrapper_workspace_server_js_not_duplicated(tmp_path):
    _write_repo(tmp_path, {
        "project-main/README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web\n```\n"
        ),
        "project-main/package.json": _ROOT_WORKSPACES_PKG,
        "project-main/packages/web/package.json": '{"name":"web","version":"1.0.0"}',
        "project-main/packages/web/server.js": "console.log('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_archive_wrapper_workspace_missing_server_js_reports(tmp_path):
    _write_repo(tmp_path, {
        "project-main/README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web\n```\n"
        ),
        "project-main/package.json": _ROOT_WORKSPACES_PKG,
        "project-main/packages/web/package.json": '{"name":"web","version":"1.0.0"}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_archive_wrapper_workspace_script_start_is_valid(tmp_path):
    _write_repo(tmp_path, {
        "project-main/README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace web\n```\n"
        ),
        "project-main/package.json": _ROOT_WORKSPACES_PKG,
        "project-main/packages/web/package.json": '{"name":"web","scripts":{"start":"node app.js"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Round 6 Issue 3: npm -w=web short param ----

@pytest.mark.parametrize(
    ("command", "web_has_dev", "api_has_dev", "should_report"),
    (
        ("npm run dev -w=web", True, False, False),
        ("npm run dev -w=web", False, False, True),
        ("npm -w=web run dev", True, False, False),
        ("npm -w=web run dev", False, False, True),
        ("npm run dev -w=web -w=api", True, True, False),
        ("npm run dev -w=web -w=api", True, False, True),
        ("npm run dev -w=web -w=api", False, True, True),
    ),
)
def test_npm_short_workspace_equal_param(
    tmp_path, command, web_has_dev, api_has_dev, should_report,
):
    web_scripts = {"dev": "vite"} if web_has_dev else {}
    api_scripts = {"dev": "vite"} if api_has_dev else {}
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":' + json.dumps(web_scripts) + '}',
        "packages/api/package.json": '{"name":"api","scripts":' + json.dumps(api_scripts) + '}',
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


# ---- Round 6 Issue 4: Go -C parameter positions and equals form ----

@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go -C=service build ./...", {"service/go.mod": "module app\n"}, False),
        ("go -C=service build ./...", {}, True),
        ("go build -C service ./...", {"service/go.mod": "module app\n"}, False),
        ("go build -C service ./...", {}, True),
        ("go build -C=service ./...", {"service/go.mod": "module app\n"}, False),
        ("go build -C=service ./...", {}, True),
        ("go run -C service main.go", {"service/main.go": "package main\n"}, False),
        ("go run -C service main.go", {}, True),
        ("go run -C=service main.go", {"service/main.go": "package main\n"}, False),
    ),
)
def test_go_c_parameter_variations(tmp_path, command, files, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


# ---- Round 6 Issue 5: multiple pnpm filters conservative skip ----

@pytest.mark.parametrize(
    ("command", "web_has_dev", "api_has_dev"),
    (
        ("pnpm --filter web --filter api dev", True, True),
        ("pnpm --filter api --filter web dev", True, True),
        ("pnpm --filter web --filter api dev", True, False),
        ("pnpm --filter api --filter web dev", False, True),
        ("pnpm --filter ./packages/web --filter api dev", True, True),
        ("pnpm --filter api --filter ./packages/web dev", True, True),
    ),
)
def test_multiple_pnpm_filters_skip(tmp_path, command, web_has_dev, api_has_dev):
    web_scripts = {"dev": "vite"} if web_has_dev else {}
    api_scripts = {"dev": "vite"} if api_has_dev else {}
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "packages/web/package.json": '{"name":"web","scripts":' + json.dumps(web_scripts) + '}',
        "packages/api/package.json": '{"name":"api","scripts":' + json.dumps(api_scripts) + '}',
    })
    # Conservative skip: no C003 regardless of script presence
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_multiple_pnpm_filters_order_independent(tmp_path):
    """Same selectors in different order must produce the same result."""
    base_files = {
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    }
    cmd_a = "pnpm --filter web --filter api dev"
    cmd_b = "pnpm --filter api --filter web dev"

    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{cmd_a}\n```\n",
        **base_files,
    })
    result_a = "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)

    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{cmd_b}\n```\n",
        **base_files,
    })
    result_b = "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)

    assert result_a == result_b


# ---- Round 6 Issue 6: Go -pgo and unknown parameters ----

@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -pgo off ./...", False),
        ("go build -pgo auto ./...", False),
        ("go build -pgo profile.pgo ./...", False),
        ("go build -pgo=off ./...", False),
        ("go build -pgo=auto ./...", False),
        ("go build -pgo=profile.pgo ./...", False),
        ("go build -unknown-flag ./...", False),
        ("go build -v ./...", False),
        ("go build -race ./...", False),
    ),
)
def test_go_pgo_and_known_boolean_options(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


def test_go_unknown_flag_does_not_pollute_package_targets(tmp_path):
    """Unknown flag with a value must not treat the value as a package path."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo build -unknown-flag somevalue ./...\n```\n"
        ),
        "go.mod": "module app\n",
    })
    # Conservative skip: no C003 despite unknown flag
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_go_pgo_value_not_treated_as_package(tmp_path):
    """-pgo profile.pgo must not check profile.pgo as a file path."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo build -pgo profile.pgo ./...\n```\n"
        ),
        "go.mod": "module app\n",
    })
    # profile.pgo is consumed as -pgo value, not treated as a package
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)

    # Without go.mod, ./... should still report (pgo value doesn't affect this)
    (tmp_path / "go.mod").unlink()
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Round 7 Issue 1: pnpm filter counting respects -- separator ----

def test_pnpm_filter_after_separator_reports_c003_root(tmp_path):
    """--filter after -- is a script argument, not a pnpm selector."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm run missing -- --filter web --filter api\n```\n"
        ),
        "package.json": '{"scripts":{"dev":"vite"}}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_pnpm_filter_after_separator_reports_c003_workspace(tmp_path):
    """Single real --filter before --; second --filter after -- is a script arg."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --filter web run missing -- --filter api\n```\n"
        ),
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_pnpm_multiple_filters_before_separator_still_skips(tmp_path):
    """Multiple --filter before -- still conservatively skips."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\npnpm --filter web --filter api dev\n```\n"
        ),
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_pnpm_filter_separator_order_independent(tmp_path):
    """Swapping real selector order produces the same result."""
    base_files = {
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/api/package.json": '{"name":"api","scripts":{"dev":"vite"}}',
    }
    cmd_a = "pnpm --filter web run missing -- --filter api"
    cmd_b = "pnpm --filter api run missing -- --filter web"

    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{cmd_a}\n```\n",
        **base_files,
    })
    result_a = "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)

    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{cmd_b}\n```\n",
        **base_files,
    })
    result_b = "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)

    assert result_a == result_b == True


# ---- Round 7 Issue 2: npm --if-present handling ----

@pytest.mark.parametrize(
    "command",
    (
        "npm run start --if-present",
        "npm run --if-present start",
        "npm --if-present run start",
    ),
)
def test_npm_if_present_suppresses_missing_root_script(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "npm run start --if-present --workspace web",
        "npm run --if-present start --workspace web",
    ),
)
def test_npm_if_present_suppresses_missing_workspace_script(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": '{"name":"web","scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_if_present_suppresses_missing_dev_script(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_if_present_after_separator_does_not_suppress(tmp_path):
    """--if-present after -- is a script argument, not an npm flag."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -- --if-present\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_with_existing_script_still_valid(tmp_path):
    """When script exists, --if-present doesn't change behavior."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present\n```\n"
        ),
        "package.json": '{"scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Round 7 Issue 3: npm workspace validates root workspaces config ----

def test_npm_workspace_no_root_workspaces_reports_c003(tmp_path):
    """Root package.json without workspaces config → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web\n```\n"
        ),
        "package.json": '{"scripts":{}}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_no_root_package_reports_c003(tmp_path):
    """No root package.json at all → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web\n```\n"
        ),
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_array_form_declared(tmp_path):
    """Root workspaces as array → valid."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_object_form_declared(tmp_path):
    """Root workspaces as {packages:[...]} → valid."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --workspace web\n```\n"
        ),
        "package.json": '{"workspaces":{"packages":["packages/*"]}}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_dir_only_server_js_no_package_json_reports_c003(tmp_path):
    """Workspace dir has server.js but no package.json → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace packages/web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/web/server.js": "console.log('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_with_package_json_and_server_js_valid(tmp_path):
    """Workspace has package.json and server.js, declared by root → valid."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --workspace packages/web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/web/package.json": '{"name":"web","version":"1.0.0"}',
        "packages/web/server.js": "console.log('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Round 7 Issue 4: Go import path vs local path ----

@pytest.mark.parametrize(
    "command",
    (
        "go build cmd/gofmt",
        "go run cmd/gofmt -h",
        "go run golang.org/x/tools/cmd/stringer@latest",
    ),
)
def test_go_import_path_not_validated_as_local(tmp_path, command):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_go_local_path_existing_dir_valid(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo build ./cmd/app\n```\n"
        ),
        "cmd/app/main.go": "package main\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_go_local_path_missing_dir_reports(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo build ./cmd/missing\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_go_existing_go_file_valid(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo run main.go\n```\n"
        ),
        "main.go": "package main\n",
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_go_missing_go_file_reports(tmp_path):
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\ngo run missing.go\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Round 7 Issue 5: Go boolean parameter value validation ----

@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -race=true ./...", False),
        ("go build -race=false ./...", False),
        ("go build -race=maybe ./...", True),
    ),
)
def test_go_race_boolean_value_validation(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -buildvcs=auto ./...", False),
        ("go build -buildvcs=true ./...", False),
        ("go build -buildvcs=false ./...", False),
        ("go build -buildvcs=maybe ./...", True),
    ),
)
def test_go_buildvcs_boolean_value_validation(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -v=true ./...", False),
        ("go build -v=false ./...", False),
        ("go build -v=maybe ./...", True),
    ),
)
def test_go_v_boolean_value_validation(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


# ---- Round 8 Issue 1: --if-present must not ignore missing/corrupt manifest ----

def test_npm_if_present_no_package_json_reports(tmp_path):
    """No package.json at all → C003 even with --if-present."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_corrupt_package_json_reports(tmp_path):
    """Corrupt package.json → C003 even with --if-present."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present\n```\n"
        ),
        "package.json": "{bad",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_valid_manifest_missing_script_ok(tmp_path):
    """Valid package.json but no dev script → no C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_if_present_true_eq_form(tmp_path):
    """--if-present=true → suppress missing script."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present=true\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_if_present_false_eq_form_reports(tmp_path):
    """--if-present=false → do NOT suppress missing script."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev --if-present=false\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_true_prefix_form(tmp_path):
    """npm --if-present=true run dev → suppress missing script."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm --if-present=true run dev\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_if_present_false_prefix_form_reports(tmp_path):
    """npm --if-present=false run dev → do NOT suppress."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm --if-present=false run dev\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_after_separator_reports(tmp_path):
    """--if-present after -- is a script argument → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -- --if-present=true\n```\n"
        ),
        "package.json": '{"scripts":{}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_lifecycle_corrupt_manifest_reports(tmp_path):
    """Corrupt package.json with lifecycle command + --if-present → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start --if-present\n```\n"
        ),
        "package.json": "{bad",
        "server.js": "console.log('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_if_present_workspace_corrupt_pkg_reports(tmp_path):
    """Workspace with corrupt package.json + --if-present → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm start -w packages/web --if-present\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": "{bad",
        "packages/web/server.js": "console.log('ok')\n",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


# ---- Round 8 Issue 2: npm workspace name resolution refactor ----

def test_npm_workspace_glob_double_star(tmp_path):
    """workspaces=["packages/**"] matches nested dirs."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/**"]}',
        "packages/group/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_glob_negation_excludes(tmp_path):
    """workspaces=["packages/*","!packages/excluded"] → excluded not a workspace."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w excluded\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*","!packages/excluded"]}',
        "packages/excluded/package.json": '{"name":"excluded","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_glob_negation_includes_others(tmp_path):
    """Negation doesn't affect non-excluded packages."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*","!packages/excluded"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "packages/excluded/package.json": '{"name":"excluded","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_name_prefers_declared_over_vendor(tmp_path):
    """Same-named package in vendor must not override declared workspace."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "vendor/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_name_not_declared_reports(tmp_path):
    """Package exists but not in root workspaces → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "vendor/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_glob_nested_pattern(tmp_path):
    """apps/*/packages/* pattern."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w shared\n```\n"
        ),
        "package.json": '{"workspaces":["apps/*/packages/*"]}',
        "apps/web/packages/shared/package.json": '{"name":"shared","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_corrupt_pkg_reports(tmp_path):
    """Workspace package.json exists but corrupt → C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": _ROOT_WORKSPACES_PKG,
        "packages/web/package.json": "{bad",
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_object_form_glob(tmp_path):
    """Object form workspaces with glob pattern."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":{"packages":["packages/**"]}}',
        "packages/group/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Round 8 Issue 3: Go parameters split by subcommand ----

@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -v=1 ./...", False),
        ("go build -race=True ./...", False),
        ("go build -race=FALSE ./...", False),
        ("go build -buildvcs=1 ./...", False),
        ("go build -buildvcs=auto ./...", False),
        ("go build -race=maybe ./...", True),
    ),
)
def test_go_extended_boolean_values(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


@pytest.mark.parametrize(
    ("command", "should_report"),
    (
        ("go build -exec wrapper ./...", True),
        ("go run -o bin .", True),
        ("go build -u ./...", True),
        ("go build -d ./...", True),
        ("go build -fix ./...", True),
        ("go build -json ./...", True),
    ),
)
def test_go_wrong_subcommand_flags_report(tmp_path, command, should_report):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        "go.mod": "module app\n",
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go run -exec wrapper ./cmd/app", {"cmd/app/main.go": "package main\n"}, False),
        ("go build -o bin ./...", {"go.mod": "module app\n"}, False),
    ),
)
def test_go_correct_subcommand_flags_valid(
    tmp_path, command, files, should_report,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report


# ---- Round 9 Issue 1: npm workspace glob safety & normalization ----

def test_npm_workspace_dot_slash_prefix_pattern(tmp_path):
    """workspaces=["./packages/*"] should match normally."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["./packages/*"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_trailing_slash_pattern(tmp_path):
    """workspaces=["packages/*/"] should match normally."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*/"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_workspace_malformed_bracket_no_crash(tmp_path):
    """workspaces=["packages/[abc"] must not crash the scan."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/[abc"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    # Must not raise; may or may not report C003 but must not crash.
    _rule_ids(tmp_path)


def test_npm_workspace_question_mark_no_crash(tmp_path):
    """workspaces=["packages/?"] must not crash the scan."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/?"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    # Must not raise.
    _rule_ids(tmp_path)


def test_npm_workspace_unsupported_plus_valid_mixed(tmp_path):
    """One unsupported pattern + one valid pattern: valid workspace still works."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/[abc","packages/*"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


def test_npm_glob_no_unlimited_global_cache(tmp_path):
    """Verify that lru_cache is used instead of a global dict by feeding many patterns."""
    from app.scanner.documentation_rules import _npm_glob_compile
    # Clear any cached entries
    _npm_glob_compile.cache_clear()
    # Feed many unique normalized patterns
    for i in range(300):
        _npm_glob_compile(f"dir{i}/*")
    # lru_cache(maxsize=256) should cap at 256; info().currsize <= 256
    info = _npm_glob_compile.cache_info()
    assert info.currsize <= 256, f"Cache grew unbounded: {info.currsize}"
    _npm_glob_compile.cache_clear()


# ---- Round 9 Issue 2: duplicate workspace name → AMBIGUOUS → C003 ----

def test_npm_workspace_duplicate_name_both_have_script_reports(tmp_path):
    """Two workspaces with same name, both have dev → C003 (AMBIGUOUS)."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w dup\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/a/package.json": '{"name":"dup","scripts":{"dev":"vite"}}',
        "packages/b/package.json": '{"name":"dup","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_duplicate_name_one_missing_script_reports(tmp_path):
    """Two workspaces with same name, one has dev one doesn't → still C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w dup\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/a/package.json": '{"name":"dup","scripts":{"dev":"vite"}}',
        "packages/b/package.json": '{"name":"dup","scripts":{"build":"tsc"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_duplicate_name_order_independent(tmp_path):
    """Duplicate workspace name must report C003 regardless of file observation order."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w dup\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/zzz/package.json": '{"name":"dup","scripts":{"dev":"vite"}}',
        "packages/aaa/package.json": '{"name":"dup","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


def test_npm_workspace_single_name_vs_vendor_no_report(tmp_path):
    """One declared workspace name=web + one vendor non-workspace name=web → no C003."""
    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Running\n"
            "```sh\nnpm run dev -w web\n```\n"
        ),
        "package.json": '{"workspaces":["packages/*"]}',
        "packages/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
        "vendor/web/package.json": '{"name":"web","scripts":{"dev":"vite"}}',
    })
    assert "C003_START_COMMAND_MISMATCH" not in _rule_ids(tmp_path)


# ---- Round 9 Issue 3: go run -buildmode ----

@pytest.mark.parametrize(
    ("command", "files", "should_report"),
    (
        ("go run -buildmode=pie .", {"go.mod": "module app\n"}, False),
        ("go run -buildmode pie .", {"go.mod": "module app\n"}, False),
        ("go build -buildmode=pie .", {"go.mod": "module app\n"}, False),
        ("go run -o bin .", {"go.mod": "module app\n"}, True),
        ("go build -exec wrapper ./...", {"go.mod": "module app\n"}, True),
    ),
)
def test_go_buildmode_and_subcommand_separation(
    tmp_path, command, files, should_report,
):
    _write_repo(tmp_path, {
        "README.md": f"# App\n\n{_long_intro()}\n## Running\n```sh\n{command}\n```\n",
        **files,
    })
    assert ("C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)) == should_report
