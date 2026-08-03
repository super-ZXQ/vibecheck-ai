"""High-confidence boundaries for the documentation-consistency dimension."""

from __future__ import annotations

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
        "app.py": "print('ok')\n",
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

    _write_repo(tmp_path, {
        "README.md": (
            f"# App\n\n{_long_intro()}\n## Quick Start\n"
            "```sh\ncd frontend && npm run missing\n```\n"
        ),
    })
    assert "C003_START_COMMAND_MISMATCH" in _rule_ids(tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "python -m venv .venv",
        "python -m pip install -r requirements.txt",
        "python -m pytest",
        "npm create vite@latest",
        "yarn workspace frontend start",
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
