"""Deterministic comment-quality audit tests (no database required)."""

from __future__ import annotations

from pathlib import Path

from app.quality.analyzers.comment_quality import (
    _looks_like_trivial_translation,
    _parse_documented_params,
    analyze_backend_comments,
)
from app.quality.models import (
    REASON_LLM_DISABLED,
    REASON_NO_BACKEND,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
)
from app.quality.repository_index import RepositoryIndex

GOLDEN_REPO = Path(__file__).resolve().parents[3]


def _write(root: Path, files: dict[str, str]) -> RepositoryIndex:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return RepositoryIndex(root)


def _categories(block) -> set[str]:
    return {item["category"] for item in block.to_dict()["items"]}


def test_route_and_state_write_missing_docstrings_and_trivial_comment(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/api/routes.py": (
                '"""Routes module."""\n'
                "from fastapi import APIRouter\n\n"
                "router = APIRouter()\n\n\n"
                "@router.get('/x')\n"
                "async def get_x(user_id: str, limit: int):\n"
                "    return {'id': user_id}\n\n\n"
                "async def mark_running_owned(task_id, stage, progress, worker_id):\n"
                "    # update the progress field\n"
                "    return True\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    categories = _categories(block)
    assert "missing_route_handler_docstring" in categories
    assert "missing_state_write_docstring" in categories
    assert "trivial_line_comment" in categories


def test_docstring_structure_reports_args_returns_raises(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/services/loader.py": (
                '"""Loader module."""\n\n'
                "def load(x, y, z):\n"
                '    """Load a value."""\n'
                "    if x:\n"
                '        raise ValueError("bad")\n'
                "    return y\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    structure = [
        item
        for item in block.to_dict()["items"]
        if item["category"] == "docstring_structure_incomplete"
    ]
    assert len(structure) == 1
    missing = {
        section
        for row in structure[0]["details"]["functions"]
        for section in row["missing"]
    }
    assert {"Args", "Returns", "Raises"} <= missing


def test_stale_params_are_reported(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/services/loader.py": (
                '"""Loader module."""\n\n'
                "def load(x, y, z):\n"
                '    """Load a value.\n\n'
                "    Args:\n"
                "        x: first value.\n"
                '    """\n'
                "    return x\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    structure = [
        item
        for item in block.to_dict()["items"]
        if item["category"] == "docstring_structure_incomplete"
    ]
    assert structure
    missing = set(structure[0]["details"]["functions"][0]["missing"])
    assert "Args (stale)" in missing


def test_restates_function_name_is_reported(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/services/connector.py": (
                '"""Connector module."""\n\n'
                "def connect():\n"
                '    """Connect."""\n'
                "    return True\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    structure = [
        item
        for item in block.to_dict()["items"]
        if item["category"] == "docstring_structure_incomplete"
    ]
    assert structure
    assert "comment_restates_function_name" in structure[0]["details"]["functions"][0]["missing"]


def test_invalid_comment_patterns_are_aggregated_per_file(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/core/legacy.py": (
                '"""Legacy helpers."""\n\n'
                "# TODO: clean this up\n"
                "# updated on 2024-01-01\n"
                "# return None\n"
                "def helper():\n"
                '    """Help."""\n'
                "    return 1\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    categories = _categories(block)
    assert "todo_without_owner" in categories
    assert "change_history_comment" in categories
    assert "commented_out_code" in categories


def test_state_write_contract_and_error_contract(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/services/state.py": (
                '"""State module."""\n\n'
                "async def mark_completed_async(task_id):\n"
                '    """Mark the task completed."""\n'
                "    return True\n"
            ),
            "app/api/routes.py": (
                '"""Routes module."""\n'
                "from fastapi import APIRouter, HTTPException\n\n"
                "router = APIRouter()\n\n\n"
                "@router.get('/y')\n"
                "async def get_y():\n"
                '    """Return y."""\n'
                '    raise HTTPException(status_code=404, detail="missing")\n'
            ),
        },
    )
    block = analyze_backend_comments(index)
    categories = _categories(block)
    assert "state_write_contract_missing" in categories
    assert "error_contract_undocumented" in categories


def test_language_policy_never_emits_language_items(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/services/english.py": (
                '"""English module.\n\n'
                "This module only uses English comments on purpose.\n"
                '"""\n\n'
                "# The guard exists because the upstream API returns null.\n"
                "def guarded(value):\n"
                '    """Return a safe value.\n\n'
                "    Args:\n"
                "        value: Raw upstream value.\n\n"
                "    Returns:\n"
                "        A non-null value.\n"
                '    """\n'
                "    return value or 'fallback'\n"
            ),
        },
    )
    block = analyze_backend_comments(index)
    data = block.to_dict()
    assert data["coverage"]["language_policy"] == "match_file_majority_no_ratio_penalty"
    assert not any("language" in category for category in _categories(block))
    assert data["coverage"]["comment_language"]["latin_words"] > 0


def test_many_undocumented_helpers_aggregate_to_one_item(tmp_path):
    functions = "\n\n".join(
        f"def helper_{index}(a, b):\n    return a + b" for index in range(10)
    )
    index = _write(
        tmp_path,
        {"app/services/helpers.py": f'"""Helpers module."""\n\n{functions}\n'},
    )
    block = analyze_backend_comments(index)
    missing = [
        item
        for item in block.to_dict()["items"]
        if item["category"] == "docstring_missing"
    ]
    assert len(missing) == 1
    assert missing[0]["details"]["count"] == 10


def test_backend_without_byok_is_partial_llm_disabled(tmp_path):
    index = _write(
        tmp_path,
        {
            "app/api/routes.py": (
                '"""Routes module."""\n'
                "from fastapi import APIRouter\n\n"
                "router = APIRouter()\n\n\n"
                "@router.get('/x')\n"
                "async def get_x():\n"
                '    """Return a constant value."""\n'
                "    return {'ok': True}\n"
            ),
        },
    )
    data = analyze_backend_comments(index, None).to_dict()
    assert data["status"] == STATUS_PARTIAL
    assert data["reason_code"] == REASON_LLM_DISABLED
    assert data["conclusion"]["llm"]["state"] == "disabled"
    manual = [
        item for item in data["items"] if item["category"] == "semantic_review_pending"
    ]
    assert manual and manual[0]["manual_decision_required"] is True
    assert "LLM_DISABLED" in manual[0]["limitation"]


def test_empty_repo_is_not_applicable(tmp_path):
    data = analyze_backend_comments(RepositoryIndex(tmp_path)).to_dict()
    assert data["status"] == STATUS_NOT_APPLICABLE
    assert data["reason_code"] == REASON_NO_BACKEND


def test_golden_repo_reports_no_flood_and_no_english_penalty():
    data = analyze_backend_comments(RepositoryIndex(GOLDEN_REPO), None).to_dict()
    counts = data["conclusion"]["counts"]
    assert data["status"] == STATUS_PARTIAL
    assert data["reason_code"] == REASON_LLM_DISABLED
    assert counts["covered_functions"] > 0
    assert counts["risk_p0"] == 0
    assert counts["risk_p1"] == 0
    assert len(data["items"]) < 200
    assert not any("language" in item["category"] for item in data["items"])


def test_google_returns_and_raises_headers_are_not_stale_params():
    doc = (
        "Return a page of items.\n\n"
        "Args:\n"
        "    limit: page size.\n"
        "    offset: start index.\n\n"
        "Returns:\n"
        "    A dict with items.\n\n"
        "Raises:\n"
        "    ValueError: when the page is invalid.\n"
    )
    documented, missing, extra = _parse_documented_params(doc, ["limit", "offset"])
    assert documented == {"limit", "offset"}
    assert missing == []
    assert extra == []


def test_english_explanatory_comment_is_not_trivial():
    lines = [
        "# Validate name (path traversal, null bytes, etc.)",
        "name = validate_name(name)",
        "# Get task from database",
        "task = get_task(task_id)",
    ]
    assert not _looks_like_trivial_translation(lines[0], lines, 0)
    assert _looks_like_trivial_translation(lines[2], lines, 2)
