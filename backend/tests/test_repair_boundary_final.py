"""P0-7 fifth-round boundary regression tests.

Covers the four final boundary fixes:
1. agent_prompt never exceeds max_chars (single return path guarantee)
2. repair_group type validated before any field access
3. Serialization and read share snapshot semantic validation
4. related_files normalized and validated at both boundaries
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.error_codes import REPAIR_PLAN_INTERNAL_ERROR
from app.db import database
from app.db.database import _get_connection
from app.services import background_runner, task_manager
from app.services.repair_policy import (
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
    AGENT_PROMPT_REQUIREMENTS,
    PARTIAL_DECLARATION,
    ACTION_MANUAL_REVIEW_REQUIRED,
    ACTION_RERUN_SECURITY_SCAN,
    ACTION_REVOKE_OR_ROTATE_SECRET,
)
from app.services.repair_service import (
    generate_repair_plan,
    serialize_repair_plan,
    save_repair_result,
    get_repair_result,
    RepairPlanInternalError,
    RepairPlanTooLargeError,
    RepairPlanSerializationError,
    _generate_agent_prompt,
    _validate_repair_snapshot_semantics,
)
from app.services.task_manager import create_task, mark_completed


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(test_db):
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_runner():
    background_runner.reset_runner_state()
    yield
    background_runner.reset_runner_state()


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_task(repo_url="https://github.com/test/repo"):
    task = create_task(repo_url, "test", "repo")
    mark_completed(task.id, file_count=10, total_size=1024, top_level_dir="test-repo")
    return task.id


def _make_valid_safe_plan(task_id="test-task"):
    """Create a valid serialized complete repair plan."""
    plan = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": "complete",
        "summary": {
            "total_repair_groups": 1,
            "blocking_repair_groups": 1,
            "manual_review_required": False,
            "coverage_warning": False,
            "groups_truncated": False,
        },
        "repair_groups": [{
            "group_id": "RG001",
            "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
            "priority": 1, "blocking": True,
            "highest_severity": "critical", "highest_confidence": "high",
            "title": "Test", "description": "Test",
            "related_rule_ids": ["R001_GITHUB_TOKEN"],
            "related_files": ["config.py"],
            "total_related_files": 1, "returned_related_files": 1,
            "related_files_truncated": False, "finding_count": 1,
            "steps": ["step1"], "commands": [], "safety_notes": ["note"],
            "verification_steps": ["verify1"],
        }],
        "verification_steps": ["step1"],
        "agent_prompt": "",
        "source_scan_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_policy_version": "p0-6-v1",
        "created_at": None, "updated_at": None,
    }
    return serialize_repair_plan(
        task_id=task_id,
        repair_plan=plan,
        source_scan_updated_at="2026-01-01T00:00:00Z",
        source_assessment_updated_at="2026-01-01T00:00:00Z",
        source_assessment_policy_version="p0-6-v1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )


def _make_valid_partial_safe_plan(task_id="test-task"):
    """Create a valid serialized partial repair plan with MANUAL_REVIEW_REQUIRED."""
    plan = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": "partial",
        "summary": {
            "total_repair_groups": 1,
            "blocking_repair_groups": 0,
            "manual_review_required": True,
            "coverage_warning": True,
            "groups_truncated": False,
        },
        "repair_groups": [{
            "group_id": "RG001",
            "action_code": ACTION_MANUAL_REVIEW_REQUIRED,
            "priority": 12, "blocking": False,
            "highest_severity": "info", "highest_confidence": "low",
            "title": "Test", "description": "Test",
            "related_rule_ids": [], "related_files": [],
            "total_related_files": 0, "returned_related_files": 0,
            "related_files_truncated": False, "finding_count": 0,
            "steps": [], "commands": [], "safety_notes": [],
            "verification_steps": [],
        }],
        "verification_steps": [],
        "agent_prompt": "",
        "source_scan_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_updated_at": "2026-01-01T00:00:00Z",
        "source_assessment_policy_version": "p0-6-v1",
        "created_at": None, "updated_at": None,
    }
    return serialize_repair_plan(
        task_id=task_id,
        repair_plan=plan,
        source_scan_updated_at="2026-01-01T00:00:00Z",
        source_assessment_updated_at="2026-01-01T00:00:00Z",
        source_assessment_policy_version="p0-6-v1",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )


def _compute_fixed_content(plan_status: str) -> str:
    """Compute the fixed content of _generate_agent_prompt for a given status."""
    lines = ["# VibeCheck 安全修复指引", ""]
    if plan_status == "partial":
        lines.append(PARTIAL_DECLARATION)
        lines.append("")
    lines.append("## 安全要求")
    lines.append("")
    for req in AGENT_PROMPT_REQUIREMENTS:
        lines.append(req)
    return "\n".join(lines)


def _make_repair_group(action_code=ACTION_REVOKE_OR_ROTATE_SECRET,
                       blocking=True, related_files=None):
    """Build a minimal repair group dict for prompt tests."""
    return {
        "action_code": action_code,
        "title": "Test Action",
        "finding_count": 1,
        "related_rule_ids": ["R001_GITHUB_TOKEN"],
        "related_files": related_files or ["config.py"],
        "blocking": blocking,
    }


def _insert_raw_repair_row(task_id, repair_json_str, plan_status="complete",
                           total_repair_groups=1, blocking_repair_groups=1):
    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO repair_results
               (task_id, schema_version, policy_version, repair_scope,
                repair_json, plan_status, total_repair_groups,
                blocking_repair_groups, source_scan_updated_at,
                source_assessment_updated_at,
                source_assessment_policy_version,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (task_id, REPAIR_SCHEMA_VERSION, POLICY_VERSION, REPAIR_SCOPE,
             repair_json_str, plan_status, total_repair_groups,
             blocking_repair_groups,
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "p0-6-v1",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# --- Fix 1: agent_prompt never exceeds max_chars ---
# ---------------------------------------------------------------------------

class TestAgentPromptMaxChars:
    """Verify _generate_agent_prompt never returns an over-limit prompt."""

    def test_max_chars_equals_fixed_content_complete(self):
        """max_chars == len(fixed_content), groups non-empty → returns
        fixed_content, length <= max_chars."""
        fc = _compute_fixed_content("complete")
        groups = [_make_repair_group()]
        prompt = _generate_agent_prompt(groups, "complete", len(fc))
        assert len(prompt) <= len(fc)
        assert prompt == fc

    def test_max_chars_equals_fixed_content_partial(self):
        """Same test with partial fixed content."""
        fc = _compute_fixed_content("partial")
        groups = [_make_repair_group()]
        prompt = _generate_agent_prompt(groups, "partial", len(fc))
        assert len(prompt) <= len(fc)
        assert prompt == fc

    def test_max_chars_just_below_fixed_plus_header(self):
        """max_chars == len(fixed) + len(variable_header) - 1 → must not
        return an over-limit prompt."""
        fc = _compute_fixed_content("complete")
        vh = "\n\n## 修复动作摘要\n\n"
        max_chars = len(fc) + len(vh) - 1
        groups = [_make_repair_group()]
        prompt = _generate_agent_prompt(groups, "complete", max_chars)
        assert len(prompt) <= max_chars

    def test_max_chars_exactly_fits_variable_header(self):
        """max_chars just enough for variable_header → final length <= max."""
        fc = _compute_fixed_content("complete")
        vh = "\n\n## 修复动作摘要\n\n"
        max_chars = len(fc) + len(vh)
        groups = [_make_repair_group()]
        prompt = _generate_agent_prompt(groups, "complete", max_chars)
        assert len(prompt) <= max_chars

    def test_max_chars_exactly_fits_variable_header_partial(self):
        """Same boundary test with partial fixed content."""
        fc = _compute_fixed_content("partial")
        vh = "\n\n## 修复动作摘要\n\n"
        max_chars = len(fc) + len(vh)
        groups = [_make_repair_group()]
        prompt = _generate_agent_prompt(groups, "partial", max_chars)
        assert len(prompt) <= max_chars

    def test_fixed_content_exceeds_max_chars_raises(self):
        """Fixed content alone exceeds max_chars → RepairPlanTooLargeError."""
        fc = _compute_fixed_content("complete")
        max_chars = len(fc) - 1
        groups = [_make_repair_group()]
        with pytest.raises(RepairPlanTooLargeError):
            _generate_agent_prompt(groups, "complete", max_chars)

    def test_empty_groups_returns_fixed_content(self):
        """Empty repair_groups → prompt == fixed_content."""
        fc = _compute_fixed_content("complete")
        prompt = _generate_agent_prompt([], "complete", len(fc) + 1000)
        assert prompt == fc
        assert len(prompt) <= len(fc) + 1000

    @pytest.mark.parametrize("plan_status", ["complete", "partial"])
    def test_boundary_value_loop(self, plan_status):
        """Loop over multiple boundary values — all results satisfy
        len(prompt) <= max_chars."""
        fc = _compute_fixed_content(plan_status)
        vh = "\n\n## 修复动作摘要\n\n"
        groups = [_make_repair_group() for _ in range(5)]

        # Test various max_chars values around the boundaries
        test_values = [
            len(fc) - 1,           # Below fixed → should raise
            len(fc),               # Exactly fixed
            len(fc) + 1,           # One above fixed
            len(fc) + len(vh) - 1, # Just below header
            len(fc) + len(vh),     # Exactly header
            len(fc) + len(vh) + 1, # One above header
            len(fc) + len(vh) + 50,  # Small room for groups
            len(fc) + len(vh) + 500, # More room
            100000,                # Large limit
        ]

        for max_chars in test_values:
            if max_chars < len(fc):
                with pytest.raises(RepairPlanTooLargeError):
                    _generate_agent_prompt(groups, plan_status, max_chars)
            else:
                prompt = _generate_agent_prompt(groups, plan_status, max_chars)
                assert len(prompt) <= max_chars, (
                    f"plan_status={plan_status}, max_chars={max_chars}, "
                    f"len(prompt)={len(prompt)}"
                )


# ---------------------------------------------------------------------------
# --- Fix 2: repair_group type validated before field access ---
# ---------------------------------------------------------------------------

class TestRepairGroupTypeValidation:
    """Verify corrupted repair_groups elements are caught as
    RepairPlanInternalError, never AttributeError/TypeError/KeyError."""

    @pytest.mark.parametrize("corrupt_groups", [
        ["damaged"],
        [123],
        [None],
        [[]],
    ])
    def test_get_repair_result_raises_internal_error(self, test_db, corrupt_groups):
        """Corrupted repair_groups → RepairPlanInternalError."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"] = corrupt_groups
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    @pytest.mark.parametrize("corrupt_groups", [
        ["damaged"],
        [123],
        [None],
        [[]],
    ])
    def test_api_returns_500(self, client, corrupt_groups):
        """Corrupted repair_groups → API returns 500
        REPAIR_PLAN_INTERNAL_ERROR."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"] = corrupt_groups
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_INTERNAL_ERROR

    @pytest.mark.parametrize("corrupt_groups", [
        ["damaged"],
        [123],
        [None],
        [[]],
    ])
    def test_no_attribute_error_leaks(self, test_db, corrupt_groups):
        """Corrupted repair_groups → no AttributeError/TypeError/KeyError
        or internal exception messages in the raised error."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"] = corrupt_groups
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError) as exc_info:
            get_repair_result(task_id)
        # The error message must NOT contain internal exception details
        msg = str(exc_info.value)
        assert "AttributeError" not in msg
        assert "TypeError" not in msg
        assert "KeyError" not in msg
        assert "has no attribute" not in msg
        assert "object is not" not in msg


# ---------------------------------------------------------------------------
# --- Fix 3: Shared snapshot semantics validation ---
# ---------------------------------------------------------------------------

class TestSharedSnapshotSemantics:
    """Verify serialization and read share the same semantic validation."""

    def test_complete_with_manual_review_serialization_rejects(self):
        """complete + MANUAL_REVIEW_REQUIRED → serialization rejects."""
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": "test",
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1,
                "blocking_repair_groups": 0,
                "manual_review_required": True,
                "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_MANUAL_REVIEW_REQUIRED,
                "priority": 12, "blocking": False,
                "highest_severity": "info", "highest_confidence": "low",
                "title": "Test", "description": "Test",
                "related_rule_ids": [], "related_files": [],
                "total_related_files": 0, "returned_related_files": 0,
                "related_files_truncated": False, "finding_count": 0,
                "steps": [], "commands": [], "safety_notes": [],
                "verification_steps": [],
            }],
            "verification_steps": [],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id="test",
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_complete_with_groups_truncated_rejects(self):
        """complete + groups_truncated + manual + rerun → serialization rejects."""
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": "test",
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 2,
                "blocking_repair_groups": 0,
                "manual_review_required": True,
                "coverage_warning": False,
                "groups_truncated": True,
            },
            "repair_groups": [
                {
                    "group_id": "RG001",
                    "action_code": ACTION_MANUAL_REVIEW_REQUIRED,
                    "priority": 12, "blocking": False,
                    "highest_severity": "info", "highest_confidence": "low",
                    "title": "Test", "description": "Test",
                    "related_rule_ids": [], "related_files": [],
                    "total_related_files": 0, "returned_related_files": 0,
                    "related_files_truncated": False, "finding_count": 0,
                    "steps": [], "commands": [], "safety_notes": [],
                    "verification_steps": [],
                },
                {
                    "group_id": "RG002",
                    "action_code": ACTION_RERUN_SECURITY_SCAN,
                    "priority": 13, "blocking": False,
                    "highest_severity": "info", "highest_confidence": "low",
                    "title": "Test", "description": "Test",
                    "related_rule_ids": [], "related_files": [],
                    "total_related_files": 0, "returned_related_files": 0,
                    "related_files_truncated": False, "finding_count": 0,
                    "steps": [], "commands": [], "safety_notes": [],
                    "verification_steps": [],
                },
            ],
            "verification_steps": [],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id="test",
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_complete_with_related_files_truncated_rejects(self):
        """complete + related_files_truncated → serialization rejects."""
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": "test",
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1,
                "blocking_repair_groups": 1,
                "manual_review_required": False,
                "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": ["config.py"],
                "total_related_files": 5, "returned_related_files": 1,
                "related_files_truncated": True, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id="test",
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_partial_without_reason_rejects(self):
        """partial but no partial-trigger action, no truncation → rejects."""
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": "test",
            "plan_status": "partial",
            "summary": {
                "total_repair_groups": 1,
                "blocking_repair_groups": 1,
                "manual_review_required": False,
                "coverage_warning": True,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": ["config.py"],
                "total_related_files": 1, "returned_related_files": 1,
                "related_files_truncated": False, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id="test",
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_valid_complete_passes_both_boundaries(self, test_db):
        """Valid complete plan: serialization and read both pass."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        # Verify read validation passes
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        result = get_repair_result(task_id)
        assert result is not None
        assert result["plan_status"] == "complete"

    def test_valid_partial_passes_both_boundaries(self, test_db):
        """Valid partial plan: serialization and read both pass."""
        task_id = _make_task()
        safe = _make_valid_partial_safe_plan(task_id=task_id)
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
            plan_status="partial",
            total_repair_groups=1,
            blocking_repair_groups=0,
        )
        result = get_repair_result(task_id)
        assert result is not None
        assert result["plan_status"] == "partial"

    @pytest.mark.parametrize("plan_status,has_manual", [
        ("complete", False),
        ("partial", True),
    ])
    def test_serialize_success_passes_read_semantics(self, plan_status, has_manual):
        """Every serialize success result passes read semantic validation."""
        if plan_status == "complete":
            safe = _make_valid_safe_plan()
        else:
            safe = _make_valid_partial_safe_plan()

        # The serialized result must pass read-boundary semantic validation
        _validate_repair_snapshot_semantics(
            plan_status=safe["plan_status"],
            summary=safe["summary"],
            repair_groups=safe["repair_groups"],
            error_cls=RepairPlanInternalError,
        )


# ---------------------------------------------------------------------------
# --- Fix 4: related_files normalization ---
# ---------------------------------------------------------------------------

class TestRelatedFilesNormalization:
    """Verify related_files are normalized at serialization and validated
    at read boundary."""

    def test_duplicates_deduplicated(self, test_db):
        """related_files = ["config.py", "config.py"] → only one kept."""
        task_id = _make_task()
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1, "blocking_repair_groups": 1,
                "manual_review_required": False, "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": ["config.py", "config.py"],
                "total_related_files": 2, "returned_related_files": 2,
                "related_files_truncated": False, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=plan,
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        files = safe["repair_groups"][0]["related_files"]
        assert files == ["config.py"]
        assert safe["repair_groups"][0]["returned_related_files"] == 1
        assert safe["repair_groups"][0]["total_related_files"] == 1
        assert safe["repair_groups"][0]["related_files_truncated"] is False

    def test_unsorted_sorted(self, test_db):
        """related_files = ["z.py", "a.py"] → sorted to ["a.py", "z.py"]."""
        task_id = _make_task()
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1, "blocking_repair_groups": 1,
                "manual_review_required": False, "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": ["z.py", "a.py"],
                "total_related_files": 2, "returned_related_files": 2,
                "related_files_truncated": False, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=plan,
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        files = safe["repair_groups"][0]["related_files"]
        assert files == ["a.py", "z.py"]

    def test_empty_string_removed(self, test_db):
        """related_files containing empty string after sanitization
        → empty removed, not in output."""
        task_id = _make_task()
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1, "blocking_repair_groups": 1,
                "manual_review_required": False, "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": ["config.py", ""],
                "total_related_files": 2, "returned_related_files": 2,
                "related_files_truncated": False, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=plan,
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        files = safe["repair_groups"][0]["related_files"]
        assert files == ["config.py"]
        assert "" not in files

    def test_redacted_path_duplicates_deduplicated(self, test_db):
        """Multiple unsafe paths → all become <redacted-path>,
        duplicates deduplicated to one."""
        task_id = _make_task()
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "complete",
            "summary": {
                "total_repair_groups": 1, "blocking_repair_groups": 1,
                "manual_review_required": False, "coverage_warning": False,
                "groups_truncated": False,
            },
            "repair_groups": [{
                "group_id": "RG001",
                "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                "priority": 1, "blocking": True,
                "highest_severity": "critical", "highest_confidence": "high",
                "title": "Test", "description": "Test",
                "related_rule_ids": ["R001_GITHUB_TOKEN"],
                "related_files": [
                    "/etc/secrets/config.py",
                    "C:\\Users\\admin\\keys.txt",
                    "src/safe.py",
                ],
                "total_related_files": 3, "returned_related_files": 3,
                "related_files_truncated": False, "finding_count": 1,
                "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                "verification_steps": ["verify1"],
            }],
            "verification_steps": ["step1"],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=plan,
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        files = safe["repair_groups"][0]["related_files"]
        assert files == ["<redacted-path>", "src/safe.py"]
        assert files.count("<redacted-path>") == 1

    def test_truncated_preserves_total(self, test_db):
        """When input is truncated, normalization preserves total count.
        related_files_truncated requires partial status with
        MANUAL_REVIEW_REQUIRED and RERUN_SECURITY_SCAN."""
        task_id = _make_task()
        plan = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "repair_scope": REPAIR_SCOPE,
            "task_id": task_id,
            "plan_status": "partial",
            "summary": {
                "total_repair_groups": 3, "blocking_repair_groups": 1,
                "manual_review_required": True, "coverage_warning": True,
                "groups_truncated": False,
            },
            "repair_groups": [
                {
                    "group_id": "RG001",
                    "action_code": ACTION_REVOKE_OR_ROTATE_SECRET,
                    "priority": 1, "blocking": True,
                    "highest_severity": "critical", "highest_confidence": "high",
                    "title": "Test", "description": "Test",
                    "related_rule_ids": ["R001_GITHUB_TOKEN"],
                    "related_files": ["config.py", "config.py"],
                    "total_related_files": 5, "returned_related_files": 2,
                    "related_files_truncated": True, "finding_count": 1,
                    "steps": ["step1"], "commands": [], "safety_notes": ["note"],
                    "verification_steps": ["verify1"],
                },
                {
                    "group_id": "RG002",
                    "action_code": ACTION_MANUAL_REVIEW_REQUIRED,
                    "priority": 12, "blocking": False,
                    "highest_severity": "info", "highest_confidence": "low",
                    "title": "Test", "description": "Test",
                    "related_rule_ids": [], "related_files": [],
                    "total_related_files": 0, "returned_related_files": 0,
                    "related_files_truncated": False, "finding_count": 0,
                    "steps": [], "commands": [], "safety_notes": [],
                    "verification_steps": [],
                },
                {
                    "group_id": "RG003",
                    "action_code": ACTION_RERUN_SECURITY_SCAN,
                    "priority": 13, "blocking": False,
                    "highest_severity": "info", "highest_confidence": "low",
                    "title": "Test", "description": "Test",
                    "related_rule_ids": [], "related_files": [],
                    "total_related_files": 0, "returned_related_files": 0,
                    "related_files_truncated": False, "finding_count": 0,
                    "steps": [], "commands": [], "safety_notes": [],
                    "verification_steps": [],
                },
            ],
            "verification_steps": [],
            "agent_prompt": "",
            "source_scan_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_updated_at": "2026-01-01T00:00:00Z",
            "source_assessment_policy_version": "p0-6-v1",
            "created_at": None, "updated_at": None,
        }
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=plan,
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        grp = safe["repair_groups"][0]
        assert grp["related_files"] == ["config.py"]
        assert grp["returned_related_files"] == 1
        assert grp["total_related_files"] == 5
        assert grp["related_files_truncated"] is True

    def test_read_rejects_duplicates(self, test_db):
        """Corrupted DB with duplicate related_files → RepairPlanInternalError."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["config.py", "config.py"]
        safe["repair_groups"][0]["returned_related_files"] = 2
        safe["repair_groups"][0]["total_related_files"] = 2
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    def test_read_rejects_empty_string(self, test_db):
        """Corrupted DB with empty string in related_files → error."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["config.py", ""]
        safe["repair_groups"][0]["returned_related_files"] = 2
        safe["repair_groups"][0]["total_related_files"] = 2
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    def test_read_rejects_unsorted(self, test_db):
        """Corrupted DB with unsorted related_files → error."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["z.py", "a.py"]
        safe["repair_groups"][0]["returned_related_files"] = 2
        safe["repair_groups"][0]["total_related_files"] = 2
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)
