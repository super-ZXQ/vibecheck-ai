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
    _validate_repair_snapshot_identity,
    _validate_persisted_repair_plan,
    _sanitize_file_path,
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

    def test_empty_string_rejected(self, test_db):
        """related_files containing empty string → RepairPlanSerializationError.

        Empty paths must NOT be silently deleted — silent deletion would
        lose Finding positions. The serialization boundary must reject
        them explicitly."""
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
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id=task_id,
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

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


# ===========================================================================
# Sixth-round: Identity field validation at serialization boundary
# ===========================================================================

class TestSnapshotIdentitySerialization:
    """Verify serialize_repair_plan rejects invalid identity fields."""

    def _make_base_plan(self, task_id="test-task"):
        return {
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

    def _serialize(self, **overrides):
        """Call serialize_repair_plan with given parameter overrides."""
        defaults = dict(
            task_id="test-task",
            repair_plan=self._make_base_plan(),
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        defaults.update(overrides)
        return serialize_repair_plan(**defaults)

    def test_task_id_empty_rejected(self):
        """task_id='' → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(task_id="")

    def test_source_scan_updated_at_empty_rejected(self):
        """source_scan_updated_at='' → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(source_scan_updated_at="")

    def test_source_assessment_updated_at_none_rejected(self):
        """source_assessment_updated_at=None → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(source_assessment_updated_at=None)

    def test_source_assessment_policy_version_wrong_rejected(self):
        """source_assessment_policy_version='wrong' → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(source_assessment_policy_version="wrong")

    def test_created_at_none_rejected(self):
        """created_at=None → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(created_at=None)

    def test_updated_at_list_rejected(self):
        """updated_at=[] → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(updated_at=[])

    def test_task_id_int_rejected(self):
        """task_id=123 (int, not str) → RepairPlanSerializationError.
        No implicit str conversion allowed."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(task_id=123)

    def test_created_at_bool_rejected(self):
        """created_at=True (bool) → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(created_at=True)

    def test_source_scan_updated_at_float_rejected(self):
        """source_scan_updated_at=1.5 (float) → RepairPlanSerializationError."""
        with pytest.raises(RepairPlanSerializationError):
            self._serialize(source_scan_updated_at=1.5)

    def test_valid_identity_fields_pass_both_boundaries(self, test_db):
        """Valid top-level fields → serialization and full read validation
        both pass.

        Assembles matching db_columns from the serialized result and passes
        them to _validate_persisted_repair_plan — must pass normally.
        """
        task_id = _make_task()
        safe = serialize_repair_plan(
            task_id=task_id,
            repair_plan=self._make_base_plan(task_id=task_id),
            source_scan_updated_at="2026-01-01T00:00:00Z",
            source_assessment_updated_at="2026-01-01T00:00:00Z",
            source_assessment_policy_version="p0-6-v1",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )

        # Assemble matching db_columns from safe_plan
        db_columns = {
            "task_id": safe["task_id"],
            "plan_status": safe["plan_status"],
            "total_repair_groups": safe["summary"]["total_repair_groups"],
            "blocking_repair_groups": safe["summary"]["blocking_repair_groups"],
            "source_scan_updated_at": safe["source_scan_updated_at"],
            "source_assessment_updated_at": safe["source_assessment_updated_at"],
            "source_assessment_policy_version": safe["source_assessment_policy_version"],
            "created_at": safe["created_at"],
            "updated_at": safe["updated_at"],
        }

        # Must pass full persisted validation
        result = _validate_persisted_repair_plan(safe, task_id, db_columns)
        assert result is not None
        assert result["task_id"] == task_id

        # Also verify via the full read path
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        retrieved = get_repair_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id


# ===========================================================================
# Sixth-round: Empty related_files rejection (no silent deletion)
# ===========================================================================

class TestEmptyRelatedFilesRejection:
    """Verify empty related_files are rejected, never silently deleted."""

    def _make_plan_with_files(self, task_id, related_files, total=None,
                              returned=None, truncated=False):
        if total is None:
            total = len(related_files)
        if returned is None:
            returned = len(related_files)
        return {
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
                "related_files": related_files,
                "total_related_files": total,
                "returned_related_files": returned,
                "related_files_truncated": truncated,
                "finding_count": 1,
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

    def test_only_empty_string_rejected(self, test_db):
        """related_files=[''] → RepairPlanSerializationError.

        Must NOT silently delete to produce []."""
        task_id = _make_task()
        plan = self._make_plan_with_files(task_id, [""])
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id=task_id,
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_empty_string_with_valid_rejected(self, test_db):
        """related_files=['config.py', ''] → RepairPlanSerializationError."""
        task_id = _make_task()
        plan = self._make_plan_with_files(task_id, ["config.py", ""])
        with pytest.raises(RepairPlanSerializationError):
            serialize_repair_plan(
                task_id=task_id,
                repair_plan=plan,
                source_scan_updated_at="2026-01-01T00:00:00Z",
                source_assessment_updated_at="2026-01-01T00:00:00Z",
                source_assessment_policy_version="p0-6-v1",
                created_at="2026-01-01T00:00:00Z",
                updated_at="2026-01-01T00:00:00Z",
            )

    def test_redacted_path_input_duplicates_deduplicated(self, test_db):
        """related_files=['<redacted-path>', '<redacted-path>'] →
        output one '<redacted-path>'.

        <redacted-path> is a valid safe placeholder; duplicates are
        deduplicated normally."""
        task_id = _make_task()
        plan = self._make_plan_with_files(
            task_id, ["<redacted-path>", "<redacted-path>"],
        )
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
        assert files == ["<redacted-path>"]
        assert safe["repair_groups"][0]["returned_related_files"] == 1
        assert safe["repair_groups"][0]["total_related_files"] == 1

    def test_read_empty_string_api_500(self, client):
        """Corrupted DB with empty string in related_files →
        RepairPlanInternalError → API 500."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = [""]
        safe["repair_groups"][0]["returned_related_files"] = 1
        safe["repair_groups"][0]["total_related_files"] = 1
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        response = client.get(f"/api/check/{task_id}/repair-plan")
        assert response.status_code == 500
        assert response.json()["detail"]["error_code"] == REPAIR_PLAN_INTERNAL_ERROR


# ===========================================================================
# Sixth-round: Path normalization before deduplication
# ===========================================================================

class TestPathNormalization:
    """Verify _sanitize_file_path normalizes paths to canonical form
    before deduplication."""

    def test_backslash_normalized(self):
        """src\\config.py → src/config.py."""
        assert _sanitize_file_path("src\\config.py") == "src/config.py"

    def test_dot_slash_normalized(self):
        """./src/config.py → src/config.py."""
        assert _sanitize_file_path("./src/config.py") == "src/config.py"

    def test_double_slash_normalized(self):
        """src//config.py → src/config.py."""
        assert _sanitize_file_path("src//config.py") == "src/config.py"

    def test_multiple_normalizations_combined(self):
        """./src//config\\..py segments are handled correctly."""
        # ./src//config.py → src/config.py
        assert _sanitize_file_path("./src//config.py") == "src/config.py"

    def test_all_variants_deduplicate(self, test_db):
        """['src\\\\config.py', 'src/config.py', './src/config.py',
        'src//config.py'] → ['src/config.py'].

        All four variants normalize to the same canonical path and
        must be deduplicated to a single entry."""
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
                    "src\\config.py",
                    "src/config.py",
                    "./src/config.py",
                    "src//config.py",
                ],
                "total_related_files": 4, "returned_related_files": 4,
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
        assert files == ["src/config.py"]
        assert safe["repair_groups"][0]["returned_related_files"] == 1
        assert safe["repair_groups"][0]["total_related_files"] == 1

    def test_read_rejects_backslash(self, test_db):
        """Corrupted DB with backslash in related_files →
        RepairPlanInternalError (path not in canonical form)."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["src\\config.py"]
        safe["repair_groups"][0]["returned_related_files"] = 1
        safe["repair_groups"][0]["total_related_files"] = 1
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    def test_read_rejects_dot_slash(self, test_db):
        """Corrupted DB with ./ prefix in related_files →
        RepairPlanInternalError (path not in canonical form)."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["./config.py"]
        safe["repair_groups"][0]["returned_related_files"] = 1
        safe["repair_groups"][0]["total_related_files"] = 1
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

    def test_read_rejects_double_slash(self, test_db):
        """Corrupted DB with // in related_files →
        RepairPlanInternalError (path not in canonical form)."""
        task_id = _make_task()
        safe = _make_valid_safe_plan(task_id=task_id)
        safe["repair_groups"][0]["related_files"] = ["src//config.py"]
        safe["repair_groups"][0]["returned_related_files"] = 1
        safe["repair_groups"][0]["total_related_files"] = 1
        safe["repair_groups"][0]["related_files_truncated"] = False
        _insert_raw_repair_row(
            task_id, json.dumps(safe, ensure_ascii=False),
        )
        with pytest.raises(RepairPlanInternalError):
            get_repair_result(task_id)

