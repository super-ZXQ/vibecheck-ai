"""Tests for service restart hook — P0-3.

Tests that stale running and pending tasks are correctly marked as failed
when the service restarts. Also verifies that completed/failed tasks are
not affected.

Test coverage:
9. Service startup marks running tasks as failed
10. Service startup marks pending tasks as failed
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import SERVICE_RESTARTED, get_error_message
from app.db import database
from app.services import task_manager


# --- Fixtures ---

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Set up a temporary test database."""
    db_path = tmp_path / "test_restart.db"
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


# ============================================================
# Test 9 & 10: Service restart marks stale tasks as failed
# ============================================================

class TestMarkStaleTasks:
    """Tests for mark_stale_tasks_as_failed() — the restart hook."""

    def test_running_tasks_marked_failed(self, test_db):
        """Running tasks should be marked as failed on service restart."""
        # Create a task and manually set it to running
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        task_manager.mark_running(task.id, "downloading", 25)

        # Verify it's running
        assert task_manager.get_task(task.id).status == "running"

        # Simulate service restart
        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 1

        # Verify the task is now failed
        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == SERVICE_RESTARTED
        assert result.error_message == get_error_message(SERVICE_RESTARTED)
        assert result.completed_at is not None

    def test_pending_tasks_marked_failed(self, test_db):
        """Pending tasks should be marked as failed on service restart."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        assert task_manager.get_task(task.id).status == "pending"

        # Simulate service restart
        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 1

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == SERVICE_RESTARTED
        assert result.completed_at is not None

    def test_completed_tasks_not_affected(self, test_db):
        """Completed tasks should NOT be affected by service restart."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        task_manager.mark_completed(task.id, 5, 1024, "test-repo")

        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 0  # No stale tasks

        result = task_manager.get_task(task.id)
        assert result.status == "completed"
        assert result.error_code is None

    def test_already_failed_tasks_not_affected(self, test_db):
        """Already-failed tasks should NOT be affected by service restart."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        task_manager.mark_failed(task.id, "DOWNLOAD_FAILED")

        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 0

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "DOWNLOAD_FAILED"

    def test_mixed_tasks_only_stale_marked(self, test_db):
        """Only running and pending tasks should be marked as failed."""
        # Create tasks in different states
        running_task = task_manager.create_task(
            "https://github.com/user1/repo1", "user1", "repo1"
        )
        task_manager.mark_running(running_task.id, "extracting", 50)

        pending_task = task_manager.create_task(
            "https://github.com/user2/repo2", "user2", "repo2"
        )

        completed_task = task_manager.create_task(
            "https://github.com/user3/repo3", "user3", "repo3"
        )
        task_manager.mark_completed(completed_task.id, 3, 500, "repo3")

        failed_task = task_manager.create_task(
            "https://github.com/user4/repo4", "user4", "repo4"
        )
        task_manager.mark_failed(failed_task.id, "DOWNLOAD_FAILED")

        # Simulate service restart
        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 2  # running + pending

        # Verify states
        assert task_manager.get_task(running_task.id).status == "failed"
        assert task_manager.get_task(running_task.id).error_code == SERVICE_RESTARTED

        assert task_manager.get_task(pending_task.id).status == "failed"
        assert task_manager.get_task(pending_task.id).error_code == SERVICE_RESTARTED

        assert task_manager.get_task(completed_task.id).status == "completed"
        assert task_manager.get_task(failed_task.id).status == "failed"
        assert task_manager.get_task(failed_task.id).error_code == "DOWNLOAD_FAILED"

    def test_no_stale_tasks_returns_zero(self, test_db):
        """No stale tasks should return 0."""
        count = task_manager.mark_stale_tasks_as_failed()
        assert count == 0


# ============================================================
# Test: Startup event integration
# ============================================================

class TestStartupEvent:
    """Tests for the FastAPI startup event integration."""

    def test_startup_marks_stale_tasks(self, test_db):
        """The startup event should mark stale tasks as failed."""
        # Create stale tasks before starting the app
        running_task = task_manager.create_task(
            "https://github.com/user1/repo1", "user1", "repo1"
        )
        task_manager.mark_running(running_task.id, "downloading", 10)

        pending_task = task_manager.create_task(
            "https://github.com/user2/repo2", "user2", "repo2"
        )

        # Start the app — startup event will run
        from app.main import app
        with TestClient(app) as client:
            # Verify health check works
            response = client.get("/api/health")
            assert response.status_code == 200

        # Verify stale tasks are now failed
        r1 = task_manager.get_task(running_task.id)
        assert r1.status == "failed"
        assert r1.error_code == SERVICE_RESTARTED

        r2 = task_manager.get_task(pending_task.id)
        assert r2.status == "failed"
        assert r2.error_code == SERVICE_RESTARTED

    def test_startup_error_message_is_safe(self, test_db):
        """The SERVICE_RESTARTED error message must be safe for users."""
        task = task_manager.create_task(
            "https://github.com/user/repo", "user", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 50)

        task_manager.mark_stale_tasks_as_failed()

        result = task_manager.get_task(task.id)
        msg = result.error_message or ""

        # Must NOT contain sensitive content
        assert "/tmp/" not in msg
        assert "Traceback" not in msg
        assert "ghp_" not in msg
        assert "token" not in msg.lower()
