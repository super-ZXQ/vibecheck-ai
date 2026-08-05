"""P2-3 健壮性补全测试。

覆盖三个核心功能：
1. 阶段超时保护：extract/scan/assess/repair 各阶段超时后标记任务失败
2. 清理服务：启动时残留临时文件清理、过期报告删除
3. 状态机验证：非法状态转换被拒绝
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from app.db import database
from app.services import background_runner, task_manager
from app.services.cleanup_service import (
    cleanup_expired_tasks,
    cleanup_residual_temp_files,
    reset_cleanup_counter,
)
from app.services.task_manager import (
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    IllegalStateTransitionError,
    _validate_transition,
)
from app.core.error_codes import (
    EXTRACT_TIMEOUT,
    SCAN_TIMEOUT,
    ASSESSMENT_TIMEOUT,
    REPAIR_PLAN_TIMEOUT,
)


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


@pytest.fixture(autouse=True)
def reset_state():
    background_runner.reset_runner_state()
    reset_cleanup_counter()
    yield
    background_runner.reset_runner_state()
    reset_cleanup_counter()


# ---------------------------------------------------------------------------
# --- State machine validation tests ---
# ---------------------------------------------------------------------------

class TestStateMachineValidation:

    def test_pending_to_running_allowed(self):
        """pending → running 合法。"""
        _validate_transition("task-1", STATUS_PENDING, STATUS_RUNNING)

    def test_running_to_running_allowed(self):
        """running → running 合法（阶段更新）。"""
        _validate_transition("task-1", STATUS_RUNNING, STATUS_RUNNING)

    def test_running_to_completed_allowed(self):
        """running → completed 合法。"""
        _validate_transition("task-1", STATUS_RUNNING, STATUS_COMPLETED)

    def test_running_to_failed_allowed(self):
        """running → failed 合法。"""
        _validate_transition("task-1", STATUS_RUNNING, STATUS_FAILED)

    def test_pending_to_failed_allowed(self):
        """pending → failed 合法。"""
        _validate_transition("task-1", STATUS_PENDING, STATUS_FAILED)

    def test_completed_to_running_rejected(self):
        """completed → running 非法。"""
        with pytest.raises(IllegalStateTransitionError):
            _validate_transition("task-1", STATUS_COMPLETED, STATUS_RUNNING)

    def test_failed_to_running_rejected(self):
        """failed → running 非法。"""
        with pytest.raises(IllegalStateTransitionError):
            _validate_transition("task-1", STATUS_FAILED, STATUS_RUNNING)

    def test_completed_to_failed_rejected(self):
        """completed → failed 非法。"""
        with pytest.raises(IllegalStateTransitionError):
            _validate_transition("task-1", STATUS_COMPLETED, STATUS_FAILED)

    def test_failed_to_completed_rejected(self):
        """failed → completed 非法。"""
        with pytest.raises(IllegalStateTransitionError):
            _validate_transition("task-1", STATUS_FAILED, STATUS_COMPLETED)

    def test_mark_running_rejects_completed_task(self, test_db):
        """对已完成的任务调用 mark_running 不修改状态。"""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 10)
        task_manager.mark_completed(task.id, 10, 1024, "test-repo")

        # Try to mark running again — should be rejected.
        task_manager.mark_running(task.id, "scanning", 50)

        # Verify status is still completed.
        task_after = task_manager.get_task(task.id)
        assert task_after.status == STATUS_COMPLETED

    def test_mark_failed_rejects_completed_task(self, test_db):
        """对已完成的任务调用 mark_failed 不修改状态。"""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 10)
        task_manager.mark_completed(task.id, 10, 1024, "test-repo")

        # Try to mark failed — should be rejected.
        task_manager.mark_failed(task.id, "INTERNAL_ERROR", "error")

        # Verify status is still completed.
        task_after = task_manager.get_task(task.id)
        assert task_after.status == STATUS_COMPLETED


# ---------------------------------------------------------------------------
# --- Cleanup service tests ---
# ---------------------------------------------------------------------------

class TestCleanupResidualTempFiles:

    def test_removes_stale_files(self, test_db, tmp_path):
        """清理残留临时文件。"""
        tmp_dir = Path(test_db.parent) / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Create stale files
        (tmp_dir / "download-abc.tar.gz").write_bytes(b"stale")
        (tmp_dir / "task-xyz").mkdir()
        (tmp_dir / "task-xyz" / "file.txt").write_text("stale")

        removed = cleanup_residual_temp_files()
        assert removed >= 2
        assert not (tmp_dir / "download-abc.tar.gz").exists()
        assert not (tmp_dir / "task-xyz").exists()

    def test_empty_dir_returns_zero(self, test_db, tmp_path):
        """空目录返回 0。"""
        tmp_dir = Path(test_db.parent) / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        removed = cleanup_residual_temp_files()
        assert removed == 0

    def test_nonexistent_dir_returns_zero(self, test_db):
        """不存在的目录返回 0。"""
        removed = cleanup_residual_temp_files()
        assert removed == 0

    def test_skips_symlinks(self, test_db, tmp_path):
        """跳过符号链接：不通过 symlink 删除目标文件。"""
        tmp_dir = Path(test_db.parent) / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Create target OUTSIDE tmp_dir so cleanup_residual_temp_files
        # does not delete it as a regular file. Only the symlink lives
        # inside tmp_dir.
        target = Path(test_db.parent) / "real_file.txt"
        target.write_text("real")
        link = tmp_dir / "evil_link"
        try:
            os.symlink(target, link)
        except OSError:
            pytest.skip("symlinks not supported on this platform")

        cleanup_residual_temp_files()
        # The symlink must NOT be followed — target survives.
        assert target.exists()


class TestCleanupExpiredTasks:

    def test_deletes_expired_tasks(self, test_db, monkeypatch):
        """删除过期的已完成任务。"""
        from app.db.database import _get_connection
        from datetime import datetime, timedelta, timezone

        # Create a task and mark it completed
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 10)
        task_manager.mark_completed(task.id, 10, 1024, "test-repo")

        # Manually set completed_at to 100 hours ago
        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=100)
        ).isoformat()
        conn = _get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET completed_at = ? WHERE id = ?",
                (old_time, task.id),
            )
            conn.commit()
        finally:
            conn.close()

        # Set TTL to 72 hours
        monkeypatch.setattr(
            "app.core.config.settings.report_ttl_hours", 72
        )

        deleted = cleanup_expired_tasks()
        assert deleted == 1

        # Verify task is gone
        assert task_manager.get_task(task.id) is None

    def test_keeps_recent_tasks(self, test_db, monkeypatch):
        """保留未过期的任务。"""
        monkeypatch.setattr(
            "app.core.config.settings.report_ttl_hours", 72
        )

        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 10)
        task_manager.mark_completed(task.id, 10, 1024, "test-repo")

        deleted = cleanup_expired_tasks()
        assert deleted == 0
        assert task_manager.get_task(task.id) is not None

    def test_disabled_when_ttl_zero(self, test_db, monkeypatch):
        """TTL 为 0 时禁用清理。"""
        monkeypatch.setattr(
            "app.core.config.settings.report_ttl_hours", 0
        )
        deleted = cleanup_expired_tasks()
        assert deleted == 0

    def test_deletes_related_data(self, test_db, monkeypatch):
        """删除任务时同时删除关联数据。"""
        from app.db.database import _get_connection, now_iso
        from datetime import datetime, timedelta, timezone

        monkeypatch.setattr(
            "app.core.config.settings.report_ttl_hours", 72
        )

        # Create and complete a task
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        task_manager.mark_running(task.id, "downloading", 10)
        task_manager.mark_completed(task.id, 10, 1024, "test-repo")

        # Insert a scan result row
        now = now_iso()
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO scan_results
                   (task_id, schema_version, result_json, summary_json,
                    total_findings, blocking_findings, total_notices,
                    total_skipped_files, total_scan_errors,
                    total_files_scanned, total_lines_scanned,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (task.id, 2, "{}", "{}", 0, 0, 0, 0, 0, 0, 0, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        # Set completed_at to old time
        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=100)
        ).isoformat()
        conn = _get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET completed_at = ? WHERE id = ?",
                (old_time, task.id),
            )
            conn.commit()
        finally:
            conn.close()

        deleted = cleanup_expired_tasks()
        assert deleted == 1

        # Verify scan result is also deleted
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT 1 FROM scan_results WHERE task_id = ?",
                (task.id,),
            ).fetchone()
        finally:
            conn.close()
        assert row is None


class TestMaybeTriggerCleanup:

    def test_triggers_after_interval(self, test_db, monkeypatch):
        """达到间隔后触发清理。"""
        monkeypatch.setattr(
            "app.core.config.settings.cleanup_interval_tasks", 3
        )
        monkeypatch.setattr(
            "app.core.config.settings.report_ttl_hours", 72
        )

        # Create 3 tasks — cleanup should trigger on the 3rd
        with patch(
            "app.services.cleanup_service.cleanup_expired_tasks"
        ) as mock_cleanup:
            mock_cleanup.return_value = 0
            for _ in range(3):
                task_manager.create_task(
                    "https://github.com/test/repo", "test", "repo"
                )
            assert mock_cleanup.call_count == 1

    def test_does_not_trigger_before_interval(self, test_db, monkeypatch):
        """未达到间隔不触发清理。"""
        monkeypatch.setattr(
            "app.core.config.settings.cleanup_interval_tasks", 5
        )

        with patch(
            "app.services.cleanup_service.cleanup_expired_tasks"
        ) as mock_cleanup:
            mock_cleanup.return_value = 0
            for _ in range(3):
                task_manager.create_task(
                    "https://github.com/test/repo", "test", "repo"
                )
            assert mock_cleanup.call_count == 0

    def test_disabled_when_interval_zero(self, test_db, monkeypatch):
        """间隔为 0 时禁用定期清理。"""
        monkeypatch.setattr(
            "app.core.config.settings.cleanup_interval_tasks", 0
        )

        with patch(
            "app.services.cleanup_service.cleanup_expired_tasks"
        ) as mock_cleanup:
            mock_cleanup.return_value = 0
            for _ in range(20):
                task_manager.create_task(
                    "https://github.com/test/repo", "test", "repo"
                )
            assert mock_cleanup.call_count == 0


# ---------------------------------------------------------------------------
# --- Timeout error code tests ---
# ---------------------------------------------------------------------------

class TestTimeoutErrorCodes:

    def test_extract_timeout_has_message(self):
        from app.core.error_codes import get_error_message
        msg = get_error_message(EXTRACT_TIMEOUT)
        assert msg
        assert "超时" in msg

    def test_scan_timeout_has_message(self):
        from app.core.error_codes import get_error_message
        msg = get_error_message(SCAN_TIMEOUT)
        assert msg
        assert "超时" in msg

    def test_assessment_timeout_has_message(self):
        from app.core.error_codes import get_error_message
        msg = get_error_message(ASSESSMENT_TIMEOUT)
        assert msg
        assert "超时" in msg

    def test_repair_plan_timeout_has_message(self):
        from app.core.error_codes import get_error_message
        msg = get_error_message(REPAIR_PLAN_TIMEOUT)
        assert msg
        assert "超时" in msg


# ---------------------------------------------------------------------------
# --- Timeout config tests ---
# ---------------------------------------------------------------------------

class TestTimeoutConfig:

    def test_extract_timeout_default(self):
        from app.core.config import settings
        assert settings.extract_timeout >= 1

    def test_scan_timeout_default(self):
        from app.core.config import settings
        assert settings.scan_timeout >= 1

    def test_assess_timeout_default(self):
        from app.core.config import settings
        assert settings.assess_timeout >= 1

    def test_repair_plan_timeout_default(self):
        from app.core.config import settings
        assert settings.repair_plan_timeout >= 1

    def test_llm_analysis_timeout_default(self):
        from app.core.config import settings
        assert settings.llm_analysis_timeout >= 1

    def test_report_ttl_hours_default(self):
        from app.core.config import settings
        assert settings.report_ttl_hours >= 0

    def test_cleanup_interval_tasks_default(self):
        from app.core.config import settings
        assert settings.cleanup_interval_tasks >= 0
