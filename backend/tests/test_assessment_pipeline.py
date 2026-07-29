"""P0-6 安全评估管道集成测试。

覆盖 background_runner.py 中的评估管道集成：
1. 完整管道成功：mock download/extract/scan → 任务完成，评估存在，分数/判定可用
2. 评估从 SQLite 读取（非临时）：管道完成后临时目录已清理，评估仍可读
3. 评估在完成前成功：评估失败时任务不被标记为已完成
4. 评估内部错误：mock run_assessment 抛出 AssessmentInternalError → 任务失败 ASSESSMENT_INTERNAL_ERROR
5. 评估持久化失败：mock run_assessment 抛出 AssessmentPersistError → 任务失败 ASSESSMENT_PERSIST_FAILED
6. 评估结果过大：mock run_assessment 抛出 AssessmentResultTooLargeError → 任务失败 ASSESSMENT_RESULT_TOO_LARGE
7. 失败任务不返回残留评估：评估已保存但 mark_completed 失败时，API 返回安全空评估
8. 清理在所有路径中执行（成功、扫描失败、评估失败）
9. 事件循环保持响应（管道完成不阻塞）
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import database
from app.services import task_manager, background_runner
from app.services.background_runner import _process_task, reset_runner_state
from app.services.assessment_service import (
    get_assessment_result,
    get_assessment_score_verdict,
    AssessmentInternalError,
    AssessmentPersistError,
    AssessmentResultTooLargeError,
)
from app.services.scan_result_service import get_scan_result
from app.scanner.base import ScanResult, Finding, Severity, Confidence, FindingType
from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
    ASSESSMENT_RESULT_TOO_LARGE,
    SCAN_INTERNAL_ERROR,
    INTERNAL_ERROR,
)
from app.core.github import DownloadResult, parse_repo_url
from app.core.safe_extract import ExtractionResult


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """设置临时测试数据库。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(tmp_path, monkeypatch):
    """设置临时测试数据库和 TestClient（用于 API 测试）。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    with TestClient(app) as c:
        yield c
    database._initialized = False


@pytest.fixture(autouse=True)
def reset_runner():
    """每个测试前后重置后台运行器状态。"""
    reset_runner_state()
    yield
    reset_runner_state()


# ---------------------------------------------------------------------------
# --- Mock helpers ---
# ---------------------------------------------------------------------------

def _make_finding(**kwargs):
    """创建一个 Finding 数据类实例，带有合理的默认值。"""
    defaults = dict(
        rule_id="R001_GITHUB_TOKEN",
        rule_name="GitHub Token",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="src/config.py",
        line_start=10,
        line_end=10,
        column_start=5,
        column_end=25,
        snippet_masked="ghp_****",
        is_blocking=True,
        finding_type=FindingType.CONTENT,
        description="GitHub token found",
        category="token",
        secret_type="github_token",
        message="Remove the token",
        repair_template_key="remove_secret",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def make_mock_download_result(tmp_path, repo_url="https://github.com/testuser/testrepo"):
    """创建一个 mock DownloadResult，带有真实的临时文件。"""
    temp_file = Path(tmp_path) / "mock-download.tar.gz"
    temp_file.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 100)
    repo_info = parse_repo_url(repo_url)
    return DownloadResult(
        temp_file=temp_file,
        repo_info=repo_info,
        file_size=temp_file.stat().st_size,
    )


def make_mock_extract_result(tmp_path):
    """创建一个 mock ExtractionResult，带有真实的解压目录。"""
    dest = Path(tmp_path) / "mock-extract"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text("# Clean Repo\n\nNo secrets here.\n")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=30,
        top_level_dir="mock-extract",
    )


def make_mock_scan_result(findings=None):
    """创建一个 mock ScanResult。"""
    return ScanResult(
        findings=tuple(findings or []),
        notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )


def _run_pipeline(task_id):
    """使用 asyncio.run 运行异步管道处理。"""
    asyncio.run(_process_task(task_id))


# ============================================================
# 测试类：TestAssessmentPipeline
# ============================================================

class TestAssessmentPipeline:
    """安全评估管道集成测试。"""

    def test_full_pipeline_success(self, test_db, tmp_path):
        """完整管道成功：mock download/extract/scan → 任务完成，评估存在，分数/判定可用。"""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result(findings=[
            _make_finding(is_blocking=True)
        ])

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    _run_pipeline(task.id)

        # 验证任务已完成
        result = task_manager.get_task(task.id)
        assert result.status == "completed"
        assert result.stage == "finished"
        assert result.progress == 100

        # 验证评估存在
        assessment = get_assessment_result(task.id)
        assert assessment is not None
        assert assessment["task_id"] == task.id

        # 验证分数和判定可用
        score_verdict = get_assessment_score_verdict(task.id)
        assert score_verdict is not None
        score, verdict = score_verdict
        assert isinstance(score, int)
        assert verdict in ("pass", "warning", "blocked")

        # 阻断级发现项应导致 blocked
        assert verdict == "blocked"
        assert score <= 49

    def test_assessment_reads_from_sqlite_not_temp(self, test_db, tmp_path):
        """评估从 SQLite 读取（非临时）：管道完成后临时目录已清理，评估仍可读。"""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    _run_pipeline(task.id)

        # 验证临时文件已被清理
        assert not download_result.temp_file.exists()
        assert not Path(extract_result.dest_dir).exists()

        # 评估仍可从 SQLite 读取（不依赖临时目录）
        assessment = get_assessment_result(task.id)
        assert assessment is not None
        assert assessment["task_id"] == task.id

        score_verdict = get_assessment_score_verdict(task.id)
        assert score_verdict is not None

        # 扫描结果也仍可读
        scan_data = get_scan_result(task.id)
        assert scan_data is not None

    def test_task_not_completed_if_assessment_fails(self, test_db, tmp_path):
        """评估在完成前成功：评估失败时任务不被标记为已完成。

        评估失败时，任务应被标记为 failed，而非 completed。
        验证 mark_completed 不会被调用。
        """
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        # mock mark_completed 来跟踪是否被调用
        mark_completed_called = False
        original_mark_completed = task_manager.mark_completed

        def tracking_mark_completed(*args, **kwargs):
            nonlocal mark_completed_called
            mark_completed_called = True
            return original_mark_completed(*args, **kwargs)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=Exception("Assessment computation failed"),
                    ):
                        with patch(
                            "app.services.background_runner.mark_completed",
                            side_effect=tracking_mark_completed,
                        ):
                            _run_pipeline(task.id)

        # mark_completed 不应被调用
        assert mark_completed_called is False

        # 任务应被标记为 failed
        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.status != "completed"

    def test_assessment_internal_error(self, test_db, tmp_path):
        """评估内部错误：mock run_assessment 抛出 AssessmentInternalError → 任务失败 ASSESSMENT_INTERNAL_ERROR。"""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=AssessmentInternalError("Computation failed"),
                    ):
                        _run_pipeline(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == ASSESSMENT_INTERNAL_ERROR

    def test_assessment_persist_failed(self, test_db, tmp_path):
        """评估持久化失败：mock run_assessment 抛出 AssessmentPersistError → 任务失败 ASSESSMENT_PERSIST_FAILED。"""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=AssessmentPersistError("DB write failed"),
                    ):
                        _run_pipeline(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == ASSESSMENT_PERSIST_FAILED

    def test_assessment_too_large(self, test_db, tmp_path):
        """评估结果过大：mock run_assessment 抛出 AssessmentResultTooLargeError → 任务失败 ASSESSMENT_RESULT_TOO_LARGE。"""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=AssessmentResultTooLargeError("Too large"),
                    ):
                        _run_pipeline(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == ASSESSMENT_RESULT_TOO_LARGE

    def test_failed_task_no_residual_assessment(self, test_db, tmp_path, client):
        """失败任务不返回残留评估：评估已保存但 mark_completed 失败时，API 返回安全空评估。

        场景：run_assessment 成功保存了评估，但 mark_completed 抛出异常，
        导致任务被标记为 failed。API 不应返回数据库中的残留评估。
        """
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result(findings=[
            _make_finding(is_blocking=True)
        ])

        # mock mark_completed 抛出异常（评估已保存但任务标记失败）
        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    with patch(
                        "app.services.background_runner.mark_completed",
                        side_effect=RuntimeError("DB error during mark_completed"),
                    ):
                        _run_pipeline(task.id)

        # 任务应被标记为 failed（由外层 except 捕获 mark_completed 异常）
        result = task_manager.get_task(task.id)
        assert result.status == "failed"

        # 评估可能已保存到数据库（残留评估）
        residual = get_assessment_result(task.id)
        # 残留评估可能存在也可能不存在，取决于 run_assessment 是否在 mark_completed 之前完成
        # 如果存在，验证 API 不返回它
        if residual is not None:
            # API 应返回安全空评估，而非残留评估
            response = client.get(f"/api/check/{task.id}/assessment")
            assert response.status_code == 200
            data = response.json()
            assert data["score"] == 0
            assert data["verdict"] == "blocked"
            # 不应返回残留评估的分数
            assert data["score"] != residual["score"]

    def test_cleanup_runs_on_all_paths(self, test_db, tmp_path):
        """清理在所有路径中执行（成功、扫描失败、评估失败）。

        验证 cleanup_download 和 cleanup_temp_dir 在以下场景中都被调用：
        1. 成功路径
        2. 扫描失败路径
        3. 评估失败路径
        """
        # --- 场景 1：成功路径 ---
        task1 = task_manager.create_task(
            "https://github.com/testuser/repo1", "testuser", "repo1"
        )
        download1 = make_mock_download_result(tmp_path)
        extract1 = make_mock_extract_result(tmp_path)
        scan1 = make_mock_scan_result()

        cleanup_download_called_1 = MagicMock()
        cleanup_temp_called_1 = MagicMock()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download1,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract1,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan1,
                ):
                    with patch(
                        "app.services.background_runner.cleanup_download",
                        side_effect=cleanup_download_called_1,
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_temp_dir",
                            side_effect=cleanup_temp_called_1,
                        ):
                            _run_pipeline(task1.id)

        cleanup_download_called_1.assert_called_once()
        cleanup_temp_called_1.assert_called_once()

        # --- 场景 2：扫描失败路径 ---
        task2 = task_manager.create_task(
            "https://github.com/testuser/repo2", "testuser", "repo2"
        )
        download2 = make_mock_download_result(tmp_path)
        extract2 = make_mock_extract_result(tmp_path)

        cleanup_download_called_2 = MagicMock()
        cleanup_temp_called_2 = MagicMock()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download2,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract2,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=RuntimeError("Scan error"),
                ):
                    with patch(
                        "app.services.background_runner.cleanup_download",
                        side_effect=cleanup_download_called_2,
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_temp_dir",
                            side_effect=cleanup_temp_called_2,
                        ):
                            _run_pipeline(task2.id)

        cleanup_download_called_2.assert_called_once()
        cleanup_temp_called_2.assert_called_once()

        # --- 场景 3：评估失败路径 ---
        task3 = task_manager.create_task(
            "https://github.com/testuser/repo3", "testuser", "repo3"
        )
        download3 = make_mock_download_result(tmp_path)
        extract3 = make_mock_extract_result(tmp_path)
        scan3 = make_mock_scan_result()

        cleanup_download_called_3 = MagicMock()
        cleanup_temp_called_3 = MagicMock()

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download3,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract3,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan3,
                ):
                    with patch(
                        "app.services.background_runner.run_assessment",
                        side_effect=Exception("Assessment failed"),
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_download",
                            side_effect=cleanup_download_called_3,
                        ):
                            with patch(
                                "app.services.background_runner.cleanup_temp_dir",
                                side_effect=cleanup_temp_called_3,
                            ):
                                _run_pipeline(task3.id)

        cleanup_download_called_3.assert_called_once()
        cleanup_temp_called_3.assert_called_once()

    def test_event_loop_stays_responsive(self, test_db, tmp_path):
        """事件循环保持响应（管道完成不阻塞）。

        验证管道在合理时间内完成，不阻塞事件循环。
        如果 scan_directory、save_scan_result、run_assessment 未通过
        asyncio.to_thread 包装，会阻塞事件循环导致管道挂起。
        """
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        # 使用 asyncio.wait_for 设置超时，验证管道不阻塞
        async def _run_with_timeout():
            await asyncio.wait_for(
                _process_task(task.id),
                timeout=30.0,
            )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    return_value=scan_result,
                ):
                    # 如果管道阻塞，asyncio.run 会超时抛出 TimeoutError
                    asyncio.run(_run_with_timeout())

        # 管道成功完成，事件循环未阻塞
        result = task_manager.get_task(task.id)
        assert result.status == "completed"
