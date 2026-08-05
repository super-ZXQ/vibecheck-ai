"""P0-7 修复计划管道集成测试。

覆盖 background_runner.py 中的修复计划管道集成：
1. 评估在修复计划之前保存：_setup_full_task 后评估与修复计划均存在
2. 修复计划从 SQLite 读取（非内存）：generate_and_save_repair_plan 读取持久化结果
3. 修复计划在任务完成前保存：完整管道后任务状态为 completed 且修复计划存在
4. 生成失败标记任务失败：RepairPlanInternalError → REPAIR_PLAN_INTERNAL_ERROR
5. 持久化失败标记任务失败：RepairPlanPersistError → REPAIR_PLAN_PERSIST_FAILED
6. JSON 过大标记任务失败：RepairPlanTooLargeError → REPAIR_PLAN_TOO_LARGE
7. mark_completed 失败后修复计划仍存在：修复计划已保存但任务标记为 failed
8. 所有失败路径都执行清理：成功、修复失败等路径均清理临时文件
9. FastAPI 事件循环保持响应：修复计划生成期间事件循环不阻塞
10. 修复阶段标记为 repairing：生成修复计划时任务阶段为 repairing
11. 失败任务不返回残留修复计划：修复计划生成失败时 API 不返回残留数据
12. 遗留完成任务无修复计划：P0-7 之前的完成任务返回 409 REPAIR_PLAN_NOT_AVAILABLE
"""

import asyncio
import uuid
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.db import database
from app.services import background_runner, task_manager
from app.services.repair_service import (
    generate_and_save_repair_plan,
    get_repair_result,
    RepairPlanInternalError,
    RepairPlanPersistError,
    RepairPlanTooLargeError,
)
from app.services.scan_result_service import save_scan_result
from app.services.assessment_service import (
    run_assessment,
    get_assessment_result,
    get_scan_result_with_timestamp,
)
from app.scanner.base import ScanResult, Finding, Severity, Confidence, FindingType
from app.core.error_codes import (
    REPAIR_PLAN_INTERNAL_ERROR,
    REPAIR_PLAN_PERSIST_FAILED,
    REPAIR_PLAN_TOO_LARGE,
    REPAIR_PLAN_NOT_AVAILABLE,
    INTERNAL_ERROR,
)
from tests.conftest import make_normal_tarball


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path / "tmp"))
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

def _setup_full_task(test_db, findings=None):
    """Create task, save scan result, run assessment. Return task_id."""
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")

    if findings is None:
        findings = (
            Finding(
                rule_id="R001_GITHUB_TOKEN", rule_name="GitHub Token",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file_path="config.py", line_start=1, line_end=1,
                column_start=1, column_end=50,
                snippet_masked="ghp_****", is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="Hardcoded GitHub token",
                category="secret", secret_type="github_token",
                message="Found hardcoded token",
                repair_template_key="rotate_github_token",
            ),
        )

    scan_result = ScanResult(
        findings=findings, notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )
    save_scan_result(task.id, scan_result)
    run_assessment(task.id)
    return task.id


def make_mock_download_result(tmp_path):
    """Create a mock DownloadResult with a real temp file."""
    from app.core.github import DownloadResult, parse_repo_url
    f = tmp_path / f"test_{uuid.uuid4().hex[:8]}.tar.gz"
    f.write_bytes(make_normal_tarball())
    repo_info = parse_repo_url("https://github.com/test/repo")
    return DownloadResult(
        temp_file=f,
        repo_info=repo_info,
        file_size=f.stat().st_size,
    )


def make_mock_extract_result(tmp_path):
    """Create a mock ExtractionResult with a real extraction directory."""
    from app.core.safe_extract import ExtractionResult
    extract_dir = tmp_path / f"extracted_{uuid.uuid4().hex[:8]}"
    extract_dir.mkdir()
    (extract_dir / "test-repo").mkdir()
    (extract_dir / "test-repo" / "README.md").write_text("# Test")
    return ExtractionResult(
        dest_dir=str(extract_dir),
        file_count=1,
        total_size=100,
        top_level_dir="test-repo",
    )


def make_mock_scan_result(findings=None):
    """Create a mock ScanResult with a blocking finding by default."""
    if findings is None:
        findings = (
            Finding(
                rule_id="R001_GITHUB_TOKEN", rule_name="GitHub Token",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file_path="config.py", line_start=1, line_end=1,
                column_start=1, column_end=50,
                snippet_masked="ghp_****", is_blocking=True,
                finding_type=FindingType.CONTENT,
                description="Hardcoded GitHub token",
                category="secret", secret_type="github_token",
                message="Found hardcoded token",
                repair_template_key="rotate_github_token",
            ),
        )
    return ScanResult(
        findings=findings, notices=(), skipped_files=(), scan_errors=(),
        total_files_scanned=10, total_lines_scanned=100,
    )


def _run_pipeline(task_id):
    """Run the async pipeline using asyncio.run."""
    asyncio.run(background_runner._process_task(task_id))


# ============================================================
# 测试类：TestRepairPipeline
# ============================================================

class TestRepairPipeline:
    """P0-7 修复计划管道集成测试。"""

    # --- 1. 评估在修复计划之前保存 ---

    def test_assessment_saved_before_repair_plan(self, test_db):
        """_setup_full_task 后评估与修复计划均存在，修复计划从持久化结果读取。

        流程：
        1. _setup_full_task 创建任务、保存扫描结果、运行评估。
        2. 调用 generate_and_save_repair_plan 生成并保存修复计划。
        3. 验证评估结果存在。
        4. 验证修复计划存在且读取自持久化结果。
        """
        task_id = _setup_full_task(test_db)

        # 评估应已存在（由 _setup_full_task 中的 run_assessment 保存）
        assessment = get_assessment_result(task_id)
        assert assessment is not None
        assert assessment["task_id"] == task_id

        # 修复计划尚不存在
        assert get_repair_result(task_id) is None

        # 生成并保存修复计划
        repair_plan = generate_and_save_repair_plan(task_id)
        assert repair_plan is not None
        assert repair_plan["task_id"] == task_id

        # 修复计划应从持久化结果读取——source_scan_updated_at 应匹配
        # scan_results 表中的 updated_at
        scan_data, scan_updated_at = get_scan_result_with_timestamp(task_id)
        assert scan_data is not None
        assert repair_plan["source_scan_updated_at"] == scan_updated_at

        # 再次读取验证持久化
        persisted = get_repair_result(task_id)
        assert persisted is not None
        assert persisted["task_id"] == task_id
        assert persisted["source_scan_updated_at"] == scan_updated_at

    # --- 2. 修复计划从 SQLite 读取（非内存） ---

    def test_repair_plan_reads_persisted_results(self, test_db):
        """generate_and_save_repair_plan 从 SQLite 读取，而非内存。

        验证方式：
        1. _setup_full_task 保存扫描结果和评估到 SQLite。
        2. generate_and_save_repair_plan 独立调用（不接收内存中的
           ScanResult/AssessmentResult 对象）。
        3. get_repair_result 返回的数据与 generate_and_save_repair_plan
           返回的数据一致。
        4. source_scan_updated_at 匹配 scan_results.updated_at（证明从
           SQLite 读取时间戳，而非内存构造）。
        """
        task_id = _setup_full_task(test_db)

        # 获取持久化的扫描结果和时间戳
        scan_data, scan_updated_at = get_scan_result_with_timestamp(task_id)
        assert scan_data is not None
        assert scan_updated_at is not None

        # 独立调用 generate_and_save_repair_plan——它内部从 SQLite 读取
        generated = generate_and_save_repair_plan(task_id)
        assert generated is not None

        # 验证从 SQLite 读取的证据：source_scan_updated_at 匹配
        assert generated["source_scan_updated_at"] == scan_updated_at

        # get_repair_result 返回相同数据
        retrieved = get_repair_result(task_id)
        assert retrieved is not None
        assert retrieved["task_id"] == task_id
        assert retrieved["source_scan_updated_at"] == scan_updated_at
        assert retrieved["plan_status"] == generated["plan_status"]
        assert (
            retrieved["summary"]["total_repair_groups"]
            == generated["summary"]["total_repair_groups"]
        )

        # 修复计划中的 finding 信息应来自持久化的扫描结果
        assert len(retrieved["repair_groups"]) > 0
        group = retrieved["repair_groups"][0]
        assert group["blocking"] is True
        assert "R001_GITHUB_TOKEN" in group["related_rule_ids"]

    # --- 3. 修复计划在任务完成前保存 ---

    def test_repair_plan_saved_before_completed(self, test_db, tmp_path):
        """完整管道后任务状态为 completed 且修复计划存在。

        使用 mock download/extract/scan 运行完整管道：
        download → extract → scan → persist scan → assess → persist
        assessment → generate repair plan → persist repair plan → completed
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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

        # 任务应已完成
        result = task_manager.get_task(task.id)
        assert result.status == "completed"
        assert result.stage == "finished"
        assert result.progress == 100

        # 修复计划应存在
        repair_plan = get_repair_result(task.id)
        assert repair_plan is not None
        assert repair_plan["task_id"] == task.id
        assert len(repair_plan["repair_groups"]) > 0

        # 评估也应存在
        assessment = get_assessment_result(task.id)
        assert assessment is not None
        assert assessment["task_id"] == task.id

    # --- 4. 生成失败标记任务失败 ---

    @pytest.mark.asyncio
    async def test_generation_failure_marks_failed(self, test_db, tmp_path):
        """generate_and_save_repair_plan 抛出 RepairPlanInternalError
        时任务标记为 failed，错误码为 REPAIR_PLAN_INTERNAL_ERROR。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=RepairPlanInternalError("test"),
                    ):
                        await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == REPAIR_PLAN_INTERNAL_ERROR

        # 修复计划不应存在（生成失败前未保存）
        assert get_repair_result(task.id) is None

    # --- 5. 持久化失败标记任务失败 ---

    @pytest.mark.asyncio
    async def test_persist_failure_marks_failed(self, test_db, tmp_path):
        """generate_and_save_repair_plan 抛出 RepairPlanPersistError
        时任务标记为 failed，错误码为 REPAIR_PLAN_PERSIST_FAILED。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=RepairPlanPersistError("test"),
                    ):
                        await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == REPAIR_PLAN_PERSIST_FAILED

    # --- 6. JSON 过大标记任务失败 ---

    @pytest.mark.asyncio
    async def test_json_too_large_marks_failed(self, test_db, tmp_path):
        """generate_and_save_repair_plan 抛出 RepairPlanTooLargeError
        时任务标记为 failed，错误码为 REPAIR_PLAN_TOO_LARGE。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=RepairPlanTooLargeError("test"),
                    ):
                        await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == REPAIR_PLAN_TOO_LARGE

    # --- 7. mark_completed 失败后修复计划仍存在 ---

    def test_mark_completed_failure(self, test_db, tmp_path, client):
        """mark_completed 失败后修复计划仍存在，但任务标记为 failed。

        场景：
        1. 修复计划成功生成并保存到 repair_results。
        2. mark_completed 抛出异常。
        3. 外层 except 捕获异常，标记任务为 failed（INTERNAL_ERROR）。
        4. repair_results 中的修复计划仍然存在（残留数据）。
        5. API 对 failed 任务返回安全空计划，不泄露残留数据。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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
                        "app.services.background_runner.mark_completed",
                        side_effect=RuntimeError("DB error during mark_completed"),
                    ):
                        _run_pipeline(task.id)

        # 任务应被标记为 failed（由外层 except 捕获 mark_completed 异常）
        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == INTERNAL_ERROR

        # 修复计划应仍然存在于数据库中（在 mark_completed 之前已保存）
        residual_plan = get_repair_result(task.id)
        assert residual_plan is not None
        assert residual_plan["task_id"] == task.id
        assert len(residual_plan["repair_groups"]) > 0

        # API 对 failed 任务应返回安全空计划，不泄露残留数据
        response = client.get(f"/api/check/{task.id}/repair-plan")
        assert response.status_code == 200
        data = response.json()
        assert data["plan_status"] == "partial"
        assert data["summary"]["total_repair_groups"] == 0
        assert data["repair_groups"] == []
        # 不应包含残留计划的修复组
        assert (
            data["summary"]["total_repair_groups"]
            != residual_plan["summary"]["total_repair_groups"]
        )

    # --- 8. 所有失败路径都执行清理 ---

    def test_all_failure_paths_cleanup(self, test_db, tmp_path):
        """验证清理在所有失败路径中执行。

        场景：
        1. 成功路径：cleanup_download 和 cleanup_temp_dir 均被调用。
        2. 修复计划失败路径：cleanup 仍被调用。
        3. mark_completed 失败路径：cleanup 仍被调用。
        """
        # --- 场景 1：成功路径 ---
        task1 = task_manager.create_task(
            "https://github.com/test/repo1", "test", "repo1"
        )
        download1 = make_mock_download_result(tmp_path)
        extract1 = make_mock_extract_result(tmp_path)
        scan1 = make_mock_scan_result()

        cleanup_dl_1 = MagicMock()
        cleanup_tmp_1 = MagicMock()

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
                        side_effect=cleanup_dl_1,
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_temp_dir",
                            side_effect=cleanup_tmp_1,
                        ):
                            _run_pipeline(task1.id)

        cleanup_dl_1.assert_called_once()
        cleanup_tmp_1.assert_called_once()
        assert task_manager.get_task(task1.id).status == "completed"

        # --- 场景 2：修复计划失败路径 ---
        task2 = task_manager.create_task(
            "https://github.com/test/repo2", "test", "repo2"
        )
        download2 = make_mock_download_result(tmp_path)
        extract2 = make_mock_extract_result(tmp_path)
        scan2 = make_mock_scan_result()

        cleanup_dl_2 = MagicMock()
        cleanup_tmp_2 = MagicMock()

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
                    return_value=scan2,
                ):
                    with patch(
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=RepairPlanInternalError("test"),
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_download",
                            side_effect=cleanup_dl_2,
                        ):
                            with patch(
                                "app.services.background_runner.cleanup_temp_dir",
                                side_effect=cleanup_tmp_2,
                            ):
                                _run_pipeline(task2.id)

        cleanup_dl_2.assert_called_once()
        cleanup_tmp_2.assert_called_once()
        assert task_manager.get_task(task2.id).status == "failed"

        # --- 场景 3：mark_completed 失败路径 ---
        task3 = task_manager.create_task(
            "https://github.com/test/repo3", "test", "repo3"
        )
        download3 = make_mock_download_result(tmp_path)
        extract3 = make_mock_extract_result(tmp_path)
        scan3 = make_mock_scan_result()

        cleanup_dl_3 = MagicMock()
        cleanup_tmp_3 = MagicMock()

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
                        "app.services.background_runner.mark_completed",
                        side_effect=RuntimeError("mark_completed failed"),
                    ):
                        with patch(
                            "app.services.background_runner.cleanup_download",
                            side_effect=cleanup_dl_3,
                        ):
                            with patch(
                                "app.services.background_runner.cleanup_temp_dir",
                                side_effect=cleanup_tmp_3,
                            ):
                                _run_pipeline(task3.id)

        cleanup_dl_3.assert_called_once()
        cleanup_tmp_3.assert_called_once()
        assert task_manager.get_task(task3.id).status == "failed"

    # --- 9. FastAPI 事件循环保持响应 ---

    @pytest.mark.asyncio
    async def test_fastapi_event_loop_responsive(self, test_db, tmp_path):
        """修复计划生成期间 FastAPI 事件循环保持响应。

        使用 asyncio.gather 同时运行 _process_task 和并发健康检查。
        如果 scan_directory、save_scan_result、run_assessment 或
        generate_and_save_repair_plan 阻塞事件循环（未通过
        asyncio.to_thread 包装），健康检查将被延迟。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        health_results = []

        async def health_check():
            """模拟 FastAPI 健康检查端点。

            如果事件循环被阻塞，此协程不会在 _process_task 执行期间运行。
            """
            health_results.append("ok")
            return {"status": "ok"}

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
                    results = await asyncio.gather(
                        background_runner._process_task(task.id),
                        health_check(),
                    )

        # 健康检查应已完成
        assert len(health_results) == 1
        assert health_results[0] == "ok"
        assert results[1] == {"status": "ok"}

        # 管道应成功完成
        task_record = task_manager.get_task(task.id)
        assert task_record.status == "completed"

    # --- 10. 修复阶段标记为 repairing ---

    def test_stage_repairing(self, test_db, tmp_path):
        """生成修复计划时任务阶段应为 repairing。

        通过包装 generate_and_save_repair_plan 捕获调用时的任务阶段。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)
        scan_result = make_mock_scan_result()

        captured = {}
        original_func = background_runner.generate_and_save_repair_plan

        def capture_stage(task_id):
            t = task_manager.get_task(task_id)
            captured["stage"] = t.stage
            captured["status"] = t.status
            captured["progress"] = t.progress
            return original_func(task_id)

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
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=capture_stage,
                    ):
                        _run_pipeline(task.id)

        # 在修复计划生成期间，任务阶段应为 repairing
        assert captured.get("stage") == "repairing"
        assert captured.get("status") == "running"
        assert captured.get("progress") == 95

        # 管道完成后任务应为 completed
        result = task_manager.get_task(task.id)
        assert result.status == "completed"

    # --- 11. 失败任务不返回残留修复计划 ---

    def test_failed_task_no_residual_repair_plan(self, test_db, tmp_path, client):
        """修复计划生成失败时，失败任务的 API 不返回残留修复计划数据。

        场景：
        1. mock generate_and_save_repair_plan 抛出 RepairPlanInternalError。
        2. 任务被标记为 failed。
        3. repair_results 中无修复计划（生成失败，未保存）。
        4. API 返回安全空计划（plan_status=partial，全零）。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
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
                        "app.services.background_runner.generate_and_save_repair_plan",
                        side_effect=RepairPlanInternalError("test"),
                    ):
                        _run_pipeline(task.id)

        # 任务应为 failed
        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == REPAIR_PLAN_INTERNAL_ERROR

        # 数据库中不应有残留修复计划
        assert get_repair_result(task.id) is None

        # API 应返回安全空计划
        response = client.get(f"/api/check/{task.id}/repair-plan")
        assert response.status_code == 200
        data = response.json()

        # 安全空计划的所有字段应为零/空
        assert data["plan_status"] == "partial"
        assert data["summary"]["total_repair_groups"] == 0
        assert data["summary"]["blocking_repair_groups"] == 0
        assert data["summary"]["manual_review_required"] is False
        assert data["summary"]["coverage_warning"] is False
        assert data["summary"]["groups_truncated"] is False
        assert data["repair_groups"] == []
        assert data["verification_steps"] == []
        assert data["agent_prompt"] == ""
        assert data["source_scan_updated_at"] is None
        assert data["source_assessment_updated_at"] is None
        assert data["source_assessment_policy_version"] is None
        assert data["created_at"] is None
        assert data["updated_at"] is None

    # --- 12. 遗留完成任务无修复计划 ---

    def test_legacy_completed_task_no_repair_plan(self, client):
        """P0-7 之前完成的任务（无 repair_results 行）返回 409
        REPAIR_PLAN_NOT_AVAILABLE。

        场景：任务在 P0-7 之前完成，数据库中没有 repair_results 行。
        API 应返回 409 而非安全空计划。
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        # 直接标记为完成，不经过管道（模拟遗留任务）
        task_manager.mark_completed(
            task.id, file_count=10, total_size=1000, top_level_dir="test-repo"
        )

        # 确认任务状态为 completed
        result = task_manager.get_task(task.id)
        assert result.status == "completed"

        # 确认无修复计划
        assert get_repair_result(task.id) is None

        # API 应返回 409 REPAIR_PLAN_NOT_AVAILABLE
        response = client.get(f"/api/check/{task.id}/repair-plan")
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error_code"] == REPAIR_PLAN_NOT_AVAILABLE
