/**
 * Check result page — polls task status and displays results.
 *
 * Uses the useCheckTask hook for the full lifecycle:
 *   startPolling(taskId) → polling → loading_results → completed/failed/timeout
 *
 * task_id is validated as a UUID before any API call is made.
 * task_id is never used as an auth credential or injected into
 * non-API paths.
 */

"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { CheckProgress } from "@/components/CheckProgress";
import { ErrorState } from "@/components/ErrorState";
import { RepairPlan } from "@/components/RepairPlan";
import { ResultTabs } from "@/components/ResultTabs";
import { ScoreSummary } from "@/components/ScoreSummary";
import { useCheckTask } from "@/hooks/use-check-task";
import { exportReport } from "@/lib/export";
import { addHistory, entryFromTaskStatus } from "@/lib/history";

// UUID v4 format validation (case-insensitive)
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default function CheckPage() {
  const params = useParams<{ task_id: string }>();
  const taskId = params.task_id;
  const isValidUuid = UUID_REGEX.test(taskId);

  const hook = useCheckTask();
  const { startPolling } = hook;

  // Each effect setup owns one polling session and stops that same session.
  useEffect(() => {
    if (!isValidUuid) return;
    return startPolling(taskId);
  }, [isValidUuid, startPolling, taskId]);

  // Save to localStorage history exactly once when the task completes
  // or fails (failed status only when reported by the backend status API).
  const historySavedRef = useRef<string | null>(null);
  useEffect(() => {
    if (!hook.taskStatus) return;
    const status = hook.taskStatus.status;
    if (status !== "completed" && status !== "failed") return;
    if (historySavedRef.current === hook.taskStatus.task_id) return;
    historySavedRef.current = hook.taskStatus.task_id;
    addHistory(entryFromTaskStatus(hook.taskStatus));
  }, [hook.taskStatus]);

  // --- Invalid task_id ---
  if (!isValidUuid) {
    return (
      <main className="container">
        <ErrorState message="任务ID格式无效。" />
      </main>
    );
  }

  const { state, taskStatus, errorMessage } = hook;

  // --- Submitting ---
  if (state === "submitting") {
    return (
      <main className="container">
        <div className="card">
          <span className="spinner" /> 提交中...
        </div>
      </main>
    );
  }

  // --- Polling ---
  if (state === "polling") {
    return (
      <main className="container">
        <h1 className="page-title">检测进行中</h1>
        {taskStatus ? (
          <CheckProgress taskStatus={taskStatus} />
        ) : (
          <div className="card">
            <span className="spinner" /> 正在获取任务状态...
          </div>
        )}
      </main>
    );
  }

  // --- Loading results ---
  if (state === "loading_results") {
    return (
      <main className="container">
        <h1 className="page-title">检测完成，加载结果中...</h1>
        <div className="card">
          <span className="spinner" /> 正在加载扫描结果、安全评估和修复计划...
        </div>
      </main>
    );
  }

  // --- Completed ---
  if (state === "completed") {
    return (
      <main className="container">
        <div className="page-header-row">
          <h1 className="page-title">检测结果</h1>
          <div className="page-header-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() =>
                exportReport(
                  taskId,
                  hook.scanResult,
                  hook.assessment,
                  hook.repairPlan,
                  hook.llmAnalysis,
                )
              }
            >
              导出报告
            </button>
            <Link href="/" className="btn btn-secondary">
              返回首页
            </Link>
          </div>
        </div>
        {taskStatus && <ScoreSummary taskStatus={taskStatus} />}
        <ResultTabs
          scanResult={hook.scanResult}
          scanResultStatus={hook.scanResultStatus}
          assessment={hook.assessment}
          assessmentStatus={hook.assessmentStatus}
          repairPlan={hook.repairPlan}
          repairPlanStatus={hook.repairPlanStatus}
          llmAnalysis={hook.llmAnalysis}
          llmAnalysisStatus={hook.llmAnalysisStatus}
          renderRepairPlan={(plan) => <RepairPlan plan={plan} />}
        />
      </main>
    );
  }

  // --- Failed ---
  if (state === "failed") {
    return (
      <main className="container">
        <h1 className="page-title">检测失败</h1>
        {errorMessage && <ErrorState message={errorMessage} />}
        <div className="page-header-actions">
          <Link href="/" className="btn btn-primary">
            重新检测
          </Link>
          <Link href="/" className="btn btn-secondary">
            返回首页
          </Link>
        </div>
      </main>
    );
  }

  // --- Timeout ---
  if (state === "timeout") {
    return (
      <main className="container">
        <h1 className="page-title">检测超时</h1>
        <ErrorState message="检测超时，请稍后重试。" />
        <div className="page-header-actions">
          <Link href="/" className="btn btn-primary">
            重新检测
          </Link>
          <Link href="/" className="btn btn-secondary">
            返回首页
          </Link>
        </div>
      </main>
    );
  }

  // --- Idle (should not normally reach here) ---
  return (
    <main className="container">
      <div className="card">
        <span className="spinner" /> 初始化中...
      </div>
    </main>
  );
}
