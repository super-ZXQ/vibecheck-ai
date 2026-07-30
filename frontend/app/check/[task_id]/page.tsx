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

import { useEffect, useRef } from "react";

import { CheckProgress } from "@/components/CheckProgress";
import { ErrorState } from "@/components/ErrorState";
import { useCheckTask } from "@/hooks/use-check-task";

// UUID v4 format validation (case-insensitive)
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface CheckPageProps {
  params: { task_id: string };
}

export default function CheckPage({ params }: CheckPageProps) {
  const taskId = params.task_id;
  const isValidUuid = UUID_REGEX.test(taskId);

  const hook = useCheckTask();
  const startedRef = useRef(false);

  // Start polling on mount (only if valid UUID)
  useEffect(() => {
    if (!isValidUuid || startedRef.current) return;
    startedRef.current = true;
    hook.startPolling(taskId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isValidUuid, taskId]);

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
    // Phase 4 will replace this with full results display
    return (
      <main className="container">
        <h1 className="page-title">检测结果</h1>
        <div className="card">
          <p>检测已完成。结果加载完毕。</p>
        </div>
      </main>
    );
  }

  // --- Failed ---
  if (state === "failed") {
    return (
      <main className="container">
        <h1 className="page-title">检测失败</h1>
        {errorMessage && <ErrorState message={errorMessage} />}
      </main>
    );
  }

  // --- Timeout ---
  if (state === "timeout") {
    return (
      <main className="container">
        <h1 className="page-title">检测超时</h1>
        <ErrorState message="检测超时，请稍后重试。" />
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
