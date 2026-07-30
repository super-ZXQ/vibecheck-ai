/**
 * Task lifecycle hook: submit → poll → load results.
 *
 * State machine (frozen):
 *   idle → submitting → polling → loading_results → completed
 *                                    ↘ failed
 *                                    ↘ timeout
 *
 * Polling rules:
 * - Recursive setTimeout (never setInterval).
 * - Previous request must settle before the next is scheduled.
 * - Page-unload aborts the AbortController and clears the timer.
 * - Terminal states (completed, failed, timeout) stop polling immediately.
 * - timeout does NOT fake a backend "failed" status — it is its own state.
 *
 * Result loading:
 * - Uses Promise.allSettled for /result, /assessment, /repair-plan.
 * - loading_results ends when all three are settled (not all successful).
 * - Each Tab independently tracks: available | unavailable | error.
 * - Legacy 409 on assessment/repair → "unavailable" (not an error).
 */

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  ApiAbortError,
  ApiConfigError,
  ApiHttpError,
  ApiNetworkError,
  getAssessment,
  getRepairPlan,
  getScanResult,
  getTaskStatus,
  submitCheck,
} from "@/lib/api";
import { getErrorMessage } from "@/lib/error-messages";
import type {
  AssessmentResult,
  RepairPlan,
  ScanResult,
  TaskStatusResponse,
} from "@/lib/types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_POLL_TIMEOUT_MS = 300_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UIState =
  | "idle"
  | "submitting"
  | "polling"
  | "loading_results"
  | "completed"
  | "failed"
  | "timeout";

export type ResultTabStatus = "available" | "unavailable" | "error";

export interface UseCheckTaskOptions {
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
}

export interface UseCheckTaskResult {
  state: UIState;
  taskId: string | null;
  taskStatus: TaskStatusResponse | null;
  errorMessage: string | null;

  // Results (populated when state === "completed")
  scanResult: ScanResult | null;
  scanResultStatus: ResultTabStatus;
  assessment: AssessmentResult | null;
  assessmentStatus: ResultTabStatus;
  repairPlan: RepairPlan | null;
  repairPlanStatus: ResultTabStatus;

  // Actions
  submit: (repoUrl: string) => Promise<void>;
  startPolling: (existingTaskId: string) => void;
  reset: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useCheckTask(options?: UseCheckTaskOptions): UseCheckTaskResult {
  const pollIntervalMs = options?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const pollTimeoutMs = options?.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;

  const [state, setState] = useState<UIState>("idle");
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskStatus, setTaskStatus] = useState<TaskStatusResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanResultStatus, setScanResultStatus] = useState<ResultTabStatus>("unavailable");
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [assessmentStatus, setAssessmentStatus] = useState<ResultTabStatus>("unavailable");
  const [repairPlan, setRepairPlan] = useState<RepairPlan | null>(null);
  const [repairPlanStatus, setRepairPlanStatus] = useState<ResultTabStatus>("unavailable");

  // --- Refs for cleanup ---
  const abortControllerRef = useRef<AbortController | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startTimeRef = useRef<number>(0);
  const isMountedRef = useRef<boolean>(true);

  // --- Cleanup helper ---
  const cleanup = useCallback(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  }, []);

  // --- Cleanup on unmount ---
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      cleanup();
    };
  }, [cleanup]);

  // --- Load results when task is completed ---
  const loadResults = useCallback(
    async (id: string, signal: AbortSignal) => {
      if (!isMountedRef.current) return;
      setState("loading_results");

      // Use Promise.allSettled — we care about settled, not success.
      const [resultRes, assessmentRes, repairRes] = await Promise.allSettled([
        getScanResult(id, signal),
        getAssessment(id, signal),
        getRepairPlan(id, signal),
      ]);

      if (!isMountedRef.current) return;

      // --- Scan result ---
      if (resultRes.status === "fulfilled") {
        setScanResult(resultRes.value);
        setScanResultStatus("available");
      } else {
        const err = resultRes.reason;
        if (err instanceof ApiHttpError && err.statusCode === 409) {
          setScanResultStatus("unavailable");
        } else if (err instanceof ApiAbortError) {
          // Aborted — don't change state, component is unmounting
          return;
        } else {
          setScanResultStatus("error");
        }
        setScanResult(null);
      }

      // --- Assessment ---
      if (assessmentRes.status === "fulfilled") {
        setAssessment(assessmentRes.value);
        setAssessmentStatus("available");
      } else {
        const err = assessmentRes.reason;
        if (err instanceof ApiHttpError && err.statusCode === 409) {
          // Legacy 409 → unavailable, not error
          setAssessmentStatus("unavailable");
        } else if (err instanceof ApiAbortError) {
          return;
        } else {
          setAssessmentStatus("error");
        }
        setAssessment(null);
      }

      // --- Repair plan ---
      if (repairRes.status === "fulfilled") {
        setRepairPlan(repairRes.value);
        setRepairPlanStatus("available");
      } else {
        const err = repairRes.reason;
        if (err instanceof ApiHttpError && err.statusCode === 409) {
          // Legacy 409 → unavailable, not error
          setRepairPlanStatus("unavailable");
        } else if (err instanceof ApiAbortError) {
          return;
        } else {
          setRepairPlanStatus("error");
        }
        setRepairPlan(null);
      }

      if (!isMountedRef.current) return;
      setState("completed");
    },
    [],
  );

  // --- Single poll iteration ---
  const pollOnce = useCallback(
    async (id: string, signal: AbortSignal) => {
      try {
        const status = await getTaskStatus(id, signal);
        if (!isMountedRef.current) return;

        setTaskStatus(status);

        // Terminal states
        if (status.status === "completed") {
          cleanup();
          await loadResults(id, signal);
          return;
        }

        if (status.status === "failed") {
          cleanup();
          if (!isMountedRef.current) return;
          // Priority: backend error_message (already desensitized) → error_code mapping
          const msg =
            status.error_message ||
            getErrorMessage(status.error_code);
          setErrorMessage(msg);
          setState("failed");
          return;
        }

        // Still pending/running — schedule next poll
        // Check timeout
        const elapsed = Date.now() - startTimeRef.current;
        if (elapsed >= pollTimeoutMs) {
          cleanup();
          if (!isMountedRef.current) return;
          setState("timeout");
          return;
        }

        // Schedule next poll with recursive setTimeout
        pollTimerRef.current = setTimeout(() => {
          if (!isMountedRef.current) return;
          if (abortControllerRef.current?.signal.aborted) return;
          pollOnce(id, abortControllerRef.current!.signal);
        }, pollIntervalMs);
      } catch (err) {
        if (err instanceof ApiAbortError) {
          // Aborted by unmount or cleanup — do nothing
          return;
        }

        if (!isMountedRef.current) return;

        // Network error — retry on next interval (don't transition to failed)
        // Check timeout first
        const elapsed = Date.now() - startTimeRef.current;
        if (elapsed >= pollTimeoutMs) {
          cleanup();
          setState("timeout");
          return;
        }

        // Schedule retry
        pollTimerRef.current = setTimeout(() => {
          if (!isMountedRef.current) return;
          if (abortControllerRef.current?.signal.aborted) return;
          pollOnce(id, abortControllerRef.current!.signal);
        }, pollIntervalMs);
      }
    },
    [cleanup, loadResults, pollIntervalMs, pollTimeoutMs],
  );

  // --- Start polling for an existing task (e.g., page refresh) ---
  const startPolling = useCallback(
    (existingTaskId: string) => {
      if (!isMountedRef.current) return;

      // Clean up any previous polling
      cleanup();

      // Reset state
      setTaskId(existingTaskId);
      setTaskStatus(null);
      setErrorMessage(null);
      setScanResult(null);
      setScanResultStatus("unavailable");
      setAssessment(null);
      setAssessmentStatus("unavailable");
      setRepairPlan(null);
      setRepairPlanStatus("unavailable");

      // Create new AbortController for this polling session
      const controller = new AbortController();
      abortControllerRef.current = controller;
      startTimeRef.current = Date.now();
      setState("polling");

      // Start first poll immediately
      pollOnce(existingTaskId, controller.signal);
    },
    [cleanup, pollOnce],
  );

  // --- Submit a new check ---
  const submit = useCallback(
    async (repoUrl: string) => {
      if (!isMountedRef.current) return;

      cleanup();
      setState("submitting");
      setErrorMessage(null);

      // Create AbortController early so unmount during submit also aborts
      const controller = new AbortController();
      abortControllerRef.current = controller;

      try {
        const response = await submitCheck(repoUrl, controller.signal);
        if (!isMountedRef.current) return;

        setTaskId(response.task_id);
        startTimeRef.current = Date.now();
        setState("polling");

        // Start polling
        pollOnce(response.task_id, controller.signal);
      } catch (err) {
        if (err instanceof ApiAbortError) {
          // Aborted by unmount — do nothing
          return;
        }

        if (!isMountedRef.current) return;

        if (err instanceof ApiConfigError) {
          setErrorMessage("后端 API 地址未配置，请检查环境变量 NEXT_PUBLIC_API_BASE_URL。");
        } else if (err instanceof ApiHttpError) {
          // Use backend error_message if available, then error_code mapping
          const msg =
            err.errorMessage ||
            getErrorMessage(err.errorCode);
          setErrorMessage(msg);
        } else if (err instanceof ApiNetworkError) {
          setErrorMessage("网络连接失败，请检查网络后重试。");
        } else {
          setErrorMessage(getErrorMessage(null));
        }

        setState("failed");
      }
    },
    [cleanup, pollOnce],
  );

  // --- Reset to idle ---
  const reset = useCallback(() => {
    cleanup();
    if (!isMountedRef.current) return;
    setState("idle");
    setTaskId(null);
    setTaskStatus(null);
    setErrorMessage(null);
    setScanResult(null);
    setScanResultStatus("unavailable");
    setAssessment(null);
    setAssessmentStatus("unavailable");
    setRepairPlan(null);
    setRepairPlanStatus("unavailable");
  }, [cleanup]);

  return {
    state,
    taskId,
    taskStatus,
    errorMessage,
    scanResult,
    scanResultStatus,
    assessment,
    assessmentStatus,
    repairPlan,
    repairPlanStatus,
    submit,
    startPolling,
    reset,
  };
}
