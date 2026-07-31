/**
 * Task lifecycle hook: submit → poll → load results.
 *
 * Polling uses recursive setTimeout. Each session owns its timer and
 * AbortController so an old effect cleanup cannot stop a newer session.
 */

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  ApiAbortError,
  ApiConfigError,
  ApiHttpError,
  ApiNetworkError,
  ApiRequestTimeoutError,
  getAssessment,
  getRepairPlan,
  getScanResult,
  getTaskStatus,
  submitCheck,
} from "@/lib/api";
import {
  CONFIG_ERROR_MESSAGE,
  getErrorMessage,
  NETWORK_ERROR_MESSAGE,
} from "@/lib/error-messages";
import type {
  AssessmentResult,
  RepairPlan,
  ScanResult,
  TaskStatusResponse,
} from "@/lib/types";

const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_POLL_TIMEOUT_MS = 300_000;

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
  scanResult: ScanResult | null;
  scanResultStatus: ResultTabStatus;
  assessment: AssessmentResult | null;
  assessmentStatus: ResultTabStatus;
  repairPlan: RepairPlan | null;
  repairPlanStatus: ResultTabStatus;
  submit: (repoUrl: string) => Promise<void>;
  startPolling: (existingTaskId: string) => () => void;
  reset: () => void;
}

interface PollingSession {
  controller: AbortController;
  timer: ReturnType<typeof setTimeout> | null;
  startedAt: number;
}

export function useCheckTask(options?: UseCheckTaskOptions): UseCheckTaskResult {
  const pollIntervalMs = options?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const pollTimeoutMs = options?.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;

  const [state, setState] = useState<UIState>("idle");
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskStatus, setTaskStatus] = useState<TaskStatusResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanResultStatus, setScanResultStatus] =
    useState<ResultTabStatus>("unavailable");
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [assessmentStatus, setAssessmentStatus] =
    useState<ResultTabStatus>("unavailable");
  const [repairPlan, setRepairPlan] = useState<RepairPlan | null>(null);
  const [repairPlanStatus, setRepairPlanStatus] =
    useState<ResultTabStatus>("unavailable");

  const activeSessionRef = useRef<PollingSession | null>(null);
  const isMountedRef = useRef(true);

  const stopSession = useCallback((session: PollingSession) => {
    if (session.timer) {
      clearTimeout(session.timer);
      session.timer = null;
    }
    session.controller.abort();
    if (activeSessionRef.current === session) {
      activeSessionRef.current = null;
    }
  }, []);

  const stopActiveSession = useCallback(() => {
    const session = activeSessionRef.current;
    if (session) {
      stopSession(session);
    }
  }, [stopSession]);

  const isSessionActive = useCallback(
    (session: PollingSession) =>
      isMountedRef.current &&
      activeSessionRef.current === session &&
      !session.controller.signal.aborted,
    [],
  );

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      stopActiveSession();
    };
  }, [stopActiveSession]);

  const resetResults = useCallback(() => {
    setTaskStatus(null);
    setErrorMessage(null);
    setScanResult(null);
    setScanResultStatus("unavailable");
    setAssessment(null);
    setAssessmentStatus("unavailable");
    setRepairPlan(null);
    setRepairPlanStatus("unavailable");
  }, []);

  const loadResults = useCallback(
    async (id: string, session: PollingSession) => {
      if (!isSessionActive(session)) return;
      setState("loading_results");

      const [resultRes, assessmentRes, repairRes] = await Promise.allSettled([
        getScanResult(id, session.controller.signal),
        getAssessment(id, session.controller.signal),
        getRepairPlan(id, session.controller.signal),
      ]);

      if (!isSessionActive(session)) return;
      if (
        [resultRes, assessmentRes, repairRes].some(
          (result) =>
            result.status === "rejected" &&
            result.reason instanceof ApiAbortError,
        )
      ) {
        return;
      }

      if (resultRes.status === "fulfilled") {
        setScanResult(resultRes.value);
        setScanResultStatus("available");
      } else {
        setScanResult(null);
        setScanResultStatus(
          resultRes.reason instanceof ApiHttpError &&
            resultRes.reason.statusCode === 409
            ? "unavailable"
            : "error",
        );
      }

      if (assessmentRes.status === "fulfilled") {
        setAssessment(assessmentRes.value);
        setAssessmentStatus("available");
      } else {
        setAssessment(null);
        setAssessmentStatus(
          assessmentRes.reason instanceof ApiHttpError &&
            assessmentRes.reason.statusCode === 409
            ? "unavailable"
            : "error",
        );
      }

      if (repairRes.status === "fulfilled") {
        setRepairPlan(repairRes.value);
        setRepairPlanStatus("available");
      } else {
        setRepairPlan(null);
        setRepairPlanStatus(
          repairRes.reason instanceof ApiHttpError &&
            repairRes.reason.statusCode === 409
            ? "unavailable"
            : "error",
        );
      }

      if (!isSessionActive(session)) return;
      stopSession(session);
      setState("completed");
    },
    [isSessionActive, stopSession],
  );

  const pollOnce = useCallback(
    async (id: string, session: PollingSession) => {
      try {
        const status = await getTaskStatus(id, session.controller.signal);
        if (!isSessionActive(session)) return;

        setTaskStatus(status);

        if (status.status === "completed") {
          await loadResults(id, session);
          return;
        }

        if (status.status === "failed") {
          const message =
            status.error_message || getErrorMessage(status.error_code);
          stopSession(session);
          setErrorMessage(message);
          setState("failed");
          return;
        }

        if (Date.now() - session.startedAt >= pollTimeoutMs) {
          stopSession(session);
          setState("timeout");
          return;
        }

        session.timer = setTimeout(() => {
          session.timer = null;
          if (isSessionActive(session)) {
            void pollOnce(id, session);
          }
        }, pollIntervalMs);
      } catch (err) {
        if (err instanceof ApiAbortError || !isSessionActive(session)) {
          return;
        }

        if (
          err instanceof ApiNetworkError ||
          err instanceof ApiRequestTimeoutError
        ) {
          if (Date.now() - session.startedAt >= pollTimeoutMs) {
            stopSession(session);
            setState("timeout");
            return;
          }
          session.timer = setTimeout(() => {
            session.timer = null;
            if (isSessionActive(session)) {
              void pollOnce(id, session);
            }
          }, pollIntervalMs);
          return;
        }

        let message: string;
        if (err instanceof ApiConfigError) {
          message = CONFIG_ERROR_MESSAGE;
        } else if (err instanceof ApiHttpError) {
          message = getErrorMessage(err.errorCode);
        } else {
          message = getErrorMessage("INTERNAL_ERROR");
        }
        stopSession(session);
        setErrorMessage(message);
        setState("failed");
      }
    },
    [
      isSessionActive,
      loadResults,
      pollIntervalMs,
      pollTimeoutMs,
      stopSession,
    ],
  );

  const startPolling = useCallback(
    (existingTaskId: string) => {
      if (!isMountedRef.current) return () => {};

      stopActiveSession();
      resetResults();
      setTaskId(existingTaskId);

      const session: PollingSession = {
        controller: new AbortController(),
        timer: null,
        startedAt: Date.now(),
      };
      activeSessionRef.current = session;
      setState("polling");
      void pollOnce(existingTaskId, session);

      return () => {
        stopSession(session);
      };
    },
    [pollOnce, resetResults, stopActiveSession, stopSession],
  );

  const submit = useCallback(
    async (repoUrl: string) => {
      if (!isMountedRef.current) return;

      stopActiveSession();
      resetResults();
      setState("submitting");

      const session: PollingSession = {
        controller: new AbortController(),
        timer: null,
        startedAt: Date.now(),
      };
      activeSessionRef.current = session;

      try {
        const response = await submitCheck(repoUrl, session.controller.signal);
        if (!isSessionActive(session)) return;

        setTaskId(response.task_id);
        session.startedAt = Date.now();
        setState("polling");
        void pollOnce(response.task_id, session);
      } catch (err) {
        if (err instanceof ApiAbortError || !isSessionActive(session)) {
          return;
        }

        let message: string;
        if (err instanceof ApiConfigError) {
          message = CONFIG_ERROR_MESSAGE;
        } else if (err instanceof ApiHttpError) {
          message = getErrorMessage(err.errorCode);
        } else if (
          err instanceof ApiNetworkError ||
          err instanceof ApiRequestTimeoutError
        ) {
          message = NETWORK_ERROR_MESSAGE;
        } else {
          message = getErrorMessage("INTERNAL_ERROR");
        }
        stopSession(session);
        setErrorMessage(message);
        setState("failed");
      }
    },
    [
      isSessionActive,
      pollOnce,
      resetResults,
      stopActiveSession,
      stopSession,
    ],
  );

  const reset = useCallback(() => {
    stopActiveSession();
    if (!isMountedRef.current) return;
    setState("idle");
    setTaskId(null);
    resetResults();
  }, [resetResults, stopActiveSession]);

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
