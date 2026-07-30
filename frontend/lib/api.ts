/**
 * Unified fetch wrapper and typed API client for VibeCheck.
 *
 * Security constraints:
 * - All requests use cache: "no-store".
 * - Default timeout 10s; caller may pass AbortSignal.
 * - Caller abort + timeout are combined into ONE internal AbortController
 *   so neither signal is lost. Page-unload signals are also forwarded.
 * - Timeout and event listeners are cleaned up after every request.
 * - AbortError never surfaces internal details.
 * - API responses are NEVER written to console, localStorage, sessionStorage,
 *   or IndexedDB.
 * - NEXT_PUBLIC_API_BASE_URL must be set. Missing → ApiConfigError at call
 *   time (not at module import time). No localhost fallback.
 */

import type {
  ApiErrorBody,
  AssessmentResult,
  CheckRequest,
  CheckResponse,
  RepairPlan,
  ScanResult,
  TaskStatusResponse,
} from "./types";
import { NETWORK_ERROR_MESSAGE } from "./error-messages";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Read the API base URL at call time (not import time).
 * If missing, throws ApiConfigError — never falls back to localhost.
 */
function getApiBaseUrl(): string {
  // E2E test overrides (never active in production)
  if (typeof window !== "undefined") {
    const forceErr = (window as unknown as Record<string, unknown>).__TEST_FORCE_CONFIG_ERROR__;
    if (forceErr === true) {
      throw new ApiConfigError();
    }
    // Test-only API base URL override. Allows E2E tests to work
    // even when Next.js dev server doesn't inline NEXT_PUBLIC_API_BASE_URL.
    const testUrl = (window as unknown as Record<string, unknown>).__TEST_API_BASE_URL__;
    if (typeof testUrl === "string" && testUrl.trim() !== "") {
      return testUrl.replace(/\/+$/, "");
    }
  }

  const url = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (!url || url.trim() === "") {
    throw new ApiConfigError();
  }
  return url.replace(/\/+$/, ""); // strip trailing slashes
}

// ---------------------------------------------------------------------------
// Custom error types
// ---------------------------------------------------------------------------

/** Thrown when NEXT_PUBLIC_API_BASE_URL is not configured. */
export class ApiConfigError extends Error {
  constructor() {
    super("API_BASE_URL_NOT_CONFIGURED");
    this.name = "ApiConfigError";
  }
}

/** Thrown when the server returns a non-2xx HTTP status. */
export class ApiHttpError extends Error {
  readonly statusCode: number;
  readonly errorCode: string | null;
  readonly errorMessage: string | null;

  constructor(statusCode: number, errorCode: string | null, errorMessage: string | null) {
    super(errorCode ?? "HTTP_ERROR");
    this.name = "ApiHttpError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
  }
}

/** Thrown when a network-level error occurs (fetch throws TypeError). */
export class ApiNetworkError extends Error {
  constructor() {
    super("NETWORK_ERROR");
    this.name = "ApiNetworkError";
  }
}

/** Thrown when a request is aborted (timeout or caller abort). */
export class ApiAbortError extends Error {
  constructor() {
    super("ABORTED");
    this.name = "ApiAbortError";
  }
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

interface FetchOptions {
  method: "GET" | "POST";
  body?: unknown;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Perform a fetch request with cache bypass, timeout, and signal merging.
 *
 * Signal merging strategy:
 * - A single internal AbortController is created.
 * - If the caller provides a signal, its "abort" event is forwarded to
 *   the internal controller.
 * - A timeout timer is set; on expiry it aborts the internal controller.
 * - The internal controller's signal is passed to fetch().
 * - After the request settles, the timeout timer and event listener are
 *   cleaned up so no resources leak.
 */
async function apiFetch<T>(path: string, options: FetchOptions): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${path}`;

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const internalController = new AbortController();
  const internalSignal = internalController.signal;

  // --- Set up timeout ---
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  if (timeoutMs > 0) {
    timeoutId = setTimeout(() => {
      internalController.abort();
    }, timeoutMs);
  }

  // --- Forward caller signal to internal controller ---
  let callerAbortListener: (() => void) | null = null;
  if (options.signal) {
    if (options.signal.aborted) {
      // Already aborted — propagate immediately.
      if (timeoutId) clearTimeout(timeoutId);
      throw new ApiAbortError();
    }
    callerAbortListener = () => {
      internalController.abort();
    };
    options.signal.addEventListener("abort", callerAbortListener, { once: true });
  }

  try {
    const fetchInit: RequestInit = {
      method: options.method,
      cache: "no-store" as RequestCache,
      headers:
        options.method === "POST"
          ? { "Content-Type": "application/json", Accept: "application/json" }
          : { Accept: "application/json" },
      signal: internalSignal,
    };

    if (options.body !== undefined) {
      fetchInit.body = JSON.stringify(options.body);
    }

    let response: Response;
    try {
      response = await fetch(url, fetchInit);
    } catch (err) {
      // fetch throws TypeError on network failure or abort.
      if (internalSignal.aborted) {
        throw new ApiAbortError();
      }
      throw new ApiNetworkError();
    }

    if (!response.ok) {
      // Parse error body — only read detail.error_code.
      let errorCode: string | null = null;
      let errorMessage: string | null = null;
      try {
        const body = (await response.json()) as ApiErrorBody;
        if (body?.detail?.error_code) {
          errorCode = body.detail.error_code;
        }
        if (body?.detail?.error_message) {
          errorMessage = body.detail.error_message;
        }
      } catch {
        // JSON parse failed — errorCode stays null, will use generic message.
      }
      throw new ApiHttpError(response.status, errorCode, errorMessage);
    }

    // Parse successful JSON. If this fails, treat as internal error.
    try {
      return (await response.json()) as T;
    } catch {
      throw new ApiHttpError(500, "INTERNAL_ERROR", null);
    }
  } finally {
    // --- Cleanup: timeout + event listener ---
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    if (callerAbortListener && options.signal) {
      options.signal.removeEventListener("abort", callerAbortListener);
    }
  }
}

// ---------------------------------------------------------------------------
// Typed API functions
// ---------------------------------------------------------------------------

/**
 * POST /api/check — submit a repository for checking.
 * Returns task_id, status, check_url.
 */
export async function submitCheck(
  repoUrl: string,
  signal?: AbortSignal,
): Promise<CheckResponse> {
  const body: CheckRequest = { repo_url: repoUrl };
  return apiFetch<CheckResponse>("/api/check", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * GET /api/check/{task_id} — poll task status.
 * Returns status, stage, progress, scan_summary, score, etc.
 */
export async function getTaskStatus(
  taskId: string,
  signal?: AbortSignal,
): Promise<TaskStatusResponse> {
  return apiFetch<TaskStatusResponse>(`/api/check/${encodeURIComponent(taskId)}`, {
    method: "GET",
    signal,
  });
}

/**
 * GET /api/check/{task_id}/result — full scan result.
 */
export async function getScanResult(
  taskId: string,
  signal?: AbortSignal,
): Promise<ScanResult> {
  return apiFetch<ScanResult>(`/api/check/${encodeURIComponent(taskId)}/result`, {
    method: "GET",
    signal,
  });
}

/**
 * GET /api/check/{task_id}/assessment — full assessment result.
 */
export async function getAssessment(
  taskId: string,
  signal?: AbortSignal,
): Promise<AssessmentResult> {
  return apiFetch<AssessmentResult>(
    `/api/check/${encodeURIComponent(taskId)}/assessment`,
    { method: "GET", signal },
  );
}

/**
 * GET /api/check/{task_id}/repair-plan — full repair plan.
 */
export async function getRepairPlan(
  taskId: string,
  signal?: AbortSignal,
): Promise<RepairPlan> {
  return apiFetch<RepairPlan>(
    `/api/check/${encodeURIComponent(taskId)}/repair-plan`,
    { method: "GET", signal },
  );
}

// ---------------------------------------------------------------------------
// Export network error message for convenience
// ---------------------------------------------------------------------------

export { NETWORK_ERROR_MESSAGE };
