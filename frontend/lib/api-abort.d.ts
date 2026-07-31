export type AbortCause = "caller" | "timeout" | null;

export class ApiRequestTimeoutError extends Error {}
export class ApiAbortError extends Error {}

export function throwAbortOutcome(
  signal: AbortSignal,
  abortCause: AbortCause,
): void;
