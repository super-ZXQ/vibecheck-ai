/** Thrown when a single request exceeds its timeout. */
export class ApiRequestTimeoutError extends Error {
  constructor() {
    super("REQUEST_TIMEOUT");
    this.name = "ApiRequestTimeoutError";
  }
}

/** Thrown when a request is aborted by its caller. */
export class ApiAbortError extends Error {
  constructor() {
    super("ABORTED");
    this.name = "ApiAbortError";
  }
}

export function throwAbortOutcome(signal, abortCause) {
  if (!signal.aborted) return;

  if (abortCause === "timeout") {
    throw new ApiRequestTimeoutError();
  }

  throw new ApiAbortError();
}
