import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiAbortError,
  ApiRequestTimeoutError,
  throwAbortOutcome,
} from "../lib/api-abort.mjs";

test("a timeout abort is classified as ApiRequestTimeoutError", () => {
  const controller = new AbortController();
  controller.abort();

  assert.throws(
    () => throwAbortOutcome(controller.signal, "timeout"),
    ApiRequestTimeoutError,
  );
});

test("a caller abort is classified as ApiAbortError", () => {
  const controller = new AbortController();
  controller.abort();

  assert.throws(
    () => throwAbortOutcome(controller.signal, "caller"),
    ApiAbortError,
  );
});

test("an unaborted signal does not throw", () => {
  const controller = new AbortController();

  assert.doesNotThrow(() =>
    throwAbortOutcome(controller.signal, "timeout"),
  );
});
