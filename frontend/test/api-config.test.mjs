import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiConfigError,
  getApiBaseUrl,
} from "../lib/api-config.mjs";

test("missing API base URL fails with a fixed configuration error", () => {
  assert.throws(() => getApiBaseUrl(undefined), ApiConfigError);
  assert.throws(() => getApiBaseUrl("  "), ApiConfigError);
});

test("configured API base URL has trailing slashes removed", () => {
  assert.equal(getApiBaseUrl("http://localhost:8000///"), "http://localhost:8000");
});
