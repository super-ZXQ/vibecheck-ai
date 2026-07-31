import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiConfigError,
  normalizeApiBaseUrl,
} from "../lib/api-config.mjs";

test("undefined API base URL fails with a fixed configuration error", () => {
  assert.throws(() => normalizeApiBaseUrl(undefined), ApiConfigError);
});

test("empty API base URL fails with a fixed configuration error", () => {
  assert.throws(() => normalizeApiBaseUrl(""), ApiConfigError);
});

test("whitespace API base URL fails with a fixed configuration error", () => {
  assert.throws(() => normalizeApiBaseUrl("  "), ApiConfigError);
});

test("configured API base URL is returned unchanged", () => {
  assert.equal(
    normalizeApiBaseUrl("http://localhost:8000"),
    "http://localhost:8000",
  );
});

test("configured API base URL has trailing slashes removed", () => {
  assert.equal(
    normalizeApiBaseUrl("http://localhost:8000///"),
    "http://localhost:8000",
  );
});
