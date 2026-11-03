import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  SUBMITTER_KEY_HEADER,
  SUBMITTER_KEY_STORAGE,
  buildSubmitterHeaders,
  createSubmitterKey,
  resolveSubmitterKey,
} from "../lib/submitter-key.mjs";

/**
 * The browser generates the task ownership key, the backend validates it
 * against a pattern in app/core/task_access.py. These tests pin both sides so
 * a key minted here can never be rejected there.
 */

function stubRandom(fill = 0xab) {
  let calls = 0;
  return {
    fn: (bytes) => {
      calls += 1;
      bytes.fill(fill);
      return bytes;
    },
    get calls() {
      return calls;
    },
  };
}

function fakeStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  const state = { writes: 0, reads: 0 };
  return {
    state,
    getItem() {
      state.reads += 1;
      const value = data.get(SUBMITTER_KEY_STORAGE);
      return value === undefined ? null : value;
    },
    setItem(_key, value) {
      state.writes += 1;
      data.set(SUBMITTER_KEY_STORAGE, value);
    },
  };
}

async function backendKeyPattern() {
  const source = await readFile(
    new URL("../../backend/app/core/task_access.py", import.meta.url),
    "utf8",
  );
  const match = source.match(/_KEY_PATTERN = re\.compile\(r"([^"]+)"\)/);
  assert.ok(match, "backend no longer defines _KEY_PATTERN the way this test expects");
  return new RegExp(`^${match[1]}$`);
}

test("generated key satisfies the backend validation pattern", async () => {
  const pattern = await backendKeyPattern();
  const key = createSubmitterKey(stubRandom().fn);
  assert.match(key, pattern);
  assert.equal(key.length, 32);
  assert.equal(key, "ab".repeat(16));
});

test("header name matches the backend alias", async () => {
  const source = await readFile(
    new URL("../../backend/app/core/task_access.py", import.meta.url),
    "utf8",
  );
  assert.match(source, /SUBMITTER_KEY_HEADER = "X-Submitter-Key"/);
  assert.equal(SUBMITTER_KEY_HEADER, "X-Submitter-Key");
});

test("first use mints and stores one key, later reads reuse it", () => {
  const storage = fakeStorage();
  const random = stubRandom(0x01);
  const first = resolveSubmitterKey(storage, random.fn);
  const second = resolveSubmitterKey(storage, random.fn);
  assert.equal(first, "01".repeat(16));
  assert.equal(second, first);
  assert.equal(random.calls, 1);
  assert.equal(storage.state.writes, 1);
});

test("a tampered stored value is replaced, not sent", () => {
  const storage = fakeStorage({ [SUBMITTER_KEY_STORAGE]: "short" });
  const key = resolveSubmitterKey(storage, stubRandom(0x0f).fn);
  assert.equal(key, "0f".repeat(16));
  assert.equal(storage.state.writes, 1);
});

test("unusable storage falls back to a session key", () => {
  const readBroken = {
    getItem() {
      throw new Error("blocked");
    },
    setItem() {},
  };
  assert.equal(resolveSubmitterKey(readBroken, stubRandom().fn), null);

  const writeBroken = {
    getItem: () => null,
    setItem() {
      throw new Error("quota");
    },
  };
  // Ownership is kept for this session instead of silently making the task public.
  assert.equal(resolveSubmitterKey(writeBroken, stubRandom().fn), "ab".repeat(16));
});

test("no storage at all still yields a valid key", () => {
  assert.equal(resolveSubmitterKey(null, stubRandom(0x7a).fn), "7a".repeat(16));
});

test("buildSubmitterHeaders stays empty outside the browser", () => {
  // Server rendering owns no tasks; minting a throwaway key per request would
  // make every task unfindable on the next poll.
  assert.deepEqual(buildSubmitterHeaders(), {});
});
