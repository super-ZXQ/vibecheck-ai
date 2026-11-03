import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_POLL_TIMEOUT_MS,
} from "../lib/polling-config.mjs";

/**
 * The frontend must keep polling for at least one full backend attempt,
 * otherwise a healthy slow task is reported to the user as "检测超时".
 * The bound is the one the backend itself enforces for temp-file lifetime:
 * every stage timeout plus one lease.
 */
async function backendAttemptBoundSeconds() {
  const source = await readFile(
    new URL("../../backend/app/core/config.py", import.meta.url),
    "utf8",
  );
  const names = [
    "download_timeout",
    "extract_timeout",
    "scan_timeout",
    "assess_timeout",
    "repair_plan_timeout",
    "llm_analysis_timeout",
    "task_lease_seconds",
  ];
  return names.reduce((sum, name) => {
    const match = source.match(new RegExp(`^\\s+${name}: [^=]+?=\\s*([^#\n]+)`, "m"));
    assert.ok(match, `backend config no longer declares ${name}`);
    const raw = match[1].trim();
    // Plain int, or Field(default=...) — either way one literal number.
    const value = raw.match(/(\d+)/);
    assert.ok(value, `cannot read the default for ${name} (${raw})`);
    return sum + Number(value[1]);
  }, 0);
}

test("poll deadline covers one full backend attempt", async () => {
  const boundSeconds = await backendAttemptBoundSeconds();
  assert.ok(
    DEFAULT_POLL_TIMEOUT_MS >= boundSeconds * 1000,
    `frontend polls for ${DEFAULT_POLL_TIMEOUT_MS}ms but a backend attempt can take ${boundSeconds}s`,
  );
});

test("poll interval is far below the deadline", () => {
  assert.ok(DEFAULT_POLL_INTERVAL_MS > 0);
  assert.ok(
    DEFAULT_POLL_TIMEOUT_MS >= 100 * DEFAULT_POLL_INTERVAL_MS,
    "the deadline must allow many polls, not a handful",
  );
});
