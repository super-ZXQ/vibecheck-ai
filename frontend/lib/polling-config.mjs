/**
 * Polling budget for a check task, shared by the task hook and its E2E specs.
 *
 * The deadline must cover one legitimate backend attempt. A single attempt can
 * run for the sum of every stage timeout plus one full lease — the same bound
 * backend/app/core/config.py `_temp_ttl_exceeds_task_lifetime` enforces —
 * before any queue wait. A shorter client deadline would show "检测超时" on a
 * task that is still healthy, so `test/polling-deadline.test.mjs` keeps the
 * two in sync.
 */

export const DEFAULT_POLL_INTERVAL_MS = 2000;

export const DEFAULT_POLL_TIMEOUT_MS = 900_000;
