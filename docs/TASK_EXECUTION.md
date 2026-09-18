# Task Execution Model

VibeCheck uses a **single-instance bounded concurrency** background task
engine on SQLite (WAL). It is **not** a distributed queue. Python locks
reduce contention; **SQLite `BEGIN IMMEDIATE` transactions are the
correctness boundary** for claim and recovery.

## Status machine

| Status | Meaning | API `status` |
| --- | --- | --- |
| `pending` | Queued or waiting for retry (`next_attempt_at`) | `pending` |
| `running` | Claimed by a worker with an active lease | `running` |
| `completed` | Pipeline finished; results persisted | `completed` |
| `failed` | Terminal failure (permanent error or retries exhausted) | `failed` |
| `cancelled` | Cancel requested; resources released | `failed` (`TASK_CANCELLED`) |
| `dead` | Lease expired after max attempts (crash recovery terminal) | `failed` |

Legal transitions (terminal states never return to `running`):

```
pending  → running | completed | failed | cancelled | dead
running  → running | completed | failed | cancelled | dead | pending (retry/recover)
completed/failed/cancelled/dead → ∅
```

## Atomic claim

`claim_next_pending(worker_id)`:

1. `BEGIN IMMEDIATE`
2. Select oldest `pending` task with `next_attempt_at` due and `cancelled_at IS NULL`
3. Update to `running`, set `worker_id`, `lease_expires_at`, `last_heartbeat_at`,
   increment `attempt_count`
4. Commit only if `rowcount == 1`

Two concurrent dispatchers cannot claim the same task.

## Lease, heartbeat, recovery

- Config: `TASK_LEASE_SECONDS`, `TASK_HEARTBEAT_SECONDS`, `MAX_TASK_ATTEMPTS`,
  `RETRY_BASE_SECONDS`, `RETRY_MAX_SECONDS`, `MAX_RUNNING_TASKS`
- Workers update `last_heartbeat_at` / extend `lease_expires_at` while running
- Startup calls `recover_expired_tasks()` (never force-fails pending tasks):
  - lease not expired → leave `running`
  - lease expired + attempts remaining → `pending`
  - lease expired + attempts exhausted → `dead`
  - terminal statuses untouched
- Unfinished tasks after graceful shutdown rely on lease expiry for recovery

## Deduplication

Key: `normalized_repo_url|resolved_commit_sha|scanner_version`

- Commit SHA is resolved after GitHub download (codeload redirect / headers)
- Completed match: new task copies desensitized result rows, sets
  `reused_from_task_id`, metrics `vibecheck_deduplicated_tasks_total`
- Running match at submit: API returns the **existing** `task_id` (coalescing)
- Local uploads are not reused across users by default
- `scanner_version` change invalidates reuse

## Retry policy

Failure categories in `app/services/task_errors.py`:

- **Retryable**: `DOWNLOAD_TIMEOUT`, `GITHUB_RATE_LIMITED`,
  `GITHUB_TEMPORARY_ERROR`, `LLM_RATE_LIMITED`, `LLM_TIMEOUT`,
  `SCAN_TIMEOUT`, `TEMP_STORAGE_EXHAUSTED`, `INTERNAL_TRANSIENT`
- **Permanent**: invalid repo/archive, path traversal, extraction limits,
  oversized downloads, permanent internal errors

Backoff: exponential with jitter, persisted in `next_attempt_at` (workers
never `sleep` a full backoff while holding a slot).

## Concurrency

- Default `MAX_RUNNING_TASKS=2` (bounded)
- Dispatcher loop fills free slots continuously
- Blocking work (SQLite, extract, scan, cleanup) via `asyncio.to_thread`
- `MAX_PENDING_TASKS` still enforces `429 QUEUE_FULL`
- Graceful shutdown: stop claiming → grace window → lease recovery later

## Cancel

`POST /api/check/{task_id}/cancel`

- `pending` → immediate `cancelled`
- `running` → cooperative cancel between stages; temp + BYOK cleared
- terminal → idempotent no-op
- Path deletion only after verifying the target is under a temp root

## BYOK (user LLM keys)

- Credentials live **only in process memory** (`llm_user_config`)
- Never written to SQLite, logs, traces, or metric labels
- Cleared on task finish/fail/cancel and on process shutdown
- Missing key after restart → LLM stage degrades to templates (`source=fallback`)

## Observability

`GET /metrics` (Prometheus text). Examples:

- `vibecheck_queue_depth`, `vibecheck_active_tasks`
- `vibecheck_tasks_total{status=...}`
- `vibecheck_task_duration_seconds`, `vibecheck_stage_duration_seconds{stage=...}`
- `vibecheck_retries_total{category=...}`, `vibecheck_recoveries_total`
- `vibecheck_deduplicated_tasks_total`, `vibecheck_cancelled_tasks_total`
- `vibecheck_cleanup_failures_total`

Forbidden labels: `repo_url`, `owner`, `repo_name`, `task_id`, paths, secrets.

`GET /api/ready` checks **database** readiness; LLM outage is reported under
`dependencies.llm` and does not fail readiness.

## ADR-001: Stage boundary for crash recovery

**Decision.** After a crash, a task that already persisted `scan_results`
still re-runs download/extract/scan/assess/repair when re-queued, unless the
same `commit_sha + scanner_version` already has a **completed** task to reuse.

**Rationale.** Intermediate stage reuse across different task IDs is complex
and easy to get wrong (stale assessment vs new scan). Completed-result reuse
via dedup is the safe, testable boundary. We do **not** silently re-hit
GitHub more than needed for SHA resolution when a completed twin exists.

## Concurrency correctness (P1 hardening)

- **Atomic admission**: `admit_repo_task` / `admit_upload_task` use one
  `BEGIN IMMEDIATE` transaction for coalesce + capacity + insert.
- **Claim token fencing**: each `claim_next_pending()` writes a unique
  `worker_id` token; heartbeat and stage/completion updates require it.
- **Conditional updates**: `mark_*` / `fail_or_retry` use `WHERE` predicates
  including `status` / `worker_id` / `cancelled_at IS NULL` and check
  `rowcount`.
- **Runtime reaper**: dispatcher periodically calls `recover_expired_tasks()`
  (`LEASE_REAPER_SECONDS`, must be ≤ lease).
- **Cleanup boundary**: only VibeCheck-named dirs under `settings.tmp_dir`.
- **Streaming download**: GitHub tarball uses `httpx.AsyncClient.stream()`.

## Honest capability statement

- Single-instance bounded concurrency on SQLite WAL
- Not horizontally scalable as a distributed queue
- Load/fault experiments use local synthetic repos and mocks — not production traffic
