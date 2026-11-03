# Task Execution Model

VibeCheck uses **PostgreSQL-backed durable bounded task execution** with
**multi-worker-safe database claiming**. It is **not** a Celery/distributed
broker queue.

**Claim correctness boundary:** PostgreSQL transaction + `SELECT ... FOR UPDATE
SKIP LOCKED` (SQLite `BEGIN IMMEDIATE` was the pre-upgrade boundary).

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

## Schema authority

- **Alembic** owns the PostgreSQL schema (`alembic upgrade head`)
- `create_all` is only for isolated tests / local smoke, never `production`
- Runtime default is `postgresql+asyncpg://...`; SQLite is not a production
  database in this architecture

## Atomic claim (PostgreSQL)

`claim_next_pending_async(worker_id)`:

1. Open an `AsyncSession` transaction
2. `SELECT` one claimable task — `status = pending`, `cancelled_at IS NULL`,
   `next_attempt_at` due — `ORDER BY next_attempt_at NULLS FIRST, created_at`
   with `FOR UPDATE SKIP LOCKED LIMIT 1`
3. Guarded `UPDATE` to `running` with `worker_id`, `lease_expires_at`,
   `last_heartbeat_at`, `attempt_count + 1`, `next_attempt_at = NULL`
4. Return the task only if `rowcount == 1`

Two concurrent dispatchers cannot claim the same task. `SKIP LOCKED` is applied
only when the dialect is PostgreSQL, so tests on other backends still claim
with plain `FOR UPDATE`.

## Lease, heartbeat, recovery

- Config: `TASK_LEASE_SECONDS`, `TASK_HEARTBEAT_SECONDS`, `LEASE_REAPER_SECONDS`
  (must be ≤ lease), `MAX_TASK_ATTEMPTS`, `RETRY_BASE_SECONDS`,
  `RETRY_MAX_SECONDS`, `MAX_RUNNING_TASKS`
- Times stored as `TIMESTAMPTZ` (timezone-aware UTC in Python)
- Workers `await touch_heartbeat_async()` to extend `lease_expires_at`; the
  update only matches rows still `running`, `cancelled_at IS NULL` and owned by
  that `worker_id`, so a fenced-out worker cannot keep a task alive
- Startup and the runtime reaper call `recover_expired_tasks_async()` (never
  force-fails pending tasks):
  - lease not expired → leave `running`
  - lease expired + attempts remaining → `pending`
  - lease expired + attempts exhausted → `dead`
  - terminal statuses untouched
- Recovery selects `FOR UPDATE SKIP LOCKED`, so concurrent recoverers do not
  double-requeue the same task
- Unfinished tasks after a crash or graceful shutdown rely on lease expiry

## Deduplication

`tasks.deduplication_key` holds one of two shapes, and the switch happens at
completion (`mark_completed`):

- while queued/running: `normalized_repo_url|active|scanner_version|owner_scope`
  (`owner_scope` is the SHA-256 digest of the submitter key, or `public` when no key was sent)
- once completed: `normalized_repo_url|resolved_commit_sha|scanner_version`

- Partial unique index `uq_tasks_active_dedup` covers active rows only
  (`status IN ('pending','running') AND deduplication_key IS NOT NULL`), which
  is why the shared commit-level key must not be written earlier: two owners
  scanning one commit would collide
- Commit SHA is resolved after GitHub download (codeload redirect / headers);
  `set_resolved_commit_sha` records the SHA and publishes the commit-level key
  only if the row is already completed, so both orderings end up discoverable
- Completed match: new task copies desensitized result rows, sets
  `reused_from_task_id`, metrics `vibecheck_deduplicated_tasks_total`
- Running match at submit: API returns the **existing** `task_id` (coalescing)
- Local uploads are not reused across users by default
- `scanner_version` change invalidates reuse

## Task ownership (X-Submitter-Key)

A task id used to be the only credential: anyone who learned one could read
that report and cancel that job — and because active tasks coalesced per
repository, a second visitor was handed the first visitor's `task_id`.

- The browser generates one anonymous key (32 hex chars, `lib/submitter-key.mjs`,
  kept in localStorage) and sends it as `X-Submitter-Key` on every task request.
- `tasks.submitter_key` records its SHA-256 digest, never the raw key: a
  database dump alone cannot be replayed as a bearer credential, while the
  browser that holds the raw key still matches it exactly.
- Reads (`status`, `result`, `assessment`, `repair-plan`, `llm-analysis`)
  and `cancel` answer `404 TASK_NOT_FOUND` — identical to an unknown task id
  — when the key does not match.
- Active-task coalescing is scoped to the key, so concurrent submissions of
  the same repository from different browsers create separate tasks. The cost
  control that survives: repeats from the same browser still share one task,
  and keyless clients still share with each other.
- No key on submit means no owner is recorded; that task stays reachable by
  task id alone. The header is optional by design (API clients may opt out),
  and the browser always sends it.
- Completed-result reuse remains cross-browser for **public GitHub
  repositories**: the source is public and any visitor could rescan it, so
  copying a desensitized result is cost control, not a leak. Uploads never
  take this path (`build_deduplication_key` returns `None` for local URLs).
- The key is not an identity and is never returned by the API. Clearing site
  data (or private mode) loses access to tasks created beforehand.

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
- Claim, lease, heartbeat, status and cancel writes are awaited on the event
  loop; only CPU/IO-bound work (extract, scan, cleanup) runs via
  `asyncio.to_thread`
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
- Never written to the database, logs, traces, or metric labels
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

- **Atomic admission**: `admit_repo_task` / `admit_upload_task` count and
  insert inside one transaction, serialized by
  `pg_advisory_xact_lock(747123)` and backed by a partial unique index on
  `deduplication_key` for the coalesce race.
- **Claim token fencing**: each `claim_next_pending_async()` writes a unique
  `worker_id` token; heartbeat and stage/completion updates require it.
- **Conditional updates**: `mark_*` / `fail_or_retry` use `WHERE` predicates
  including `status` / `worker_id` / `cancelled_at IS NULL` and check
  `rowcount`.
- **Runtime reaper**: dispatcher periodically calls
  `recover_expired_tasks_async()` (`LEASE_REAPER_SECONDS`, must be ≤ lease).
- **Cleanup boundary**: only VibeCheck-named dirs under `settings.tmp_dir`.
- **Streaming download**: GitHub tarball uses `httpx.AsyncClient.stream()`.

## Why not Celery?

Broker + worker fleet + complex routing is unnecessary for V1. PostgreSQL
`SKIP LOCKED` + lease + heartbeat + bounded retry gives reliable task execution
with one less moving part.

## Honest capability statement

- **PostgreSQL-backed durable bounded task execution**, single-instance
  bounded concurrency
- **Multi-worker-safe database claiming** (`SKIP LOCKED` + lease fencing)
- **Anonymous per-browser task ownership** (`X-Submitter-Key`) — scoping, not
  authentication: there are no accounts, and a key is only as secret as the
  browser that holds it
- Not a Celery/Kafka distributed queue and not horizontally scalable
- Load/fault experiments use local synthetic repos and mocks — not production
  traffic
