# ADR-001: Crash recovery stage boundary

## Status

Accepted

## Context

After a process crash, a task may have persisted some pipeline outputs
(`scan_results`, maybe assessment/repair) and still be marked `running` with
an expired lease. Naively re-running from download can duplicate external
calls; blindly skipping stages can serve mismatched assessment/scan pairs.

## Decision

1. Startup never force-fails the whole queue. Use `recover_expired_tasks()`.
2. Expired running leases re-queue to `pending` while `attempt_count < max_attempts`.
3. Completed results for the same `normalized_repo_url|commit_sha|scanner_version`
   are reused (copy desensitized rows + `reused_from_task_id`).
4. Intermediate partial stage reuse across task IDs is **not** implemented;
   re-queued tasks re-enter the pipeline. This is the safe boundary.
5. Local uploads are not cross-user deduplicated.

## Consequences

- At most one download to resolve SHA when a completed twin may exist.
- Deterministic assessment/repair policies remain consistent with persisted scan.
- Operators understand single-instance + SQLite WAL limits from README.

## Alternatives considered

- Full stage checkpoint resume (complexity high, silent mismatch risk)
- Force-fail all running tasks on restart (old MVP; loses valid work)
