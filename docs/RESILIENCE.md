# Resilience Design

## Goals

Prove production-like behavior without claiming distributed-scale capacity:

1. Bounded concurrency (default 2 running tasks)
2. Atomic claim (no double execution)
3. Lease + heartbeat + crash recovery
4. Bounded retries with classification
5. Commit + scanner_version deduplication
6. Safe cancel + temp cleanup
7. BYOK credentials never leave process memory
8. Queue full → stable `429 QUEUE_FULL`

## Failure modes and handling

| Failure | Detection | Handling |
| --- | --- | --- |
| Worker/process crash | Lease not renewed | `recover_expired_tasks()` re-queues or marks `dead` |
| GitHub 429 | HTTP status / error code | `GITHUB_RATE_LIMITED`, retry with backoff |
| Download timeout | `httpx.TimeoutException` | `DOWNLOAD_TIMEOUT`, retry |
| Invalid URL / private repo | Parse / 404 | `INVALID_REPOSITORY`, no retry |
| Path traversal / symlink | Extract validators | `INVALID_ARCHIVE`, no retry |
| Extract limits | Size/count caps | `EXTRACTION_LIMIT_EXCEEDED`, no retry |
| Scan timeout | `asyncio.wait_for` | `SCAN_TIMEOUT`, retry if budget remains |
| Temp disk full | `OSError` errno 28 | `TEMP_STORAGE_EXHAUSTED`, retry |
| LLM 429/timeout/invalid | HTTP / parse | Non-blocking fallback templates |
| Queue overload | pending ≥ max | `429 QUEUE_FULL` |
| Cancel mid-flight | Cooperative checks | Terminal `cancelled`, cleanup + BYOK pop |

## Recovery rules

```
if status not running: skip
if lease_expires_at > now: leave alone
if attempt_count < max_attempts: pending (clear worker/lease)
else: dead
```

Pending tasks are **never** force-failed on restart.

Runtime recovery: dispatcher reaper (`LEASE_REAPER_SECONDS`) calls
`recover_expired_tasks()` while the process is alive, so a crashed worker
coroutine does not pin a task as `running` until process restart. Stale
claim tokens cannot heartbeat or complete after recovery (fencing).

## What we do not claim

- No multi-node leader election
- No Kafka/Kubernetes/LangGraph/RAG
- No production traffic numbers
- No GitHub public API high-rate load tests

## Controlled experiments

See `docs/LOAD_TEST_REPORT.md` and `load/locustfile.py`.
Default load uses `tests/fixtures/load_repositories/` synthetic content and
mocked GitHub behavior — never production GitHub at scale.

## Manual restart drill

1. Start backend, submit a slow/synthetic task
2. Kill the process while status=`running`
3. Restart backend
4. Observe: task returns to `pending` (if attempts remain) and is claimed again
5. `/metrics` shows `vibecheck_recoveries_total` increase

## Metrics to watch

- `vibecheck_queue_depth`
- `vibecheck_active_tasks`
- `vibecheck_retries_total{category}`
- `vibecheck_lease_expirations_total`
- `vibecheck_cleanup_failures_total`
- `vibecheck_deduplicated_tasks_total`
