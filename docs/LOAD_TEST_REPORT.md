# Load & Fault Experiment Report

**Status honesty rule:** any scenario not actually executed in this
repository revision is marked **未执行**. No guessed numbers.

Environment used for executed runs:

- OS: Windows (developer machine)
- Python: 3.12.6
- Config under test: `MAX_RUNNING_TASKS=2`, `MAX_PENDING_TASKS=5`,
  `MAX_TASK_ATTEMPTS=3` (unless a scenario overrides)
- Load target: in-process / local API via tests — **not** public GitHub

## Fixtures

- `tests/fixtures/load_repositories/` — synthetic mini-repositories
- `load/locustfile.py` — Locust scenarios (local base URL only)
- Mock GitHub errors injected in pytest (`GITHUB_RATE_LIMITED`, timeout)

## Scenario matrix

| # | Scenario | Method | Status |
| --- | --- | --- | --- |
| 1 | 20–50 concurrent submissions | pytest + TestClient / load script | 见下方实测 |
| 2 | Queue full → 429 | `test_queue_full_429` / API tests | **已执行** |
| 3 | Two dispatchers claim race | `test_concurrent_claims_unique` ThreadPool | **已执行** |
| 4 | Duplicate repo submit | dedup/coalesce tests | **已执行** |
| 5 | GitHub 429 mock | `test_github_rate_limit_maps...` | **已执行** |
| 6 | GitHub timeout/reset mock | error classification unit tests | **已执行** |
| 7 | Corrupt archive | existing safe_extract tests | **已执行**（既有） |
| 8 | Path traversal / symlink | existing extract security tests | **已执行**（既有） |
| 9 | Extract limit exceeded | existing extract limit tests | **已执行**（既有） |
| 10 | Scan timeout | error category mapping + pipeline timeout tests | **已执行**（既有+分类） |
| 11 | Temp space insufficient | `TEMP_STORAGE_EXHAUSTED` mapping unit | **已执行**（单元） |
| 12 | LLM 429/timeout/invalid | llm_service non-blocking tests | **已执行**（既有） |
| 13 | Simulated service restart | lease recovery tests | **已执行** |
| 14 | Lease expiry recovery | `recover_expired_tasks` tests | **已执行** |
| 15 | Cancel running task | cancel API/pipeline tests | **已执行** |
| 16 | Temp cleanup after complete/fail/cancel | cleanup tests | **已执行** |

## Measured results (pytest / local)

Recorded from backend suite on this machine (no external traffic):

| Metric | Value | Source |
| --- | --- | --- |
| Backend pytest | **1931 passed, 9 skipped** | `python -m pytest tests/ -q` |
| Backend ruff | All checks passed | `ruff check app tests` |
| Backend mypy | Success, 42 source files | `mypy app` |
| Frontend unit | 25 passed | `npm run test:unit` |
| Frontend build | success | `npm run build` |
| Playwright e2e | **63 passed** (2.3m) | `npx playwright test` |
| Claim uniqueness | 20 tasks / 8 threads — 20 unique claims | `TestAtomicClaim` |
| Bounded concurrency | max concurrent downloads ≤ 2 | `TestBoundedConcurrency` |
| Recovery requeue | expired lease → pending | `TestLeaseRecovery` |
| Dedup counter | incremented on reuse | `TestDeduplication` |
| Queue full | HTTP 429 QUEUE_FULL | `TestQueueFullAPI` |
| BYOK not in DB bytes | secret absent from sqlite file | `TestBYOKSecurity` |

### Locust (optional)

```bash
cd backend
pip install locust
# Start API locally first (mocked/fake GitHub in tests; do not hammer github.com)
locust -f ../load/locustfile.py --host http://127.0.0.1:8000
```

**Locust full distributed run:** 未执行（本环境未对本地服务起完整 Locust 主从压测）。

### Event loop latency

Covered by `TestEventLoopNotBlocked.test_api_polling_during_scan`:
poll iterations complete while a 300ms scan runs in a worker thread;
max poll latency asserted < 250ms in-test.

### P50/P95/P99 task duration

**未执行** — requires a sustained local load run against a live server with
duration histograms exported. Metrics scaffolding
(`vibecheck_task_duration_seconds`) is present; full histogram run not
executed in this revision.

## How to reproduce

```bash
cd backend
python -m pytest tests/test_production_task_execution.py tests/test_service_restart.py -v
python -m pytest tests/ -q
```

## Remaining gaps

- Full Locust soak against a long-running uvicorn process: 未执行
- GitHub public API rate-limit live drill: 未执行（禁止高频压测公共接口）
- Multi-instance claim race across two OS processes: 未执行（当前单实例设计）
