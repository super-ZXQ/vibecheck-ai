# Public Deployment Notes

## Capability statement (must stay honest)

VibeCheck production mode is:

- **Single-instance bounded concurrency** (default `MAX_RUNNING_TASKS=2`,
  one uvicorn worker — see "Task execution knobs")
- **PostgreSQL 16** persistence — not a distributed queue, no broker
- Safe input handling + reliable background tasks as the engineering core
- **Not** LangGraph / RAG / Text-to-SQL / Kafka / Kubernetes

Load and fault numbers in docs come from **local synthetic** experiments and
**mocked** GitHub/LLM failures — not live business traffic — unless a future
deployment record says otherwise.

## Schema migration

Alembic owns the production schema. Startup does not create tables in
`production`; it verifies them and refuses to serve if migrations were not
applied. Apply migrations before starting the backend:

```
docker compose -f docker-compose.production.yml up -d postgres
docker compose -f docker-compose.production.yml run --rm backend alembic upgrade head
docker compose -f docker-compose.production.yml up -d backend frontend
```

`/api/ready` returns 503 with `"database schema is not initialized — run
`alembic upgrade head`"` in the server log until step 2 has run.

## Required production config

See `production.env.example`. Backend refuses to start in `production` when:

- `PRODUCTION_CONFIG_CONFIRMED` is not true
- `DATABASE_URL` is not a PostgreSQL `asyncpg` URL
- `DATABASE_URL` still uses the development `vibecheck:vibecheck` credentials
- Trusted hosts omit `127.0.0.1` or contain `*`
- CORS uses wildcard

## Database connections

The application engine is created once on the FastAPI lifespan event loop and
pools connections (`DB_POOL_SIZE=5`, `DB_MAX_OVERFLOW=10`,
`DB_POOL_RECYCLE_SECONDS=1800`; disabled under `APP_ENV=test`).

asyncpg binds every connection to the loop that opened it, so a second event
loop cannot check one out of that pool. `app/db/session.py` therefore gives any
foreign loop its own **unpooled** engine instead of handing it a poisoned
connection. Sync facades called from `asyncio.to_thread` land on that per-loop
engine: correct, but uncached. Keep request and worker paths on the `*_async`
functions so they stay on the pooled engine.

| Env | Default | Meaning |
| --- | --- | --- |
| `DB_POOL_SIZE` | 5 | Persistent pooled connections on the app loop |
| `DB_MAX_OVERFLOW` | 10 | Extra connections allowed above the pool |
| `DB_POOL_RECYCLE_SECONDS` | 1800 | Recycle age, survives DB restarts |

## Task execution knobs

| Env | Default | Meaning |
| --- | --- | --- |
| `MAX_PENDING_TASKS` | 5 | Queue capacity (429 when full) |
| `MAX_RUNNING_TASKS` | 2 | Bounded concurrency |
| `TASK_LEASE_SECONDS` | 120 | Claim lease TTL |
| `TASK_HEARTBEAT_SECONDS` | 20 | Heartbeat interval |
| `MAX_TASK_ATTEMPTS` | 3 | Retry budget |
| `RETRY_BASE_SECONDS` | 2 | Backoff base |
| `RETRY_MAX_SECONDS` | 60 | Backoff cap |

## Submission rate limits

`POST /api/check` and `POST /api/check/upload` share two token buckets: one per
client IP (the anchor a caller cannot mint) and one per `X-Submitter-Key` (one
browser's friction). Both must allow the request; otherwise the response is
`429 RATE_LIMITED` with a `Retry-After` header. Status polling is a GET and is
never throttled.

| Env | Default | Meaning |
| --- | --- | --- |
| `RATE_LIMIT_ENABLED` | true | Set false to disable both buckets |
| `RATE_LIMIT_IP_PER_MINUTE` | 10 | Sustained submissions per client IP |
| `RATE_LIMIT_IP_BURST` | 5 | Initial burst per client IP |
| `RATE_LIMIT_SUBMITTER_PER_MINUTE` | 3 | Sustained submissions per submitter key |
| `RATE_LIMIT_SUBMITTER_BURST` | 2 | Initial burst per submitter key |

Buckets live in process memory, which matches the single-uvicorn-worker model:
there is one shared budget, and a restart resets it.

The IP bucket reads `request.client.host`. Behind the TLS proxy described below,
that is the proxy address unless uvicorn trusts the proxy's forwarding header.
Set `FORWARDED_ALLOW_IPS` to the proxy address (uvicorn's default is
`127.0.0.1`, which matches the shipped loopback bind). Without it every visitor
shares one bucket and normal traffic throttles itself. Never set it to `*`:
clients could then spoof `X-Forwarded-For` and bypass the per-IP limit.

## Endpoints

| Endpoint | Notes |
| --- | --- |
| `POST /api/check` | Submit; coalesces running same-repo+scanner_version |
| `POST /api/check/upload` | Local zip/folder path |
| `POST /api/check/{id}/cancel` | Idempotent cancel |
| `GET /api/check/{id}` | Poll status (cancelled/dead → `failed`) |
| `GET /api/health` | Liveness |
| `GET /api/ready` | DB readiness + dependency degradation |
| `GET /metrics` | Prometheus text (no high-cardinality labels) |

## BYOK

User LLM keys are process-memory only. After restart they are gone; scan
results remain valid; LLM stage falls back to templates with `source=fallback`.

## Task ownership header

`X-Submitter-Key` is the second browser-held header. The frontend generates an
anonymous 32-character key once, stores it in localStorage, and sends it on
every task request; the backend records it on the task and requires the same
value to read or cancel it. `allow_headers` in `app/main.py` must keep it or
browsers cannot send it across origins.

- Migration `0002_submitter_key` adds one nullable column; no backfill and no
  downtime. Tasks created before the upgrade stay reachable by task id, which
  matters only until the retention window passes.
- Requests with a wrong or absent key get the same `404 TASK_NOT_FOUND` as an
  unknown task, so the check does not confirm existence.
- A submission without the header records no owner and remains reachable by
  task id alone — an intentional opt-out for API clients, not for the site.
- The key is never stored server-side beyond that column, never returned, and
  not an identity: clearing browser data drops access to that browser's tasks.

## Restart behavior

Crash-safe: expired leases re-queue; pending tasks stay pending. Operators
should not expect `SERVICE_RESTARTED` force-fail of the whole queue.

## TLS / reverse proxy

Terminate TLS in front of the containers. Set `CORS_ALLOWED_ORIGINS` to real
HTTPS origins and append public hostnames to `TRUSTED_HOSTS`. Keep
`127.0.0.1` for local healthchecks.

## What we still do not provide

- Accounts: task ownership is per browser, not per person, and cannot be
  recovered if the browser's localStorage is cleared
- Horizontal scale-out of the task queue
- Exactly-once external side effects across multiple replicas
- Real production traffic SLOs
