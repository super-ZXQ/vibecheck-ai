# Public Deployment Notes

## Capability statement (must stay honest)

VibeCheck production mode is:

- **Single-instance bounded concurrency** (default `MAX_RUNNING_TASKS=2`)
- **SQLite WAL** persistence — not a distributed queue
- Safe input handling + reliable background tasks as the engineering core
- **Not** LangGraph / RAG / Text-to-SQL / Kafka / Kubernetes

Load and fault numbers in docs come from **local synthetic** experiments and
**mocked** GitHub/LLM failures — not live business traffic — unless a future
deployment record says otherwise.

## Required production config

See `production.env.example`. Backend refuses to start in `production` when:

- `PRODUCTION_CONFIG_CONFIRMED` is not true
- Database path is not a SQLite `.db` under `/data`
- Trusted hosts omit `127.0.0.1` or contain `*`
- CORS uses wildcard

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

## Restart behavior

Crash-safe: expired leases re-queue; pending tasks stay pending. Operators
should not expect `SERVICE_RESTARTED` force-fail of the whole queue.

## TLS / reverse proxy

Terminate TLS in front of the containers. Set `CORS_ALLOWED_ORIGINS` to real
HTTPS origins and append public hostnames to `TRUSTED_HOSTS`. Keep
`127.0.0.1` for local healthchecks.

## What we still do not provide

- Horizontal scale-out of the task queue
- Exactly-once external side effects across multiple replicas
- Real production traffic SLOs
