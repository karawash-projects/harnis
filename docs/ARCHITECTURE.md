# Architecture

This document is for teams evaluating or operating Harnis. It describes the components, how a request flows through them, where state lives, how tenants are kept apart, which boundaries are security boundaries, and how the system scales. Module paths refer to the `harnis/` package.

## Components

```
                         clients: web console, CLI (harnis), CI with API keys, your apps
                                         |  HTTPS: Authorization: Bearer <OIDC JWT | local JWT | API key>
                                         |  WSS:   /v1/ws?token=...
                                         v
 +--------------------------------- API replica (stateless; N of them) ----------------------------------+
 |                                                                                                        |
 |  auth.py            api.py                   orchestrator.py (checkpointed state machine)              |
 |  Authenticator -->  tenant active? owner? -->  ingest -> route -> [cache_lookup] -> agent <-> tools     |
 |  (OIDC JWKS,        rate limit (infra.py)       |         |           |               |        |       |
 |   local JWT,        session lock (infra.py)     |      fast model   cache.py       LLM router  |       |
 |   API keys)                                   guardrails.py                       llm/router  |       |
 |                                                                                               |       |
 |  plugins.py: Registry of tools, agents, providers (built-ins and PLUGINS)       low risk: run now     |
 |                                                                                 high risk: SUSPEND    |
 +-----+-------------------------+------------------------+---------------------------+--------+---------+
       |                         |                        |                           |        |
       | tenant_tx (RLS)         | rate limits, locks,    | HTTPS                     |        | workspace
       v                         | events, breaker, cache v                           v        v files
 +-------------+          +-------------+        +------------------+       +-------------------------+
 | PostgreSQL  |          |   Redis     |        | Model providers  |       | Sandbox (one per command)|
 | sessions,   |          | (Stack for  |        | Anthropic,OpenAI,|       |  Docker container  or   |
 | approvals,  |          |  vector     |        | Gemini, Nova,    |       |  Kubernetes Pod         |
 | ledger,     |          |  search)    |        | plugins; mock    |       |  no network, read-only, |
 | audit, keys |          |             |        | in development   |       |  non-root, no caps      |
 +-------------+          +-------------+        +------------------+       +-------------------------+
                                                                             WORKSPACES_DIR (shared
                                                                             volume when N > 1)
```

| Component | Module | Responsibility |
|---|---|---|
| API | `api.py` | FastAPI app factory (`create_app`) wiring every dependency; HTTP routes, WebSocket stream, health and readiness. All dependencies are injectable, which is how the tests run without services. |
| Authentication | `auth.py` | Turns a bearer credential into a `Principal` (user, tenant, roles). OIDC (`AUTH_MODE=oidc`), local HS256 JWT (`AUTH_MODE=local`), and API keys (`hrn_...`, in both modes). |
| Orchestrator | `orchestrator.py` | The turn engine: an explicit state machine with budgets, loop breaker, approvals and hand-offs, checkpointed after every node. |
| Tools | `tools.py` | Tool definitions: Pydantic argument models, risk tiers, workspace confinement, action hashing and diffs for reviewers. |
| Plugin registry | `plugins.py` | One registry for tools, agents and model providers. Built-ins register the same way as plugins named in `PLUGINS` ([plugins.md](plugins.md)). |
| Sandbox | `sandbox.py`, `k8s_sandbox.py` | Runs agent commands and tests in a throwaway, locked-down container (`DockerSandbox`) or Pod (`KubernetesSandbox`, `SANDBOX_BACKEND=kubernetes`). |
| Guardrails | `guardrails.py` | Input checks and redaction, untrusted-data fencing for tool output, output redaction. |
| LLM layer | `llm/` | Provider-neutral types, provider adapters, failover router with retries and a shared circuit breaker, pricing. |
| Store | `store.py`, `db.py` | All Postgres access, through tenant-scoped transactions. |
| Redis primitives | `infra.py`, `cache.py` | Token-bucket rate limiter, per-session lock, event bus; tenant-scoped semantic cache. |
| Operations | `migrate.py`, `maintenance.py`, `telemetry.py`, `alerts.py` | Migrations and roles; ledger partitions and analytics refresh; OpenTelemetry; Slack/Discord alerts. |
| Clients | `cli.py`, `static/index.html`, `evals.py`, `redteam/run.py` | CLI coding agent, web console, eval runner, red-team checks. All use the public API. |

## Request flow

### A turn

`POST /v1/sessions/{id}/turns` with a message:

1. **Authenticate.** `Authenticator` verifies the credential and produces a `Principal`. The tenant comes from the verified token claim or the API key record, never from the request.
2. **Authorize.** The caller needs the `user` role, the tenant must exist and be active, and only the session's owner can send messages (`load_owned` reads the session through RLS, so another tenant's session is simply not found).
3. **Rate limit.** A token bucket per (tenant, user) in Redis, atomic via Lua. Over the limit returns 429 with `Retry-After`.
4. **Lock.** A Redis lock per session (`SET NX` with TTL, released by token) ensures one turn at a time per session across replicas. The session is re-read under the lock.
5. **Orchestrate.** `Orchestrator.start_turn` runs nodes until the turn ends or suspends. After **every** node the state is checkpointed with an optimistic version check (`UPDATE ... WHERE version = $expected`); a concurrent writer causes a conflict instead of a silent overwrite. Each node also publishes an event.
   * `ingest`: input guard (injection heuristics on normalized text, secret and PII redaction). Blocked input ends the turn as `rejected`. The raw input is not persisted.
   * `route`: on a new session, and on every message while the session is with `support`, the fast model picks an agent with a forced `route` tool call.
   * `cache_lookup`: only for the first message of a support session, the tenant- and scope-isolated semantic cache may answer directly.
   * `agent`: calls the LLM router with the agent's prompt (from the tenant's prompt registry, or the default) and the agent's tools. Usage and cost are recorded in the token ledger; the per-turn cost budget is checked.
   * `tools`: validates arguments, applies the loop breaker and the tool-call budget, then runs low-risk tools immediately, handles `handoff` / `escalate_to_human`, and suspends for high-risk tools (below). Output of tools that read untrusted content is fenced and scanned for injection.
   * `respond`: output guard (redaction); a safe support answer may be stored in the cache.
6. **Respond.** The HTTP response carries the session view: `completed`, `awaiting_approval`, `rejected`, `escalated` or `failed`, with the reply, flags and turn counters. The turn runs inside the request, so the response arrives when the turn completes or suspends.

### An approval

1. When the agent calls a high-risk tool (`write_file`, `run_command`, or a plugin tool marked `high`), the orchestrator builds the action a reviewer will see (tool, arguments, and a diff for file writes), computes its SHA-256, inserts an `approvals` row with an expiry, sets the session to `awaiting_approval`, publishes `approval_required` to the tenant's reviewers channel, and returns `SUSPEND`. Nothing waits in memory.
2. A reviewer lists `GET /v1/approvals` and decides with `POST /v1/approvals/{id}/decision`, quoting the `action_hash`. The API checks the role (approve needs `reviewer`; deny is allowed to the requester), separation of duties (no self-approval unless `ALLOW_SELF_APPROVAL`, which production refuses), and then `decide_approval` locks the row (`SELECT ... FOR UPDATE`), checks it is still pending, that the hash matches, and whether it has expired (expired counts as denied). The decision and an audit event are written in the same transaction. The API returns 202.
3. The resume runs as a background task on the replica that received the decision: it takes the session lock, reloads the session, and re-enters the `tools` node. The action is described and hashed again; if the workspace changed so that the action now differs from what was approved, it is **not** executed (and the mismatch is audited). Otherwise it runs, and the turn continues.

### Events

The orchestrator publishes to Redis channels `events:{tenant}:user:{user_id}` and `events:{tenant}:reviewers`. Each API replica's WebSocket handler subscribes only to the channels of the authenticated principal, so a client receives events from any replica. Events carry a W3C trace context so the console can link to traces.

## Data model

All tables live in one Postgres database. Every tenant-scoped table has a `tenant_id` column and the `tenant_isolation` RLS policy.

| Table / view | Contents | Notes |
|---|---|---|
| `tenants` | id, name, `allowed_providers`, `max_cost_usd_per_turn`, `active` | Tenant policy, cached in the API for 30 seconds. |
| `sessions` | owner, status, current node, `state` (JSONB: messages, agent, pending tool calls, budgets, flags), `version` | The checkpoint. One row per session. |
| `approvals` | requested action (JSONB), `action_hash`, status, decider, expiry | Decisions are bound to the hash. |
| `api_keys` | key id, SHA-256 of the secret, roles, expiry, last use, revocation | The secret itself is never stored. |
| `prompt_registry` | per-tenant prompt versions | The version is part of the cache scope. |
| `audit_log` | append-only security events | The app role can insert and select, not update or delete. Exported via `/v1/admin/audit`. |
| `token_ledger` | per-call provider, model, tokens, cost | Partitioned by month with a DEFAULT partition; partitions created ahead by the maintenance job. |
| `run_metrics` | per-turn latency, cache hit, outcome, steps | Feeds analytics. |
| `run_metrics_hourly_mv` | hourly aggregates for all tenants | Materialized view owned by `harnis_analytics`; never granted to the app. |
| `tenant_analytics_hourly` | the current tenant's rows of the matview | Security-barrier view filtered on the tenant context. |
| `tenant_usage_by_model` | usage totals | `security_invoker` view, so RLS applies to the caller. |

Database roles:

| Role | Login | Purpose |
|---|---|---|
| owner (migration role) | yes | Runs `harnis.migrate` and `harnis.maintenance`. Never used by the API. |
| `harnis_app` | yes | The API. Not owner, not superuser, so RLS applies. Only the grants it needs; no `DELETE`. |
| `harnis_analytics` | no | Owns the analytics matview and its refresh function. |
| `harnis_platform` | no | Owns the few `SECURITY DEFINER` functions for cross-tenant platform operations: resolving an API key before the tenant is known, and listing and updating tenants. The API only calls them for `platform-admin` principals (and for key resolution). |

Migrations are plain SQL files in `harnis/migrations/`, applied in order by `python -m harnis.migrate` as the owner role.

## Tenancy

A tenant is an id (letters, digits, `_ . -`, at most 64 characters) that appears in every place state is kept:

* **Postgres**: every tenant-scoped query runs in `tenant_tx`, which sets `app.tenant_id` for the transaction with `set_config(..., true)`. The policies compare `tenant_id` with that setting; when it is unset the comparison is NULL and no rows match, so a missing context fails closed. RLS is **forced**, so it also applies to the table owner.
* **Redis**: keys and channels are prefixed with the tenant (`ratelimit:{tenant}:{user}`, `events:{tenant}:...`). Cache entries carry `tenant_id` and `scope` tags and lookups filter on both. Session locks and circuit-breaker keys are keyed by session id and provider respectively.
* **Filesystem**: session workspaces are at `WORKSPACES_DIR/{tenant}/{session}`.
* **Model providers**: the router only uses providers in the tenant's `allowed_providers`, including during failover.
* **Roles** are per tenant (`user`, `reviewer`, `admin`); `platform-admin` manages tenants but grants nothing inside one.

Tenants share the API processes, the database and Redis. Isolation is logical (enforced by the database and the code), not physical. Deployments that need physical separation run one Harnis installation per tenant.

## Security boundaries

| Boundary | What enforces it | Notes and limits |
|---|---|---|
| Client to API | Credential verification (JWKS for OIDC with pinned algorithms, issuer and audience; HS256 with pinned algorithm locally; constant-time hash comparison for API keys); roles; per-session ownership | The WebSocket token travels in the query string, because browsers cannot set headers on upgrades: keep tokens short-lived and do not log query strings. `/dev/token` exists only in development and only for local clients. |
| Tenant to tenant | Postgres RLS (forced, non-owner app role), tenant-prefixed Redis keys and cache tags, per-tenant workspaces | Superusers and table owners bypass RLS: never run the API as either. |
| Model to side effects | Risk tiers; approval bound to the action hash; re-hash before execution; expiry; separation of duties; budgets; loop breaker | Prompt injection is assumed possible. The guardrail heuristics are not a boundary; the approval step and the sandbox are. |
| Agent commands to host | Sandbox: no network, read-only root, all capabilities dropped, no-new-privileges, non-root user, resource limits, timeout, capped output; validated copy-back (only regular files and directories inside the workspace) | Docker with `runc`, and Kubernetes without a sandboxed RuntimeClass, share the host kernel. Use gVisor (`SANDBOX_RUNTIME=runsc`, or a `runtimeClassName`), Kata or Firecracker for untrusted code. On Kubernetes, network isolation depends on the chart's NetworkPolicy and a CNI that enforces it, and PID limits come from the kubelet's `podPidsLimit`. |
| Dependency installs to the network | Only an approved `install_dependencies` run has network access: an isolated network (Docker internal network, or Kubernetes NetworkPolicy) whose only reachable endpoint is the egress proxy, which tunnels HTTPS to allowlisted registry hostnames and refuses IP literals and private addresses | Packages from public registries can contain malicious code that runs when tests import them (inside the sandbox). Use an internal mirror or disable installs if that is unacceptable. |
| API to sandbox runtime | Docker: access to the Docker API. Kubernetes: RBAC limited to Pods in the sandbox namespace | Access to a Docker socket is equivalent to root on that host; `tasks.py up-full` mounts it for local use only. In production use the Kubernetes backend or a separate minimal runner. |
| Data leaving to providers | Per-tenant provider allow-list | Prompts, file contents and tool output in a session are sent to the selected provider. |
| Plugins | Explicit opt-in: only modules named in `PLUGINS` load | Plugins run inside the API process with its privileges and database role. Review them like your own code. |
| Telemetry and alerts | Spans record shapes (tool names, argv0, status), not prompts, commands or file contents; alerts carry ids only | Logs and traces still contain tenant and session ids. |

See also the README's security section and [SECURITY.md](../SECURITY.md). Harnis is provided as is; these boundaries are design goals, not guarantees.

## Where state lives

| State | Store | Durability | If it is lost |
|---|---|---|---|
| Sessions and their checkpoints, approvals, audit log, ledger, metrics, prompts, tenants, API keys | Postgres | Durable; back it up | Data loss. This is the system of record. |
| Session workspaces (files the agent reads and writes) | Filesystem at `WORKSPACES_DIR` on the API side | As durable as that volume | Sessions lose their files. With more than one replica this must be a shared volume (ReadWriteMany on Kubernetes), because a resume can run on any replica. |
| Rate-limit buckets, session locks, circuit-breaker state, event fan-out | Redis | Ephemeral | Limits and breakers reset, in-flight WebSocket events are missed; no durable state is lost. Locks expire by TTL. |
| Semantic cache | Redis (RediSearch index when available) | Ephemeral, with TTL | Answers are recomputed. |
| Sandbox containers and Pods | Docker or Kubernetes | Deleted after every command | Nothing; a sandbox never outlives one `run()`. `k8s_sandbox.py` has a reaper for Pods left by a crashed replica. |
| JWKS keys, tenant policy | API process memory | Cache (1 hour and 30 seconds by default) | Re-fetched. |

The API process holds no session state between requests, except approval resumes running as background tasks: if a replica stops during a resume, the session stays in its last checkpoint.

## Scaling and operations

* **API replicas** keep no session state in memory and can be added behind a load balancer. All replicas must share Postgres and Redis and use the same authentication settings.
* **Session workspaces with more than one replica.** Session files live on disk under `WORKSPACES_DIR`, and a session can continue on any replica (an approval is decided on whichever replica receives it, which then resumes the session and runs the sandbox). So with more than one replica, `WORKSPACES_DIR` must be shared storage (ReadWriteMany on Kubernetes: EFS, Filestore, Azure Files, CephFS, NFS; the Helm chart's `workspaces.persistence`). Local disk or an `emptyDir` is only correct for a single replica. See [Kubernetes: session workspaces](kubernetes.md#session-workspaces-and-multiple-replicas).
* **Turn latency** is dominated by model calls. A turn runs within its HTTP request, so set load-balancer and client timeouts above your expected turn time (the CLI and console also follow progress through the WebSocket). Size the uvicorn worker concurrency and `DB_POOL_MAX` per replica accordingly; total database connections are replicas times `DB_POOL_MAX` (plus migration and maintenance jobs).
* **Postgres** is the main shared bottleneck: one checkpoint write per node, plus ledger, metrics and audit inserts. Keep it close to the API and monitor `harnis.db.checkpoint` latency (an alert threshold is configured by default).
* **Redis** load is light (a few commands per request); use Redis Stack or Redis 8 for vector search in the cache, otherwise the cache falls back to a brute-force scan per tenant and scope.
* **Sandboxes** scale with your container capacity: each command creates one container or Pod. On Kubernetes, run sandboxes in their own namespace on dedicated, tainted nodes with a sandboxed RuntimeClass and a ResourceQuota (all configurable in the Helm chart).
* **Rate limits and budgets** protect shared capacity: per-user token bucket, and per-turn steps, cost, tool calls and hand-offs. Model provider rate limits still apply per provider account, shared by all tenants on that account.
* **Scheduled work**: run `python -m harnis.maintenance` hourly as the owner role (the Helm chart installs a CronJob) to create ledger partitions ahead of time and refresh analytics. Approval expiry needs no job.
* **Upgrades**: run migrations (`python -m harnis.migrate`, a Job in the chart) before rolling out new API replicas. Migrations within a major version are designed to be safe while older replicas are still serving; test upgrades in your own environment first.
* **Observability**: OpenTelemetry traces over OTLP (FastAPI, psycopg, Redis and GenAI spans), `/health` for liveness, `/ready` (checks Redis and Postgres) for readiness, and Slack or Discord alerts for halted turns, open circuit breakers and latency thresholds.
