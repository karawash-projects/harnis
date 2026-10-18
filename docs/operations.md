# Operating Harnis in production

This guide is for the people who run Harnis for a company: what to configure before going live, and how to handle installs, prices, personal data, backups, upgrades, monitoring and capacity. Harnis is provided as is (see [GOVERNANCE.md](../GOVERNANCE.md)); test every step in your own environment.

## Go-live checklist

Work through this list on a staging deployment that mirrors production, then again on production.

**Identity and access**
- [ ] `AUTH_MODE=oidc` against your identity provider, with `OIDC_ROLE_MAP` mapping your groups to `user`, `reviewer`, `admin` and `platform-admin` ([README: Single sign-on](../README.md#2-single-sign-on-oidc)). Rehearse it locally with `python tasks.py sso-up` ([keycloak.md](keycloak.md)).
- [ ] Console sign-in works: a public SPA client with redirect URI `https://<host>/`, `OIDC_CONSOLE_CLIENT_ID` set.
- [ ] `ALLOW_SELF_APPROVAL=false` (enforced in production) and enough reviewers in each tenant.
- [ ] Service accounts use API keys with the fewest roles and an expiry.

**Sandbox**
- [ ] Kubernetes backend with a sandboxed RuntimeClass (gVisor or Kata) on dedicated, tainted nodes, `podPidsLimit` set on those nodes, and a CNI that enforces NetworkPolicy. Run `python tasks.py gvisor-check` on a Linux host (or WSL2) to see the sandbox tests pass under gVisor ([gvisor.md](gvisor.md)).
- [ ] Dependency installs: decide whether they are allowed (`sandbox.install.enabled`), and from where (`SANDBOX_EGRESS_ALLOW`, an internal mirror, an upstream proxy). See below.

**Data**
- [ ] Postgres: managed service or replicated cluster with point-in-time recovery; the API connects as `harnis_app` (never owner or superuser).
- [ ] Shared ReadWriteMany storage for workspaces if you run more than one API replica ([kubernetes.md: Scaling](kubernetes.md#scaling)).
- [ ] Retention set (`RETENTION_SESSION_DAYS`, `RETENTION_AUDIT_DAYS`) to match your policy, and the maintenance CronJob running.
- [ ] A restore drill done: back up, restore into a scratch environment, run the feature check against it.
- [ ] Each tenant's `allowed_providers` matches where its data may go (data residency, contracts).

**Models and cost**
- [ ] Every model in `LLM_PROVIDERS` has a confirmed price (`PRICING_OVERRIDES`); the API refuses to start otherwise.
- [ ] `MAX_COST_USD_PER_TURN` and per-tenant caps set; provider spending limits set in each provider's console too.

**Operations**
- [ ] Prometheus scrapes `/metrics` with the token (`metrics.serviceMonitor.enabled` or your own scrape config); the alerts below are in place; traces go to your collector (`OTEL_EXPORTER_OTLP_ENDPOINT`); alert webhooks (`ALERT_WEBHOOK_URL`) reach your on-call channel.
- [ ] A load test at your expected peak (`python tasks.py load`) passes on staging.
- [ ] The feature check passes against production with your credentials:
  `python scripts/harnis_check.py --api https://harnis.example.com --admin-token ... --platform-token ... --other-admin-token ...`

## Dependency installs and the egress proxy

Agent commands and tests never have network access. The one exception is the `install_dependencies` tool: the agent asks to install a project's dependencies (pip from `requirements*.txt` or `pyproject.toml`, npm from `package.json`), a reviewer approves the exact manifest and command, and the install runs in a sandbox that can reach only the **egress proxy**. The proxy (`harnis/egress_proxy.py`, about 200 lines, standard library only):

- tunnels HTTPS only (`CONNECT host:443`) and only to hostnames on `SANDBOX_EGRESS_ALLOW` (default `pypi.org,files.pythonhosted.org,registry.npmjs.org`; `*.example.com` allows subdomains);
- refuses IP addresses, other ports and plain HTTP, and refuses names that resolve to private, loopback, link-local or metadata addresses (unless `SANDBOX_EGRESS_ALLOW_PRIVATE=true` for an internal mirror);
- can chain through a corporate proxy (`SANDBOX_EGRESS_UPSTREAM_PROXY=http://user:pass@proxy:3128`);
- logs every request as a JSON line.

Installed packages go to `.harnis/deps` in the session workspace, which later commands and tests use automatically (`PYTHONPATH`, `NODE_PATH`, `PATH`). That folder is hidden from file listings, diffs and the CLI, can't be written by agent file tools, and has its own limits (`SANDBOX_DEPS_MAX_BYTES`, `SANDBOX_DEPS_MAX_FILES`). npm lifecycle scripts are disabled. Node.js isn't in the default sandbox image: build it with `--build-arg WITH_NODE=true` if your projects use npm.

An install can only change `.harnis/deps`: anything else the package code writes in the workspace is discarded, so an install can't alter the project the reviewer approved.

**Where it runs.** With Docker, every install run gets a private internal network of its own (no route out, and on Docker 28+ an isolated gateway, so the Docker host has no address on it); the hardened proxy container is attached to it for the duration of the run and reaches the registries through its own outbound network. On older Docker versions the host stays reachable from install runs (Harnis logs a warning): upgrade Docker or use Kubernetes. On Kubernetes, the chart deploys the proxy in the sandbox namespace; install Pods carry the label `harnis/egress: registry`, and NetworkPolicies let them reach only the proxy (not even DNS: the API passes them its IP address), and the proxy only DNS and public HTTPS (`sandbox.install.egress.to`/`ports`; add your corporate proxy's address there when you use one).

**Risk to accept or remove.** Packages come from public registries. A reviewer can see what is requested, not what a package does; a malicious package can run code when tests import it, inside the sandbox (no network, no secrets). For stricter environments point `SANDBOX_EGRESS_ALLOW` at an internal mirror that only serves vetted packages, or turn installs off (`SANDBOX_INSTALL_ENABLED=false`, chart `sandbox.install.enabled: false`).

## Model prices

`python tasks.py pricing` asks for the input and output price (USD per million tokens) of every model Harnis is configured to call and stores them in `PRICING_OVERRIDES`. In Kubernetes set `config.PRICING_OVERRIDES` in the chart values, or mount a JSON file and set `PRICING_FILE`. The shipped table in `harnis/llm/pricing.py` is only a reference. In production the API refuses to start while a configured model has no confirmed price; admins see the status in the console under Usage & analytics.

**Plugins and the database.** The data lifecycle functions (erasure, tenant deletion) are callable by the application's database role; the API decides who may call them. Plugins run inside the API process with that role, so review plugins like your own code.

## Personal data: retention, export, erasure

**Retention** (applied hourly by the maintenance job):
- `RETENTION_SESSION_DAYS`: sessions not updated for this many days are deleted with their messages, approvals and workspace files. Sessions waiting for an approval are kept.
- `RETENTION_AUDIT_DAYS`: older audit events are deleted.
- 0 keeps data forever (the default).

**Requests from a person** (tenant admins; console: Tenant admin > User data):
- *Access / portability*: `GET /v1/admin/users/{id}/export` returns their sessions (messages and workspace files), approvals they requested or decided, their audit events, and API keys and prompt versions they created.
- *Erasure*: `DELETE /v1/admin/users/{id}/data?confirm={id}` deletes their sessions, messages, approvals and workspace files, and clears the tenant's answer cache. Where their id appears in history kept for accountability or billing (audit log, approvals they decided, authorship of prompts and keys), it is replaced by a random pseudonym (`erased-...`), the same one everywhere, and the erasure itself is audited. Token usage stays, attached only to the deleted session id.

The user id is the one Harnis derives from the identity provider (shown in conversations and the audit log). Erasure is irreversible; check your obligations (for example GDPR) for what you must keep.

**Deleting a tenant** (platform admins; console: Platform > Tenants): disable it first, then `DELETE /v1/admin/tenants/{id}?confirm={id}`. Everything the tenant owns is removed: sessions, workspaces, approvals, prompts, API keys, usage, analytics and its audit log. The deletion is recorded in the platform audit log (`GET /v1/admin/platform-events`).

## Backups and restore

```bash
python tasks.py backup                                   # local stack: backups/harnis-<timestamp>/
python -m harnis.backup create --out /backups            # anywhere, as the owner role (MIGRATION_DATABASE_URL)
python -m harnis.backup verify /backups/harnis-...       # checksums and schema version
python -m harnis.backup restore /backups/harnis-... --yes
```

A backup holds the database (`pg_dump` custom format), the workspaces (`tar.gz`) and a manifest with checksums, the Harnis version and the schema version. Redis is not backed up: it only holds caches, rate-limit buckets and locks. Restore empties the database's `public` schema, restores, applies any newer migrations (so an older backup restores into a newer Harnis) and refreshes analytics. Stop the API during a restore.

In production, use your managed Postgres's point-in-time recovery for the database and your storage's snapshots for the workspaces volume; use `harnis.backup` for portable copies and for restore drills. **Do a restore drill before go-live and after major upgrades**: restore into a scratch environment and run `scripts/harnis_check.py` against it.

## Upgrades

1. Read `CHANGELOG.md` for the versions you are crossing.
2. Back up (or take a snapshot).
3. Run migrations before rolling out new API replicas: the chart does this as a pre-upgrade Job; elsewhere `python -m harnis.migrate`. Migrations within a major version are designed to run while older replicas are still serving, and each is recorded, so re-running is safe.
4. Roll out, then run the feature check.

The test suite includes an upgrade test (an older schema with data, migrated to the current one) and a restore drill (`tests/test_upgrade.py`, `tests/test_backup.py`).

## Metrics and alerts

`/metrics` serves Prometheus metrics. In production it is only served with `METRICS_TOKEN` set (the chart generates one; scrapers send `Authorization: Bearer <token>`), because ingresses usually route every path to the API. Labels never contain tenant or user ids, prompts or commands; per-tenant figures are in the database (`/v1/usage`, `/v1/analytics`).

| Metric | What |
|---|---|
| `harnis_http_requests_total`, `harnis_http_request_duration_seconds` | per route template and status |
| `harnis_turns_total{status,agent}`, `harnis_turn_duration_seconds` | turns that ended (completed, failed, escalated, rejected) or suspended for approval |
| `harnis_llm_calls_total{provider,model,outcome}`, `harnis_llm_call_duration_seconds`, `harnis_llm_tokens_total`, `harnis_llm_cost_usd_total` | model calls, latency, tokens and estimated cost |
| `harnis_circuit_breaker_open_total{provider}` | provider outages |
| `harnis_tool_calls_total{tool,outcome}`, `harnis_approvals_requested_total{tool}`, `harnis_approval_decisions_total{decision}` | agent actions and approvals |
| `harnis_sandbox_runs_total{backend,kind,outcome}`, `harnis_sandbox_run_duration_seconds` | sandbox commands and installs |
| `harnis_rate_limited_total`, `harnis_guardrail_events_total{kind}`, `harnis_cache_lookups_total{result}` | limits, guardrails, cache |

Suggested alerts (adapt thresholds to your traffic):

```yaml
- alert: HarnisTurnsFailing
  expr: sum(rate(harnis_turns_total{status="failed"}[10m])) / sum(rate(harnis_turns_total[10m])) > 0.05
- alert: HarnisProviderDown
  expr: increase(harnis_circuit_breaker_open_total[10m]) > 0
- alert: HarnisSandboxErrors
  expr: sum(rate(harnis_sandbox_runs_total{outcome="error"}[10m])) > 0
- alert: HarnisSlowRequests
  expr: histogram_quantile(0.95, sum by (le) (rate(harnis_http_request_duration_seconds_bucket{route!="/v1/sessions/{session_id}/turns"}[10m]))) > 2
- alert: HarnisCostSpike
  expr: sum(increase(harnis_llm_cost_usd_total[1h])) > 50
```

Harnis also sends its own alerts (halted turns, open circuit breakers, slow spans) to `ALERT_WEBHOOK_URL`.

## Capacity and load testing

`python tasks.py load` (or `scripts/load_test.py --api url1,url2 ...`) runs concurrent virtual users against one or more replicas with the mock model: support questions, and coding sessions whose approvals are decided through a *different* replica than the one that ran the turn, with tests running in the sandbox. It reports p50/p95/p99 per operation and fails above `--max-error-rate` or `--max-p95`.

Reference run (one 2-vCPU development VM; two API replicas, one Postgres, one Redis, Docker sandbox, mock model):

| Users x sessions | Errors | Turn p95 | Approval decision p95 | Coding session end to end, p50 |
|---|---|---|---|---|
| 20 x 4 (80 sessions, 80 cross-replica approvals) | 0 | 0.4 s | 0.16 s | 11 s |
| 50 x 2 (100 sessions, 100 cross-replica approvals) | 0 | 0.9 s | 0.41 s | 36 s |

The API itself stays fast; end-to-end time is dominated by sandbox runs (one fresh container per command), which queue when many start at once on one host. Scale sandboxes with nodes (Kubernetes) rather than API replicas, and measure on your own infrastructure: real models add seconds per turn.

## What has and hasn't been verified

Verified in the project's own test runs: the full test suite (unit, Postgres RLS, API end to end, Docker sandbox hardening, egress isolation, upgrade, restore drill), the web console in Chromium (including SSO against a real Keycloak and a mock identity provider), the feature check against a live API, the load test above, the eval suite with the mock model and Amazon Nova, and the red-team checks.

Verified on a fresh Ubuntu 24.04 EC2 instance (t3.xlarge, Docker 29, runsc release-20261012.0, kind 0.33, helm 3.21):
- the sandbox test suite under **gVisor**, including a real dependency install (the fork-bomb test is an expected failure under gVisor, see [gvisor.md](gvisor.md));
- the Helm chart on a **kind** cluster: the full feature check passed (55/55) with sandbox commands running as Pods and the NetworkPolicies in place;
- local **Keycloak** through Docker Compose (`tasks.py sso-up`), the SSO feature check and the Keycloak browser tests;
- backup and restore with `tasks.py backup` / `restore`, followed by a passing feature check.

Not verified by the project, so verify them in your environment: a production Kubernetes cluster (managed control plane, your CNI, a gVisor RuntimeClass on real nodes), your identity provider, your models at your load, and an independent penetration test.

## Configuration precedence

Environment variables override `.env` (and the chart's ConfigMap and Secret are environment variables). A provider key exported in your shell, for example `ANTHROPIC_API_KEY` set for another tool, is picked up by the API even if `.env` leaves it empty; `python tasks.py dev` points this out.
