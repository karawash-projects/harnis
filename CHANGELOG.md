# Changelog

All notable changes to Harnis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) on a best-effort basis (see [GOVERNANCE.md](GOVERNANCE.md)).

## [Unreleased]

## [1.0.1] - 2026-10-19

### Fixed
- Links in the README (license, notice, docs and other project files) are absolute, so they work on the PyPI project page as well as on GitHub.
- The release workflow downloads only the package and chart artifacts; downloading every artifact failed on Docker build records and stopped the GitHub Release from being created.

## [1.0.0] - 2026-10-17

First public release, under the Apache License 2.0.

### Added

#### Workloads
- CLI coding agent (`harnis`): uploads a local project into an isolated session workspace, asks for approval of each file write (with a diff) and each command, and applies the final diff to local files only after confirmation.
- Multi-agent workflow: a router on the fast model sends each message to a `support` or `coder` agent; agents can hand off to each other or escalate to a human. Support sessions are routed again on every message.
- Multi-tenant HTTP API (FastAPI) with sessions, turns, approvals, usage, analytics and a prompt registry, a WebSocket event stream (`/v1/ws`) fed through Redis pub/sub so events reach clients on any replica, and a web console: single sign-on (OIDC authorization code with PKCE), conversations with inline approvals and diffs, an approvals queue, usage and analytics, agents and per-tenant prompts, API keys, the audit log and tenant administration, shown according to the signed-in user's roles; served with a strict Content-Security-Policy and security headers, and can be turned off (`CONSOLE_ENABLED=false`).

#### Authentication and tenancy
- The tenant is always taken from verified credentials, never from the request.
- `AUTH_MODE=oidc`: SSO with any OpenID Connect provider (for example Okta, Entra ID, Auth0, Keycloak, Google). Tokens are verified against the provider's JWKS (discovered from the issuer or configured), with configurable user, tenant and roles claims (dotted paths), a role map from IdP groups to Harnis roles, a default tenant for single-tenant deployments, clock leeway and JWKS caching.
- `AUTH_MODE=local`: HS256 tokens signed with `JWT_SECRET`, for development or behind an internal gateway; `python -m harnis.auth mint` and `python tasks.py token` mint them.
- Service API keys (`hrn_<id>_<secret>`) for CI and service accounts, accepted in both modes. Only a SHA-256 of the secret is stored; keys have roles, optional expiry, last-used tracking and revocation.
- Roles: `user`, `reviewer`, `admin` (tenant admin, implies user and reviewer) and `platform-admin` (manages tenants, grants nothing inside a tenant).
- Postgres Row-Level Security, enabled and forced on every tenant table. The API connects as `harnis_app`, which is neither owner nor superuser; the tenant is bound to each transaction with `set_config`. `harnis.migrate` creates the roles. Analytics are served through a security-barrier view over a materialized view the app cannot read directly.
- Platform operations that span tenants (resolving an API key, listing and updating tenants) go through a small set of `SECURITY DEFINER` functions owned by the `harnis_platform` role.
- Per-tenant provider allow-list (`tenants.allowed_providers`) for data residency, and per-tenant cost cap.

#### Operations
- Approved dependency installs: an `install_dependencies` tool (pip and npm) whose runs are the only sandbox runs with network access, through an allowlisting HTTPS egress proxy (Docker: an internal network and a hardened proxy container; Kubernetes: a proxy Deployment and NetworkPolicies). Installed packages live in a hidden `.harnis/deps` folder with their own size limits.
- Model prices: operator-confirmed prices (`PRICING_OVERRIDES` / `PRICING_FILE`, `python tasks.py pricing`); production refuses to start with an unpriced model; `GET /v1/admin/pricing` and a console view.
- Personal data: retention (`RETENTION_SESSION_DAYS`, `RETENTION_AUDIT_DAYS`), per-user export and erasure with pseudonymization of retained history, tenant deletion, a platform audit log, and an orphaned-workspace sweep in the maintenance job (migration 006).
- Prometheus metrics at `/metrics` (token-protected in production; Helm ServiceMonitor).
- Backup, verify and restore (`python -m harnis.backup`, `python tasks.py backup|restore`) with a tested restore drill; an upgrade test from an earlier schema.
- Local test setups: Keycloak SSO (`tasks.py sso-up`), gVisor (`tasks.py gvisor-check`, WSL2 guide), a kind cluster (`tasks.py k8s-up|k8s-check`), and CI workflows for gVisor and kind.
- `scripts/load_test.py` (`tasks.py load`): concurrent users across several replicas, with approvals decided on a different replica.
- `docs/operations.md`: go-live checklist and operating guide.

#### Security
An independent review of this release led to these fixes before publication:
- bind workspace mode: symlinks created by sandboxed code are removed after every run, and file listings, the files API and exports read only regular files without following links (they could previously expose or change host files);
- dependency installs: only changes under `.harnis/deps` are applied; each install runs on its own isolated network so it can't reach the Docker host or other installs; Kubernetes install Pods get no DNS; the approval covers the whole manifest and the files it includes;
- separation of duties treats an API key and the user who created it as the same person;
- the sandbox's output archive is streamed with a size cap instead of being read into memory;
- `.harnis` is reserved case-insensitively; OIDC-derived ids can't collide with literal ids.

#### Fixed during pre-release testing on EC2
- The semantic cache now uses the brute-force fallback on a Redis database other than 0 (RediSearch only indexes db 0) and recreates its index if it was dropped (a FLUSHDB on any database drops every index).
- Dependency installs work under gVisor: install runs get the egress proxy by IP address, because gVisor can't use Docker's embedded DNS.
- Kubernetes sandbox: before copying the workspace in and running the command, Harnis checks inside the Pod that NetworkPolicy already blocks it, and refuses the command if it doesn't within `sandbox.networkProbe.timeoutSeconds` (fail closed). Some CNIs, kind's kindnetd among them, apply policy to a new Pod 1 to 3 seconds after it starts, and code could reach the network in that window.
- `scripts/k8s_local.py` refuses kind releases older than v0.24, which don't enforce NetworkPolicy; the `k8s-e2e` workflow pins kind v0.33.0 and shows failed checks as annotations.
- `tasks.py dev` only reloads on changes to the `harnis` package; it used to restart the API in the middle of turns whenever an agent wrote a Python file into the workspaces folder.
- `tasks.py` reads `.env` values with inline comments correctly (`sso-up` failed on a fresh install), and sees provider keys from the shell environment the way the API does.

#### Verification
- `scripts/harnis_check.py` (`python tasks.py check`): a standalone, standard-library-only script that checks every feature of a running deployment end to end and exits non-zero on any failure; works with local auth (throwaway tenants) or with SSO/API-key credentials.
- `python tasks.py status` shows which local services are reachable.

#### Admin API
- Tenant admins: create, list and revoke API keys (`/v1/admin/api-keys`) and read the tenant's append-only audit log (`/v1/admin/audit`, paged, JSON or NDJSON for SIEM ingestion).
- Platform admins: list, create and update tenants, including enabling and disabling a tenant without deleting its data (`/v1/admin/tenants`).

#### Orchestration and approvals
- Explicit state machine (ingest, route, cache lookup, agent, tools, respond) checkpointed to Postgres after every node with optimistic versioning, so turns survive crashes and resume on any replica.
- Human approval for high-risk tools (`write_file`, `run_command`): the session is suspended in the database, the decision is bound to the SHA-256 of the exact action shown to the reviewer, the action is re-hashed before execution and not run if it changed, approvals expire, and separation of duties prevents approving your own request (`ALLOW_SELF_APPROVAL`, refused in production).
- Budgets per turn: steps, USD cost (with per-tenant override), hand-offs and tool calls, all kept in checkpointed state.
- Loop breaker: repeated identical tool calls produce a warning to the model, then escalation and an alert.
- Auto-continue for coder turns that announce a next step without calling a tool (`AUTO_CONTINUE_MAX`).
- Per-session Redis lock so only one turn runs per session across replicas.

#### Tools and sandbox
- Tools with Pydantic-validated arguments, risk tiers and workspace confinement with portable path rules (no `..`, absolute or drive paths, symlink escapes or Windows-reserved names).
- Docker sandbox for agent commands and tests: no network, read-only root filesystem, all capabilities dropped, `no-new-privileges`, non-root user, memory, CPU and PID limits, noexec tmpfs, wall-clock timeout and capped output. The workspace is copied in and out through the Docker API (any OS, remote daemons) and validated on the way back (symlinks, hard links, devices and paths outside the workspace are dropped), or bind-mounted on Linux. `SANDBOX_RUNTIME=runsc` selects gVisor.
- Kubernetes sandbox backend: each command runs in a short-lived Pod with the same workspace semantics, as non-root with a read-only root filesystem, no privilege escalation, all capabilities dropped, RuntimeDefault seccomp, no service account token, resource limits, size-limited volumes, a hard deadline and an optional RuntimeClass (gVisor or Kata). Network isolation comes from the NetworkPolicy installed by the Helm chart. Requires the `k8s` extra.

#### Guardrails
- Input guard with prompt-injection heuristics over Unicode-normalized text, secret redaction and PII redaction (with Luhn-checked card numbers), and a pluggable classifier.
- Tool output is fenced as untrusted data, with suspected injections flagged and audited; output redaction on replies. The guardrails are documented as heuristics: containment is structural (approvals, sandbox, budgets).

#### LLM providers
- Provider-neutral message format with adapters for Anthropic, OpenAI, Google Gemini (API key or Vertex AI; thought signatures are preserved and replayed) and Amazon Nova on Bedrock (Converse API, standard AWS credential chain), plus a deterministic mock provider for development and tests (refused when `ENV=production`).
- Router with retries only on retryable errors, jittered exponential backoff, failover on outages and auth errors, immediate failure on bad requests, a circuit breaker shared through Redis, and failover limited to each tenant's allowed providers.
- Token ledger and cost accounting per tenant, provider and model, with configurable prices (`PRICING_OVERRIDES`).

#### Caching, rate limits and data
- Tenant- and scope-isolated semantic cache (scope includes agent and prompt version) with TTL, using RediSearch HNSW vector search or a brute-force fallback on plain Redis, used only where a prompt-keyed answer is safe (first message of a support session).
- Per-tenant, per-user token-bucket rate limiting, atomic in Redis (Lua).
- Per-tenant prompt registry with versions.
- Monthly-partitioned token ledger with a DEFAULT partition, append-only audit log, run metrics and hourly analytics; `python tasks.py maintenance` creates partitions ahead and refreshes analytics.

#### Observability
- OpenTelemetry tracing with OTLP export, FastAPI, psycopg and Redis auto-instrumentation and GenAI semantic conventions; prompts, commands and file contents are not recorded on spans. TLS to the collector for https:// endpoints; when the collector is unreachable the API logs one clear warning instead of a stream of exporter errors.
- Latency-threshold alerts and incident alerts to Slack or Discord, sent in the background, de-duplicated, carrying IDs only.

#### Extensibility
- Plugin SDK for adding LLM providers, tools and agents without modifying Harnis, documented in `docs/plugins.md`.

#### Quality
- Eval suite (`python tasks.py eval`): YAML cases for support, coding, approvals, guardrails, multi-agent and robustness, run against a live API with one tenant per provider; checks replies, tools, approvals, files, sandboxed test results, flags, cost and latency, and writes HTML and JSON reports. Can gate CI with `--min-pass-rate`.
- Red-team script (`python tasks.py redteam`) with attack checks against a live API; exits non-zero on failure.
- Unit, integration (Postgres RLS, API end to end) and sandbox test suites; CI on Ubuntu, macOS and Windows.

#### Deployment and tooling
- Cross-platform task runner `tasks.py` (standard library only) for install, local services, migrations, development server, tests, evals and maintenance on Windows, macOS and Linux, including automatic host-port conflict resolution and Docker Desktop detection.
- Docker Compose stack for local development (Postgres, Redis Stack, Jaeger).
- API and sandbox container images (non-root).
- Helm chart (`deploy/helm/harnis`) for Kubernetes, including the NetworkPolicy that isolates sandbox Pods.
- Release automation: PyPI package with trusted publishing, multi-architecture images on GHCR with SBOM and provenance attestations and cosign signatures, and the Helm chart as an OCI artifact.

