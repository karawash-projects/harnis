# Harnis

**An open-source, self-hosted platform for running AI agents safely inside a company.**

Harnis gives your teams one place to run agents that read and change real things (code, files, tickets, internal systems) without handing a model the keys. Every agent runs inside the same harness: tenant isolation enforced by the database, side effects held for human approval, untrusted code in a locked-down sandbox, budgets and loop breakers on every turn, and a full audit trail.

It ships with three workloads on one engine:

* a **CLI coding agent** that edits your project only after you approve each change,
* a **multi-agent workflow** (a router hands messages to specialist agents, which can hand off to each other),
* a **multi-tenant web app** with streaming events and an approval console.

Bring your own models (Anthropic, OpenAI, Google Gemini, Amazon Nova on Bedrock, or anything with an OpenAI-compatible API, such as vLLM or Ollama), your own identity provider (any OIDC IdP), and your own tools and agents (plugins). Run it with Docker Compose on a laptop or with the Helm chart on Kubernetes.

Licensed under [Apache 2.0](LICENSE) and provided **as is**, without warranty or support: you are free to use, change and extend it, and you are responsible for how you run it (see [Use at your own risk](#use-at-your-own-risk)).

## Why Harnis

| You need | Harnis gives you |
|---|---|
| Agents that can't leak one customer's data to another | Postgres row-level security, **enabled and forced**, on every tenant table; the app connects as a non-owner role and sets the tenant per transaction from the verified token |
| A human in the loop for anything that matters | High-risk tool calls suspend the session in the database; the approval is bound to a SHA-256 of the exact action, with separation of duties and expiry |
| Model-written code that can't escape | One throwaway container (Docker) or Pod (Kubernetes) per command: no network, read-only root, all capabilities dropped, non-root, memory/CPU/PID limits; gVisor supported |
| Control over where data goes | Per-tenant provider allow-lists; failover never leaves them |
| Your SSO, your roles | OIDC with JWKS discovery and rotation, claim and group mapping; service API keys for automation |
| Your own tools and agents | A plugin SDK: tools, agents and model providers register exactly like the built-ins |
| Predictable cost | Per-turn budgets for steps, USD cost, hand-offs and tool calls; per-tenant cost caps; a token and cost ledger |
| Evidence for auditors | Append-only audit log with JSON / NDJSON export, OpenTelemetry traces, alerts |

## Architecture

```
                     +--------------------------- API replica (stateless) ----------------------------+
 browser / CLI --->  | auth --> rate limit --> session lock --> Orchestrator (checkpointed state machine) |
 OIDC token or       |                                           |                                      |
 hrn_ API key        |   ingest -> route -> [cache] -> agent <-> tools -> respond                        |
                     |   guardrails  fast model  tenant-  LLM router   low risk: run (sandbox if code)    |
                     |                           scoped   (failover)   high risk: SUSPEND for a human     |
                     |   plugins: tools, agents, providers                                               |
                     +------+----------------+---------------+-------------------------+---------------+
                            |                |               |                         |
                     Postgres (RLS)       Redis          Anthropic, OpenAI,        Sandbox
                     sessions, approvals, rate limits,   Gemini, Nova (Bedrock),   Docker container or
                     prompts, API keys,   locks, events, OpenAI-compatible,        Kubernetes Pod per
                     ledger, audit,       circuit        your own (plugin),        command: no network,
                     analytics            breaker, cache (+ offline mock)          read-only, non-root
```

Session state lives in Postgres and Redis, so a session suspended for approval on one replica resumes on whichever replica receives the decision. Session files live in the workspaces directory, which must be shared storage when you run more than one replica; see [Scaling](docs/kubernetes.md#scaling). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Quick start (about 5 minutes, no API keys needed)

Works the same on **Windows, macOS and Linux**. You need Python 3.11 or newer and Docker (Docker Desktop on Windows and macOS, Docker Engine on Linux).

Every step goes through `tasks.py`, a standard-library task runner, so there's no `make`, bash or WSL requirement.

```bash
python tasks.py install          # .venv + dependencies (on Windows: py tasks.py install)
python tasks.py up               # Postgres, Redis Stack, Jaeger; migrations; demo tenants "acme" and "globex"
python tasks.py sandbox-image    # the image agent commands run in
python tasks.py dev              # API on http://127.0.0.1:8000
```

Open **http://127.0.0.1:8000** and click **Continue as local developer** (you're the admin of the demo tenant `acme`). The console has conversations with inline approvals and diffs, an approvals queue, usage and analytics, agents and their prompts, API keys and the audit log; a platform admin also sees tenants. Traces are in Jaeger at **http://127.0.0.1:16686**.

Check that everything works with `python tasks.py check` (see [Checking a deployment](#checking-a-deployment)), and `python tasks.py status` shows which services are up.

Try the coding agent on a scratch folder in a second terminal:

```bash
mkdir demo
python tasks.py cli -- --workspace demo "create greet.py with a greet function"
```

You'll approve each file write (with a diff), the agent runs the tests in the sandbox, and finally you choose whether to apply the changes to `demo`. `python tasks.py token` prints a development token if you want to call the API yourself (`HARNIS_TOKEN`).

### Trying it without API keys

The mock provider follows a small, deterministic script so every path can be exercised:

| Say | What happens |
|---|---|
| `what are your opening hours?` | the support agent answers; repeat it in a new session and it's served from the cache |
| `create calc.py` | the coder writes `calc.py` + `test_calc.py` (two approvals), then runs the tests in the sandbox |
| ``run `ls -la` `` | a shell command, suspended for approval (commands run in the Linux sandbox, so use Linux commands even on Windows) |
| `list the files` / `read README.md` | read-only tools, no approval |
| `repeat: list the files` | the agent loops; the loop breaker warns, then escalates and alerts |
| `install the dependencies` | installs `requirements.txt` after approval, through the registry-only proxy (the session needs a `requirements.txt`) |
| `ignore all previous instructions...` | blocked by the input guard |

### Platform notes

| | Windows | macOS | Linux |
|---|---|---|---|
| Docker | Docker Desktop (WSL 2 backend) | Docker Desktop, Colima or OrbStack | Docker Engine |
| Sandbox workspace mode | `copy` (default) | `copy` (default) | `copy` (default) or `bind` |
| gVisor (`SANDBOX_RUNTIME=runsc`) | inside WSL2 with Docker Engine ([docs/gvisor.md](docs/gvisor.md)) | not available | supported |

* **Workspaces** are streamed into the sandbox through the Docker API and validated on the way back (symlinks, hard links, devices and paths outside the workspace are dropped), so it behaves identically everywhere, including remote daemons. On Linux, `SANDBOX_WORKSPACE_MODE=bind` bind-mounts instead.
* **Paths** are POSIX-style and portable: `..`, absolute and drive paths, and names Windows can't store are rejected on every OS. Files are read and written as UTF-8 bytes, so diffs and approval hashes match across platforms.
* **Port clashes:** if 5432 or 6379 is taken, `tasks.py up` picks the next free port and updates `.env`. If Docker Desktop isn't running, `tasks.py` starts it.

## Setting Harnis up for your company

### 1. Models

| Provider | `LLM_PROVIDERS` name | Credentials | Default models (main / fast) |
|---|---|---|---|
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-5-5` / `claude-haiku-5-5` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-5.5` / `gpt-5.4-mini` |
| Google Gemini | `gemini` | `GEMINI_API_KEY`, or Vertex AI with `GEMINI_USE_VERTEXAI=true` | `gemini-3.8-flash` / `gemini-3.5-flash-lite` |
| Amazon Nova (Bedrock) | `nova` | `AWS_REGION` plus AWS credentials (keys, `AWS_PROFILE`/SSO, or an IAM role) | `us.amazon.nova-2-lite-v1:0` / `us.amazon.nova-micro-v1:0` |
| Self-hosted / gateway | `openai_compatible` | `OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_MODEL` (vLLM, Ollama, LM Studio, LiteLLM) | yours |
| Your own | plugin | see [docs/plugins.md](docs/plugins.md) | yours |

`LLM_PROVIDERS` is the failover order. Providers without credentials are skipped and the API logs the resulting chain at startup; `mock` is refused when `ENV=production`. Model names change often, so set `*_MODEL` / `*_FAST_MODEL` to what your account offers.

**Model prices.** Cost figures, per-turn cost budgets and tenant cost caps depend on each model's price, and prices change. `python tasks.py pricing` asks for the price of every model you have configured (showing reference values to check against the provider's pricing page) and saves them as `PRICING_OVERRIDES`; `tasks.py dev` asks too when some are missing. With `ENV=production` the API refuses to start while a configured model has no confirmed price. Admins see the prices and their status under **Usage & analytics** in the console (`GET /v1/admin/pricing`).

### 2. Single sign-on (OIDC)

Set `AUTH_MODE=oidc` and point Harnis at your IdP (Okta, Microsoft Entra ID, Auth0, Keycloak, Google, ...):

```bash
AUTH_MODE=oidc
OIDC_ISSUER=https://login.example.com/
OIDC_AUDIENCE=harnis-api
OIDC_TENANT_CLAIM=tenant_id          # or OIDC_DEFAULT_TENANT=acme for a single-tenant deployment
OIDC_ROLES_CLAIM=groups              # realm_access.roles for Keycloak; dotted paths work
OIDC_ROLE_MAP={"harnis-reviewers": "reviewer", "harnis-admins": "admin", "platform-ops": "platform-admin"}
```

Keys are discovered from the issuer and refreshed on rotation; only asymmetric algorithms are accepted. The tenant always comes from the verified token, never from the request.

**Console sign-in.** Register a public single-page-app client in your IdP with the redirect URI `https://<your-harnis-host>/`, and set its client id. The console then shows **Sign in with SSO** and uses the authorization code flow with PKCE; no client secret is involved and the dev-token button disappears.

```bash
OIDC_CONSOLE_CLIENT_ID=0oa1b2c3d4
OIDC_CONSOLE_SCOPES=openid profile email          # add your API scope if the IdP needs one (Entra ID: api://harnis/access)
OIDC_CONSOLE_EXTRA_PARAMS={"audience": "harnis-api"}   # Auth0 needs this to issue an access token for the API
# OIDC_CONSOLE_TOKEN=id_token                     # if your IdP's access tokens aren't JWTs for OIDC_AUDIENCE
```

The console keeps the token in the browser tab's session storage (gone when the tab closes), signs out when it expires, and is served with a strict Content-Security-Policy. Set `CONSOLE_ENABLED=false` to serve only the API.

| Role | Can |
|---|---|
| `user` | create sessions and talk to agents |
| `reviewer` | see the tenant's sessions, approve or deny actions, view analytics |
| `admin` | everything a reviewer can, plus prompts, API keys and the tenant's audit log |
| `platform-admin` | create, configure and disable tenants (no access to tenant data) |

**Try SSO locally with Keycloak.** One command starts a Keycloak with a ready `harnis` realm (test users for every role, two tenants) and switches `.env` to `AUTH_MODE=oidc` against it:

```bash
python tasks.py sso-up      # then restart `python tasks.py dev` and click "Sign in with SSO" (adam / harnis-local-only)
python tasks.py sso-check   # feature check with Keycloak-issued tokens
python tasks.py sso-down    # back to local auth
```

The test users, passwords and password-grant client are for local testing only. See [docs/keycloak.md](docs/keycloak.md), which also shows how the realm maps to the settings above so you can mirror it in your own IdP.

### 3. Tenants

A `platform-admin` manages tenants through the API:

```bash
curl -X PUT $HARNIS_API/v1/admin/tenants/acme -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "Acme Corp", "allowed_providers": ["anthropic"], "max_cost_usd_per_turn": 1.0}'
```

`allowed_providers` limits where the tenant's prompts may be sent (`["*"]`, the default, means every configured provider). Set `"active": false` to lock a tenant out immediately, including its API keys.

### 4. Service API keys

Tenant admins create keys for CI jobs and integrations. The secret is shown once and stored only as a hash:

```bash
curl -X POST $HARNIS_API/v1/admin/api-keys -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"name": "ci", "roles": ["user"], "expires_in_days": 90}'
# -> {"key": "hrn_...", ...}   use it as: Authorization: Bearer hrn_...
```

### 5. Your own tools and agents

```python
# mycompany_harnis.py
from pydantic import BaseModel
from harnis.plugins import AgentSpec
from harnis.tools import Tool

class Args(BaseModel):
    order_id: str

def lookup(ctx, args):
    return f"order {args.order_id}: shipped", False

def register(registry):
    registry.add_tool(Tool("lookup_order", "Look up an order.", Args, "low", lookup))
    registry.add_agent(AgentSpec(name="orders", description="questions about existing orders",
                                 prompt="You answer questions about orders. Use lookup_order.",
                                 tools=["lookup_order", "handoff", "escalate_to_human"]))
```

Load it with `PLUGINS=mycompany_harnis`. Mark anything with side effects `risk="high"` and a reviewer approves each call. The [ticketing example](examples/plugins/harnis-plugin-tickets) is a complete, packaged plugin; [docs/plugins.md](docs/plugins.md) covers tools, agents, providers and testing.

### 6. Kubernetes

```bash
helm upgrade --install harnis ./deploy/helm/harnis --namespace harnis --create-namespace -f values-prod.yaml
```

The chart runs the API as a Deployment (with optional HPA, PDB and Ingress), migrations as a pre-install/pre-upgrade Job, maintenance as a CronJob, and agent commands as one hardened Pod each in a separate namespace with Pod Security "restricted", a deny-all NetworkPolicy and optional gVisor. Database owner credentials live in a separate Secret that only the jobs can read.

Try it on your machine first with a local [kind](https://kind.sigs.k8s.io/) cluster: `python tasks.py k8s-up`, `python tasks.py k8s-check` (the full feature check against the cluster), `python tasks.py k8s-down`.

Read [docs/kubernetes.md](docs/kubernetes.md) before installing: it covers images, sandbox nodes, gVisor, Postgres and Redis, secrets, values and troubleshooting. The chart is linted, schema-validated and exercised on kind in CI, but has not been run on a production cluster, so test it in your own environment first. For running several API replicas, see [Scaling](docs/kubernetes.md#scaling).

### 7. Operating it

[docs/operations.md](docs/operations.md) covers running Harnis in production: dependency installs and the egress proxy, model prices, data retention and user data requests (export and erasure), deleting tenants, backups and restore drills, upgrades, metrics and alerts, load testing, and a go-live checklist.

## API

All endpoints except `/health`, `/ready` and `/` need `Authorization: Bearer <OIDC token, local JWT or hrn_ API key>`. Interactive docs are at `/docs`.

| Method & path | Role | Purpose |
|---|---|---|
| `POST /v1/sessions` | user | create a session, optional `{"files": {path: content}}` seed |
| `POST /v1/sessions/{id}/turns` | user (owner) | send a message; returns `completed`, `awaiting_approval`, `rejected`, `escalated` or `failed` |
| `GET /v1/sessions[/{id}]` | owner / reviewer | list or view sessions |
| `GET /v1/sessions/{id}/files` | owner / reviewer | the session workspace |
| `GET /v1/approvals` | reviewer | pending approvals with diff / command and `action_hash` |
| `POST /v1/approvals/{id}/decision` | reviewer (approve), requester or reviewer (deny) | `{"approved": bool, "action_hash": "..."}`; the session resumes in the background |
| `GET /v1/agents` | any | registered agents and their tools |
| `GET /v1/usage` | any | tokens and cost by model for your tenant |
| `GET /v1/analytics` | reviewer | hourly runs, latency, cache hit %, success % |
| `POST /v1/prompts`, `GET /v1/prompts/{key}` | admin | per-tenant prompt versions |
| `POST/GET /v1/admin/api-keys`, `DELETE /v1/admin/api-keys/{key_id}` | admin | service API keys |
| `GET /v1/admin/audit?after=&limit=&event_type=&format=ndjson` | admin | the tenant's audit log, paginated |
| `GET /v1/admin/pricing` | admin | model prices in use and whether the operator confirmed them |
| `GET /v1/admin/users/{id}/export` | admin | everything stored about one user of the tenant (right of access) |
| `DELETE /v1/admin/users/{id}/data?confirm={id}` | admin | erase a user's data; their id in retained history becomes a pseudonym |
| `GET /v1/admin/tenants`, `PUT /v1/admin/tenants/{id}` | platform-admin | tenant administration |
| `DELETE /v1/admin/tenants/{id}?confirm={id}` | platform-admin | delete a disabled tenant with all its data |
| `GET /v1/admin/platform-events` | platform-admin | platform audit trail (tenant deletions) |
| `GET /metrics` | scraper (`METRICS_TOKEN`) | Prometheus metrics |
| `GET /me` | any | who the token says you are |
| `WS /v1/ws?token=...` | any | live events (your sessions; plus approvals for reviewers) |

## Checking a deployment

`scripts/harnis_check.py` is a standalone script (Python standard library only, no Harnis install needed) that exercises every feature against a running API and prints PASS / FAIL / SKIP for each: health and security headers, authentication and roles, API keys, conversations and routing, the semantic cache, approvals bound to the exact action, the sandbox (including that it has no network), guardrails, the loop breaker, separation of duties, tenant isolation, tenant administration, prompts, usage, the audit log, live events and rate limits.

```bash
python tasks.py check                                    # local: uses .env, tests in throwaway tenants
python scripts/harnis_check.py --api https://harnis.example.com \
    --admin-token "$TENANT_ADMIN_TOKEN_OR_API_KEY" \
    --platform-token "$PLATFORM_ADMIN_TOKEN" --other-admin-token "$ADMIN_OF_ANOTHER_TENANT" \
    --report check.json                                  # any deployment, including SSO
```

With the JWT secret (local auth) it creates its own tenants and tests everything; with an admin token it runs inside that admin's tenant and skips what needs more credentials. Agent behaviour is checked exactly with the `mock` model; against a deployment without it, pass `--provider` (with a secret) and a smaller set of agent checks runs against the real model. It exits non-zero on any failure, so it can gate a deployment pipeline. Run `python scripts/harnis_check.py --help` for all options.

## Testing gVisor and Kubernetes locally

* **gVisor** (kernel isolation for untrusted code): on Linux, or on Windows inside WSL2 with Docker Engine (Docker Desktop can't run `runsc`), install runsc and run `python tasks.py gvisor-check`. It verifies the runtime and runs the sandbox tests under gVisor. See [docs/gvisor.md](docs/gvisor.md). CI runs the same check on every push (`.github/workflows/gvisor.yml`).
* **Kubernetes**: with Docker Desktop (or Docker Engine), kind, kubectl and helm, run `python tasks.py k8s-up`, then `python tasks.py k8s-check`, then `python tasks.py k8s-down`. This deploys the Helm chart with throwaway Postgres/Redis and runs the full feature check, with sandbox commands running as Pods. See [docs/kubernetes.md](docs/kubernetes.md#try-it-locally-with-kind). CI runs it in `.github/workflows/k8s-e2e.yml`.

## Tests and evals

```bash
python tasks.py test unit          # no services needed (runs on Windows, macOS and Linux CI)
python tasks.py test integration   # RLS, auth and API end to end against real Postgres + Redis
python tasks.py test sandbox       # container hardening against a real Docker daemon
python tasks.py test               # everything
python tasks.py redteam            # attack checks against a running API
python tasks.py test browser       # the web console in Chromium, incl. SSO (pip install playwright; playwright install chromium)
python tasks.py eval -- --providers mock,anthropic,gemini,nova --repeat 3
```

The eval suite (`evals/`) drives the live API like a user and a reviewer would, across support, coding, approvals, guardrails, multi-agent and robustness cases, and writes an HTML and JSON report. Each provider runs in its own tenant restricted to that provider, so results are comparable. Add cases for your own agents; see [evals/README.md](evals/README.md).

## Security model: read before deploying

* **Prompt injection is not solved by the guardrail.** It catches common patterns. The containment is structural: least-privilege tools, a human for anything with side effects, commands in a sandbox without network, and budgets that stop runaway loops.
* **Containers are not a hard boundary** for hostile code: they share the kernel. Use gVisor (`SANDBOX_RUNTIME=runsc` with Docker, `sandbox.runtimeClassName` on Kubernetes), Kata or Firecracker for untrusted workloads.
* **Dependency installs are the one network path.** An approved `install_dependencies` run can reach only an allowlisting proxy, which tunnels HTTPS to the configured registries (PyPI and npm by default). Packages come from the internet: the reviewer approves the manifest, and npm lifecycle scripts are disabled, but a malicious package can still run code when the project's tests import it, inside the sandbox. Set `SANDBOX_INSTALL_ENABLED=false` or point `SANDBOX_EGRESS_ALLOW` at an internal mirror if that is not acceptable.
* **The Docker socket is root.** `python tasks.py up-full` mounts it into the API container for local convenience only. In production use the Kubernetes backend or a separate minimal runner.
* **Plugins run inside the API process** with its permissions. Install only plugins you trust and review them like your own code.
* **Never run the app as a Postgres superuser or table owner**; superusers bypass RLS even when it's forced. `harnis.migrate` creates the right roles.
* **Data leaving your boundary:** failover can send a tenant's prompts to another provider. Restrict it with `allowed_providers`, and check your privacy obligations (e.g. GDPR) before sending personal data to providers in other jurisdictions.
* With `AUTH_MODE=local`, use a long random `JWT_SECRET` and short-lived tokens. Don't log query strings (the WebSocket token travels there because browsers can't set headers on upgrades).

See [SECURITY.md](SECURITY.md) for the security model and how to share a vulnerability (there is no response commitment).

## Project layout

```
tasks.py              cross-platform task runner (install, up, dev, test, cli, eval, ...)
harnis/
  api.py              FastAPI app, routes, admin API, WebSocket
  auth.py             local JWT, OIDC, API keys, roles
  orchestrator.py     state machine, budgets, loop breaker, approvals
  plugins.py          registry and plugin SDK (built-in agents and providers register here too)
  tools.py            built-in tools, risk tiers, workspace confinement
  sandbox.py          hardened Docker runner
  k8s_sandbox.py      hardened Kubernetes Pod runner
  guardrails.py       input / output / tool-output filters
  llm/                neutral types, providers, router, pricing
  cache.py            tenant-scoped semantic cache
  store.py, db.py     Postgres access (RLS)
  infra.py            rate limits, locks, event bus
  egress_proxy.py     allowlisting HTTPS proxy for dependency installs
  metrics.py          Prometheus metrics
  backup.py           backup, verify, restore
  telemetry.py, alerts.py, config.py, migrate.py, maintenance.py, cli.py, evals.py
  migrations/         SQL
  static/             web console
deploy/helm/harnis/   Helm chart
deploy/keycloak/      local Keycloak realm (testing only)
deploy/local-k8s/     kind cluster, throwaway Postgres/Redis, chart values
docs/                 architecture, operations, Kubernetes, gVisor, Keycloak, plugins
scripts/              harnis_check.py (feature check), load_test.py, keycloak_local.py, k8s_local.py, gvisor_check.py
examples/plugins/     a complete example plugin
tests/  redteam/  evals/
```

## Contributing

Contributions are welcome (bug reports, docs, plugins, providers and fixes), with no commitment to review or merge them. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup and the sign-off (DCO) we ask for, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). How decisions are made is in [GOVERNANCE.md](GOVERNANCE.md); what changed is in [CHANGELOG.md](CHANGELOG.md).

## Use at your own risk

Harnis is provided **"as is", without warranties or conditions of any kind**, and the authors accept no liability for its use (Apache License 2.0, sections 7 and 8). There are no supported versions, no support and no guaranteed fixes. You are free to use, change, extend and redistribute it under the license, and when you do, you are responsible for:

* deploying, configuring, securing and operating it, including the actions agents take in your environment;
* the third-party software it relies on (Python packages such as the LGPL-licensed `psycopg` Postgres driver, container base images, Postgres, Redis, Kubernetes components) and the model providers and models you use: reviewing their licenses and terms, and obtaining any licenses you need;
* the data you send to model providers and your legal and contractual obligations.

## License

Copyright 2026 Ahmad Karawash. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
