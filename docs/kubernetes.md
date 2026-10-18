# Running Harnis on Kubernetes

This guide covers deploying Harnis with the Helm chart in
[`deploy/helm/harnis`](../deploy/helm/harnis), and how agent commands run in
per-command sandbox Pods instead of Docker containers.

```
                         release namespace (e.g. harnis)                    sandbox namespace (harnis-sandbox)
                 +-------------------------------------------+        +----------------------------------------+
 Ingress ------> | Service -> API Deployment (N replicas)    |  exec  |  one Pod per command, deleted after:   |
                 |            ServiceAccount + Role binding  | -----> |  non-root, read-only root, no caps,    |
                 |            workspaces volume (RWX PVC)     | create |  seccomp, no SA token, no network,     |
                 | migrate Job (Helm hook)                    | delete |  cpu/mem/ephemeral limits, deadline,   |
                 | maintenance CronJob, sandbox reaper        |        |  optional gVisor/Kata RuntimeClass     |
                 +------+-------------------+----------------+        +----------------------------------------+
                        |                   |                                 deny-all NetworkPolicy
                 managed Postgres 15+   managed Redis / Redis Stack           Pod Security "restricted"
```

The chart does not install Postgres or Redis. Use managed services, or
separate charts you operate yourself (for example the Bitnami PostgreSQL and
Redis charts, CloudNativePG, or the Redis Stack images).

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes 1.27+ | `autoscaling/v2`, `policy/v1`, Pod Security Admission. |
| Helm 3.8+ or Helm 4 | The chart is `apiVersion: v2`. |
| Postgres 15+ | Managed (RDS, Cloud SQL, Azure Database, ...). You need an owner/admin login that can `CREATE ROLE`; the app itself connects as `harnis_app`, which migrations create. |
| Redis 7+ | Redis Stack (RediSearch) enables the vector semantic cache; plain Redis works with a brute-force fallback. Pub/sub must be allowed (it carries WebSocket events between replicas). |
| Ingress controller | ingress-nginx, Traefik, a cloud load balancer controller, ... WebSockets (`/v1/ws`) must be allowed with long read timeouts. |
| A CNI that enforces NetworkPolicy | Calico, Cilium, Antrea, or a cloud CNI with network policy enabled. Without it the sandbox deny-all policy has no effect; Harnis detects this and refuses to run sandbox commands (see [Network isolation check](#network-isolation-check)). |
| ReadWriteMany storage (for more than one replica) | EFS, Filestore, Azure Files, CephFS, NFS. See [Workspaces](#session-workspaces-and-multiple-replicas). |
| Optional: gVisor or Kata | Strongly recommended for untrusted code; exposed as a RuntimeClass. |

## Try it locally with kind

Before a real cluster, run the chart on [kind](https://kind.sigs.k8s.io/) v0.24 or newer (works with Docker Desktop on Windows and macOS; older kind releases don't enforce NetworkPolicy, so Harnis refuses to run sandbox commands on them):

```bash
winget install Kubernetes.kind Kubernetes.kubectl Helm.Helm   # macOS: brew install kind kubectl helm
python tasks.py k8s-up      # cluster "harnis", builds harnis:local + harnis-sandbox:local, kind load,
                            # Postgres + Redis (namespace harnis-deps), helm upgrade --install
python tasks.py k8s-check   # port-forward + scripts/harnis_check.py, report in .k8s-local/
python tasks.py k8s-down
```

`deploy/local-k8s/values-kind.yaml` uses local-only credentials, the `mock` model (`ENV=development` through `api.extraEnv`) and one replica: kind's `local-path` storage is ReadWriteOnce only, so workspaces stay on an emptyDir. kind's default CNI (kindnetd) enforces NetworkPolicy, so the sandbox deny-all policy is really tested; it applies policy to a new Pod about 1 to 3 seconds after the Pod starts, which the [network isolation check](#network-isolation-check) waits out. `python scripts/k8s_local.py debug` prints pods, events and logs. CI runs the same flow in `.github/workflows/k8s-e2e.yml`. gVisor itself is tested with Docker, see [gvisor.md](gvisor.md).

## 1. Build and push the images

```bash
docker build -t registry.example.com/harnis:1.0.0 .
docker build -f Dockerfile.sandbox -t registry.example.com/harnis-sandbox:1.0.0 .
docker push registry.example.com/harnis:1.0.0
docker push registry.example.com/harnis-sandbox:1.0.0
```

The API image must include the `kubernetes` Python package (the `k8s` extra).
The sandbox image needs `sh`, `sleep`, `tar`, `head` and `timeout`
(coreutils); the provided `Dockerfile.sandbox` has them. Pin both images by
digest in production (`image.digest`, `sandbox.image.digest`).

## 2. Prepare the cluster

### Dedicated sandbox nodes (recommended)

Run sandboxes on their own node pool so untrusted code never shares a kernel
(or a noisy neighbour) with the API or other workloads:

```bash
kubectl label nodes <node> harnis.dev/pool=sandbox
kubectl taint nodes <node> harnis.dev/sandbox=true:NoSchedule
```

```yaml
sandbox:
  nodeSelector:
    harnis.dev/pool: sandbox
  tolerations:
    - key: harnis.dev/sandbox
      operator: Exists
      effect: NoSchedule
```

### PID limits (kubelet `podPidsLimit`)

Docker sandboxes get a per-container PID limit. **The Kubernetes Pod spec has
no equivalent field**: the limit is a kubelet setting, `podPidsLimit`, that
applies to every Pod on the node. Set it on the sandbox node pool, for
example in the kubelet configuration:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
podPidsLimit: 256
```

(EKS: launch template / `nodeadm` config; GKE: node system configuration
`podPidsLimit`; AKS: custom node configuration `podMaxPids`.) Without it, a
fork bomb in a sandbox is limited only by the node-wide PID limit and the
CPU/memory limits.

### gVisor RuntimeClass (recommended)

runc shares the node's kernel, so a kernel exploit in a sandbox escapes it.
With gVisor installed on the sandbox nodes (GKE Sandbox does this for you),
create a RuntimeClass and point the chart at it:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
scheduling:
  nodeSelector:
    harnis.dev/pool: sandbox
```

```yaml
sandbox:
  runtimeClassName: gvisor     # GKE Sandbox: "gvisor"; Kata: e.g. "kata-qemu"
```

## 3. Prepare Postgres and Redis

Create the database and an owner login on your managed Postgres (the
migration Job creates the `harnis_app` and `harnis_analytics` roles):

```sql
CREATE DATABASE harnis;
-- An owner role that can create roles; on managed services this is usually
-- the admin login or a role with CREATEROLE.
```

Choose a strong password for `harnis_app`: the migration Job sets the role's
password to `externalDatabase.appPassword` (`APP_DB_PASSWORD`) on every
install and upgrade, and `DATABASE_URL` must use the same one.

Size connections: each API replica opens up to `DB_POOL_MAX` (default 10)
connections, so `maxReplicas x DB_POOL_MAX` plus jobs must fit under the
server's `max_connections`. If you put a pooler such as PgBouncer in front,
session pooling is the safe choice; test transaction pooling with your
pooler version before relying on it (psycopg uses server-side prepared
statements for repeated queries).

## 4. Secrets

Harnis needs two groups of secrets, kept in **separate** Secrets so that a
compromised API Pod never holds the table owner's credentials:

| Secret | Keys | Used by |
|---|---|---|
| runtime | `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, optional `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ALERT_WEBHOOK_URL` | API (`envFrom`) |
| migration | `MIGRATION_DATABASE_URL`, `APP_DB_PASSWORD` | migration Job, maintenance CronJob |

**Option A: let the chart render them from values** (simple; the values file
then holds secrets, so keep it out of git or use helm-secrets / SOPS):

```yaml
externalDatabase:
  host: harnis.abc123.eu-west-1.rds.amazonaws.com
  sslmode: verify-full
  appPassword: "<harnis_app password>"
  ownerUser: harnis_owner
  ownerPassword: "<owner password>"
externalRedis:
  host: master.harnis.abc123.euw1.cache.amazonaws.com
  password: "<redis auth token>"
  tls: true
secrets:
  anthropicApiKey: "<key>"
  # jwtSecret: leave empty to generate one (kept across upgrades)
```

Passwords are percent-encoded into the URLs. For unusual setups set
`externalDatabase.url` / `.migrationUrl` / `externalRedis.url` directly.

**Option B: bring your own Secrets** (External Secrets Operator, Sealed
Secrets, Vault, ...). Create them before installing:

```bash
kubectl create namespace harnis
kubectl -n harnis create secret generic harnis-runtime \
  --from-literal=DATABASE_URL='postgresql://harnis_app:...@db:5432/harnis?sslmode=verify-full' \
  --from-literal=REDIS_URL='rediss://:...@redis:6379/0' \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=ANTHROPIC_API_KEY='...'
kubectl -n harnis create secret generic harnis-owner \
  --from-literal=MIGRATION_DATABASE_URL='postgresql://harnis_owner:...@db:5432/harnis?sslmode=verify-full' \
  --from-literal=APP_DB_PASSWORD='...'
```

```yaml
secrets:
  existingSecret: harnis-runtime
  existingMigrationSecret: harnis-owner
```

With `existingSecret` set the chart renders no Secret objects. (If you only
set `existingSecret`, the jobs read the owner keys from it too, and the API
then also sees them. Prefer two Secrets.)

Cloud credentials for Bedrock (Nova) or Vertex AI (Gemini) are best supplied
through workload identity instead of keys:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/harnis-bedrock   # IRSA
    # iam.gke.io/gcp-service-account: harnis@my-project.iam.gserviceaccount.com # GKE
config:
  AWS_REGION: eu-west-1
```

## 5. Install

A minimal production values file (`values-prod.yaml`):

```yaml
image:
  repository: registry.example.com/harnis
  tag: "1.0.0"
sandbox:
  image:
    repository: registry.example.com/harnis-sandbox
    tag: "1.0.0"
  runtimeClassName: gvisor
  nodeSelector: {harnis.dev/pool: sandbox}
  tolerations:
    - {key: harnis.dev/sandbox, operator: Exists, effect: NoSchedule}
secrets:
  existingSecret: harnis-runtime
  existingMigrationSecret: harnis-owner
config:
  LLM_PROVIDERS: "anthropic,openai"
  OTEL_ENABLED: "true"
  OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel-collector.observability:4317"
workspaces:
  persistence:
    enabled: true
    storageClass: efs-sc
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: harnis.example.com
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: harnis-tls
      hosts: [harnis.example.com]
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 8
```

```bash
helm upgrade --install harnis ./deploy/helm/harnis \
  --namespace harnis --create-namespace \
  -f values-prod.yaml --wait --timeout 10m
kubectl -n harnis rollout status deploy/harnis
```

Read the install notes: they warn about missing database/Redis settings, a
missing RuntimeClass, and multi-replica setups without shared workspaces.

Tenants are created through the admin API by a `platform-admin` (with OIDC,
map one of your IdP groups to it with `OIDC_ROLE_MAP`):

```bash
curl -X PUT https://harnis.example.com/v1/admin/tenants/acme \
  -H "Authorization: Bearer $PLATFORM_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "allowed_providers": ["anthropic"]}'
```

For people to sign in to the web console with SSO, set `AUTH_MODE=oidc`, the
`OIDC_*` settings and `OIDC_CONSOLE_CLIENT_ID` under `config:` (see the
README's single sign-on section). The API Pods need HTTPS egress to the IdP;
with `apiNetworkPolicy.enabled`, a public IdP is covered by `apiNetworkPolicy.https`,
and an in-cluster or private one goes in `apiNetworkPolicy.extraEgress`.

### Verify the installation

Run the feature check from any machine that can reach the ingress. With SSO,
pass a tenant admin's token or an `hrn_` API key; add a platform-admin token
and an admin of a second tenant to cover tenant administration and isolation:

```bash
python scripts/harnis_check.py --api https://harnis.example.com \
  --admin-token "$TENANT_ADMIN_KEY" --platform-token "$PLATFORM_ADMIN_TOKEN" \
  --other-admin-token "$OTHER_TENANT_ADMIN_KEY" --report harnis-check.json
```

Production refuses the `mock` model, so agent checks run against your real
model (a few cents of usage) and the checks that need the deterministic mock
are skipped. Every check that fails is a reason not to go live.

### Network isolation check

Some CNIs apply NetworkPolicy to a new Pod a moment after it is Running (kind's kindnetd takes about 1 to 3 seconds; others, such as Calico, close the gap only with their CNI policy-setup option). Code that opened a connection in that window would get out. So before the workspace is copied into a sandbox Pod and before the command runs, Harnis runs a short probe inside the Pod: it connects to an address the sandbox policies must block and waits until two attempts in a row fail. If the Pod can still reach it after `sandbox.networkProbe.timeoutSeconds` (default 20), the command is not run and the tool result says so. Install Pods are probed the same way. This fails closed: without an enforcing CNI, or without the chart's sandbox NetworkPolicies, no sandbox command runs. It costs about 1 second per command (two blocked attempts, starting `python3`, the exec round trip), plus the enforcement delay of your CNI: on kind, measured over 15 commands, a sandbox command took 5.4 s (median) with the check against 1.1 s without it, and 0 of 15 commands reached the network with the check against 8 of 15 without it.

| Setting (values / env) | Default | Meaning |
|---|---|---|
| `sandbox.networkProbe.targets` / `SANDBOX_K8S_NETWORK_PROBE` | `auto` | `auto`: the API server's ClusterIP (from `KUBERNETES_SERVICE_HOST` in the Pod). Or comma-separated `host:port` addresses the sandbox policy blocks. `off` (on its own) skips the check: only for a CNI that enforces policy before a Pod starts, verified by you. If your CNI always lets Pods reach their node (for example Calico with `DefaultEndpointToHostAction=ACCEPT`) and the API server runs on that node, `auto` refuses every command: give targets the policy really blocks. |
| `sandbox.networkProbe.timeoutSeconds` / `SANDBOX_K8S_NETWORK_PROBE_TIMEOUT` | `20` | How long to wait for the policy before refusing the command. |

The probe runs `python3` in the sandbox image (the default image has it); a custom image without `python3` needs it added, or the check turned off.

## Upgrades and migrations

`helm upgrade` runs the migration Job (`python -m harnis.migrate`) as a
`pre-install,pre-upgrade` hook, before any new API Pod starts:

* The owner credentials come from the migration Secret
  (`MIGRATION_DATABASE_URL`, `APP_DB_PASSWORD`). When the chart renders that
  Secret it is itself a hook (weight -10), so it exists before the Job runs.
  Hook resources are not removed by `helm uninstall`: delete it by hand.
* Migrations are forward-only and each file is applied in a transaction. A
  failed migration fails the upgrade; the old Pods keep running. Fix the
  problem and upgrade again. `helm rollback` does not undo schema changes,
  so write migrations that the previous release can still run against.
* The Job is deleted when it succeeds; when it fails it stays for
  inspection (`kubectl -n harnis logs job/<release>-harnis-migrate`) and is
  replaced on the next attempt.
* API Pods roll with `maxUnavailable: 0` and a preStop sleep, and uvicorn
  finishes in-flight requests on SIGTERM. Raise
  `api.terminationGracePeriodSeconds` if turns can run longer than two
  minutes.

Maintenance (`python -m harnis.maintenance`: next months' ledger partitions,
analytics refresh) runs hourly as a CronJob with the same owner credentials.

## Scaling

* **The API keeps no session state in memory.** Sessions, approvals and checkpoints
  are in Postgres; rate limits, session locks, the circuit breaker and the
  cache in Redis; WebSocket events travel over Redis pub/sub, so a client
  connected to one replica sees events produced on another. Scale with the
  HPA (`autoscaling.*`); the PDB keeps replicas up during node drains.
* **Workspaces** need shared ReadWriteMany storage beyond one replica (see below).
* **Long requests.** A turn holds an HTTP request while the model and
  sandbox run. Size `terminationGracePeriodSeconds`, ingress timeouts and
  `LLM_TIMEOUT_SECONDS` together.
* **Sandboxes scale with the cluster**, not with the API: each command is a
  Pod sized by `sandbox.resources`. Give the sandbox node pool its own
  autoscaling and cap usage with `sandbox.resourceQuota`.
* **Postgres connections**: `replicas x DB_POOL_MAX` (see above).
* **Redis**: use a single primary with replicas / automatic failover (the
  usual managed-service setup). Harnis uses pub/sub and Lua scripts; Redis
  Cluster mode has not been tested.

### Session workspaces and multiple replicas

Session files live on the API Pods at `WORKSPACES_DIR`
(`workspaces.mountPath`). A session can continue on any replica: approvals
are decided on whichever replica receives the request, which then resumes the
session and runs the sandbox. So **with more than one replica the
workspaces must be on shared ReadWriteMany storage**:

```yaml
workspaces:
  persistence:
    enabled: true
    storageClass: efs-sc        # or existingClaim: harnis-workspaces
    size: 50Gi
```

The created PVC has `helm.sh/resource-policy: keep`, so uninstalling the
release does not delete session files. With persistence disabled an emptyDir
is used; that is only correct for a single replica, and files are lost when
the Pod is replaced.

## Observability

* **Traces**: set `config.OTEL_ENABLED: "true"` and
  `OTEL_EXPORTER_OTLP_ENDPOINT` to an OpenTelemetry Collector (OTLP/gRPC,
  plaintext inside the cluster; the collector handles TLS to your backend).
  Spans cover FastAPI, psycopg, Redis, model calls (`gen_ai.*`) and
  `harnis.sandbox.run`, which on Kubernetes also carries
  `harnis.sandbox.backend`, `harnis.sandbox.k8s.namespace`,
  `harnis.sandbox.k8s.pod` and `harnis.sandbox.k8s.runtime_class`. Prompts,
  file contents and command arguments are never recorded.
* **Latency alerts**: Pod start adds latency to `harnis.sandbox.run`; raise its
  threshold if needed, e.g.
  `LATENCY_THRESHOLDS_MS='{"gen_ai.chat": 30000, "harnis.sandbox.run": 40000, "harnis.db.checkpoint": 200}'`.
* **Logs** go to stdout; collect them with your cluster's log agent.
* **Health**: `/health` (liveness, process only) and `/ready` (readiness,
  Postgres and Redis).
* **Usage and analytics**: `GET /v1/usage` and `GET /v1/analytics` per tenant.
* **Sandbox Pods** are short-lived; to watch them:

  ```bash
  kubectl -n harnis-sandbox get pods -l harnis/sandbox=true -w
  kubectl -n harnis-sandbox get events --sort-by=.lastTimestamp
  ```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Install hangs on the migration hook | Wrong `MIGRATION_DATABASE_URL`, the database is unreachable (API NetworkPolicy, security groups), or `APP_DB_PASSWORD` is missing (`CreateContainerConfigError`). `kubectl -n harnis describe job <release>-harnis-migrate`. |
| API Pods not Ready | `/ready` cannot reach Postgres or Redis. Check `DATABASE_URL` (role `harnis_app`, password = `APP_DB_PASSWORD`) and `REDIS_URL` (`rediss://` for TLS). |
| API exits at start with a settings error | `ENV=production` refuses a weak `JWT_SECRET` and the `mock` provider; remove `mock` from `LLM_PROVIDERS`. |
| Tool results say `sandbox error: NetworkNotIsolated: the sandbox pod still had network access` | The CNI does not enforce NetworkPolicy, the sandbox NetworkPolicies are missing (`kubectl -n <sandbox namespace> get networkpolicy`), a policy allows the probe target, or enforcement takes longer than `sandbox.networkProbe.timeoutSeconds`. See [Network isolation check](#network-isolation-check). |
| Tool results say `sandbox error: ApiException: HTTP 403 Forbidden` | RBAC: the API's ServiceAccount is not bound in the sandbox namespace (namespace name mismatch, `serviceAccount.create: false` with a different name). |
| `sandbox pod cannot start: ImagePullBackOff` | Wrong `sandbox.image`, or the pull Secret is not in the sandbox namespace. |
| `sandbox pod did not start within 60s` | No schedulable sandbox node (taints, nodeSelector, quota, autoscaler lag) or slow image pulls. Raise `sandbox.podStartTimeoutSeconds` or pre-pull. |
| Sandbox Pods rejected with a quota error | `sandbox.resourceQuota` is full; raise it or scale down concurrency. |
| `pods ... is forbidden: violates PodSecurity "restricted"` | A custom sandbox image or setting violates the restricted profile. |
| Files missing after an approval | Several replicas without shared workspace storage. |
