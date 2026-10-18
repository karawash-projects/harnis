# Security

Harnis is provided **"as is", without warranty of any kind**, under the [Apache License 2.0](LICENSE) (see sections 7 and 8: Disclaimer of Warranty and Limitation of Liability). There are no supported versions, no security response commitments and no guaranteed fixes. Whoever deploys Harnis is responsible for assessing it, securing it, and keeping it and its dependencies up to date.

If you find a vulnerability and want to share it, you can use GitHub's private vulnerability reporting on the repository (the **Security** tab, when it is enabled) or open a pull request with a fix. Please don't post exploit details in public issues.

## Security model in brief

Harnis does not try to make the model trustworthy. It assumes the model, and everything the model reads, can be adversarial, and limits what that can lead to:

* the tenant always comes from a verified credential, and Postgres Row-Level Security (enabled and forced; the app role is neither owner nor superuser) scopes every query;
* tools are least-privilege and confined to the session workspace; anything with side effects (writing files, running commands) suspends the session until a reviewer approves the exact action, identified by its SHA-256;
* commands run in a throwaway container or Pod with no network, a read-only root, no capabilities, a non-root user and resource limits; results are validated before they are copied back;
* budgets and a loop breaker stop runaway turns; tool output is fenced as untrusted data;
* failover only sends a tenant's data to providers on that tenant's allow-list.

These are design goals, not guarantees. Read the **Security model** section of the [README](README.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before deploying. In short: plain Docker (runc) is not a hard boundary for hostile code; use gVisor, Kata or Firecracker, never give the API direct access to a Docker socket in production, and never connect the app to Postgres as a superuser or table owner.
