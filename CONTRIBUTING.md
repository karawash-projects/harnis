# Contributing to Harnis

Thanks for considering a contribution. This document covers how to set up a development environment, what we expect from a change, and how releases are made.

Harnis is provided as is (see [GOVERNANCE.md](GOVERNANCE.md)); contributions are welcome but there is no commitment to review or merge them. By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Please don't post exploit details in public issues: see [SECURITY.md](SECURITY.md).

## Before you start

* **Bug fixes and small improvements**: open a pull request directly. Link the issue if there is one.
* **New features, new dependencies, API or schema changes**: open an issue first (use the feature request template) so the design can be discussed before you spend time on it. Changes to tenant isolation, approvals or the sandbox always need a design discussion.
* **Questions**: use GitHub Discussions if enabled, otherwise an issue.

## Development setup

You need Python 3.11 or newer and Docker (Docker Desktop on Windows and macOS, Docker Engine on Linux). Everything runs through `tasks.py`, a standard-library task runner that behaves the same on Windows, macOS and Linux (`py tasks.py ...` on Windows if `python` is not on PATH).

```bash
python tasks.py install          # creates .venv and installs harnis with the dev extras (editable)
python tasks.py up               # Postgres, Redis Stack, Jaeger; runs migrations; seeds demo tenants
python tasks.py sandbox-image    # builds harnis-sandbox:latest, the image agent commands run in
python tasks.py dev              # API with auto-reload on http://127.0.0.1:8000
```

`python tasks.py --help` lists every task. `python tasks.py token` prints a development JWT, and `python tasks.py cli -- --workspace demo "..."` drives the coding agent. No model API keys are needed: the `mock` provider follows a deterministic script (see the README). `python tasks.py down` stops the containers and keeps the database volume.

## Tests

```bash
python tasks.py test unit          # no services needed; runs on Windows, macOS and Linux
python tasks.py test integration   # Postgres RLS and the API end to end (needs `tasks.py up`)
python tasks.py test sandbox       # container hardening against a real Docker daemon (needs the sandbox image)
python tasks.py test               # everything
```

Arguments after the suite name go to pytest, for example `python tasks.py test unit -k guardrails -x`. Integration tests create and drop their own database.

CI (`.github/workflows/ci.yml`) runs the unit tests on Ubuntu, macOS and Windows with Python 3.11 and 3.13, and the full suite, the red-team script and the mock evals on Ubuntu. A pull request must pass all of them.

## Evals and red team

Both run against a live API (`python tasks.py dev` in another terminal):

```bash
python tasks.py redteam                                        # attack checks; non-zero exit on failure
python tasks.py eval                                           # eval suite on the mock model
python tasks.py eval -- --providers mock,anthropic --repeat 3  # compare real providers
```

* Changes to the orchestrator, routing, tools, guardrails, approvals or prompts must pass `python tasks.py eval` on `mock`. If you have credentials, also run at least one real provider with `--repeat 3` and mention the pass rates in the pull request.
* A bug that an eval case or red-team check could have caught should come with a new case. The case format is documented in [evals/README.md](evals/README.md).
* Reports are written to `evals/reports/` and are not committed.

## What we expect from a change

### Invariants you must not weaken

These are the security properties Harnis exists to provide. A change that weakens one will not be merged, however useful it is otherwise. If you think one needs to change, open an issue first.

* **The tenant comes only from the verified credential** (token claims, API key record or OIDC claims), never from a request body, path, header or query parameter.
* **Every tenant-scoped database access goes through `tenant_tx`**, so Row-Level Security applies. New tenant tables get RLS enabled *and* forced with the `tenant_isolation` policy, and only the grants the app actually needs (no `DELETE` unless essential; the audit log stays insert/select). The app role is never the owner or a superuser.
* **Redis keys, cache entries, event channels and workspaces are tenant-scoped.**
* **Side effects need approval.** A tool that writes files, runs commands, calls external systems or otherwise changes state is `risk="high"`. The approval is bound to the SHA-256 of the exact action the reviewer saw, and the action is re-hashed before execution. Separation of duties and approval expiry stay in place.
* **The sandbox stays locked down**: no network, read-only root, all capabilities dropped, no-new-privileges, non-root user, resource limits, and validated copy-back. Do not add mounts, capabilities or network access.
* **Tool output is untrusted.** Content the model reads goes through `wrap_untrusted`; prompts, commands and file contents are not put on spans, logs or alerts.
* **Data leaves only to allowed providers.** Failover respects `tenants.allowed_providers`.

Tests for these properties live in `tests/test_rls.py`, `tests/test_orchestrator.py`, `tests/test_sandbox*.py`, `tests/test_guardrails.py` and the red-team script. Changes in these areas need tests that would fail if the property were broken.

### Code style

* **Typed code.** New and changed functions have type hints (`from __future__ import annotations` at the top of modules, as elsewhere). Prefer Pydantic models for anything parsed from outside (requests, tool arguments, settings).
* **Follow the existing style**: small modules, explicit dependencies passed in (see `Deps` and `create_app`), docstrings that explain *why*. Keep lines under about 120 characters.
* **Cross-platform.** The unit tests run on Windows and macOS. Use `pathlib`, read and write files as UTF-8 bytes, keep workspace paths POSIX-style, and put any new developer task into `tasks.py` rather than a shell script.
* **Configuration** goes into `harnis/config.py` with a safe local default, and is documented in `.env.example`. Anything secret must be refused in production when left at its default.
* **No new runtime dependencies without discussion.** Every dependency is attack surface, install weight and a license obligation for everyone who adopts Harnis. Open an issue explaining why the standard library or an existing dependency is not enough. Prefer permissively licensed packages, and run `pip-audit` on the result. Optional integrations should be optional extras.
* **Tests are required** for bug fixes (a test that fails before the fix) and features. Unit tests must not need network access or real model credentials; use the mock provider and `fakeredis`.
* **Documentation**: update the README, `.env.example`, `docs/` and `CHANGELOG.md` (under `Unreleased`) when behaviour, configuration or the API changes.

### Database migrations

* Add a new numbered file in `harnis/migrations/` (`004_...sql`). Never edit a migration that has been released.
* Migrations must be idempotent where possible (`IF NOT EXISTS`) and safe to run while older API replicas are still running. Prefer additive changes; a destructive change is a breaking change and needs a major version.
* Include grants for `harnis_app` and RLS for any new tenant table, and add a test in `tests/test_rls.py` that another tenant cannot see the rows.

## Extending Harnis: providers, tools and agents

The plugin SDK is documented in [docs/plugins.md](docs/plugins.md). In short:

* **LLM providers** implement the provider interface in `harnis/llm/types.py` (neutral messages in, `LLMResponse` out, and errors mapped to `ProviderError` with the correct `retryable` flag so the router retries and fails over correctly). Add pricing to `harnis/llm/pricing.py`, settings to `config.py` and `.env.example`, adapter tests to `tests/test_provider_adapters.py`, and remember that tenants opt in through `allowed_providers`.
* **Tools** declare a Pydantic argument model, a risk tier and a workspace-confined implementation. Anything with side effects is `high` risk and goes through approval; `describe_action` must show the reviewer everything the hash covers.
* **Agents** are a prompt plus an allow-list of tools. Give an agent the fewest tools it needs, and add eval cases for it.

Plugins that can live outside this repository should, using the SDK. Changes to the SDK's interface are breaking changes for plugin authors; call them out in `CHANGELOG.md`.

## Developer Certificate of Origin (DCO)

Harnis uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a contributor license agreement. By adding a `Signed-off-by` line to a commit, you certify that you wrote the change or otherwise have the right to submit it under the project's license (Apache-2.0). Read the full text at the link above; it is short.

Every commit in a pull request must be signed off, with your real name and an email address you can be reached at:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Git adds this for you with `-s`:

```bash
git commit -s -m "Fix approval expiry check"
```

To sign off commits you already made: `git commit --amend -s` for the last one, or `git rebase --signoff main` for all commits on your branch, then force-push. Pull requests with commits that are not signed off are not merged; the maintainers run a DCO check on pull requests to report them.

If your employer has rights to your work, make sure you are allowed to contribute it under Apache-2.0 before signing off.

## Pull request checklist

The pull request template repeats this list.

* [ ] The change is focused; unrelated refactors are in a separate pull request.
* [ ] Tests added or updated; `python tasks.py test unit` passes locally (and `integration` / `sandbox` if those areas changed).
* [ ] Evals pass on `mock` if the orchestrator, tools, guardrails, routing or prompts changed; red-team script passes if security-relevant code changed.
* [ ] No invariant from the list above is weakened.
* [ ] Migrations are new files, include RLS and grants, and have an isolation test.
* [ ] No new dependency, or it was agreed in an issue.
* [ ] `.env.example`, docs and `CHANGELOG.md` (Unreleased) updated.
* [ ] All commits are signed off (`git commit -s`).

## Review

Maintainers review pull requests when they can and merge at their discretion. Changes to authentication, tenant isolation, approvals, the sandbox, migrations or the release workflow get extra scrutiny.

## Release process (overview)

Maintainers release; contributors don't need to do anything special.

1. Make sure `main` is green, and move the `Unreleased` entries in `CHANGELOG.md` to a new version section with the date.
2. Bump `version` in `pyproject.toml` (the API reads its version from the package; also bump the chart's `version`/`appVersion` in `deploy/helm/harnis/Chart.yaml`), following [Semantic Versioning](https://semver.org/).
3. Merge, then tag the release commit: `git tag -a v1.2.3 -m "v1.2.3" && git push origin v1.2.3` (use `-s` instead of `-a` to sign the tag).
4. The tag runs `.github/workflows/release.yml`: unit tests, then the sdist and wheel are built and published to PyPI with trusted publishing; the `harnis` and `harnis-sandbox` images are built for amd64 and arm64 with SBOM and provenance attestations, pushed to GHCR and signed with cosign (keyless); the Helm chart is pushed to GHCR as an OCI artifact; and a GitHub Release is created with the notes from `CHANGELOG.md`.
5. Security fixes follow the same path.
