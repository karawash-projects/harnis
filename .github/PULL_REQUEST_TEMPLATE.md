## What and why

<!-- What does this change do, and why? Link the issue: "Fixes #123". -->

## How it was tested

<!-- Commands you ran and their results. For behaviour changes, eval pass rates on mock (and real providers if you have credentials). -->

## Checklist

- [ ] The change is focused; unrelated refactors are in a separate pull request.
- [ ] Tests added or updated; `python tasks.py test unit` passes (and `integration` / `sandbox` if those areas changed).
- [ ] `python tasks.py eval` passes on `mock` if the orchestrator, tools, guardrails, routing or prompts changed.
- [ ] `python tasks.py redteam` passes if authentication, tenancy, approvals, the sandbox or guardrails changed.
- [ ] No invariant in CONTRIBUTING.md ("Invariants you must not weaken") is weakened: tenant from credentials only, RLS on every tenant table, approval bound to the action hash, sandbox lockdown, untrusted tool output, provider allow-list.
- [ ] Database changes are in a **new** migration file, are safe while older replicas run, include RLS and grants for new tables, and have an isolation test in `tests/test_rls.py`. (Or: no migration.)
- [ ] No new dependency, or it was agreed in an issue and passes `pip-audit`.
- [ ] Settings documented in `.env.example`; README, `docs/` and `CHANGELOG.md` (Unreleased) updated.
- [ ] Breaking change? If yes, described below and labelled.
- [ ] All commits are signed off (`git commit -s`) under the Developer Certificate of Origin.

## Breaking changes / upgrade notes

<!-- "None", or what operators and plugin authors need to do. -->
