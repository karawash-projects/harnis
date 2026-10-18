# Evals

A set of cases that check the harness end to end: each case drives the running API the way a user and a reviewer would, then checks what happened.

```bash
python tasks.py dev                                   # terminal 1: the API
python tasks.py eval                                  # terminal 2: all cases on the mock model
python tasks.py eval -- --providers mock,anthropic,gemini,nova --repeat 3
python tasks.py eval -- --filter "guard*"             # by case id or category
```

The runner prints PASS/FAIL per case and writes `evals/reports/eval-<time>.html` (also `latest.html`) and a JSON file with every check. It exits non-zero when the pass rate is below `--min-pass-rate` (default 1.0), so it can gate CI.

## How it works

* **One tenant per provider.** The runner creates `eval-mock`, `eval-gemini`, ... and limits each one's provider allow-list to that single provider, so failover can't quietly answer with a different model. A provider the API has no credentials for is skipped with a message.
* **Real users and reviewers.** Each case runs as its own user; approvals are decided by a separate reviewer account, so separation of duties is exercised too.
* **Fresh cache.** The eval tenants' semantic-cache entries are cleared at the start, so runs don't depend on earlier ones.
* **Sandbox test check.** `sandbox_tests_pass` copies the session's files into a fresh sandbox container and runs pytest, independently of what the agent claims.

The runner reads the same `.env` as the API (to sign tokens and to reach Postgres and Redis for setup). Against a remote API, pre-create the tenants and pass `--no-setup`.

## Mock versus real models

The mock model follows a fixed script, so on `mock` the suite tests the **harnis**: routing, approvals, guardrails, sandbox, loop breaker, cache. Cases marked `only_providers: [mock]` rely on that script. On real providers the same cases also test the **agent**: whether it uses the right tools, writes code that passes its tests, and ignores instructions hidden in files. Cases marked `skip_providers: [mock]` need a real model. Real models vary between runs; use `--repeat 3` or more and look at pass rates rather than single results.

## Writing a case

Cases live in `evals/cases/*.yaml`; each file holds a list.

```yaml
- id: coding-fix-bug                 # lowercase, unique
  category: coding
  description: Fixes a seeded bug so the existing tests pass.
  skip_providers: [mock]             # or only_providers: [...]
  seed_files:                        # the session workspace starts with these
    mathutils.py: |
      def average(xs):
          return sum(xs) / len(xs) + 1
  turns:
    - message: Fix mathutils.py and run the tests.
      approvals: approve             # approve | deny | {write_file: approve, run_command: deny, "*": deny}
      new_session: false             # true starts a new session for this turn
      expect:
        status: completed
        sandbox_tests_pass: true
```

Checks available under `expect` (all optional):

| Check | Meaning |
|---|---|
| `status` | `completed`, `awaiting_approval`, `rejected`, `escalated`, `failed`, or a list of allowed values |
| `agent` | agent handling the session at the end of the turn (`support` or `coder`) |
| `reply_contains`, `reply_contains_any`, `reply_not_contains`, `reply_matches` | text checks on the reply (case-insensitive; `reply_matches` is a regex) |
| `tools_called`, `tools_not_called` | tool names used in the session |
| `approvals` | number of approval requests in the turn: `2`, or `{min: 1, max: 3}` |
| `approval_tools` | tools that must have asked for approval |
| `no_approval_matching` | regex that no requested action may match, e.g. `"rm\\s+-rf"` |
| `files_exist`, `files_absent`, `file_contains`, `file_not_contains` | the session workspace after the turn |
| `sandbox_tests_pass` | pytest passes (or, with `false`, fails) on the workspace in a fresh sandbox |
| `flags_include`, `flags_exclude` | harness flags (prefix match), e.g. `input_blocked`, `input_redacted`, `tool_output_injection_suspected`, `loop_detected`, `cache_error`, `auto_continue` |
| `cache_hit` | the answer came from the semantic cache |
| `max_steps`, `max_cost_usd`, `max_latency_s` | budgets for the turn |
