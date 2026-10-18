# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The eval runner: case loading, check logic, and a real run through the API."""
from pathlib import Path

import pytest

from harnis.evals import Case, Expect, Range, evaluate, load_cases, render_html, summarize

CASES_DIR = Path(__file__).resolve().parent.parent / "evals" / "cases"


def view(**kw):
    base = {"status": "completed", "agent": "support", "reply": "We open at 9.", "flags": [],
            "messages": [], "turn": {"steps": 4, "cache_hit": False}}
    base.update(kw)
    return base


def failed(checks):
    return [c.name for c in checks if not c.ok]


def test_all_shipped_cases_are_valid():
    cases = load_cases(CASES_DIR)
    assert len(cases) >= 15
    assert {c.category for c in cases} >= {"support", "coding", "approvals", "guardrails", "multi-agent"}


def test_invalid_case_is_reported(tmp_path):
    (tmp_path / "bad.yaml").write_text("- id: x\n  category: c\n  turns:\n    - message: hi\n      expect: {nope: 1}\n")
    with pytest.raises(SystemExit) as e:
        load_cases(tmp_path)
    assert "bad.yaml" in str(e.value)


def test_checks_pass_and_fail():
    v = view(messages=[{"role": "tool_call", "text": "read_file"}], flags=["input_redacted:EMAIL"])
    ok = Expect(status="completed", agent="support", reply_contains=["open"], tools_called=["read_file"],
                tools_not_called=["run_command"], flags_include=["input_redacted"], max_steps=10, approvals=0)
    assert failed(evaluate(ok, v, [], None, 1.0, 0.0, None)) == []
    bad = Expect(status="rejected", reply_contains=["closed"], tools_called=["write_file"], cache_hit=True,
                 approvals=Range(min=1), max_latency_s=0.5)
    assert len(failed(evaluate(bad, v, [], None, 1.0, 0.0, None))) == 6


def test_file_and_approval_checks():
    files = {"a.py": "def f(): pass\n"}
    approvals = [{"tool": "run_command", "args": {"command": "rm -rf /"}, "decision": "deny"}]
    e = Expect(files_exist=["a.py"], files_absent=["b.py"], file_contains={"a.py": ["def f"]},
               approval_tools=["run_command"], no_approval_matching=r"rm\s+-rf")
    assert failed(evaluate(e, view(), approvals, files, 1, 0, None)) == ["no approval request matching /rm\\s+-rf/"]


def test_sandbox_result_check():
    e = Expect(sandbox_tests_pass=True)
    assert failed(evaluate(e, view(), [], {}, 1, 0, (True, "1 passed"))) == []
    assert failed(evaluate(e, view(), [], {}, 1, 0, (False, "1 failed"))) == ["tests pass in sandbox"]


def test_provider_filters():
    c = Case(id="x", category="c", only_providers=["mock"], turns=[{"message": "hi"}])
    assert c.runs_on("mock") and not c.runs_on("gemini")
    c = Case(id="y", category="c", skip_providers=["mock"], turns=[{"message": "hi"}])
    assert not c.runs_on("mock") and c.runs_on("nova")


def test_summary_and_report_render():
    from harnis.evals import Check, RunResult

    rs = [RunResult("a", "support", "mock", 1, "pass", latency_s=1.0),
          RunResult("b", "coding", "mock", 1, "fail", [Check("status", False, "got 'failed'")], latency_s=2.0),
          RunResult("a", "support", "gemini", 1, "error", error="boom")]
    s = summarize(rs)
    assert s["by_provider"]["mock"]["passed"] == 1 and s["by_provider"]["gemini"]["errors"] == 1
    page = render_html(rs, s, {"started": "now", "api": "x", "repeat": 1})
    assert "got &#x27;failed&#x27;" in page and "boom" in page and "<title>Harnis Eval Report</title>" in page


# ---------------------------------------------------------------------------
# Real run: API + Postgres + Redis + mock model, through HTTP
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_runner_end_to_end(pg, app_pool, redis_client, tmp_path):
    from fastapi.testclient import TestClient

    from harnis.api import create_app
    from harnis.config import Settings
    from harnis.evals import Runner
    from harnis.llm.providers import MockProvider
    from harnis.llm.router import LLMRouter
    from harnis.store import PgStore

    from .conftest import FakeSandbox

    settings = Settings(workspaces_dir=str(tmp_path / "ws"), redis_url="redis://127.0.0.1:6379/15",
                        migration_database_url=pg["owner"], rate_limit_capacity=100)
    app = create_app(settings, store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=FakeSandbox())
    wanted = {"support-basic-question", "support-cache-repeat", "coding-read-file", "approval-deny-write",
              "guard-direct-injection", "guard-indirect-injection", "handoff-support-to-coder", "loop-breaker"}
    cases = [c for c in load_cases(CASES_DIR) if c.id in wanted]
    assert len(cases) == len(wanted)
    with TestClient(app) as client:
        runner = Runner(client, settings, sandbox=None, log=lambda *a: None)
        assert runner.prepare(["mock", "gemini"]) == ["mock"]  # no gemini in this API's chain
        results = [runner.run_case(c, "mock", 1) for c in cases]
    bad = {r.case_id: [c.name for c in r.checks if not c.ok] or r.error for r in results if r.outcome != "pass"}
    assert bad == {}
    # Repeats must not see each other's cache entries.
    cache_case = next(c for c in cases if c.id == "support-cache-repeat")
    with TestClient(app) as client:
        runner = Runner(client, settings, sandbox=None, log=lambda *a: None)
        runner.prepare(["mock"])
        repeats = [runner.run_case(cache_case, "mock", i) for i in (1, 2, 3)]
    assert [r.outcome for r in repeats] == ["pass"] * 3, [c.detail for r in repeats for c in r.checks if not c.ok]
    deny = next(r for r in results if r.case_id == "approval-deny-write")
    assert {a["decision"] for a in deny.approvals} == {"deny"}
