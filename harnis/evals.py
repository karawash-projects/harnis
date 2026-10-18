# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Evaluation suite runner: run a set of cases against a live harness API and
check what happened.

    python -m harnis.evals                          # all cases, mock provider
    python -m harnis.evals --providers mock,anthropic,gemini --repeat 3
    python -m harnis.evals --filter coding --out evals/reports

Each case (YAML, see evals/cases/) seeds a workspace, sends one or more
messages, answers approval requests by policy, and then checks the outcome:
status, agent, reply text, tools used, approvals requested, files written,
whether the generated code's tests pass in the sandbox, flags, steps, cost
and latency.

Providers are compared fairly by giving each one its own tenant whose
provider allow-list contains only that provider (`eval-<provider>`), so the
API's failover can't quietly answer with a different model. The runner needs
the same .env as the API (to mint tokens), and, unless --no-setup is given,
the migration database URL (to create those tenants) and Redis (to clear the
eval tenants' semantic cache so runs are independent).
"""
from __future__ import annotations

import argparse
import fnmatch
import html
import json
import re
import statistics
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Union

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field

from .auth import mint_token
from .config import Settings, get_settings

ApprovalDecision = Literal["approve", "deny"]


# ---------------------------------------------------------------------------
# Case format
# ---------------------------------------------------------------------------
class Range(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min: int | None = None
    max: int | None = None


class Expect(BaseModel):
    """Every field is optional; only the ones given are checked."""
    model_config = ConfigDict(extra="forbid")

    status: str | list[str] | None = None
    agent: str | None = None
    reply_contains: list[str] = Field(default_factory=list)       # all, case-insensitive
    reply_contains_any: list[str] = Field(default_factory=list)   # at least one
    reply_not_contains: list[str] = Field(default_factory=list)
    reply_matches: str | None = None                              # regex
    tools_called: list[str] = Field(default_factory=list)
    tools_not_called: list[str] = Field(default_factory=list)
    approvals: int | Range | None = None                          # number of approval requests
    approval_tools: list[str] = Field(default_factory=list)       # tools that must have asked
    no_approval_matching: str | None = None                       # regex over requested actions
    files_exist: list[str] = Field(default_factory=list)
    files_absent: list[str] = Field(default_factory=list)
    file_contains: dict[str, list[str]] = Field(default_factory=dict)
    file_not_contains: dict[str, list[str]] = Field(default_factory=dict)
    sandbox_tests_pass: bool | None = None
    flags_include: list[str] = Field(default_factory=list)        # prefix match
    flags_exclude: list[str] = Field(default_factory=list)
    cache_hit: bool | None = None
    max_steps: int | None = None
    max_cost_usd: float | None = None
    max_latency_s: float | None = None


Policy = Union[ApprovalDecision, dict[str, ApprovalDecision]]


class Turn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    new_session: bool = False
    approvals: Policy = "approve"
    max_approvals: int = 10
    expect: Expect = Field(default_factory=Expect)


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,48}$")
    category: str
    description: str = ""
    only_providers: list[str] = Field(default_factory=list)
    skip_providers: list[str] = Field(default_factory=list)
    seed_files: dict[str, str] = Field(default_factory=dict)
    turns: list[Turn] = Field(min_length=1)

    def runs_on(self, provider: str) -> bool:
        if self.only_providers and provider not in self.only_providers:
            return False
        return provider not in self.skip_providers


def load_cases(path: Path) -> list[Case]:
    files = sorted(path.glob("**/*.y*ml")) if path.is_dir() else [path]
    cases: list[Case] = []
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        for raw in data if isinstance(data, list) else [data]:
            try:
                cases.append(Case.model_validate(raw))
            except Exception as exc:
                raise SystemExit(f"{f}: invalid case {raw.get('id', '?') if isinstance(raw, dict) else ''}: {exc}")
    ids = [c.id for c in cases]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SystemExit(f"duplicate case ids: {sorted(dupes)}")
    return cases


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class RunResult:
    case_id: str
    category: str
    provider: str
    attempt: int
    outcome: Literal["pass", "fail", "error"]
    checks: list[Check] = field(default_factory=list)
    latency_s: float = 0.0
    cost_usd: float = 0.0
    providers_used: list[str] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    replies: list[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def evaluate(exp: Expect, view: dict[str, Any], approvals: list[dict[str, Any]], files: dict[str, str] | None,
             latency_s: float, cost_usd: float, sandbox_result: tuple[bool, str] | None) -> list[Check]:
    checks: list[Check] = []
    reply = view.get("reply") or ""
    low = reply.lower()
    tools = [m["text"] for m in view.get("messages", []) if m.get("role") == "tool_call"]
    flags = view.get("flags") or []
    turn = view.get("turn") or {}

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append(Check(name, bool(ok), detail))

    if exp.status is not None:
        want = [exp.status] if isinstance(exp.status, str) else exp.status
        add("status", view.get("status") in want, f"got {view.get('status')!r}, want {want}")
    if exp.agent is not None:
        add("agent", view.get("agent") == exp.agent, f"got {view.get('agent')!r}")
    for s in exp.reply_contains:
        add(f"reply contains {s!r}", s.lower() in low, _clip(reply))
    if exp.reply_contains_any:
        add(f"reply contains any of {exp.reply_contains_any}",
            any(s.lower() in low for s in exp.reply_contains_any), _clip(reply))
    for s in exp.reply_not_contains:
        add(f"reply does not contain {s!r}", s.lower() not in low, _clip(reply))
    if exp.reply_matches:
        add(f"reply matches /{exp.reply_matches}/", re.search(exp.reply_matches, reply, re.I | re.S) is not None,
            _clip(reply))
    for t in exp.tools_called:
        add(f"tool {t} called", t in tools, f"called: {tools}")
    for t in exp.tools_not_called:
        add(f"tool {t} not called", t not in tools, f"called: {tools}")
    if exp.approvals is not None:
        n = len(approvals)
        rng = Range(min=exp.approvals, max=exp.approvals) if isinstance(exp.approvals, int) else exp.approvals
        ok = (rng.min is None or n >= rng.min) and (rng.max is None or n <= rng.max)
        add("approval count", ok, f"got {n}, want {rng.min}..{rng.max}")
    asked = [a["tool"] for a in approvals]
    for t in exp.approval_tools:
        add(f"{t} required approval", t in asked, f"approvals: {asked}")
    if exp.no_approval_matching:
        bad = [a for a in approvals if re.search(exp.no_approval_matching, json.dumps(a.get("args", {})), re.I)]
        add(f"no approval request matching /{exp.no_approval_matching}/", not bad,
            f"matched: {[a['args'] for a in bad]}")
    if files is not None:
        for f in exp.files_exist:
            add(f"file {f} exists", f in files, f"files: {sorted(files)[:20]}")
        for f in exp.files_absent:
            add(f"file {f} absent", f not in files)
        for f, subs in exp.file_contains.items():
            for s in subs:
                add(f"{f} contains {s!r}", s in files.get(f, ""), "missing file" if f not in files else "")
        for f, subs in exp.file_not_contains.items():
            for s in subs:
                add(f"{f} does not contain {s!r}", s not in files.get(f, ""))
    if exp.sandbox_tests_pass is not None and sandbox_result is not None:
        passed, out = sandbox_result
        add("tests pass in sandbox", passed == exp.sandbox_tests_pass, _clip(out, 400))
    for f in exp.flags_include:
        add(f"flag {f}", any(x.startswith(f) for x in flags), f"flags: {flags}")
    for f in exp.flags_exclude:
        add(f"no flag {f}", not any(x.startswith(f) for x in flags), f"flags: {flags}")
    if exp.cache_hit is not None:
        add("cache hit" if exp.cache_hit else "no cache hit", bool(turn.get("cache_hit")) == exp.cache_hit,
            f"cache_hit={turn.get('cache_hit')}")
    if exp.max_steps is not None:
        add(f"steps <= {exp.max_steps}", (turn.get("steps") or 0) <= exp.max_steps, f"steps={turn.get('steps')}")
    if exp.max_cost_usd is not None:
        add(f"cost <= ${exp.max_cost_usd}", cost_usd <= exp.max_cost_usd, f"cost=${cost_usd:.4f}")
    if exp.max_latency_s is not None:
        add(f"latency <= {exp.max_latency_s}s", latency_s <= exp.max_latency_s, f"latency={latency_s:.1f}s")
    return checks


def _clip(text: str, n: int = 200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
class Runner:
    def __init__(self, client: httpx.Client, settings: Settings, *, setup: bool = True,
                 sandbox: Any = "auto", turn_timeout_s: float = 600, log=print):
        self.c = client
        self.s = settings
        self.setup = setup
        self.turn_timeout = turn_timeout_s
        self.log = log
        self._sandbox = sandbox

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def tenant_for(provider: str) -> str:
        return f"eval-{provider}"

    def _headers(self, user: str, tenant: str, roles: list[str]) -> dict[str, str]:
        return {"Authorization": f"Bearer {mint_token(user, tenant, roles, ttl_seconds=3 * 3600)}"}

    def _req(self, method: str, path: str, headers: dict[str, str], **kw) -> httpx.Response:
        for _ in range(30):
            r = self.c.request(method, path, headers=headers, **kw)
            if r.status_code == 429:
                time.sleep(min(30, int(r.headers.get("Retry-After", "2"))))
                continue
            if r.status_code == 409 and "already running" in r.text:
                time.sleep(1)
                continue
            return r
        return r

    def sandbox(self):
        if self._sandbox == "auto":
            try:
                import docker

                docker.from_env().images.get(self.s.sandbox_image)
                from .sandbox import DockerSandbox

                self._sandbox = DockerSandbox(self.s.sandbox_image, timeout=60,
                                              workspace_mode=self.s.sandbox_workspace_mode)
            except Exception as exc:
                self.log(f"note: sandbox test checks unavailable ({type(exc).__name__}: {exc})")
                self._sandbox = None
        return self._sandbox

    def prepare(self, providers: list[str]) -> list[str]:
        """Create one tenant per provider, clear their caches, and keep only the
        providers the API can actually reach."""
        if self.setup:
            from .migrate import create_tenant

            for p in providers:
                create_tenant(self.tenant_for(p), f"Evals ({p})", [p], dsn=self.s.migration_database_url)
            for p in providers:
                self.clear_cache(p)
        ready = []
        for p in providers:
            h = self._headers("eval-preflight", self.tenant_for(p), ["user"])
            r = self._req("POST", "/v1/sessions", h, json={})
            if r.status_code != 201:
                self.log(f"skip provider {p}: cannot create a session ({r.status_code} {r.text[:120]})")
                continue
            sid = r.json()["session_id"]
            v = self._req("POST", f"/v1/sessions/{sid}/turns", h, json={"message": "Reply with the word ready."})
            view = v.json() if v.status_code == 200 else {}
            if view.get("status") == "failed" and "llm_unavailable" in (view.get("flags") or []):
                self.log(f"skip provider {p}: the API has no working '{p}' provider "
                         f"(add its credentials to the API's .env and include it in LLM_PROVIDERS)")
                continue
            if v.status_code != 200:
                self.log(f"skip provider {p}: preflight turn failed ({v.status_code} {v.text[:120]})")
                continue
            ready.append(p)
        return ready

    def clear_cache(self, provider: str) -> None:
        """Drop the eval tenant's semantic-cache entries so every case (and every
        repeat of it) starts cold; otherwise one run's answers leak into the next."""
        if not self.setup:
            return
        try:
            import redis

            r = self._redis = getattr(self, "_redis", None) or redis.Redis.from_url(self.s.redis_url)
            t = self.tenant_for(provider)
            keys = list(r.scan_iter(f"hcache:{t}:*")) + list(r.scan_iter(f"hcache_idx:{t}:*"))
            if keys:
                r.delete(*keys)
        except Exception as exc:
            if not getattr(self, "_warned_cache", False):
                self.log(f"note: could not clear the eval cache ({exc}); cache hits may carry over between runs")
                self._warned_cache = True

    def _usage(self, headers) -> tuple[float, set[str]]:
        r = self._req("GET", "/v1/usage", headers)
        rows = r.json() if r.status_code == 200 else []
        return sum(x["cost_usd"] for x in rows), {x["provider"] for x in rows}

    def _decide(self, policy: Policy, tool: str) -> ApprovalDecision:
        if isinstance(policy, str):
            return policy
        return policy.get(tool, policy.get("*", "approve"))

    def _wait_resume(self, headers, sid: str, approval_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.turn_timeout
        while time.monotonic() < deadline:
            v = self._req("GET", f"/v1/sessions/{sid}", headers).json()
            aw = v.get("awaiting") or {}
            if v["status"] != "running" and aw.get("approval_id") != approval_id:
                return v
            time.sleep(0.25)
        raise TimeoutError(f"session {sid} did not resume within {self.turn_timeout}s")

    # -- one case ----------------------------------------------------------------
    def run_case(self, case: Case, provider: str, attempt: int) -> RunResult:
        tenant = self.tenant_for(provider)
        user = f"ev-{case.id}"[:64]
        uh = self._headers(user, tenant, ["user"])
        rh = self._headers("ev-reviewer", tenant, ["reviewer"])
        res = RunResult(case.id, case.category, provider, attempt, "pass")
        self.clear_cache(provider)
        cost0, _ = self._usage(rh)
        start = time.monotonic()
        try:
            sid = None
            for i, turn in enumerate(case.turns):
                if sid is None or turn.new_session:
                    r = self._req("POST", "/v1/sessions", uh, json={"files": case.seed_files})
                    if r.status_code != 201:
                        raise RuntimeError(f"create session: {r.status_code} {r.text[:200]}")
                    sid = r.json()["session_id"]
                t0 = time.monotonic()
                r = self._req("POST", f"/v1/sessions/{sid}/turns", uh, json={"message": turn.message})
                if r.status_code != 200:
                    raise RuntimeError(f"turn {i + 1}: {r.status_code} {r.text[:200]}")
                view = r.json()
                turn_approvals: list[dict[str, Any]] = []
                while view["status"] == "awaiting_approval":
                    if len(turn_approvals) >= turn.max_approvals:
                        raise RuntimeError(f"more than {turn.max_approvals} approval requests in one turn")
                    aw = view["awaiting"]
                    pending = {a["approval_id"]: a for a in self._req("GET", "/v1/approvals", rh).json()}
                    appr = pending.get(aw["approval_id"])
                    if appr is None:
                        raise RuntimeError("awaited approval not visible to the reviewer")
                    action = appr["action"]
                    decision = self._decide(turn.approvals, action["tool"])
                    turn_approvals.append({"tool": action["tool"], "args": action.get("args", {}),
                                           "decision": decision})
                    d = self._req("POST", f"/v1/approvals/{aw['approval_id']}/decision", rh,
                                  json={"approved": decision == "approve", "action_hash": aw["action_hash"]})
                    if d.status_code != 202:
                        raise RuntimeError(f"decision: {d.status_code} {d.text[:200]}")
                    view = self._wait_resume(uh, sid, aw["approval_id"])
                latency = time.monotonic() - t0
                res.approvals += turn_approvals
                res.replies.append(view.get("reply") or "")
                e = turn.expect
                needs_files = bool(e.files_exist or e.files_absent or e.file_contains or e.file_not_contains
                                   or e.sandbox_tests_pass is not None)
                files = self._req("GET", f"/v1/sessions/{sid}/files", uh).json() if needs_files else None
                sandbox_result = None
                if e.sandbox_tests_pass is not None:
                    sandbox_result = self._run_tests(files or {})
                    if sandbox_result is None:
                        res.checks.append(Check("tests pass in sandbox", False, "sandbox unavailable"))
                cost_now, _ = self._usage(rh)
                for ch in evaluate(e, view, turn_approvals, files, latency, cost_now - cost0, sandbox_result):
                    ch.name = f"turn {i + 1}: {ch.name}" if len(case.turns) > 1 else ch.name
                    res.checks.append(ch)
        except Exception as exc:
            res.outcome, res.error = "error", f"{type(exc).__name__}: {exc}"
        res.latency_s = round(time.monotonic() - start, 2)
        cost1, used = self._usage(rh)
        res.cost_usd = round(cost1 - cost0, 6)
        res.providers_used = sorted(used)
        if res.outcome != "error" and not all(c.ok for c in res.checks):
            res.outcome = "fail"
        return res

    def _run_tests(self, files: dict[str, str]) -> tuple[bool, str] | None:
        sb = self.sandbox()
        if sb is None:
            return None
        from .tools import safe_path, write_text

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel, text in files.items():
                p = safe_path(root, rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                write_text(p, text)
            r = sb.run("python -m pytest -q -p no:cacheprovider 2>&1", root)
            return (r.exit_code == 0, r.error or r.output)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def summarize(results: list[RunResult]) -> dict[str, Any]:
    by_provider: dict[str, dict[str, Any]] = {}
    for p in sorted({r.provider for r in results}):
        rs = [r for r in results if r.provider == p]
        lat = [r.latency_s for r in rs if r.outcome != "error"]
        by_provider[p] = {
            "runs": len(rs),
            "passed": sum(r.outcome == "pass" for r in rs),
            "failed": sum(r.outcome == "fail" for r in rs),
            "errors": sum(r.outcome == "error" for r in rs),
            "pass_rate": round(sum(r.outcome == "pass" for r in rs) / len(rs), 3) if rs else 0.0,
            "median_latency_s": round(statistics.median(lat), 2) if lat else None,
            "total_cost_usd": round(sum(r.cost_usd for r in rs), 4),
        }
    by_category: dict[str, dict[str, Any]] = {}
    for cat in sorted({r.category for r in results}):
        rs = [r for r in results if r.category == cat]
        by_category[cat] = {"runs": len(rs), "passed": sum(r.outcome == "pass" for r in rs)}
    total = len(results)
    passed = sum(r.outcome == "pass" for r in results)
    return {"runs": total, "passed": passed, "pass_rate": round(passed / total, 3) if total else 0.0,
            "by_provider": by_provider, "by_category": by_category}


def write_reports(results: list[RunResult], summary: dict[str, Any], out_dir: Path, meta: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    payload = {"meta": meta, "summary": summary, "results": [asdict(r) for r in results]}
    (out_dir / f"eval-{stamp}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    html_path = out_dir / f"eval-{stamp}.html"
    html_path.write_text(render_html(results, summary, meta), encoding="utf-8")
    (out_dir / "latest.html").write_text(html_path.read_text(encoding="utf-8"), encoding="utf-8")
    return html_path


def render_html(results: list[RunResult], summary: dict[str, Any], meta: dict[str, Any]) -> str:
    esc = html.escape
    providers = sorted({r.provider for r in results})
    cases = sorted({(r.category, r.case_id) for r in results})

    def cell(case_id: str, p: str) -> str:
        rs = [r for r in results if r.case_id == case_id and r.provider == p]
        if not rs:
            return '<td class="na">n/a</td>'
        ok = sum(r.outcome == "pass" for r in rs)
        cls = "pass" if ok == len(rs) else ("error" if all(r.outcome == "error" for r in rs) else "fail")
        label = "PASS" if cls == "pass" else ("ERROR" if cls == "error" else "FAIL")
        frac = f" {ok}/{len(rs)}" if len(rs) > 1 else ""
        lat = statistics.median([r.latency_s for r in rs])
        return f'<td class="{cls}"><a href="#{esc(case_id)}-{esc(p)}">{label}{frac}</a><small>{lat:.1f}s</small></td>'

    prov_rows = "".join(
        f"<tr><th>{esc(p)}</th><td>{s['passed']}/{s['runs']}</td><td>{s['pass_rate'] * 100:.0f}%</td>"
        f"<td>{s['errors']}</td><td>{s['median_latency_s'] if s['median_latency_s'] is not None else '-'}s</td>"
        f"<td>${s['total_cost_usd']:.4f}</td></tr>" for p, s in summary["by_provider"].items())
    matrix = "".join(
        f"<tr><td><span class=cat>{esc(cat)}</span> {esc(cid)}</td>{''.join(cell(cid, p) for p in providers)}</tr>"
        for cat, cid in cases)
    details = []
    for r in results:
        if r.outcome == "pass":
            continue
        items = "".join(f"<li>{esc(c.name)}<br><small>{esc(c.detail)}</small></li>" for c in r.checks if not c.ok)
        if r.error:
            items = f"<li>{esc(r.error)}</li>" + items
        details.append(
            f'<section id="{esc(r.case_id)}-{esc(r.provider)}"><h3>{esc(r.case_id)} <small>{esc(r.provider)} '
            f"attempt {r.attempt} - {r.outcome}</small></h3><ul>{items}</ul>"
            + "".join(f"<p class=reply><b>{'Turn ' + str(i) + ' reply' if len(r.replies) > 1 else 'Reply'}:</b> "
                      f"{esc(_clip(t, 400))}</p>" for i, t in enumerate(r.replies, 1))
            + "</section>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Harnis Eval Report</title>
<style>
:root{{--bg:#f7f6f3;--panel:#fff;--ink:#1c1c1a;--muted:#6b6a65;--line:#e4e2dc;--pass:#2f6b4f;--fail:#a4462f;--err:#8a6d1d}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151614;--panel:#1d1e1b;--ink:#ecebe6;--muted:#9d9c95;--line:#30312d;--pass:#7fc4a2;--fail:#e48a70;--err:#d9b65a}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,sans-serif;padding:24px 16px}}
main{{max-width:1100px;margin:0 auto}} h1{{font-size:20px;margin:0 0 4px}} .meta{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;background:var(--panel);margin:16px 0;font-variant-numeric:tabular-nums}}
th,td{{border-bottom:1px solid var(--line);padding:7px 10px;text-align:left}} .wrap{{overflow-x:auto}}
td.pass a{{color:var(--pass)}} td.fail a{{color:var(--fail)}} td.error a{{color:var(--err)}} td.na{{color:var(--muted)}}
td a{{font-weight:600;text-decoration:none}} td small{{color:var(--muted);margin-left:6px}}
.cat{{color:var(--muted);font-size:12px;margin-right:4px}} section{{background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:10px 14px;margin:10px 0}} section h3{{margin:0 0 6px;font-size:15px}} li small{{color:var(--muted)}}
.reply{{color:var(--muted);font-size:13px}} .big{{font-size:28px;font-weight:600}}
</style></head><body><main>
<h1>Harnis eval report</h1>
<div class=meta>{esc(meta.get("started", ""))} &middot; API {esc(meta.get("api", ""))} &middot; {len(cases)} cases &middot; repeat {meta.get("repeat", 1)}</div>
<p><span class=big>{summary["pass_rate"] * 100:.0f}%</span> passed ({summary["passed"]}/{summary["runs"]} runs)</p>
<div class=wrap><table><tr><th>Provider</th><th>Passed</th><th>Pass rate</th><th>Errors</th><th>Median latency</th><th>Cost</th></tr>{prov_rows}</table></div>
<div class=wrap><table><tr><th>Case</th>{"".join(f"<th>{esc(p)}</th>" for p in providers)}</tr>{matrix}</table></div>
<h2>Failures</h2>{"".join(details) or "<p>None.</p>"}
</main></body></html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--cases", type=Path, default=Path("evals/cases"))
    ap.add_argument("--providers", default="mock", help="comma-separated: mock,anthropic,openai,gemini,nova")
    ap.add_argument("--repeat", type=int, default=1, help="runs per case (real models vary between runs)")
    ap.add_argument("--filter", default="", help="glob over case id or category, e.g. 'coding*'")
    ap.add_argument("--out", type=Path, default=Path("evals/reports"))
    ap.add_argument("--min-pass-rate", type=float, default=1.0, help="exit non-zero below this (0..1)")
    ap.add_argument("--no-setup", action="store_true", help="don't create eval tenants or clear the cache")
    ap.add_argument("--turn-timeout", type=float, default=600)
    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    cases = load_cases(a.cases)
    if a.filter:
        cases = [c for c in cases if fnmatch.fnmatch(c.id, a.filter) or fnmatch.fnmatch(c.category, a.filter)]
    if not cases:
        print("no cases selected")
        return 2
    providers = [p.strip() for p in a.providers.split(",") if p.strip()]
    with httpx.Client(base_url=a.api, timeout=a.turn_timeout) as client:
        try:
            client.get("/health", timeout=5).raise_for_status()
        except Exception as exc:
            print(f"API not reachable at {a.api}: {exc}\nStart it with: python tasks.py dev")
            return 2
        runner = Runner(client, get_settings(), setup=not a.no_setup, turn_timeout_s=a.turn_timeout)
        ready = runner.prepare(providers)
        if not ready:
            print("no provider is usable; nothing to run")
            return 2
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        results: list[RunResult] = []
        for p in ready:
            selected = [c for c in cases if c.runs_on(p)]
            print(f"\n== {p}: {len(selected)} cases x {a.repeat}")
            for c in selected:
                for attempt in range(1, a.repeat + 1):
                    r = runner.run_case(c, p, attempt)
                    results.append(r)
                    mark = {"pass": "PASS ", "fail": "FAIL ", "error": "ERROR"}[r.outcome]
                    print(f"  {mark} {c.category:<12} {c.id:<34} {r.latency_s:6.1f}s  ${r.cost_usd:.4f}")
                    for ch in r.checks:
                        if not ch.ok:
                            print(f"         - {ch.name}: {ch.detail}")
                    if r.error:
                        print(f"         - {r.error}")
    summary = summarize(results)
    meta = {"started": started, "api": a.api, "repeat": a.repeat, "providers": ready,
            "run_id": uuid.uuid4().hex[:8], "cases": len(cases)}
    report = write_reports(results, summary, a.out, meta)
    print(f"\n{summary['passed']}/{summary['runs']} runs passed ({summary['pass_rate'] * 100:.0f}%)")
    for p, s in summary["by_provider"].items():
        print(f"  {p:<10} {s['passed']}/{s['runs']}  median {s['median_latency_s']}s  ${s['total_cost_usd']:.4f}")
    print(f"report: {report}")
    return 0 if summary["pass_rate"] >= a.min_pass_rate else 1


if __name__ == "__main__":
    sys.exit(main())
