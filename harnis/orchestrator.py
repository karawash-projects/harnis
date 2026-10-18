# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The orchestrator: an explicit, resumable state machine.

    ingest ──► route ──► [cache_lookup] ──► agent ◄──► tools ──► respond ──► END
       │                      │                          │
       └─► END (rejected)     └─► END (cache hit)        ├─► SUSPEND (awaiting approval)
                                                         └─► END (escalated / budget / loop)

Properties that the original design claimed but didn't have:
  * Every node is registered; an unknown node is a programming error caught
    at construction time, not a KeyError at 2 a.m.
  * State is checkpointed after EVERY node, with optimistic versioning, so a
    crashed worker resumes from the last node and two writers can't silently
    overwrite each other.
  * Approval suspends the session in the database (no in-memory Event), so
    the decision can arrive at any replica, minutes or hours later.
  * A decision is bound to the hash of the exact action; if the action would
    differ at execution time (e.g. the file changed), it is not executed.
  * Budgets (steps, cost, handoffs, tool calls) and the loop breaker live in
    the checkpointed state, so they survive restarts and work across replicas.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from opentelemetry import trace

from .guardrails import InputGuard, OutputGuard, wrap_untrusted
from . import metrics
from .llm.router import AllProvidersFailed, LLMRouter
from .llm.types import LLMRequest, Message, ProviderError
from .llm.pricing import cost_usd
from .plugins import Registry, default_registry
from .tools import ROUTE_TOOL, ToolContext, action_hash, describe_action

log = logging.getLogger(__name__)
tracer = trace.get_tracer("harnis.orchestrator")

END = "END"
SUSPEND = "SUSPEND"

CONTINUE_NUDGE = ("Continue: carry out the step you just described now, using the tools. Reply without a "
                  "tool call only when the whole task is complete, with a short summary of what you did.")
# The tail of a reply that announces work instead of finishing it.
_UNFINISHED = re.compile(
    r"(?:\b(?:let me|let's|i'll|i will|i am going to|i'm going to|i need to|now i|next,? i|"
    r"first,? (?:i|let))\b[^\n]{0,160}|:)\s*$", re.IGNORECASE)


def looks_unfinished(text: str) -> bool:
    """True when the last sentence promises a next action (or ends with a colon)."""
    tail = (text or "").strip()[-220:]
    if not tail:
        return False
    last = re.split(r"(?<=[.!?])\s+", tail)[-1]
    return bool(_UNFINISHED.search(last))


# ---------------------------------------------------------------------------
# Persistence + side-effect interfaces (Postgres in prod, memory in tests)
# ---------------------------------------------------------------------------
class ConflictError(Exception):
    """The session was modified by someone else since we loaded it."""


@dataclass
class SessionRecord:
    session_id: str
    tenant_id: str
    user_id: str
    status: str
    current_node: str
    state: dict[str, Any]
    version: int


class Store(Protocol):
    def load_session(self, tenant_id: str, session_id: str) -> SessionRecord | None: ...
    def save_checkpoint(self, rec: SessionRecord) -> int: ...
    def create_approval(self, tenant_id: str, session_id: str, requested_by: str,
                        action: dict[str, Any], action_hash: str) -> str: ...
    def record_usage(self, tenant_id: str, session_id: str, provider: str, model: str,
                     input_tokens: int, output_tokens: int, cost: float) -> None: ...
    def record_metric(self, tenant_id: str, session_id: str, latency_ms: int, cache_hit: bool,
                      outcome: str, steps: int) -> None: ...
    def audit(self, tenant_id: str, session_id: str | None, actor: str, event_type: str,
              detail: dict[str, Any]) -> None: ...
    def get_prompt(self, tenant_id: str, key: str) -> tuple[str, int] | None: ...
    def tenant_policy(self, tenant_id: str) -> dict[str, Any]: ...


Publisher = Callable[[str, str, dict[str, Any]], None]  # (tenant_id, channel_suffix, event)
Alerter = Callable[[str, str, str | None, dict[str, Any]], None]  # (type, tenant, session, detail)


@dataclass
class Limits:
    max_steps: int = 25
    max_cost_usd: float = 2.0
    max_handoffs: int = 6
    max_tool_calls: int = 20
    loop_window: int = 6
    loop_threshold: int = 2
    auto_continue_max: int = 2
    reroute_from_support: bool = True


@dataclass
class Deps:
    store: Store
    router: LLMRouter
    sandbox: Any
    workspaces_dir: Path
    input_guard: InputGuard = field(default_factory=InputGuard)
    output_guard: OutputGuard = field(default_factory=OutputGuard)
    cache: Any = None
    publish: Publisher = lambda tenant, channel, event: None
    alert: Alerter = lambda kind, tenant, session, detail: None
    limits: Limits = field(default_factory=Limits)
    registry: Registry = field(default_factory=default_registry)


def new_state() -> dict[str, Any]:
    return {
        "messages": [],
        "agent": None,
        "pending_tool_calls": [],
        "tool_results": [],
        "awaiting": None,
        "approval_decision": None,
        "loop_fingerprints": [],
        "turn": {},
        "reply": None,
        "flags": [],
    }


def workspace_for(base: Path, tenant_id: str, session_id: str) -> Path:
    p = base / tenant_id / session_id
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class Orchestrator:
    def __init__(self, deps: Deps):
        self.d = deps
        self.nodes: dict[str, Callable[[SessionRecord], str]] = {
            "ingest": self.ingest,
            "route": self.route,
            "cache_lookup": self.cache_lookup,
            "agent": self.agent,
            "tools": self.tools,
            "respond": self.respond,
        }

    # -- public API ----------------------------------------------------------
    def start_turn(self, rec: SessionRecord, user_text: str) -> SessionRecord:
        if rec.status in ("awaiting_approval", "running"):
            raise ConflictError(f"session is {rec.status}")
        st = rec.state
        st["turn"] = {"input": user_text, "steps": 0, "cost_usd": 0.0, "handoffs": 0, "tool_calls": 0,
                      "used_tools": False, "loop_trips": 0, "cache_hit": False,
                      "started_at": time.time()}
        st["reply"] = None
        st["loop_fingerprints"] = []
        rec.status = "running"
        rec.current_node = "ingest"
        return self._run(rec)

    def resume_after_decision(self, rec: SessionRecord, approval_id: str, approved: bool,
                              decided_by: str) -> SessionRecord:
        aw = rec.state.get("awaiting")
        if rec.status != "awaiting_approval" or not aw or aw["approval_id"] != approval_id:
            raise ConflictError("session is not waiting for this approval")
        rec.state["approval_decision"] = {"approval_id": approval_id, "approved": approved,
                                          "decided_by": decided_by}
        rec.status = "running"
        rec.current_node = "tools"
        return self._run(rec)

    # -- loop ------------------------------------------------------------------
    def _run(self, rec: SessionRecord) -> SessionRecord:
        st = rec.state
        turn = st["turn"]
        run_started = time.perf_counter()
        with tracer.start_as_current_span("harnis.turn") as span:
            span.set_attribute("harnis.tenant_id", rec.tenant_id)
            span.set_attribute("harnis.session_id", rec.session_id)
            node = rec.current_node
            while node not in (END, SUSPEND):
                if turn["steps"] >= self.d.limits.max_steps:
                    node = self._halt(rec, "failed", "step_budget_exceeded",
                                      f"Stopped: step budget of {self.d.limits.max_steps} reached.")
                    break
                turn["steps"] += 1
                with tracer.start_as_current_span(f"harnis.node.{node}"):
                    nxt = self.nodes[node](rec)
                self.d.publish(rec.tenant_id, f"user:{rec.user_id}",
                               {"type": "node", "session_id": rec.session_id, "node": node, "next": nxt})
                rec.current_node = nxt if nxt not in (END, SUSPEND) else node
                self._checkpoint(rec)
                node = nxt
            span.set_attribute("harnis.status", rec.status)

        metrics.TURN_LATENCY.observe(time.perf_counter() - run_started)
        if node == SUSPEND:
            metrics.TURNS.labels("awaiting_approval", metrics.safe(st.get("agent"))).inc()
        if node == END:
            metrics.TURNS.labels(metrics.safe(rec.status), metrics.safe(st.get("agent"))).inc()
            latency = int((time.time() - turn.get("started_at", time.time())) * 1000)
            self.d.store.record_metric(rec.tenant_id, rec.session_id, latency, turn.get("cache_hit", False),
                                       rec.status, turn.get("steps", 0))
            self.d.publish(rec.tenant_id, f"user:{rec.user_id}",
                           {"type": "turn_complete", "session_id": rec.session_id,
                            "status": rec.status, "reply": st.get("reply")})
        return rec

    def _checkpoint(self, rec: SessionRecord) -> None:
        with tracer.start_as_current_span("harnis.db.checkpoint"):
            rec.version = self.d.store.save_checkpoint(rec)

    def _halt(self, rec: SessionRecord, status: str, reason: str, reply: str) -> str:
        # Every tool_use the model emitted must get a tool_result, or the next
        # LLM call on this conversation is rejected by the provider.
        st = rec.state
        if st.get("pending_tool_calls"):
            done = {r["tool_use_id"] for r in st["tool_results"]}
            for call in st["pending_tool_calls"]:
                if call["id"] not in done:
                    st["tool_results"].append({"type": "tool_result", "tool_use_id": call["id"],
                                               "content": f"not executed: {reason}", "is_error": True})
            self._flush_results(st)
        st["awaiting"], st["approval_decision"] = None, None
        rec.status = status
        rec.state["reply"] = reply
        rec.state.setdefault("flags", []).append(reason)
        self.d.store.audit(rec.tenant_id, rec.session_id, "harnis", reason, {})
        if status in ("failed", "escalated", "rejected"):
            self.d.alert(reason, rec.tenant_id, rec.session_id, {"status": status})
        return END

    # -- nodes -----------------------------------------------------------------
    def ingest(self, rec: SessionRecord) -> str:
        st = rec.state
        result = self.d.input_guard.check(st["turn"]["input"])
        st["turn"].pop("input", None)  # never persist the raw (unredacted) input
        if not result.allowed:
            metrics.GUARD_BLOCKS.labels("input_blocked").inc()
            self.d.store.audit(rec.tenant_id, rec.session_id, rec.user_id, "input_blocked",
                               {"reasons": result.reasons})
            return self._halt(rec, "rejected", "input_blocked",
                              "Your message was blocked by the safety filter: " + ", ".join(result.reasons))
        if result.redactions:
            st["flags"].append("input_redacted:" + ",".join(sorted(set(result.redactions))))
            metrics.GUARD_BLOCKS.labels("input_redacted").inc()
        st["messages"].append(Message("user", [{"type": "text", "text": result.text}]).to_dict())
        st["turn"]["clean_input"] = result.text
        return "route"

    def route(self, rec: SessionRecord) -> str:
        st = rec.state
        # A new conversation is routed once. While it's with a non-sticky agent
        # (support), every new message is routed again, so a coding question
        # reaches the coder by construction rather than depending on the support
        # model calling `handoff`. Sticky agents (coder) keep the conversation.
        reg = self.d.registry
        previous = st["agent"]
        if previous not in reg.agents and previous is not None:
            previous = None  # agent removed from configuration since the last turn
        if previous is None or (not reg.agent(previous).sticky and self.d.limits.reroute_from_support):
            req = LLMRequest(
                system=self._prompt(rec, "router")[0],
                messages=[Message("user", [{"type": "text", "text": st["turn"]["clean_input"]}])],
                tools=[reg.tool_spec("route")], tier="fast", force_tool="route", max_tokens=200)
            resp = self._call_llm(rec, req)
            if resp is None:
                return END
            agent = previous or reg.default_agent
            for call in resp.tool_calls:
                try:
                    choice = ROUTE_TOOL.validate(call["input"]).agent  # type: ignore[attr-defined]
                except Exception:
                    choice = None
                if choice in reg.agents:
                    agent = choice
                else:
                    st["flags"].append("router_invalid_output")
            st["agent"] = agent
            if previous is not None and agent != previous:
                st["flags"].append(f"rerouted:{previous}->{agent}")
        first_message = sum(1 for m in st["messages"] if m["role"] == "user"
                            and any(b["type"] == "text" for b in m["content"])) == 1
        if self.d.cache is not None and reg.agent(st["agent"]).cacheable and first_message:
            return "cache_lookup"
        return "agent"

    def cache_lookup(self, rec: SessionRecord) -> str:
        """Only for the first message of a support session: a follow-up depends
        on conversation context, and a coding answer depends on repo state, so
        neither is safe to serve from a cache keyed on the prompt alone."""
        st = rec.state
        prompt_version = self._prompt(rec, st["agent"])[1]
        scope = f"{st['agent']}:v{prompt_version}"
        try:
            hit = self.d.cache.lookup(rec.tenant_id, scope, st["turn"]["clean_input"])
        except Exception:  # the cache is an optimisation: never fail a turn over it
            log.exception("semantic cache lookup failed; continuing without cache")
            st["flags"].append("cache_error")
            hit = None
        metrics.CACHE.labels("hit" if hit is not None else "miss").inc()
        if hit is None:
            return "agent"
        st["turn"]["cache_hit"] = True
        st["messages"].append(Message("assistant", [{"type": "text", "text": hit}]).to_dict())
        st["reply"] = hit
        rec.status = "completed"
        return END

    def agent(self, rec: SessionRecord) -> str:
        st = rec.state
        system, _ = self._prompt(rec, st["agent"])
        tools = self.d.registry.tools_for(st["agent"])
        req = LLMRequest(system=system, messages=[Message.from_dict(m) for m in st["messages"]], tools=tools)
        resp = self._call_llm(rec, req)
        if resp is None:
            return END
        st["messages"].append(Message("assistant", resp.content or [{"type": "text", "text": ""}]).to_dict())
        if resp.tool_calls:
            st["pending_tool_calls"] = resp.tool_calls
            st["tool_results"] = []
        if st["turn"]["cost_usd"] > self._cost_limit(rec):
            return self._halt(rec, "failed", "cost_budget_exceeded",
                              f"Stopped: this turn exceeded its ${self._cost_limit(rec):.2f} budget.")
        if resp.tool_calls:
            return "tools"
        if (self.d.registry.agent(st["agent"]).auto_continue and resp.stop_reason == "end_turn"
                and looks_unfinished(resp.text)
                and st["turn"].get("continues", 0) < self.d.limits.auto_continue_max):
            # Some models announce the next step ("Now let me create the test
            # file.") and end the turn without calling a tool. Nudge them on.
            st["turn"]["continues"] = st["turn"].get("continues", 0) + 1
            st["flags"].append("auto_continue")
            st["messages"].append(Message("user", [{"type": "text", "text": CONTINUE_NUDGE}]).to_dict())
            return "agent"
        st["reply"] = resp.text
        return "respond"

    def tools(self, rec: SessionRecord) -> str:
        st = rec.state
        turn = st["turn"]
        ws = workspace_for(self.d.workspaces_dir, rec.tenant_id, rec.session_id)
        ctx = ToolContext(ws, self.d.sandbox, rec.tenant_id, rec.user_id, rec.session_id)
        done = {r["tool_use_id"] for r in st["tool_results"]}

        for call in st["pending_tool_calls"]:
            if call["id"] in done:
                continue
            name, args = call["name"], call.get("input") or {}

            def result(text: str, is_error: bool = False, *, untrusted: bool = False) -> None:
                if untrusted:
                    text, flags = wrap_untrusted(name, text)
                    if flags:
                        st["flags"].append(f"tool_output_injection_suspected:{name}")
                        metrics.GUARD_BLOCKS.labels("tool_output_injection_suspected").inc()
                        self.d.store.audit(rec.tenant_id, rec.session_id, "harnis",
                                           "tool_output_injection_suspected", {"tool": name, "flags": flags})
                st["tool_results"].append({"type": "tool_result", "tool_use_id": call["id"],
                                           "content": text, "is_error": is_error})
                self.d.publish(rec.tenant_id, f"user:{rec.user_id}",
                               {"type": "tool_result", "session_id": rec.session_id, "tool": name,
                                "is_error": is_error, "preview": text[:300]})

            tool = self.d.registry.tools.get(name)
            if tool is None or name not in self.d.registry.agent(st["agent"]).tools:
                result(f"tool '{name}' is not available to the {st['agent']} agent", True)
                continue
            try:
                parsed = tool.validate(args)
            except Exception as exc:
                result(f"invalid arguments for {name}: {exc}", True)
                continue

            # Loop breaker: identical (tool, args) repeated inside the window.
            fp = hashlib.sha256(f"{name}:{json.dumps(args, sort_keys=True)}".encode()).hexdigest()[:16]
            window = st["loop_fingerprints"][-self.d.limits.loop_window:]
            st["loop_fingerprints"] = (window + [fp])[-self.d.limits.loop_window:]
            if window.count(fp) >= self.d.limits.loop_threshold:
                turn["loop_trips"] += 1
                if turn["loop_trips"] >= 2:
                    return self._halt(rec, "escalated", "loop_detected",
                                      "Stopped: the agent kept repeating the same action. A human has been notified.")
                result(f"LOOP DETECTED: you already called {name} with these exact arguments "
                       f"{window.count(fp)} times. Change your approach or explain what is blocking you.", True)
                continue

            turn["tool_calls"] += 1
            turn["used_tools"] = True
            if turn["tool_calls"] > self.d.limits.max_tool_calls:
                return self._halt(rec, "failed", "tool_budget_exceeded",
                                  f"Stopped: more than {self.d.limits.max_tool_calls} tool calls in one turn.")

            if tool.risk == "control":
                if name == "handoff":
                    if parsed.agent not in self.d.registry.agents:  # type: ignore[attr-defined]
                        result(f"unknown agent {parsed.agent!r}; available: "  # type: ignore[attr-defined]
                               f"{sorted(self.d.registry.agents)}", True)
                        continue
                    turn["handoffs"] += 1
                    if turn["handoffs"] > self.d.limits.max_handoffs:
                        return self._halt(rec, "failed", "handoff_budget_exceeded",
                                          "Stopped: agents handed the task back and forth too many times.")
                    st["agent"] = parsed.agent  # type: ignore[attr-defined]
                    result(f"handed off to {parsed.agent}")  # type: ignore[attr-defined]
                else:  # escalate_to_human
                    result("escalated to a human operator")
                    return self._halt(rec, "escalated", "escalated_by_agent",
                                      f"A human operator will take over. Reason: {parsed.reason}")  # type: ignore[attr-defined]
                continue

            if tool.risk == "high":
                action = describe_action(ws, name, parsed.model_dump(), tool)
                h = action_hash(action)
                aw, dec = st.get("awaiting"), st.get("approval_decision")
                if aw and aw["tool_use_id"] == call["id"] and dec:
                    st["awaiting"], st["approval_decision"] = None, None
                    if not dec["approved"]:
                        result(f"the reviewer denied this action ({dec['decided_by']}). Do not retry it "
                               "unchanged; ask the user how to proceed.", True)
                        continue
                    if h != aw["action_hash"]:
                        # Time-of-check/time-of-use: what would run now isn't what was approved.
                        self.d.store.audit(rec.tenant_id, rec.session_id, "harnis", "approval_stale", {"tool": name})
                        result("the approved action no longer matches what would be executed "
                               "(the workspace changed); it was NOT run.", True)
                        continue
                    self.d.store.audit(rec.tenant_id, rec.session_id, dec["decided_by"], "approved_action_executed",
                                       {"tool": name, "action_hash": h})
                else:
                    approval_id = self.d.store.create_approval(rec.tenant_id, rec.session_id, rec.user_id, action, h)
                    st["awaiting"] = {"approval_id": approval_id, "tool_use_id": call["id"], "action_hash": h}
                    rec.status = "awaiting_approval"
                    metrics.APPROVALS_REQUESTED.labels(metrics.safe(name)).inc()
                    st["reply"] = f"Waiting for a reviewer to approve `{name}`."
                    self.d.publish(rec.tenant_id, "reviewers",
                                   {"type": "approval_required", "approval_id": approval_id,
                                    "session_id": rec.session_id, "requested_by": rec.user_id, "action": action,
                                    "action_hash": h})
                    return SUSPEND

            output, is_error = tool.run(ctx, parsed)  # type: ignore[misc]
            metrics.TOOL_CALLS.labels(metrics.safe(name), "error" if is_error else "ok").inc()
            result(output, is_error, untrusted=tool.untrusted_output)

        self._flush_results(st)
        return "agent"

    @staticmethod
    def _flush_results(st: dict[str, Any]) -> None:
        if st["tool_results"]:
            st["messages"].append(Message("user", st["tool_results"]).to_dict())
        st["pending_tool_calls"], st["tool_results"] = [], []

    def respond(self, rec: SessionRecord) -> str:
        st = rec.state
        out = self.d.output_guard.check(st.get("reply") or "")
        st["reply"] = out.text
        if out.redactions:
            st["flags"].append("output_redacted")
        if (self.d.cache is not None and self.d.registry.agent(st["agent"]).cacheable
                and not st["turn"]["used_tools"]
                and not out.redactions):
            prompt_version = self._prompt(rec, st["agent"])[1]
            try:
                self.d.cache.store(rec.tenant_id, f"support:v{prompt_version}", st["turn"]["clean_input"], out.text)
            except Exception:
                log.exception("semantic cache store failed; answer not cached")
                st["flags"].append("cache_error")
        rec.status = "completed"
        return END

    # -- helpers ---------------------------------------------------------------
    def _prompt(self, rec: SessionRecord, key: str) -> tuple[str, int]:
        found = self.d.store.get_prompt(rec.tenant_id, key)
        if found:
            return found
        reg = self.d.registry
        return (reg.router_prompt() if key == "router" else reg.agent(key).prompt), 0

    def _cost_limit(self, rec: SessionRecord) -> float:
        tenant_limit = self.d.store.tenant_policy(rec.tenant_id).get("max_cost_usd_per_turn")
        return float(tenant_limit) if tenant_limit is not None else self.d.limits.max_cost_usd

    def _call_llm(self, rec: SessionRecord, req: LLMRequest):
        allowed = self.d.store.tenant_policy(rec.tenant_id).get("allowed_providers")
        if allowed is not None and "*" in allowed:
            allowed = None  # every configured provider
        try:
            resp = self.d.router.complete(req, allowed=allowed)
        except (AllProvidersFailed, ProviderError) as exc:
            log.error("LLM call failed: %s", exc)
            self._halt(rec, "failed", "llm_unavailable", "The model is unavailable right now; please retry later.")
            return None
        cost = cost_usd(resp.model, resp.usage.input_tokens, resp.usage.output_tokens)
        rec.state["turn"]["cost_usd"] = round(rec.state["turn"]["cost_usd"] + cost, 6)
        self.d.store.record_usage(rec.tenant_id, rec.session_id, resp.provider, resp.model,
                                  resp.usage.input_tokens, resp.usage.output_tokens, cost)
        return resp
