# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Plugin SDK: registry rules, loading, and plugin tools/agents/providers
running through the real orchestrator."""
import json
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

from harnis.llm.types import LLMResponse, Usage
from harnis.plugins import AgentSpec, Registry, build_registry
from harnis.tools import Tool

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plugins" / "harnis-plugin-tickets"


@pytest.fixture
def example_on_path(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    sys.modules.pop("harnis_tickets", None)


class NoArgs(BaseModel):
    pass


def noop(ctx, args):
    return "ok", False


# -- registry rules ---------------------------------------------------------------
def test_builtins_registered_and_valid():
    r = build_registry()
    assert {"coder", "support"} <= set(r.agents) and r.default_agent == "support"
    assert {"anthropic", "openai", "openai_compatible", "gemini", "nova", "mock"} <= set(r.providers)


def test_duplicate_and_reserved_names_rejected():
    r = build_registry()
    with pytest.raises(ValueError):
        r.add_tool(Tool("read_file", "x", NoArgs, "low", noop))
    r.add_tool(Tool("read_file", "replacement", NoArgs, "low", noop), replace=True)
    with pytest.raises(ValueError):
        r.add_tool(Tool("route", "x", NoArgs, "low", noop))
    with pytest.raises(ValueError):
        AgentSpec(name="Bad Name", description="x", prompt="x")
    with pytest.raises(ValueError):
        Tool("bad name", "x", NoArgs, "low", noop)
    with pytest.raises(ValueError):
        Tool("needs_run", "x", NoArgs, "high", None)


def test_agent_with_unknown_tool_fails_at_load():
    r = build_registry()
    r.add_agent(AgentSpec(name="broken", description="x", prompt="x", tools=["nope"]))
    with pytest.raises(ValueError, match="unregistered tools"):
        r.validate()


def test_only_one_default_agent():
    r = build_registry()
    r.add_agent(AgentSpec(name="frontdesk", description="x", prompt="x", default=True))
    assert r.default_agent == "frontdesk" and not r.agents["support"].default


def test_route_and_handoff_specs_list_registered_agents():
    r = build_registry()
    r.add_agent(AgentSpec(name="orders", description="order questions", prompt="x"))
    for name in ("route", "handoff"):
        assert r.tool_spec(name).input_schema["properties"]["agent"]["enum"] == ["coder", "orders", "support"]
    assert "- orders: order questions" in r.router_prompt()


# -- loading ----------------------------------------------------------------------
def test_load_by_module_path(example_on_path):
    r = build_registry(["harnis_tickets"])
    assert "triage" in r.agents and r.tools["create_ticket"].risk == "high"
    assert r.loaded_plugins == ["harnis_tickets"]


def test_load_by_module_and_function(example_on_path):
    assert "triage" in build_registry(["harnis_tickets:register"]).agents


def test_load_by_entry_point_name(example_on_path, monkeypatch):
    from importlib import metadata

    ep = metadata.EntryPoint(name="tickets", value="harnis_tickets:register", group="harnis.plugins")
    monkeypatch.setattr(metadata, "entry_points",
                        lambda group=None: [ep] if group == "harnis.plugins" else [])
    assert "triage" in build_registry(["tickets"]).agents


def test_installed_but_unlisted_plugins_are_not_loaded(example_on_path):
    assert "triage" not in build_registry([]).agents


# -- running through the orchestrator --------------------------------------------
class TriageModel:
    """Routes to triage, searches, files a ticket, then answers."""
    name = "scripted"

    def model_for(self, tier):
        return "mock-main"

    def complete(self, req):
        if req.force_tool:
            return LLMResponse([{"type": "tool_use", "id": "r", "name": "route", "input": {"agent": "triage"}}],
                               "tool_use", Usage(), self.name, "mock-main")
        assert "search_tickets" in [t.name for t in req.tools]
        used = [b["name"] for m in req.messages for b in m.content if b["type"] == "tool_use"]
        if not used:
            return self._call("s1", "search_tickets", {"query": "login"})
        if used == ["search_tickets"]:
            return self._call("c1", "create_ticket", {"title": "Login page returns 500",
                                                      "description": "Since 9am every login fails with a 500.",
                                                      "priority": "urgent"})
        if used == ["search_tickets", "create_ticket"]:
            return self._call("h1", "handoff", {"agent": "nonexistent"})
        return LLMResponse([{"type": "text", "text": "Filed TCK-login-page-returns-500."}], "end_turn",
                           Usage(), self.name, "mock-main")

    def _call(self, i, name, args):
        return LLMResponse([{"type": "tool_use", "id": i, "name": name, "input": args}], "tool_use", Usage(),
                           self.name, "mock-main")


def test_plugin_agent_and_tools_end_to_end(example_on_path, store, make_orch, tmp_path):
    from harnis.orchestrator import Orchestrator

    orch = make_orch(store, providers=[TriageModel()])
    orch.d.registry = build_registry(["harnis_tickets"])
    orch = Orchestrator(orch.d)
    rec = orch.start_turn(store.new_session(user="dana"), "The login page is down for everyone")
    assert rec.state["agent"] == "triage" and rec.status == "awaiting_approval"
    approval = store.approvals[rec.state["awaiting"]["approval_id"]]
    assert approval["action"]["tool"] == "create_ticket"
    assert approval["action"]["ticket_preview"]["priority"] == "urgent"  # reviewer sees the ticket
    rec = orch.resume_after_decision(rec, rec.state["awaiting"]["approval_id"], True, "bob")
    assert rec.status == "completed" and rec.state["reply"].startswith("Filed")
    ticket = json.loads((tmp_path / "ws" / "acme" / rec.session_id / "tickets" /
                         "login-page-returns-500.json").read_text())
    assert ticket["reporter"] == "dana" and ticket["tenant"] == "acme" and ticket["session"] == rec.session_id
    results = {b["tool_use_id"]: b for m in rec.state["messages"] for b in m["content"] if b["type"] == "tool_result"}
    assert results["s1"]["content"].startswith("<untrusted_data")  # plugin output fenced by default
    assert results["h1"]["is_error"] and "unknown agent" in results["h1"]["content"]


def test_plugin_provider_joins_the_failover_chain():
    from harnis.config import Settings
    from harnis.llm.router import build_router

    class Echo:
        name = "echo"

        def model_for(self, tier):
            return f"echo-{tier}"

        def complete(self, req):
            return LLMResponse([{"type": "text", "text": "echo"}], "end_turn", Usage(), self.name, "echo-main")

    r = build_registry()
    r.add_provider("echo", lambda s: Echo())
    router = build_router(Settings(_env_file=None, llm_providers="echo,mock"), registry=r)
    assert [p.name for p in router.providers] == ["echo", "mock"]


@pytest.mark.integration
def test_api_lists_plugin_agents_and_accepts_their_prompts(example_on_path, app_pool, redis_client, tmp_path):
    from fastapi.testclient import TestClient

    from harnis.api import create_app
    from harnis.auth import mint_token
    from harnis.config import Settings
    from harnis.llm.providers import MockProvider
    from harnis.llm.router import LLMRouter
    from harnis.store import PgStore

    from .conftest import FakeSandbox

    settings = Settings(workspaces_dir=str(tmp_path / "ws"), redis_url="redis://127.0.0.1:6379/15",
                        plugins="harnis_tickets")
    app = create_app(settings, store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=FakeSandbox())
    admin = {"Authorization": f"Bearer {mint_token('boss', 'acme', ['admin'])}"}
    with TestClient(app) as c:
        agents = {a["name"]: a for a in c.get("/v1/agents", headers=admin).json()}
        assert {"name": "create_ticket", "risk": "high"} in agents["triage"]["tools"]
        assert c.post("/v1/prompts", json={"key": "triage", "text": "You triage incidents. Be brief."},
                      headers=admin).status_code == 201
        assert c.post("/v1/prompts", json={"key": "nobody", "text": "You are nobody at all."},
                      headers=admin).status_code == 400
        assert c.get("/v1/prompts/router", headers=admin).json()["text"].count("- triage:") == 1
