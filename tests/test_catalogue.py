# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""1.8.0: starting a conversation on a chosen agent."""
import pytest

from harnis.llm.types import LLMResponse, Usage

from .conftest import MemoryStore
from .test_lifecycle import client, h, tenant, ws  # noqa: F401


class Recorder:
    """Answers directly; remembers whether the router was asked."""
    name = "rec"

    def __init__(self):
        self.routed = 0

    def model_for(self, tier):
        return "mock"

    def complete(self, req):
        if req.force_tool:
            self.routed += 1
            return LLMResponse([{"type": "tool_use", "id": "r", "name": "route", "input": {"agent": "coder"}}],
                               "tool_use", Usage(1, 1), self.name, "mock")
        return LLMResponse([{"type": "text", "text": "ok"}], "end_turn", Usage(1, 1), self.name, "mock")


def test_a_chosen_agent_is_not_re_routed(make_orch):
    store, rec_p = MemoryStore(), Recorder()
    rec = store.new_session()
    rec.state["agent"], rec.state["pinned_agent"] = "support", True
    out = make_orch(store, providers=[rec_p]).start_turn(rec, "please fix the bug in app.py")
    assert out.state["agent"] == "support" and rec_p.routed == 0


def test_an_unchosen_support_conversation_is_still_re_routed(make_orch):
    store, rec_p = MemoryStore(), Recorder()
    rec = store.new_session()
    rec.state["agent"] = "support"
    out = make_orch(store, providers=[rec_p]).start_turn(rec, "please fix the bug in app.py")
    assert out.state["agent"] == "coder" and rec_p.routed == 1


@pytest.mark.integration
def test_session_can_start_on_an_agent_and_unknown_agents_are_refused(client, tenant):
    alice = h("alice", tenant)
    sid = client.post("/v1/sessions", json={"agent": "coder"}, headers=alice).json()["session_id"]
    assert client.get(f"/v1/sessions/{sid}", headers=alice).json()["agent"] == "coder"
    r = client.post("/v1/sessions", json={"agent": "nope"}, headers=alice)
    assert r.status_code == 400
    assert client.post("/v1/sessions", json={}, headers=alice).status_code == 201  # router as before


@pytest.mark.integration
def test_agents_list_has_plain_titles_and_summaries(client, tenant):
    agents = {a["name"]: a for a in client.get("/v1/agents", headers=h("alice", tenant)).json()}
    assert agents["coder"]["title"] == "Coding assistant" and "private workspace" in agents["coder"]["summary"]
    assert agents["support"]["title"] == "General help"
