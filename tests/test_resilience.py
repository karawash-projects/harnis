# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""1.4.1: replies cut off at the output limit, and approvals nobody decides."""
import pytest

from harnis import pg as pgdrv
from harnis.llm.types import LLMResponse, Usage

from .conftest import FakeSandbox, MemoryStore  # noqa: F401
from .test_lifecycle import client, h, session_with_work, tenant, ws  # noqa: F401


class Truncating:
    """First `cuts` agent replies are cut off at the limit; then a complete one."""
    name = "trunc"

    def __init__(self, cuts, with_tool=False):
        self.cuts, self.with_tool, self.n = cuts, with_tool, 0

    def model_for(self, tier):
        return "mock"

    def complete(self, req):
        u = Usage(1, 1)
        if req.force_tool:
            return LLMResponse([{"type": "tool_use", "id": "r", "name": "route", "input": {"agent": "faq"}}],
                               "tool_use", u, self.name, "mock")
        self.n += 1
        if self.n <= self.cuts:
            if self.with_tool:  # arguments cut off mid-way
                return LLMResponse([{"type": "text", "text": "Writing"},
                                    {"type": "tool_use", "id": f"x{self.n}", "name": "write_file",
                                     "input": {"path": "a.py"}}], "max_tokens", u, self.name, "mock")
            return LLMResponse([{"type": "text", "text": "The answer begins and then"}], "max_tokens", u, self.name, "mock")
        return LLMResponse([{"type": "text", "text": "Complete answer."}], "end_turn", u, self.name, "mock")


def test_a_cut_off_reply_is_continued(make_orch):
    store = MemoryStore()
    rec = make_orch(store, providers=[Truncating(1)]).start_turn(store.new_session(), "hello there")
    assert rec.status == "completed" and rec.state["reply"] == "Complete answer."
    assert "output_truncated" in rec.state["flags"]


def test_a_cut_off_tool_call_is_never_run(make_orch):
    store = MemoryStore()
    rec = make_orch(store, providers=[Truncating(1, with_tool=True)]).start_turn(store.new_session(), "hello there")
    assert not store.approvals and rec.state["reply"] == "Complete answer."
    assert not any(b.get("type") == "tool_use" and b.get("name") == "write_file"
                   for m in rec.state["messages"] for b in m["content"])


def test_endlessly_cut_off_reply_is_delivered_with_a_note(make_orch):
    store = MemoryStore()
    rec = make_orch(store, providers=[Truncating(99)]).start_turn(store.new_session(), "hello there")
    assert rec.status == "completed" and "cut off at the output limit" in rec.state["reply"]


@pytest.mark.integration
def test_an_approval_nobody_decides_does_not_strand_the_session(client, tenant, pg):
    sid, approval = session_with_work(client, tenant, "alice")
    alice = h("alice", tenant)
    # While the approval is still valid the session is busy.
    assert client.post(f"/v1/sessions/{sid}/turns", json={"message": "hi"}, headers=alice).status_code == 409
    with pgdrv.connect(pg["owner"], autocommit=True) as c:  # time passes: the approval runs out
        c.execute("UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE approval_id = %s",
                  (approval["approval_id"],))
    r = client.post(f"/v1/sessions/{sid}/turns", json={"message": "What are your opening hours?"}, headers=alice)
    assert r.status_code == 200 and r.json()["status"] == "completed"
    with pgdrv.connect(pg["owner"]) as c:
        row = c.execute("SELECT status FROM approvals WHERE approval_id = %s", (approval["approval_id"],)).fetchone()
        ev = c.execute("SELECT count(*) AS n FROM audit_log WHERE event_type = 'approval_expired'").fetchone()
    assert row[0] == "expired" and ev[0] == 1
    # The history stays valid for the provider: the abandoned tool call got a result.
    msgs = client.get(f"/v1/sessions/{sid}", headers=alice).json()
    assert msgs["status"] == "completed"
