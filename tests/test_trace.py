# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Trace timeline: steps are recorded with timing, never with contents, and read by owner/reviewer only."""
import pytest

from harnis.orchestrator import TRACE_MAX_PER_TURN, TRACE_TURNS, Orchestrator
from tests.test_lifecycle import client, h, session_with_work, tenant, ws  # noqa: F401


def test_unit_trace_is_capped_per_turn_and_over_turns():
    st = {"turn": {"started_at": 100.0}, "turn_no": 1}
    for _ in range(TRACE_MAX_PER_TURN + 20):
        Orchestrator._trace(st, "tool", 101.0, 0.5, tool="read_file", target="a.py", ok=True)
    assert len(st["trace"]) == TRACE_MAX_PER_TURN
    assert st["trace"][0]["t"] == 1.0 and st["trace"][0]["d"] == 0.5
    for n in range(2, TRACE_TURNS + 5):
        st["turn_no"] = n
        Orchestrator._trace(st, "model", 101.0, 0.1, model="m")
    assert len({e["turn"] for e in st["trace"]}) == TRACE_TURNS


@pytest.mark.integration
def test_trace_records_model_tool_and_approval_wait(client, tenant):
    sid, approval = session_with_work(client, tenant, "alice")
    t = client.get(f"/v1/sessions/{sid}/trace", headers=h("alice", tenant)).json()
    kinds = [e["kind"] for e in t["entries"]]
    assert "model" in kinds and t["turn"] == 1
    # the approval is still pending: no wait entry yet
    assert "approval" not in kinds
    r = client.post(f"/v1/approvals/{approval['approval_id']}/decision",
                    json={"approved": True, "action_hash": approval["action_hash"]},
                    headers=h("alice", tenant, ("user", "reviewer")))
    assert r.status_code == 202
    t = client.get(f"/v1/sessions/{sid}/trace", headers=h("alice", tenant)).json()
    kinds = [e["kind"] for e in t["entries"]]
    assert "approval" in kinds and "tool" in kinds
    tool = next(e for e in t["entries"] if e["kind"] == "tool")
    assert tool["tool"] == "write_file" and tool["target"] == "calc.py"
    assert "def " not in str(t)  # no file contents


@pytest.mark.integration
def test_trace_is_private_to_owner_and_reviewers(client, tenant):
    sid, _ = session_with_work(client, tenant, "alice")
    assert client.get(f"/v1/sessions/{sid}/trace", headers=h("bob", tenant)).status_code in (403, 404)
    assert client.get(f"/v1/sessions/{sid}/trace", headers=h("rev", tenant, ("user", "reviewer"))).status_code == 200
