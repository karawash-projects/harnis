# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The handover summary a person gets when a session is escalated or fails."""
from harnis.llm.types import LLMResponse, Usage


class Escalating:
    name = "mock"

    def model_for(self, tier):
        return "mock-main"

    def complete(self, req):
        if req.force_tool:
            return LLMResponse([{"type": "tool_use", "id": "r", "name": "route", "input": {"agent": "coder"}}],
                               "tool_use", Usage(), self.name, "mock-main")
        return LLMResponse([{"type": "tool_use", "id": "e", "name": "escalate_to_human",
                             "input": {"reason": "I cannot tell which database to use"}}],
                           "tool_use", Usage(), self.name, "mock-main")


def test_escalation_by_the_agent_carries_a_handover_summary(store, make_orch):
    alerts = []
    orch = make_orch(store, providers=[Escalating()], alerts=alerts)
    rec = orch.start_turn(store.new_session(), "set up the database layer")
    assert rec.status == "escalated", rec.status
    e = rec.state["escalation"]
    assert e["reason"] == "escalated_by_agent" and e["status"] == "escalated"
    assert "database layer" in e["request"] and "which database" in e["what_happened"] and e["agent"] == "coder"
    assert e["next_steps"] and e["tests"] == "not run" and e["spent_usd"] >= 0
    detail = next(a for a in alerts if a[0] == "escalated_by_agent")[3]
    assert detail["status"] == "escalated" and "files_written" in detail


def test_the_summary_lists_files_and_tool_names_but_never_commands_or_contents(store, make_orch):
    orch = make_orch(store)
    rec = orch.start_turn(store.new_session(), "create calc.py")
    turn = rec.state["turn"]
    orch._note_action(turn, "write_file", {"path": "src/a.py", "content": "SECRET-BODY"}, False)
    orch._note_action(turn, "run_command", {"command": "curl -H 'token: hunter2' https://x"}, True)
    packet = orch._escalation_packet(rec, "failed", "tests_failing", "Stopped")
    assert packet["files_written"] == ["src/a.py"]
    flat = str(packet)
    assert "SECRET-BODY" not in flat and "hunter2" not in flat
    assert {"tool": "run_command", "target": "curl", "ok": False} in packet["recent_actions"]
    assert packet["next_steps"] == orch_steps("tests_failing")


def orch_steps(reason):
    from harnis.orchestrator import ESCALATION_NEXT_STEPS
    return ESCALATION_NEXT_STEPS[reason]


def test_unknown_reasons_get_generic_steps_and_a_new_turn_clears_the_old_summary(store, make_orch):
    orch = make_orch(store)
    rec = orch.start_turn(store.new_session(), "create calc.py")
    p = orch._escalation_packet(rec, "failed", "internal_error", "x")
    assert p["next_steps"] == orch_steps("_default")
    rec.state["escalation"] = p
    rec.status = "completed"
    rec2 = orch.start_turn(rec, "hello there")
    assert "escalation" not in rec2.state


def test_session_view_shows_the_summary_only_while_it_applies(store, make_orch):
    from harnis.api import session_view

    orch = make_orch(store, providers=[Escalating()])
    rec = orch.start_turn(store.new_session(), "set up the database layer")
    assert session_view(rec)["escalation"]["reason"] == "escalated_by_agent"
    rec.status = "completed"
    assert session_view(rec)["escalation"] is None
