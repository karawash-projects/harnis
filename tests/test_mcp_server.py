# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The MCP server: a governed route to Harnis from IDEs and coding tools."""
import asyncio

import pytest

pytest.importorskip("mcp")

from harnis.mcp_server import HarnisClient, HarnisError, build_server  # noqa: E402

from .test_lifecycle import client, h, tenant, ws  # noqa: E402,F401

pytestmark = pytest.mark.integration


def make(client, tenant, tmp_path, user="dev"):
    client.headers["Authorization"] = h(user, tenant)["Authorization"]
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "notes.txt").write_text("my notes\n")
    return HarnisClient("http://testserver", "unused", project, http=client, wait_seconds=5, poll=0.01), project


def approve_everything(client, tenant, sid):
    """What a human reviewer does in the console, until the conversation has nothing left to approve."""
    for _ in range(6):
        s = client.get(f"/v1/sessions/{sid}", headers=h("rev", tenant, ("reviewer",))).json()
        if s["status"] != "awaiting_approval":
            return s
        aw = s["awaiting"]
        r = client.post(f"/v1/approvals/{aw['approval_id']}/decision",
                        json={"approved": True, "action_hash": aw["action_hash"]}, headers=h("rev", tenant, ("reviewer",)))
        assert r.status_code == 202
    return s


def test_the_server_offers_no_way_to_approve_or_deny(client, tenant, tmp_path):
    hc, _ = make(client, tenant, tmp_path)
    names = {t.name for t in asyncio.run(build_server(hc).list_tools())}
    assert names == {"harnis_start_task", "harnis_task_status", "harnis_send_message",
                     "harnis_get_changes", "harnis_apply_changes"}
    assert not any(w in n for n in names for w in ("approve", "deny", "decide"))


def test_a_task_waits_for_a_human_then_changes_reach_local_files_only_when_applied(client, tenant, tmp_path):
    hc, project = make(client, tenant, tmp_path)
    started = hc.start_task("create calc.py")
    assert started["status"] == "awaiting_approval" and "cannot approve" in started["waiting_for"]
    assert started["files_uploaded"] == 1
    sid = started["session_id"]
    assert not (project / "calc.py").exists()

    approve_everything(client, tenant, sid)
    assert hc.status(sid)["status"] == "completed"

    changes = hc.get_changes(sid)
    assert "calc.py" in changes["files_changed"] and "+def " in changes["diffs"]["calc.py"]
    assert not (project / "calc.py").exists()                       # looking changes nothing

    result = hc.apply_changes(sid)
    assert "calc.py" in result["applied"] and (project / "calc.py").read_text().startswith("def ")
    assert (project / "notes.txt").read_text() == "my notes\n"        # untouched files stay as they were


def test_applying_requires_having_looked_and_refuses_files_edited_since(client, tenant, tmp_path):
    hc, project = make(client, tenant, tmp_path)
    sid = hc.start_task("create calc.py")["session_id"]
    approve_everything(client, tenant, sid)
    with pytest.raises(HarnisError, match="get_changes first"):
        hc.apply_changes(sid)
    hc.get_changes(sid)
    (project / "calc.py").write_text("my own version\n")             # edited after looking
    result = hc.apply_changes(sid)
    assert "calc.py" in result["skipped"] and "calc.py" not in result["applied"]
    assert (project / "calc.py").read_text() == "my own version\n"
    assert hc.apply_changes(sid, ["../etc/passwd"])["skipped"]       # only files that were shown


def test_errors_come_back_as_messages_not_crashes(client, tenant, tmp_path):
    hc, _ = make(client, tenant, tmp_path)
    srv = build_server(hc)
    out = asyncio.run(srv.call_tool("harnis_task_status", {"session_id": "sess_does_not_exist"}))
    assert "error" in str(out) and "404" in str(out)
    hc.http.headers["Authorization"] = "Bearer garbage"
    with pytest.raises(HarnisError, match="rejected the token"):
        hc.status("x")
