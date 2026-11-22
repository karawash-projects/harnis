# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""1.7.0: the approvals list carries what a reviewer needs to triage."""
import pytest

from .test_lifecycle import client, h, session_with_work, tenant, ws  # noqa: F401


@pytest.mark.integration
def test_pending_list_names_the_agent_and_context(client, tenant):
    sid, approval = session_with_work(client, tenant, "alice")
    rows = client.get("/v1/approvals", headers=h("rita", tenant, ("reviewer",))).json()
    mine = next(r for r in rows if r["approval_id"] == approval["approval_id"])
    assert mine["agent"] == "coder"
    assert "context" in mine and (mine["context"] is None or len(mine["context"]) <= 400)
    assert mine["action"]["tool"] and mine["expires_at"]
