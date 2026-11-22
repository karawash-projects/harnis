# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Manager views: spend by user and agent, approval statistics, audit filters."""
import pytest

from .test_lifecycle import client, h, session_with_work, tenant, ws  # noqa: F401

pytestmark = pytest.mark.integration


def test_spend_is_split_by_user_and_agent_and_admin_only(client, tenant, app_pool):
    sid_a, _ = session_with_work(client, tenant, "alice")
    sid_b, _ = session_with_work(client, tenant, "bob")
    with app_pool.connection() as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (tenant,))
        for sid, cost in ((sid_a, "1.5"), (sid_b, "0.25")):
            c.execute("INSERT INTO token_ledger (tenant_id, session_id, provider, model, input_tokens, output_tokens, cost_usd)"
                      " VALUES (%s, %s, 'mock', 'm', 10, 5, %s)", (tenant, sid, cost))
        c.commit()
    admin = h("root", tenant, ("admin",))
    r = client.get("/v1/admin/spend?days=7", headers=admin)
    assert r.status_code == 200
    users = {x["name"]: x for x in r.json()["by_user"]}
    assert users["alice"]["cost_usd"] == 1.5 and users["bob"]["cost_usd"] == 0.25
    assert r.json()["total_usd"] >= 1.75
    assert r.json()["by_agent"]
    assert client.get("/v1/admin/spend", headers=h("rev", tenant, ("reviewer",))).status_code == 403
    assert client.get("/v1/admin/spend?days=0", headers=admin).status_code == 422


def test_erased_users_spend_is_grouped_apart(client, tenant, app_pool):
    sid, _ = session_with_work(client, tenant, "carol")
    with app_pool.connection() as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (tenant,))
        c.execute("INSERT INTO token_ledger (tenant_id, session_id, provider, model, cost_usd) VALUES (%s, %s, 'mock', 'm', 2)",
                  (tenant, sid))
        c.commit()
    admin = h("root", tenant, ("admin",))
    assert client.delete("/v1/admin/users/carol/data?confirm=carol", headers=admin).status_code == 200
    names = [x["name"] for x in client.get("/v1/admin/spend", headers=admin).json()["by_user"]]
    assert "carol" not in names and "(erased or expired)" in names


def test_approval_stats_rate_and_decision_time(client, tenant, app_pool):
    ids = []
    for u in ("u1", "u2", "u3"):
        _, ap = session_with_work(client, tenant, u)
        ids.append((ap["approval_id"], ap["action_hash"]))
    rev = h("rev", tenant, ("reviewer",))
    assert client.post(f"/v1/approvals/{ids[0][0]}/decision", json={"approved": True, "action_hash": ids[0][1]}, headers=rev).status_code == 202
    assert client.post(f"/v1/approvals/{ids[1][0]}/decision", json={"approved": False, "action_hash": ids[1][1]}, headers=rev).status_code == 202
    r = client.get("/v1/approval-stats", headers=rev).json()
    assert (r["approved"], r["denied"]) == (1, 1) and r["pending"] >= 1
    assert r["approval_rate_pct"] == 50.0
    assert r["median_decision_s"] is not None and r["median_decision_s"] >= 0
    assert r["by_tool"][0]["tool"] == "write_file"
    assert client.get("/v1/approval-stats", headers=h("x", tenant)).status_code == 403


def test_audit_log_filters_by_user_and_date_range(client, tenant):
    session_with_work(client, tenant, "dave")
    session_with_work(client, tenant, "erin")
    admin = h("root", tenant, ("admin",))
    everyone = client.get("/v1/admin/audit?limit=1000", headers=admin).json()["events"]
    actors = {e["actor"] for e in everyone}
    assert {"dave", "erin"} <= actors
    only = client.get("/v1/admin/audit?actor=dave&limit=1000", headers=admin).json()["events"]
    assert only and {e["actor"] for e in only} == {"dave"}
    nd = client.get("/v1/admin/audit?actor=dave&format=ndjson", headers=admin)
    assert nd.status_code == 200 and "erin" not in nd.text
    assert client.get("/v1/admin/audit?since=2999-01-01T00:00:00Z", headers=admin).json()["events"] == []
    assert client.get("/v1/admin/audit?until=2000-01-01T00:00:00Z", headers=admin).json()["events"] == []
    assert len(client.get("/v1/admin/audit?since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z&limit=1000",
                          headers=admin).json()["events"]) == len(everyone)
    assert client.get("/v1/admin/audit?since=notadate", headers=admin).status_code == 422
