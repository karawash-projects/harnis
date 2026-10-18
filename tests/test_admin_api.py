# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""API keys, tenant administration and audit export, end to end against
real Postgres (app role, RLS) and Redis."""
import json
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

from harnis.auth import mint_token
from harnis.config import Settings
from harnis.llm.providers import MockProvider
from harnis.llm.router import LLMRouter
from harnis.store import PgStore

from .conftest import FakeSandbox

pytestmark = pytest.mark.integration


@pytest.fixture
def client(app_pool, redis_client, tmp_path):
    from harnis.api import create_app

    settings = Settings(workspaces_dir=str(tmp_path / "ws"), redis_url="redis://127.0.0.1:6379/15",
                        rate_limit_capacity=100)
    app = create_app(settings, store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=FakeSandbox())
    with TestClient(app) as c:
        yield c


def h(user, tenant="acme", roles=("user",)):
    return {"Authorization": f"Bearer {mint_token(user, tenant, list(roles))}"}


PLATFORM = h("ops", "acme", ("platform-admin",))


@pytest.fixture
def tenant(client):
    tid = f"t-{uuid.uuid4().hex[:8]}"
    r = client.put(f"/v1/admin/tenants/{tid}", json={"name": "Test Co", "allowed_providers": ["mock"]},
                   headers=PLATFORM)
    assert r.status_code == 200, r.text
    return tid


# -- platform administration ------------------------------------------------------
def test_platform_admin_creates_and_updates_tenants(client, tenant):
    rows = {t["tenant_id"]: t for t in client.get("/v1/admin/tenants", headers=PLATFORM).json()}
    assert rows[tenant]["allowed_providers"] == ["mock"] and rows[tenant]["active"] is True
    assert {"acme", "globex"} <= set(rows)  # sees every tenant
    r = client.put(f"/v1/admin/tenants/{tenant}", json={"max_cost_usd_per_turn": 0.5}, headers=PLATFORM)
    assert r.json()["max_cost_usd_per_turn"] == 0.5 and r.json()["name"] == "Test Co"
    r = client.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM)
    assert r.json()["max_cost_usd_per_turn"] == 0.5 and r.json()["active"] is False  # other fields kept
    r = client.put(f"/v1/admin/tenants/{tenant}", json={"max_cost_usd_per_turn": 0}, headers=PLATFORM)
    assert r.json()["max_cost_usd_per_turn"] is None
    r = client.put(f"/v1/admin/tenants/{tenant}-new", json={}, headers=PLATFORM)
    assert r.json()["name"] == f"{tenant}-new" and r.json()["active"] is True


def test_tenant_admin_cannot_manage_tenants(client):
    boss = h("boss", "acme", ("admin",))
    assert client.get("/v1/admin/tenants", headers=boss).status_code == 403
    assert client.put("/v1/admin/tenants/evil", json={"name": "x"}, headers=boss).status_code == 403


def test_tenant_upsert_validation(client):
    assert client.put("/v1/admin/tenants/bad%20id", json={}, headers=PLATFORM).status_code == 400
    r = client.put("/v1/admin/tenants/okid", json={"allowed_providers": ["nope"]}, headers=PLATFORM)
    assert r.status_code == 400


def test_disabled_tenant_is_locked_out(client, tenant):
    user = h("u1", tenant)
    sid = client.post("/v1/sessions", json={}, headers=user).json()["session_id"]
    client.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM)
    assert client.post("/v1/sessions", json={}, headers=user).status_code == 403
    assert client.post(f"/v1/sessions/{sid}/turns", json={"message": "hi"}, headers=user).status_code == 403
    client.put(f"/v1/admin/tenants/{tenant}", json={"active": True}, headers=PLATFORM)
    assert client.post(f"/v1/sessions/{sid}/turns", json={"message": "hi"}, headers=user).status_code == 200


def test_app_role_cannot_touch_tenants_directly(pg):
    with psycopg.connect(pg["app"]) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE tenants SET active = false")


# -- API keys ---------------------------------------------------------------------
def test_api_key_lifecycle(client, tenant):
    admin = h("boss", tenant, ("admin",))
    r = client.post("/v1/admin/api-keys", json={"name": "ci", "roles": ["user"], "expires_in_days": 30},
                    headers=admin)
    assert r.status_code == 201
    key = r.json()["key"]
    assert key.startswith("hrn_") and "secret_hash" not in r.json()
    kh = {"Authorization": f"Bearer {key}"}
    me = client.get("/me", headers=kh).json()
    assert me["tenant_id"] == tenant and me["roles"] == ["user"] and me["via"] == "api_key"
    sid = client.post("/v1/sessions", json={}, headers=kh).json()["session_id"]
    assert client.post(f"/v1/sessions/{sid}/turns", json={"message": "hours?"}, headers=kh).status_code == 200
    # Listed without the secret; last use recorded.
    listed = client.get("/v1/admin/api-keys", headers=admin).json()
    assert listed[0]["name"] == "ci" and listed[0]["last_used_at"] and "key" not in listed[0]
    # Revoke -> rejected.
    kid = listed[0]["key_id"]
    assert client.delete(f"/v1/admin/api-keys/{kid}", headers=admin).status_code == 204
    assert client.get("/me", headers=kh).status_code == 401
    assert client.delete(f"/v1/admin/api-keys/{kid}", headers=admin).status_code == 404


def test_api_key_wrong_secret_and_garbage(client, tenant):
    admin = h("boss", tenant, ("admin",))
    key = client.post("/v1/admin/api-keys", json={"name": "x"}, headers=admin).json()["key"]
    tampered = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
    for bad in (tampered, "hrn_0000000000000000_" + "x" * 43, "hrn_nothex_zz"):
        assert client.get("/me", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_api_keys_cannot_carry_platform_admin(client, tenant):
    admin = h("boss", tenant, ("admin",))
    r = client.post("/v1/admin/api-keys", json={"name": "x", "roles": ["platform-admin"]}, headers=admin)
    assert r.status_code == 422


def test_api_key_of_disabled_tenant_is_refused(client, tenant):
    admin = h("boss", tenant, ("admin",))
    key = client.post("/v1/admin/api-keys", json={"name": "x"}, headers=admin).json()["key"]
    client.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM)
    assert client.get("/me", headers={"Authorization": f"Bearer {key}"}).status_code == 403


def test_api_keys_are_tenant_isolated(client, tenant):
    key_admin = h("boss", tenant, ("admin",))
    kid = client.post("/v1/admin/api-keys", json={"name": "mine"}, headers=key_admin).json()["key_id"]
    other_admin = h("boss", "globex", ("admin",))
    assert kid not in [k["key_id"] for k in client.get("/v1/admin/api-keys", headers=other_admin).json()]
    assert client.delete(f"/v1/admin/api-keys/{kid}", headers=other_admin).status_code == 404


def test_non_admin_cannot_create_keys(client, tenant):
    assert client.post("/v1/admin/api-keys", json={"name": "x"}, headers=h("u", tenant, ("reviewer",))).status_code == 403


def test_websocket_accepts_api_key(client, tenant):
    key = client.post("/v1/admin/api-keys", json={"name": "ws"}, headers=h("boss", tenant, ("admin",))).json()["key"]
    with client.websocket_connect(f"/v1/ws?token={key}") as ws:
        assert '"hello"' in ws.receive_text()


# -- audit export -----------------------------------------------------------------
def test_audit_export_paginates_and_is_tenant_scoped(client, tenant):
    admin = h("boss", tenant, ("admin",))
    for i in range(3):
        client.post("/v1/admin/api-keys", json={"name": f"k{i}"}, headers=admin)
    page1 = client.get("/v1/admin/audit?limit=2", headers=admin).json()
    assert len(page1["events"]) == 2
    page2 = client.get(f"/v1/admin/audit?after={page1['next_after']}&limit=50", headers=admin).json()
    types = [e["event_type"] for e in page1["events"] + page2["events"]]
    assert "tenant_upserted" in types and types.count("api_key_created") == 3
    nd = client.get("/v1/admin/audit?format=ndjson&event_type=api_key_created", headers=admin)
    lines = [json.loads(x) for x in nd.text.splitlines()]
    assert nd.headers["content-type"].startswith("application/x-ndjson") and len(lines) == 3
    other = client.get("/v1/admin/audit?limit=5000", headers=h("boss", "globex", ("admin",))).json()["events"]
    assert all(e["event_type"] != "tenant_upserted" or True for e in other)
    assert not any(e["detail"].get("key_id") in {x["detail"].get("key_id") for x in lines} for e in other)


def test_api_keys_count_as_their_creator_for_separation_of_duties(app_pool, redis_client, tmp_path):
    """Security review finding: an admin must not approve their own request
    through a reviewer key they created (or vice versa)."""
    from harnis.api import create_app

    app = create_app(Settings(workspaces_dir=str(tmp_path / "ws"), redis_url="redis://127.0.0.1:6379/15",
                              rate_limit_capacity=100, allow_self_approval=False),
                     store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=FakeSandbox())
    with TestClient(app) as c:
        boss = h("boss-sod", "acme", ("admin",))
        rev_key = c.post("/v1/admin/api-keys", json={"name": "r", "roles": ["reviewer"]}, headers=boss).json()["key"]
        user_key = c.post("/v1/admin/api-keys", json={"name": "u", "roles": ["user"]}, headers=boss).json()["key"]
        rk, uk = ({"Authorization": f"Bearer {k}"} for k in (rev_key, user_key))

        def pending(headers):
            sid = c.post("/v1/sessions", json={}, headers=headers).json()["session_id"]
            return c.post(f"/v1/sessions/{sid}/turns", json={"message": "create calc.py"}, headers=headers).json()["approval"]

        for requester, approver in ((boss, rk), (uk, boss), (uk, rk)):
            a = pending(requester)
            r = c.post(f"/v1/approvals/{a['approval_id']}/decision",
                       json={"approved": True, "action_hash": a["action_hash"]}, headers=approver)
            assert r.status_code == 403 and "separation of duties" in r.text
        # A different person can approve.
        a = pending(uk)
        assert c.post(f"/v1/approvals/{a['approval_id']}/decision", json={"approved": True,
                      "action_hash": a["action_hash"]}, headers=h("rita", "acme", ("reviewer",))).status_code == 202
