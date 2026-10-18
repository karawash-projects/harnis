# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Data lifecycle against real Postgres: user export and erasure, tenant
deletion, retention, and the orphaned-workspace sweep."""
import os
import time
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


def h(user, tenant, roles=("user",)):
    return {"Authorization": f"Bearer {mint_token(user, tenant, list(roles))}"}


PLATFORM = h("ops", "platform", ("platform-admin",))


@pytest.fixture
def ws(tmp_path):
    return tmp_path / "ws"


@pytest.fixture
def client(app_pool, redis_client, ws):
    from harnis.api import create_app

    app = create_app(Settings(_env_file=None, workspaces_dir=str(ws), redis_url="redis://127.0.0.1:6379/15",
                              rate_limit_capacity=100, allow_self_approval=True),
                     store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=FakeSandbox())
    with TestClient(app) as c:
        yield c


@pytest.fixture
def tenant(client):
    tid = f"lc-{uuid.uuid4().hex[:8]}"
    assert client.put(f"/v1/admin/tenants/{tid}", json={"allowed_providers": ["mock"]}, headers=PLATFORM).status_code == 200
    return tid


def session_with_work(client, tenant, user):
    sid = client.post("/v1/sessions", json={"files": {"notes.txt": f"private notes of {user}"}},
                      headers=h(user, tenant)).json()["session_id"]
    v = client.post(f"/v1/sessions/{sid}/turns", json={"message": "create calc.py"}, headers=h(user, tenant)).json()
    assert v["status"] == "awaiting_approval"
    return sid, v["approval"]


def test_export_returns_everything_about_the_user(client, tenant, ws):
    sid, approval = session_with_work(client, tenant, "alice")
    session_with_work(client, tenant, "bob")
    admin = h("boss", tenant, ("admin",))
    data = client.get("/v1/admin/users/alice/export", headers=admin).json()
    assert [s["session_id"] for s in data["sessions"]] == [sid]
    assert data["sessions"][0]["files"]["notes.txt"] == "private notes of alice"
    assert data["sessions"][0]["messages"][0]["content"][0]["text"] == "create calc.py"
    assert [a["approval_id"] for a in data["approvals"]] == [approval["approval_id"]]
    assert client.get("/v1/admin/users/alice/export", headers=h("x", tenant, ("reviewer",))).status_code == 403
    assert client.get("/v1/admin/users/..%2Fetc/export", headers=admin).status_code in (400, 404)


def test_erasure_deletes_sessions_and_pseudonymizes_history(client, tenant, ws, app_pool):
    sid, approval = session_with_work(client, tenant, "alice")
    bob_sid, _ = session_with_work(client, tenant, "bob")
    other = f"lc-{uuid.uuid4().hex[:8]}"
    client.put(f"/v1/admin/tenants/{other}", json={"allowed_providers": ["mock"]}, headers=PLATFORM)
    other_sid, _ = session_with_work(client, other, "alice")  # same user id, other tenant
    admin = h("boss", tenant, ("admin",))
    assert client.delete("/v1/admin/users/alice/data?confirm=bob", headers=admin).status_code == 400
    assert client.delete("/v1/admin/users/alice/data?confirm=alice", headers=h("r", tenant, ("reviewer",))).status_code == 403
    r = client.delete("/v1/admin/users/alice/data?confirm=alice", headers=admin)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["deleted_sessions"] == 1 and result["alias"].startswith("erased-")
    assert not (ws / tenant / sid).exists() and (ws / tenant / bob_sid).exists()
    assert client.get(f"/v1/sessions/{sid}", headers=admin).status_code == 404
    events = client.get("/v1/admin/audit?limit=5000", headers=admin).json()["events"]
    assert not any(e["actor"] == "alice" for e in events)
    assert any(e["actor"] == result["alias"] for e in events)
    assert any(e["event_type"] == "user_erased" and e["actor"] == "boss" for e in events)
    assert client.get("/v1/admin/users/alice/export", headers=admin).json()["sessions"] == []
    # Other users and other tenants are untouched.
    assert client.get(f"/v1/sessions/{bob_sid}", headers=admin).status_code == 200
    assert client.get(f"/v1/sessions/{other_sid}", headers=h("alice", other)).status_code == 200


def test_app_role_cannot_erase_without_tenant_context_or_run_retention(pg):
    with psycopg.connect(pg["app"]) as c:
        with pytest.raises(psycopg.errors.RaiseException):
            c.execute("SELECT harnis_erase_user('alice', 'x')")
    with psycopg.connect(pg["app"]) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM harnis_apply_retention(1, 1)")


def test_tenant_deletion_is_two_step_and_complete(client, tenant, ws, app_pool):
    sid, _ = session_with_work(client, tenant, "alice")
    key = client.post("/v1/admin/api-keys", json={"name": "k"}, headers=h("boss", tenant, ("admin",))).json()["key"]
    assert client.delete(f"/v1/admin/tenants/{tenant}?confirm={tenant}", headers=h("boss", tenant, ("admin",))).status_code == 403
    assert client.delete(f"/v1/admin/tenants/{tenant}?confirm=nope", headers=PLATFORM).status_code == 400
    assert client.delete(f"/v1/admin/tenants/{tenant}?confirm={tenant}", headers=PLATFORM).status_code == 409  # active
    client.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM)
    r = client.delete(f"/v1/admin/tenants/{tenant}?confirm={tenant}", headers=PLATFORM)
    assert r.status_code == 200 and r.json()["deleted_sessions"] == 1
    assert not (ws / tenant).exists()
    assert tenant not in {t["tenant_id"] for t in client.get("/v1/admin/tenants", headers=PLATFORM).json()}
    assert client.get("/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    events = client.get("/v1/admin/platform-events", headers=PLATFORM).json()
    assert any(e["event_type"] == "tenant_deleted" and e["detail"]["tenant_id"] == tenant for e in events)
    assert client.delete(f"/v1/admin/tenants/{tenant}?confirm={tenant}", headers=PLATFORM).status_code == 404


def test_retention_and_orphan_sweep(client, tenant, ws, pg, app_pool):
    from harnis.maintenance import run

    old_sid, _ = session_with_work(client, tenant, "alice")
    new_sid = client.post("/v1/sessions", json={}, headers=h("alice", tenant)).json()["session_id"]
    client.post(f"/v1/sessions/{new_sid}/turns", json={"message": "hours?"}, headers=h("alice", tenant))
    done_sid = client.post("/v1/sessions", json={}, headers=h("alice", tenant)).json()["session_id"]
    client.post(f"/v1/sessions/{done_sid}/turns", json={"message": "hours?"}, headers=h("alice", tenant))
    with psycopg.connect(pg["owner"], autocommit=True) as c:  # age two sessions (one is awaiting approval)
        c.execute("UPDATE sessions SET updated_at = now() - interval '40 days' WHERE session_id = ANY(%s)",
                  ([old_sid, done_sid],))
    orphan = ws / tenant / "sess_orphan0000"
    orphan.mkdir(parents=True)
    old = time.time() - 7200
    os.utime(orphan, (old, old))
    report = run(dsn=pg["owner"], workspaces=str(ws), session_days=30, audit_days=0)
    assert report == {"retention_deleted_sessions": 1, "orphan_workspaces_removed": 1}
    admin = h("boss", tenant, ("admin",))
    assert client.get(f"/v1/sessions/{done_sid}", headers=admin).status_code == 404
    assert client.get(f"/v1/sessions/{old_sid}", headers=admin).status_code == 200  # waiting for a reviewer: kept
    assert client.get(f"/v1/sessions/{new_sid}", headers=admin).status_code == 200
    assert not (ws / tenant / done_sid).exists() and not orphan.exists() and (ws / tenant / new_sid).exists()
