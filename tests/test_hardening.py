# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""1.5.0 hardening: findings from the pre-production review."""
import io
import tarfile

import pytest

from harnis import pg as pgdrv
from harnis.orchestrator import Limits
from harnis.sandbox import WorkspaceTooLarge, unpack_workspace

from .conftest import MemoryStore
from .test_lifecycle import PLATFORM, client, h, session_with_work, tenant, ws  # noqa: F401


# -- cache scope (#15) ---------------------------------------------------------------
def test_cache_is_per_user_unless_shared(make_orch):
    store = MemoryStore()
    a, b = store.new_session(), store.new_session()
    a.user_id, b.user_id = "alice", "bob"
    private = make_orch(store)
    assert private._cache_scope(a, "faq:v0") != private._cache_scope(b, "faq:v0")
    assert private._cache_scope(a, "faq:v0") == private._cache_scope(a, "faq:v0")
    shared = make_orch(store, limits=Limits(cache_shared_across_users=True))
    assert shared._cache_scope(a, "faq:v0") == shared._cache_scope(b, "faq:v0") == "faq:v0"


# -- workspace apply is all or nothing (#21) ----------------------------------------
def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_too_large_output_changes_nothing(tmp_path):
    (tmp_path / "keep.py").write_text("old")
    archive = _tar({"workspace/a.py": b"x" * 10, "workspace/b.py": b"y" * 10_000})
    with pytest.raises(WorkspaceTooLarge):
        unpack_workspace(archive, tmp_path, 1000, 10)
    assert not (tmp_path / "a.py").exists()          # nothing was applied
    assert (tmp_path / "keep.py").read_text() == "old"  # nothing was deleted either


# -- API / auth ------------------------------------------------------------------------
@pytest.mark.integration
def test_disabled_tenant_is_refused_for_jwt_too(client, tenant):
    alice = h("alice", tenant)
    assert client.get("/v1/sessions", headers=alice).status_code == 200
    client.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM)
    # The tenant status is cached for a short time per process; the admin update clears it.
    assert client.get("/v1/sessions", headers=alice).status_code == 403
    assert client.get("/v1/agents", headers=alice).status_code == 403


@pytest.mark.integration
def test_bad_token_error_does_not_reveal_parser_details(client):
    r = client.get("/v1/sessions", headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401 and r.json()["detail"] == "invalid token"


@pytest.mark.integration
def test_a_keys_key_belongs_to_the_same_human(client, tenant):
    boss = h("boss", tenant, ("admin",))
    a = client.post("/v1/admin/api-keys", json={"name": "a", "roles": ["admin"]}, headers=boss).json()
    ha = {"Authorization": f"Bearer {a['key']}"}
    client.post("/v1/admin/api-keys", json={"name": "b", "roles": ["user"]}, headers=ha)
    rows = {k["name"]: k for k in client.get("/v1/admin/api-keys", headers=boss).json()}
    assert rows["a"]["created_by"] == "boss" and rows["b"]["created_by"] == "boss"  # not key-<a>


@pytest.mark.integration
def test_unknown_http_methods_do_not_create_metric_series(client):
    client.request("PROPFIND", "/health")
    text = client.get("/metrics").text
    assert 'method="PROPFIND"' not in text


@pytest.mark.integration
def test_a_rejected_seed_leaves_no_session_behind(client, tenant):
    alice = h("alice", tenant)
    before = len(client.get("/v1/sessions", headers=alice).json())
    r = client.post("/v1/sessions", json={"files": {"ok.txt": "x", "../escape.txt": "y"}}, headers=alice)
    assert r.status_code == 400
    assert len(client.get("/v1/sessions", headers=alice).json()) == before


# -- database ------------------------------------------------------------------------
@pytest.mark.integration
def test_partition_job_moves_rows_out_of_the_default_partition(pg):
    with pgdrv.connect(pg["owner"], autocommit=True) as c:
        c.execute("INSERT INTO tenants (tenant_id, name) VALUES ('t-part', 'x') ON CONFLICT DO NOTHING")
        c.execute("INSERT INTO token_ledger (tenant_id, session_id, provider, model, logged_at)"
                  " VALUES ('t-part', 's', 'p', 'm', date_trunc('month', now()) + interval '4 months 3 days')")
        assert c.execute("SELECT count(*) FROM token_ledger_default WHERE tenant_id = 't-part'").fetchone()[0] == 1
        c.execute("SELECT ensure_ledger_partitions(5)")  # used to fail on the overlapping row
        assert c.execute("SELECT count(*) FROM token_ledger_default WHERE tenant_id = 't-part'").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM token_ledger WHERE tenant_id = 't-part'").fetchone()[0] == 1


@pytest.mark.integration
def test_erasure_covers_sessions_made_with_the_users_keys(client, tenant):
    admin = h("boss", tenant, ("admin",))
    key = client.post("/v1/admin/api-keys", json={"name": "k", "roles": ["user"]}, headers=h("alice", tenant, ("admin",))).json()
    hk = {"Authorization": f"Bearer {key['key']}"}
    ksid = client.post("/v1/sessions", json={}, headers=hk).json()["session_id"]
    assert ksid
    bob_sid, _ = session_with_work(client, tenant, "bob")
    r = client.delete("/v1/admin/users/alice/data?confirm=alice", headers=admin)
    assert r.status_code == 200 and r.json()["deleted_sessions"] == 1
    assert client.get("/me", headers=hk).status_code == 401   # the user's key no longer works
    assert client.get(f"/v1/sessions/{bob_sid}", headers=admin).status_code == 200
