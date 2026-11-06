# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Regression tests for the pre-production review: capped log reads, bounded metric labels, serialised migrations,
literal-match erasure, key-use bookkeeping, the delete-tenant scope check, queue edge cases and output truncation."""
import hashlib
import threading
import time
import uuid

import pytest

from harnis import pg as pgdrv
from harnis.auth import new_api_key
from harnis.llm.types import LLMResponse, Usage
from harnis.migrate import apply_migrations, create_tenant
from harnis.sandbox import _LOG_COUNT_CAP, read_capped_logs
from harnis.store import PgStore

from .test_queue import PLATFORM, drain, h, new_session, queue_app, tenant  # noqa: F401  (fixtures)


# --- sandbox: output is capped while it is read ------------------------------------------------------------------
class _Chatty:
    def __init__(self, chunks):
        self.chunks, self.read = chunks, 0

    def logs(self, **kw):
        assert kw.get("stream") is True  # never the whole log in one piece
        for c in self.chunks:
            self.read += len(c)
            yield c


def test_log_read_keeps_only_the_limit_and_stops_counting():
    kept, dropped = read_capped_logs(_Chatty([b"a" * 10, b"b" * 10]), 15)
    assert kept == b"a" * 10 + b"b" * 5 and dropped == 5
    big = _Chatty([b"x" * (4 * 1024 * 1024)] * 50)  # 200 MiB of output
    kept, dropped = read_capped_logs(big, 100)
    assert len(kept) == 100 and dropped >= _LOG_COUNT_CAP and big.read < 20 * 1024 * 1024


# --- metrics: the method label cannot be made to grow ------------------------------------------------------------
def test_unknown_http_methods_share_one_metric_label(queue_app):
    c = queue_app[0]
    for m in ("FOOBAR1", "FOOBAR2"):
        c.request(m, "/v1/sessions")
    body = c.get("/metrics").text
    assert 'method="OTHER"' in body and "FOOBAR" not in body


# --- migrations: concurrent runners are serialised ---------------------------------------------------------------
def test_migrations_wait_for_the_advisory_lock(pg):
    holder = pgdrv.connect(pg["owner"], autocommit=True)
    holder.execute("SELECT pg_advisory_lock(hashtext('harnis.migrate'))")
    done = threading.Event()
    t = threading.Thread(target=lambda: (apply_migrations(pg["owner"], app_password="harnis_app"), done.set()))
    t.start()
    try:
        assert not done.wait(0.7), "the runner did not wait for the lock"
    finally:
        holder.execute("SELECT pg_advisory_unlock(hashtext('harnis.migrate'))")
        holder.close()
    t.join(10)
    assert done.is_set()


# --- erasure -----------------------------------------------------------------------------------------------------
@pytest.fixture
def store_and_tenant(pg, app_pool):
    tid = f"rv-{uuid.uuid4().hex[:8]}"
    create_tenant(tid, tid, ["mock"], dsn=pg["owner"])
    return PgStore(app_pool), tid


def test_erasure_matches_the_user_id_literally(store_and_tenant):
    store, tid = store_and_tenant
    sid = store.create_session(tid, "ab%").session_id
    store.audit(tid, sid, "ab%", "note", {"k": "unrelated"})       # does not mention the user: must stay
    store.audit(tid, sid, "sys", "note", {"who": "ab%"})           # quotes the user id: must go
    store.erase_user(tid, "ab%", "boss")
    notes = [e["detail"] for e in store.audit_events(tid) if e["event_type"] == "note"]
    assert {"k": "unrelated"} in notes and {"who": "ab%"} not in notes


def test_erasure_scrubs_export_events_and_revokes_the_keys_the_user_made(store_and_tenant):
    store, tid = store_and_tenant
    store.audit(tid, None, "boss", "user_exported", {"user_id": "carol"})
    store.create_api_key(tid, "kcarol1", "ci", hashlib.sha256(b"s").hexdigest(), ["user"], "carol", None)
    store.create_api_key(tid, "kdave001", "ci", hashlib.sha256(b"s").hexdigest(), ["user"], "dave", None)
    store.erase_user(tid, "carol", "boss")
    exported = [e for e in store.audit_events(tid) if e["event_type"] == "user_exported"]
    assert exported and all("carol" not in str(e["detail"]) for e in exported)
    keys = {k["key_id"]: k["revoked_at"] for k in store.list_api_keys(tid)}
    assert keys["kcarol1"] is not None and keys["kdave001"] is None


# --- API keys: last_used_at only moves after the secret matched --------------------------------------------------
def test_key_use_is_recorded_only_for_a_correct_secret(queue_app, tenant):
    c, app, _ = queue_app
    store = app.state.store
    key_id, _full, secret_hash = new_api_key()
    secret = _full.split("_", 2)[2]
    store.create_api_key(tenant, key_id, "ci", secret_hash, ["user"], "alice", None)
    last = lambda: {k["key_id"]: k["last_used_at"] for k in store.list_api_keys(tenant)}[key_id]  # noqa: E731
    assert store.resolve_api_key(key_id) is not None and last() is None  # resolving alone writes nothing
    bad = {"Authorization": f"Bearer hrn_{key_id}_" + "x" * 43}
    assert c.get("/v1/sessions", headers=bad).status_code == 401 and last() is None
    good = {"Authorization": f"Bearer hrn_{key_id}_{secret}"}
    assert c.get("/v1/sessions", headers=good).status_code == 200 and last() is not None


# --- delete_tenant is a platform operation -----------------------------------------------------------------------
def test_delete_tenant_refuses_to_run_inside_a_tenant_context(store_and_tenant, app_pool):
    store, tid = store_and_tenant
    with app_pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tid,))
        with pytest.raises(Exception, match="platform operation"):
            conn.execute("SELECT harnis_delete_tenant(%s)", (tid,))
    store.set_tenant_active(tid, False) if hasattr(store, "set_tenant_active") else None


# --- queue -------------------------------------------------------------------------------------------------------
def test_job_for_a_disabled_tenant_fails_the_session_instead_of_leaving_it_running(queue_app, tenant):
    c, app, settings = queue_app
    sid = new_session(c, tenant)
    assert c.post(f"/v1/sessions/{sid}/turns", json={"message": "hours?"}, headers=h("alice", tenant)).status_code == 202
    assert c.put(f"/v1/admin/tenants/{tenant}", json={"active": False}, headers=PLATFORM).status_code == 200
    drain(app, settings)
    rec = app.state.store.load_session(tenant, sid)
    assert rec.status == "failed" and "tenant_disabled" in rec.state["flags"]


def test_a_contended_job_is_offered_again_in_seconds_and_does_not_burn_an_attempt(queue_app, tenant):
    c, app, settings = queue_app
    store = app.state.store
    sid = new_session(c, tenant)
    c.post(f"/v1/sessions/{sid}/turns", json={"message": "hours?"}, headers=h("alice", tenant))
    job = store.claim_turn_job(settings.worker_lease_seconds)
    assert job["attempts"] == 1
    store.defer_turn_job(tenant, job["job_id"], settings.worker_lease_seconds, retry_after=1)
    assert store.claim_turn_job(settings.worker_lease_seconds) is None
    time.sleep(1.3)
    again = store.claim_turn_job(settings.worker_lease_seconds)
    assert again and again["job_id"] == job["job_id"] and again["attempts"] == 1


# --- output limit ------------------------------------------------------------------------------------------------
class _Cut:
    name = "cut"

    def __init__(self, blocks):
        self.blocks = blocks
        self.max_tokens_seen = []

    def model_for(self, tier):
        return "mock-main"

    def complete(self, req):
        if req.force_tool:
            return LLMResponse([{"type": "tool_use", "id": "r", "name": "route", "input": {"agent": "coder"}}],
                               "tool_use", Usage(), self.name, "mock-main")
        self.max_tokens_seen.append(req.max_tokens)
        return LLMResponse(self.blocks, "max_tokens", Usage(), self.name, "mock-main")


def test_text_cut_off_at_the_limit_is_flagged_not_silently_returned(store, make_orch):
    p = _Cut([{"type": "text", "text": "The answer is"}])
    rec = make_orch(store, providers=[p]).start_turn(store.new_session(), "explain")
    assert rec.status == "completed" and "output_truncated" in rec.state["flags"]
    assert rec.state["reply"].startswith("The answer is") and "cut off" in rec.state["reply"]
    assert p.max_tokens_seen == [4096]


def test_tool_call_cut_off_at_the_limit_is_not_run(store, make_orch, sandbox):
    p = _Cut([{"type": "tool_use", "id": "w", "name": "write_file", "input": {"path": "a.py", "content": "def f("}}])
    rec = make_orch(store, sandbox, providers=[p]).start_turn(store.new_session(), "write a.py")
    assert rec.status == "failed" and "output_truncated" in rec.state["flags"]
    assert not rec.state.get("pending_tool_calls") and not store.approvals
    assert not any(b["type"] == "tool_use" for m in rec.state["messages"] for b in m["content"])
