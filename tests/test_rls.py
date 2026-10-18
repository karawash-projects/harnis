# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Tenant isolation, verified against a real Postgres with the real app role."""
import psycopg
import pytest

from harnis.db import tenant_tx
from harnis.orchestrator import ConflictError
from harnis.store import ApprovalError, PgStore

pytestmark = pytest.mark.integration


@pytest.fixture
def store(app_pool):
    return PgStore(app_pool)


@pytest.fixture
def fresh(pg):
    """Two brand-new tenants, so aggregate assertions aren't polluted by other tests."""
    import uuid
    from harnis.migrate import create_tenant
    a, b = f"t_{uuid.uuid4().hex[:6]}", f"t_{uuid.uuid4().hex[:6]}"
    create_tenant(a, a, ["mock"], dsn=pg["owner"])
    create_tenant(b, b, ["mock"], dsn=pg["owner"])
    return a, b


def test_app_role_is_not_superuser_and_cannot_bypass_rls(pg):
    with psycopg.connect(pg["app"]) as c:
        su, bypass = c.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    assert not su and not bypass


def test_sessions_are_invisible_across_tenants(store, app_pool):
    a = store.create_session("acme", "alice")
    assert store.load_session("acme", a.session_id) is not None
    assert store.load_session("globex", a.session_id) is None
    # Even an unfiltered SELECT * only sees the current tenant.
    with tenant_tx("globex", app_pool) as conn:
        assert all(r["tenant_id"] == "globex" for r in conn.execute("SELECT * FROM sessions"))


def test_no_tenant_context_sees_nothing(store, app_pool):
    store.create_session("acme", "alice")
    with app_pool.connection() as conn:
        assert conn.execute("SELECT count(*) AS n FROM sessions").fetchone()["n"] == 0


def test_cannot_write_rows_for_another_tenant(app_pool):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with tenant_tx("acme", app_pool) as conn:
            conn.execute("INSERT INTO sessions (session_id, tenant_id, user_id) VALUES ('x', 'globex', 'eve')")


def test_cannot_move_a_row_to_another_tenant(store, app_pool):
    s = store.create_session("acme", "alice")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with tenant_tx("acme", app_pool) as conn:
            conn.execute("UPDATE sessions SET tenant_id = 'globex' WHERE session_id = %s", (s.session_id,))


def test_rls_is_forced_on_every_tenant_table(pg):
    """FORCE ROW LEVEL SECURITY applies policies to the table owner too, so a
    DATABASE_URL accidentally pointing at the (non-superuser) owner still fails
    closed. Superusers bypass RLS entirely — never run the app as one."""
    with psycopg.connect(pg["owner"]) as c:
        rows = c.execute("SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class"
                         " WHERE relname = ANY(%s)",
                         (["sessions", "approvals", "prompt_registry", "audit_log", "run_metrics",
                           "token_ledger", "tenants", "api_keys"],)).fetchall()
    assert len(rows) == 8 and all(r[1] and r[2] for r in rows)


def test_app_cannot_read_matview_or_partitions_directly(pg):
    with psycopg.connect(pg["app"]) as c:
        for rel in ("run_metrics_hourly_mv", "token_ledger_default"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(f"SELECT * FROM {rel}")
            c.rollback()


def test_analytics_view_only_shows_own_tenant(pg, store, fresh):
    a, b = fresh
    store.record_metric(a, "s1", 100, False, "completed", 3)
    store.record_metric(b, "s2", 200, True, "completed", 2)
    with psycopg.connect(pg["owner"]) as c:  # cron would do this
        c.execute("SET ROLE harnis_analytics")
        c.execute("SELECT refresh_analytics()")
        c.commit()
    rows_a = store.analytics_hourly(a)
    assert len(rows_a) == 1 and rows_a[0]["runs"] == 1 and rows_a[0]["cache_hit_pct"] == 0.0
    assert store.analytics_hourly(b)[0]["cache_hit_pct"] == 100.0


def test_usage_view_respects_rls(store, fresh):
    a, b = fresh
    store.record_usage(a, "s1", "mock", "mock-main", 10, 5, 0.01)
    store.record_usage(b, "s2", "mock", "mock-main", 999, 999, 9.99)
    rows = store.usage_by_model(a)
    assert len(rows) == 1 and rows[0]["input_tokens"] == 10


def test_ledger_partitions_and_default_catch_all(pg, store):
    store.record_usage("acme", "s1", "mock", "mock-main", 1, 1, 0)
    with psycopg.connect(pg["owner"]) as c:
        c.execute("SELECT set_config('app.tenant_id', 'acme', true)")
        # A row far in the future lands in the DEFAULT partition instead of failing.
        c.execute("INSERT INTO token_ledger (tenant_id, session_id, provider, model, logged_at)"
                  " VALUES ('acme', 's', 'mock', 'm', '2099-01-01')")
        parts = [r[0] for r in c.execute(
            "SELECT tableoid::regclass::text FROM token_ledger ORDER BY logged_at")]
    assert parts[-1] == "token_ledger_default" and parts[0].startswith("token_ledger_20")


def test_optimistic_concurrency(store):
    s = store.create_session("acme", "alice")
    a, b = store.load_session("acme", s.session_id), store.load_session("acme", s.session_id)
    a.version = store.save_checkpoint(a)
    with pytest.raises(ConflictError):
        store.save_checkpoint(b)


def test_approval_decision_binds_hash_and_is_single_use(store):
    s = store.create_session("acme", "alice")
    aid = store.create_approval("acme", s.session_id, "alice", {"tool": "run_command"}, "h" * 64)
    with pytest.raises(ApprovalError):
        store.decide_approval("acme", aid, True, "bob", "x" * 64)
    with pytest.raises(ApprovalError):
        store.decide_approval("globex", aid, True, "mallory", "h" * 64)  # other tenant: not found
    _, effective = store.decide_approval("acme", aid, True, "bob", "h" * 64)
    assert effective
    with pytest.raises(ApprovalError):
        store.decide_approval("acme", aid, True, "bob", "h" * 64)


def test_expired_approval_counts_as_denied(app_pool):
    store = PgStore(app_pool, approval_ttl_seconds=-1)
    s = store.create_session("acme", "alice")
    aid = store.create_approval("acme", s.session_id, "alice", {"tool": "x"}, "h" * 64)
    row, effective = store.decide_approval("acme", aid, True, "bob", "h" * 64)
    assert effective is False


def test_audit_log_is_append_only(app_pool, store):
    store.audit("acme", None, "alice", "test", {})
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with tenant_tx("acme", app_pool) as conn:
            conn.execute("DELETE FROM audit_log")


def test_prompt_versions_increment_per_tenant(store, fresh):
    a, b = fresh
    assert store.put_prompt(a, "support", "v1 text here", "admin") == 1
    assert store.put_prompt(a, "support", "v2 text here", "admin") == 2
    assert store.get_prompt(a, "support") == ("v2 text here", 2)
    assert store.get_prompt(b, "support") is None
