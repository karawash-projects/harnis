# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Upgrades: a database created by an earlier schema, holding real data, is
migrated to the current schema; data survives, the app works against it, and
migrating again is a no-op."""
import uuid

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from harnis.migrate import apply_migrations, create_tenant
from harnis.store import PgStore

from .conftest import OWNER_DSN_BASE, _pg_available

pytestmark = pytest.mark.integration
FIRST_RELEASE = "005"  # last migration of 1.0.0's predecessor schema


@pytest.fixture
def old_db():
    if not _pg_available():
        pytest.skip("Postgres not reachable")
    name = "harnis_upgrade_" + uuid.uuid4().hex[:8]
    with psycopg.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    owner = f"{OWNER_DSN_BASE}/{name}"
    yield owner, f"postgresql://harnis_app:harnis_app@{OWNER_DSN_BASE.split('@', 1)[1]}/{name}"
    with psycopg.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_upgrade_keeps_data_and_is_idempotent(old_db):
    owner, app = old_db
    applied = apply_migrations(owner, app_password="harnis_app", up_to=FIRST_RELEASE)
    assert applied[-1].startswith(FIRST_RELEASE)
    create_tenant("acme", "Acme", ["mock"], dsn=owner)
    pool = ConnectionPool(app, kwargs={"row_factory": dict_row}, min_size=1, max_size=2, open=True)
    try:
        store = PgStore(pool)
        rec = store.create_session("acme", "alice")
        rec.state["messages"].append({"role": "user", "content": [{"type": "text", "text": "before upgrade"}]})
        store.save_checkpoint(rec)
        approval = store.create_approval("acme", rec.session_id, "alice", {"tool": "write_file"}, "a" * 64)
        store.create_api_key("acme", "0123456789abcdef", "ci", "f" * 64, ["user"], "boss", None)

        later = apply_migrations(owner, app_password="harnis_app")
        assert later and all(n[:3] > FIRST_RELEASE for n in later)
        assert apply_migrations(owner, app_password="harnis_app") == []  # second run: nothing to do

        again = store.load_session("acme", rec.session_id)
        assert again.state["messages"][-1]["content"][0]["text"] == "before upgrade"
        assert store.get_approval("acme", approval)["status"] == "pending"
        assert store.resolve_api_key("0123456789abcdef")["tenant_id"] == "acme"
        # Features added by later migrations work on the upgraded data.
        assert store.export_user("acme", "alice")["sessions"][0]["session_id"] == rec.session_id
        assert store.erase_user("acme", "alice", "boss")["deleted_sessions"] == 1
    finally:
        pool.close()
