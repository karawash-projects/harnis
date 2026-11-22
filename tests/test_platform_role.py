# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The optional separate login for platform administration."""
import shutil
import uuid

import pytest

from harnis import pg as pgdrv
from harnis.config import get_settings
from harnis.migrate import apply_migrations, create_tenant, platform_enforced, set_platform_enforcement
from harnis.store import PgStore

from .conftest import OWNER_DSN_BASE, _pg_available

pytestmark = pytest.mark.integration


@pytest.fixture
def db(monkeypatch):
    if not _pg_available():
        pytest.skip("Postgres not reachable (run `python tasks.py up`)")
    monkeypatch.setenv("PLATFORM_DB_PASSWORD", "ops-pw")
    get_settings.cache_clear()
    name = "harnis_plat_" + uuid.uuid4().hex[:8]
    with pgdrv.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    owner = f"{OWNER_DSN_BASE}/{name}"
    apply_migrations(owner, app_password="harnis_app")
    create_tenant("acme", "Acme", ["mock"], dsn=owner)
    host = OWNER_DSN_BASE.split("@", 1)[1]
    yield owner, f"postgresql://harnis_app:harnis_app@{host}/{name}", f"postgresql://harnis_platform_ops:ops-pw@{host}/{name}"
    with pgdrv.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    get_settings.cache_clear()


def pool(dsn):
    return pgdrv.ConnectionPool(dsn, kwargs={"row_factory": pgdrv.dict_row}, min_size=1, max_size=2, open=True)


def test_enforcing_the_platform_login_takes_platform_administration_from_the_app_login(db):
    owner, app, ops = db
    app_pool, ops_pool = pool(app), pool(ops)
    try:
        assert platform_enforced(owner) is False
        PgStore(app_pool).admin_list_tenants()                      # default: the app login can still do it

        assert set_platform_enforcement(owner, True) == "enforced" and platform_enforced(owner) is True
        with pytest.raises(pgdrv.errors.InsufficientPrivilege):
            PgStore(app_pool).admin_list_tenants()
        with pytest.raises(pgdrv.errors.InsufficientPrivilege):
            PgStore(app_pool).delete_tenant("acme", "x")
        with pytest.raises(pgdrv.errors.InsufficientPrivilege):
            PgStore(app_pool).platform_events()

        platform_store = PgStore(app_pool, platform_pool=ops_pool)  # tenant work on the app login, platform work on the other
        assert any(t["tenant_id"] == "acme" for t in platform_store.admin_list_tenants())
        platform_store.admin_upsert_tenant("acme", None, None, None, False, "ops")
        assert platform_store.delete_tenant("acme", "ops")["tenant_id"] == "acme"
        assert platform_store.platform_events()[0]["event_type"] == "tenant_deleted"
        # Ordinary tenant-facing queries still work on the app login.
        assert PgStore(app_pool).tenant_active("acme") is False

        assert set_platform_enforcement(owner, False) == "relaxed"
        PgStore(app_pool).admin_list_tenants()
    finally:
        app_pool.close()
        ops_pool.close()
