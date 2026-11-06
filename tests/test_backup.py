# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Restore drill: back up a database with data and workspaces, damage it,
restore into it, and check everything is back and usable."""
import hashlib
import json
import shutil
import subprocess
import uuid

from harnis import pg as pgdrv
import pytest

from harnis.backup import create, restore, verify
from harnis.migrate import apply_migrations, create_tenant
from harnis.store import PgStore

from .conftest import OWNER_DSN_BASE, _pg_available

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    if not _pg_available() or not shutil.which("pg_dump"):
        pytest.skip("needs Postgres and pg_dump/pg_restore on PATH (python tasks.py backup uses the container's)")
    name = "harnis_backup_" + uuid.uuid4().hex[:8]
    with pgdrv.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    owner = f"{OWNER_DSN_BASE}/{name}"
    apply_migrations(owner, app_password="harnis_app")
    create_tenant("acme", "Acme", ["mock"], dsn=owner)
    yield owner, f"postgresql://harnis_app:harnis_app@{OWNER_DSN_BASE.split('@', 1)[1]}/{name}"
    with pgdrv.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_backup_and_restore_drill(db, tmp_path):
    owner, app = db
    ws = tmp_path / "ws"
    (ws / "acme" / "sess_x").mkdir(parents=True)
    (ws / "acme" / "sess_x" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    pool = pgdrv.ConnectionPool(app, kwargs={"row_factory": pgdrv.dict_row}, min_size=1, max_size=2, open=True)
    try:
        store = PgStore(pool)
        rec = store.create_session("acme", "alice")
        store.audit("acme", rec.session_id, "alice", "session_created", {})

        backup = create(tmp_path / "backups", owner, ws)
        manifest = verify(backup)
        assert manifest["tenants"] == 1 and manifest["migrations"][-1].startswith("010")

        # Disaster: data deleted, files lost, a tampered backup is refused.
        with pgdrv.connect(owner, autocommit=True) as c:
            c.execute("SELECT set_config('app.tenant_id', 'acme', false)")
            c.execute("DELETE FROM sessions")
        shutil.rmtree(ws)
        broken = tmp_path / "broken"
        shutil.copytree(backup, broken)
        (broken / "workspaces.tar.gz").write_bytes(b"tampered")
        with pytest.raises(ValueError, match="checksum"):
            verify(broken)

        result = restore(backup, owner, ws, app_password="harnis_app")
        assert result["migrations_applied"] == []
        pool.close()
        pool = pgdrv.ConnectionPool(app, kwargs={"row_factory": pgdrv.dict_row}, min_size=1, max_size=2, open=True)
        store = PgStore(pool)
        assert store.load_session("acme", rec.session_id).user_id == "alice"
        assert (ws / "acme" / "sess_x" / "calc.py").read_text().startswith("def add")
        assert any(e["event_type"] == "session_created" for e in store.audit_events("acme"))
        # The restored database still enforces tenant isolation for the app role.
        assert store.load_session("globex", rec.session_id) is None
    finally:
        pool.close()


def test_failed_restore_puts_the_current_data_and_workspaces_back(db, tmp_path):
    owner, app = db
    ws = tmp_path / "ws"
    (ws / "acme" / "sess_x").mkdir(parents=True)
    (ws / "acme" / "sess_x" / "keep.txt").write_text("live data")
    pool = pgdrv.ConnectionPool(app, kwargs={"row_factory": pgdrv.dict_row}, min_size=1, max_size=2, open=True)
    try:
        rec = PgStore(pool).create_session("acme", "alice")
        backup = create(tmp_path / "backups", owner, ws)
        # A backup whose checksums are right but whose dump is not a dump: pg_restore fails after the schema swap.
        (backup / "database.dump").write_bytes(b"not a postgres dump")
        m = json.loads((backup / "manifest.json").read_text())
        m["files"]["database.dump"] = {"sha256": hashlib.sha256(b"not a postgres dump").hexdigest(), "bytes": 19}
        (backup / "manifest.json").write_text(json.dumps(m))
        with pytest.raises(subprocess.CalledProcessError):
            restore(backup, owner, ws, app_password="harnis_app")
        pool.close()
        pool = pgdrv.ConnectionPool(app, kwargs={"row_factory": pgdrv.dict_row}, min_size=1, max_size=2, open=True)
        assert PgStore(pool).load_session("acme", rec.session_id).user_id == "alice"
        assert (ws / "acme" / "sess_x" / "keep.txt").read_text() == "live data"
        with pgdrv.connect(owner) as c:
            leftovers = c.execute("SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'harnis_pre_restore_%'").fetchone()[0]
        assert leftovers == 0
    finally:
        pool.close()
