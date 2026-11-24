# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Restore drill: back up a database with data and workspaces, damage it,
restore into it, and check everything is back and usable."""
import shutil
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
        assert manifest["tenants"] == 1 and manifest["migrations"][-1].startswith("014")

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


def test_restore_failing_midway_puts_the_previous_database_back(db, tmp_path, monkeypatch):
    import subprocess

    from harnis import backup as backup_mod

    owner, app = db
    ws = tmp_path / "ws"
    ws.mkdir()
    backup = create(tmp_path / "backups", owner, ws)
    real = subprocess.run

    def flaky(cmd, *a, **k):
        if "--single-transaction" in cmd:
            raise subprocess.CalledProcessError(1, cmd)    # fails after the old schema was set aside
        return real(cmd, *a, **k)

    monkeypatch.setattr(backup_mod.subprocess, "run", flaky)
    with pytest.raises(subprocess.CalledProcessError):
        restore(backup, owner, ws, app_password="harnis_app")
    with pgdrv.connect(owner, autocommit=True) as c:
        assert c.execute("SELECT count(*) FROM tenants WHERE tenant_id = 'acme'").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_namespace WHERE nspname = 'harnis_pre_restore'").fetchone()[0] == 0


def test_failed_restore_leaves_the_current_database_and_files_alone(db, tmp_path):
    owner, app = db
    ws = tmp_path / "ws"
    (ws / "acme" / "s1").mkdir(parents=True)
    (ws / "acme" / "s1" / "keep.txt").write_text("current")
    backup = create(tmp_path / "backups", owner, ws)

    # A backup from a newer Harnis is refused before anything is touched.
    import json
    newer = tmp_path / "newer"
    shutil.copytree(backup, newer)
    m = json.loads((newer / "manifest.json").read_text())
    m["migrations"].append("999_from_the_future.sql")
    (newer / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(ValueError, match="newer Harnis"):
        restore(newer, owner, ws, app_password="harnis_app")

    # A truncated workspace archive is refused up front too (the checksum is recomputed to get past verify()).
    from harnis.backup import _sha256
    bad = tmp_path / "bad"
    shutil.copytree(backup, bad)
    arc = bad / "workspaces.tar.gz"
    arc.write_bytes(arc.read_bytes()[:40])
    m = json.loads((bad / "manifest.json").read_text())
    m["files"]["workspaces.tar.gz"] = {"sha256": _sha256(arc), "bytes": 40}
    (bad / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(ValueError, match="workspace archive"):
        restore(bad, owner, ws, app_password="harnis_app")

    # A dump that fails halfway through pg_restore puts the existing database back.
    broken = tmp_path / "broken-dump"
    shutil.copytree(backup, broken)
    dump = broken / "database.dump"
    raw = dump.read_bytes()
    dump.write_bytes(raw[: len(raw) // 2])
    m = json.loads((broken / "manifest.json").read_text())
    m["files"]["database.dump"] = {"sha256": _sha256(dump), "bytes": dump.stat().st_size}
    (broken / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(Exception):
        restore(broken, owner, ws, app_password="harnis_app")
    with pgdrv.connect(owner, autocommit=True) as c:
        assert c.execute("SELECT count(*) FROM tenants WHERE tenant_id = 'acme'").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_namespace WHERE nspname = 'harnis_pre_restore'").fetchone()[0] == 0
    assert (ws / "acme" / "s1" / "keep.txt").read_text() == "current"
