# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Backup and restore: the database (pg_dump custom format) and the session
workspaces (tar.gz), with a manifest of checksums and the schema version.

    python -m harnis.backup create  --out backups/
    python -m harnis.backup verify  backups/harnis-20261017-1530
    python -m harnis.backup restore backups/harnis-20261017-1530 --yes

Runs as the owner/migration role (MIGRATION_DATABASE_URL). Redis holds only
caches, rate-limit buckets and locks, so it is not backed up.

`pg_dump`/`pg_restore` must be at least the server's major version. Without
them on PATH, pass a command prefix that runs them elsewhere, for example the
Postgres container of the local stack:
    --pg-bin "docker compose exec -T postgres"
(`python tasks.py backup` and `restore` do this for you.)

Restoring replaces the database contents (the `public` schema is emptied
first) and the workspaces, then applies any newer migrations, so a backup taken by an older
Harnis version can be restored into a newer one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg

from . import __version__
from .config import get_settings


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _dsn_for(prefix: list[str], dsn: str) -> str:
    """Inside a container (prefix given) the server is on localhost:5432."""
    if not prefix:
        return dsn
    u = urlsplit(dsn)
    netloc = (u.netloc.rsplit("@", 1)[0] + "@" if "@" in u.netloc else "") + "localhost:5432"
    return urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment))


def create(out_dir: Path, dsn: str, workspaces: Path, pg_bin: str = "") -> Path:
    prefix = shlex.split(pg_bin)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = out_dir / f"harnis-{stamp}"
    target.mkdir(parents=True, exist_ok=False)
    dump = target / "database.dump"
    with dump.open("wb") as f:
        # The analytics materialized view is derived data: restored empty and
        # refreshed afterwards (pg_restore can't refresh it under forced RLS).
        subprocess.run([*prefix, "pg_dump", "--format=custom", "--exclude-table-data=run_metrics_hourly_mv",
                        "--dbname", _dsn_for(prefix, dsn)], stdout=f, check=True)
    archive = target / "workspaces.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        if workspaces.is_dir():
            tar.add(workspaces, arcname="workspaces", filter=lambda ti: None if ti.issym() or ti.islnk() else ti)
    with psycopg.connect(dsn) as conn:
        migrations = [r[0] for r in conn.execute("SELECT name FROM schema_migrations ORDER BY name")]
        tenants = conn.execute("SELECT count(*) FROM harnis_admin_list_tenants()").fetchone()[0]
    manifest = {"harnis_version": __version__, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "migrations": migrations, "tenants": tenants,
                "files": {p.name: {"sha256": _sha256(p), "bytes": p.stat().st_size} for p in (dump, archive)}}
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return target


def verify(backup: Path) -> dict:
    manifest = json.loads((backup / "manifest.json").read_text())
    for name, meta in manifest["files"].items():
        p = backup / name
        if not p.is_file() or _sha256(p) != meta["sha256"]:
            raise ValueError(f"{name} is missing or does not match its checksum")
    return manifest


def restore(backup: Path, dsn: str, workspaces: Path, pg_bin: str = "", app_password: str | None = None) -> dict:
    from .migrate import _ensure_roles, apply_migrations

    manifest = verify(backup)
    prefix = shlex.split(pg_bin)
    with psycopg.connect(dsn, autocommit=True) as conn:
        _ensure_roles(conn, app_password or get_settings().app_db_password)  # roles are cluster-wide
        # Restore into an empty schema. (`pg_restore --clean` can't drop the
        # inherited constraints of the partitioned token ledger.)
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")
        # Match a fresh database's `public` schema: the dump only records
        # privileges that differ from that default.
        conn.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
        if conn.info.server_version >= 150000:
            conn.execute("ALTER SCHEMA public OWNER TO pg_database_owner")
    with (backup / "database.dump").open("rb") as f:
        subprocess.run([*prefix, "pg_restore", "--single-transaction", "--exit-on-error",
                        "--dbname", _dsn_for(prefix, dsn)], stdin=f, check=True)
    root = workspaces.resolve()
    with tarfile.open(backup / "workspaces.tar.gz", "r:gz") as tar:
        members = []
        for m in tar.getmembers():
            parts = Path(m.name).parts
            if not parts or parts[0] != "workspaces" or ".." in parts or not (m.isfile() or m.isdir()):
                continue
            members.append(m)
        if root.exists():
            import shutil
            shutil.rmtree(root)
        root.mkdir(parents=True)
        for m in members:
            rel = Path(*Path(m.name).parts[1:]) if len(Path(m.name).parts) > 1 else Path()
            dest = root / rel
            if root not in dest.resolve().parents and dest.resolve() != root:
                continue
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(m)
                if src is not None:
                    dest.write_bytes(src.read())
    newer = apply_migrations(dsn, app_password=app_password)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("SET ROLE harnis_analytics")
        conn.execute("SELECT refresh_analytics()")
    return {"restored_from": str(backup), "backup_version": manifest["harnis_version"], "migrations_applied": newer}


def main(argv: list[str] | None = None) -> int:
    s = get_settings()
    ap = argparse.ArgumentParser(description="Back up or restore Harnis (database + workspaces)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--out", default="backups")
    v = sub.add_parser("verify")
    v.add_argument("backup")
    r = sub.add_parser("restore")
    r.add_argument("backup")
    r.add_argument("--yes", action="store_true", help="confirm: replaces the database and the workspaces")
    for p in (c, r):
        p.add_argument("--dsn", default=s.migration_database_url)
        p.add_argument("--workspaces", default=s.workspaces_dir)
        p.add_argument("--pg-bin", default="", help='command prefix for pg_dump/pg_restore, e.g. '
                       '"docker compose exec -T postgres"')
    a = ap.parse_args(argv)
    if a.cmd == "create":
        path = create(Path(a.out), a.dsn, Path(a.workspaces), a.pg_bin)
        print(f"backup written to {path}")
    elif a.cmd == "verify":
        m = verify(Path(a.backup))
        print(f"ok: Harnis {m['harnis_version']}, {m['tenants']} tenants, schema {m['migrations'][-1]}")
    else:
        if not a.yes:
            print("Restoring replaces the database and the workspaces. Re-run with --yes to proceed.")
            return 2
        print(json.dumps(restore(Path(a.backup), a.dsn, Path(a.workspaces), a.pg_bin), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
