# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Apply SQL migrations as the owner role, and create the runtime roles.

    python -m harnis.migrate              # apply pending migrations
    python -m harnis.migrate --seed demo  # also create demo tenants

Roles:
  harnis_app        LOGIN, the API's role. Not owner, not superuser -> RLS applies.
  harnis_analytics  NOLOGIN, owns the analytics matview (see 001_schema.sql).
  harnis_platform   NOLOGIN, owns the platform functions (see 004_admin_and_api_keys.sql).
"""
from __future__ import annotations

import argparse
from importlib import resources

import psycopg
from psycopg import sql

from .config import get_settings


def _ensure_roles(conn: psycopg.Connection, app_password: str) -> None:
    exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'harnis_app'").fetchone()
    if exists:
        conn.execute(sql.SQL("ALTER ROLE harnis_app WITH LOGIN PASSWORD {}").format(sql.Literal(app_password)))
    else:
        conn.execute(sql.SQL("CREATE ROLE harnis_app LOGIN PASSWORD {}").format(sql.Literal(app_password)))
    # Never let the app role bypass RLS, whatever someone did by hand earlier.
    conn.execute("ALTER ROLE harnis_app NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB")
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'harnis_analytics'").fetchone():
        conn.execute("CREATE ROLE harnis_analytics NOLOGIN NOBYPASSRLS")
    # The migrator must be able to SET ROLE harnis_analytics (needed on
    # managed Postgres where the migrator is not a superuser).
    conn.execute(sql.SQL("GRANT harnis_analytics TO {}").format(sql.Identifier(conn.info.user)))
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'harnis_platform'").fetchone():
        conn.execute("CREATE ROLE harnis_platform NOLOGIN NOBYPASSRLS")
    conn.execute(sql.SQL("GRANT harnis_platform TO {}").format(sql.Identifier(conn.info.user)))
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'harnis_lifecycle'").fetchone():
        conn.execute("CREATE ROLE harnis_lifecycle NOLOGIN NOBYPASSRLS")
    conn.execute(sql.SQL("GRANT harnis_lifecycle TO {}").format(sql.Identifier(conn.info.user)))


def apply_migrations(dsn: str | None = None, app_password: str | None = None,
                     up_to: str | None = None) -> list[str]:
    """Apply pending migrations in order (all, or up to and including `up_to`,
    e.g. "005"). Each runs in its own transaction and is recorded in
    schema_migrations, so running this again only applies new files."""
    settings = get_settings()
    dsn = dsn or settings.migration_database_url
    applied: list[str] = []
    with psycopg.connect(dsn, autocommit=True) as conn:
        _ensure_roles(conn, app_password or settings.app_db_password)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
        files = sorted(
            (f for f in resources.files("harnis.migrations").iterdir() if f.name.endswith(".sql")),
            key=lambda f: f.name,
        )
        for f in files:
            if up_to and f.name[:len(up_to)] > up_to:
                break
            if f.name in done:
                continue
            with conn.transaction():
                conn.execute(f.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (f.name,))
            applied.append(f.name)
    return applied


def create_tenant(tenant_id: str, name: str, allowed_providers: list[str] | None = None,
                  dsn: str | None = None) -> None:
    """Admin operation, runs as owner. FORCE RLS applies to the owner too, so we
    set the tenant context to the tenant being created."""
    dsn = dsn or get_settings().migration_database_url
    with psycopg.connect(dsn) as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
        conn.execute(
            "INSERT INTO tenants (tenant_id, name, allowed_providers) VALUES (%s, %s, %s)"
            " ON CONFLICT (tenant_id) DO UPDATE SET name = EXCLUDED.name,"
            " allowed_providers = EXCLUDED.allowed_providers",
            (tenant_id, name, allowed_providers or ["*"]),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", choices=["demo"], help="create demo tenants")
    args = parser.parse_args()
    applied = apply_migrations()
    print("applied:", ", ".join(applied) if applied else "nothing (up to date)")
    if args.seed == "demo":
        create_tenant("acme", "Acme Corp")
        create_tenant("globex", "Globex (EU, Anthropic only)", ["anthropic", "mock"])
        print("seeded tenants: acme, globex")


if __name__ == "__main__":
    main()
