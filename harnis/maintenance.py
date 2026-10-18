# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Periodic database maintenance. Run hourly as the owner/migration role, from
cron, a systemd timer, pg_cron, Windows Task Scheduler or the Helm chart's
CronJob:

    python -m harnis.maintenance

* creates the next months' ledger partitions ahead of time, so rows land in
  real partitions rather than the DEFAULT catch-all;
* applies data retention (RETENTION_SESSION_DAYS, RETENTION_AUDIT_DAYS; 0 keeps
  data forever) and removes the deleted sessions' workspaces;
* removes workspaces whose session no longer exists (user erasure or tenant
  deletion on another replica, or a crash between the two steps);
* refreshes the analytics materialized view as `harnis_analytics`.

Approval expiry needs no job: an expired approval is treated as denied at
decision time and hidden from the pending list.
"""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

import psycopg

from .config import get_settings

log = logging.getLogger(__name__)
ORPHAN_MIN_AGE_SECONDS = 3600  # never touch a workspace younger than this (session being created)


def sweep_workspaces(conn: psycopg.Connection, workspaces: Path, now: float | None = None) -> int:
    """Delete workspace folders whose session no longer exists."""
    if not workspaces.is_dir():
        return 0
    now = now or time.time()
    candidates: dict[str, Path] = {}
    for tenant_dir in workspaces.iterdir():
        if not tenant_dir.is_dir():
            continue
        for sdir in tenant_dir.iterdir():
            if sdir.is_dir() and sdir.name.startswith("sess_") and now - sdir.stat().st_mtime > ORPHAN_MIN_AGE_SECONDS:
                candidates[sdir.name] = sdir
    removed = 0
    ids = list(candidates)
    for i in range(0, len(ids), 1000):
        batch = ids[i:i + 1000]
        alive = {r[0] for r in conn.execute("SELECT harnis_existing_sessions(%s)", (batch,))}
        for sid in batch:
            if sid not in alive:
                shutil.rmtree(candidates[sid], ignore_errors=True)
                removed += 1
    return removed


def run(dsn: str | None = None, workspaces: str | None = None, session_days: int | None = None,
        audit_days: int | None = None) -> dict[str, int]:
    s = get_settings()
    dsn = dsn or s.migration_database_url
    ws = Path(workspaces or s.workspaces_dir)
    session_days = s.retention_session_days if session_days is None else session_days
    audit_days = s.retention_audit_days if audit_days is None else audit_days
    report = {"retention_deleted_sessions": 0, "orphan_workspaces_removed": 0}
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("SELECT ensure_ledger_partitions(3)")
        if session_days or audit_days:
            rows = conn.execute("SELECT * FROM harnis_apply_retention(%s, %s)",
                                (session_days, audit_days)).fetchall()
            for tenant_id, session_id in rows:
                shutil.rmtree(ws / tenant_id / session_id, ignore_errors=True)
            report["retention_deleted_sessions"] = len(rows)
        report["orphan_workspaces_removed"] = sweep_workspaces(conn, ws)
        conn.execute("SET ROLE harnis_analytics")
        conn.execute("SELECT refresh_analytics()")
        conn.execute("RESET ROLE")
    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = run()
    print("maintenance complete:", ", ".join(f"{k}={v}" for k, v in result.items()))
