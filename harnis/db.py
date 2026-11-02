# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Postgres access. Every tenant-scoped query goes through `tenant_tx`, which
binds the tenant to the transaction so Row-Level Security filters the rows.

`set_config(..., is_local => true)` is used instead of `SET LOCAL x = %s`:
SET does not accept bind parameters, so it only "works" with client-side
interpolation. set_config is an ordinary function call and is safe with
server-side parameters.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from . import pg

from .config import get_settings

_pool: pg.ConnectionPool | None = None


def get_pool() -> pg.ConnectionPool:
    global _pool
    if _pool is None:
        s = get_settings()
        _pool = pg.ConnectionPool(
            s.database_url,
            min_size=s.db_pool_min,
            max_size=s.db_pool_max,
            kwargs={"row_factory": pg.dict_row},
            open=True,
        )
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def tenant_tx(tenant_id: str, pool: pg.ConnectionPool | None = None) -> Iterator[pg.Connection]:
    if not tenant_id:
        raise ValueError("tenant_id is required for tenant-scoped database access")
    pool = pool or get_pool()
    with pool.connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
            yield conn
