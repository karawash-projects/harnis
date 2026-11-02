# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The PostgreSQL driver, chosen once per process.

* ``pgtern`` (default): pure Python, no dependencies, Apache-2.0.
* ``psycopg`` 3: optional, LGPL-3.0. Install with ``pip install "harnis[psycopg]"``
  and set ``DB_DRIVER=psycopg``.

Both expose the same interface, so the rest of Harnis imports everything it
needs from here: ``connect``, ``ConnectionPool``, ``Connection``, ``dict_row``,
``Jsonb``, ``sql`` and ``errors`` (``pg.errors.ObjectInUse`` ...). Names resolve on
first use, after the settings (``DB_DRIVER`` in the environment or ``.env``) are
known.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

DRIVERS = ("pgtern", "psycopg")
_driver: SimpleNamespace | None = None


def _configured() -> str:
    name = os.environ.get("DB_DRIVER", "").strip().lower()
    if not name:
        try:
            from .config import get_settings

            name = get_settings().db_driver
        except Exception:  # settings unavailable (e.g. a standalone script): use the default
            name = "pgtern"
    if name not in DRIVERS:
        raise ImportError(f"DB_DRIVER must be one of {', '.join(DRIVERS)}, got {name!r}")
    return name


def _load(name: str) -> SimpleNamespace:
    if name == "psycopg":
        try:
            import psycopg
            from psycopg import errors, sql
            from psycopg.rows import dict_row
            from psycopg.types.json import Jsonb
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise ImportError('DB_DRIVER=psycopg needs the psycopg extra: pip install "harnis[psycopg]"') from exc
        return SimpleNamespace(name="psycopg", connect=psycopg.connect, Connection=psycopg.Connection,
                               Error=psycopg.Error, ConnectionPool=ConnectionPool, dict_row=dict_row,
                               Jsonb=Jsonb, sql=sql, errors=errors, module=psycopg)
    import pgtern
    from pgtern import ConnectionPool, errors, sql
    from pgtern.rows import dict_row
    from pgtern.types.json import Jsonb

    return SimpleNamespace(name="pgtern", connect=pgtern.connect, Connection=pgtern.Connection, Error=pgtern.Error,
                           ConnectionPool=ConnectionPool, dict_row=dict_row, Jsonb=Jsonb, sql=sql, errors=errors,
                           module=pgtern)


def driver() -> SimpleNamespace:
    global _driver
    if _driver is None:
        _driver = _load(_configured())
    return _driver


def __getattr__(name: str) -> Any:  # pg.connect, pg.ConnectionPool, pg.errors, ...
    if name.startswith("__"):
        raise AttributeError(name)
    d = driver()
    try:
        return getattr(d, name)
    except AttributeError:
        raise AttributeError(f"module 'harnis.pg' has no attribute {name!r}") from None
