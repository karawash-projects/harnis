# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""harnis.pg picks the PostgreSQL driver: pgtern by default, psycopg on request."""
import pytest


@pytest.fixture
def fresh_pg(monkeypatch):
    import harnis.pg as pg

    monkeypatch.setattr(pg, "_driver", None)
    yield pg
    monkeypatch.setattr(pg, "_driver", None)


def test_default_driver_is_pgtern(fresh_pg, monkeypatch):
    monkeypatch.delenv("DB_DRIVER", raising=False)
    monkeypatch.setattr("harnis.config.get_settings", lambda: type("S", (), {"db_driver": "pgtern"})())
    assert fresh_pg.driver().name == "pgtern"
    import pgtern

    assert fresh_pg.connect is pgtern.connect and fresh_pg.errors.ObjectInUse.__module__.startswith("pgtern")


def test_psycopg_on_request(fresh_pg, monkeypatch):
    pytest.importorskip("psycopg")
    pytest.importorskip("psycopg_pool")
    monkeypatch.setenv("DB_DRIVER", "psycopg")
    assert fresh_pg.driver().name == "psycopg"
    import psycopg

    assert fresh_pg.connect is psycopg.connect and fresh_pg.errors.ObjectInUse is psycopg.errors.ObjectInUse


def test_unknown_driver_is_refused(fresh_pg, monkeypatch):
    monkeypatch.setenv("DB_DRIVER", "mysql")
    with pytest.raises(ImportError, match="DB_DRIVER must be one of"):
        fresh_pg.driver()


def test_both_drivers_expose_the_same_names():
    import harnis.pg as pg

    for name in ("pgtern", "psycopg"):
        try:
            d = pg._load(name)
        except ImportError:
            continue
        for attr in ("connect", "Connection", "Error", "ConnectionPool", "dict_row", "Jsonb", "sql", "errors"):
            assert getattr(d, attr) is not None, (name, attr)
        for err in ("ObjectInUse", "InsufficientPrivilege", "RaiseException", "UniqueViolation"):
            assert hasattr(d.errors, err), (name, err)
        assert hasattr(d.sql, "Identifier") and hasattr(d.sql, "Literal") and hasattr(d.sql, "SQL")


def test_settings_accept_only_known_drivers():
    from pydantic import ValidationError

    from harnis.config import Settings

    assert Settings(_env_file=None, db_driver="psycopg").db_driver == "psycopg"
    with pytest.raises(ValidationError):
        Settings(_env_file=None, db_driver="sqlite")
