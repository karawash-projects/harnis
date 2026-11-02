# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Encrypted connections to PostgreSQL, with each available driver.

Runs against a TLS-enabled server whose certificate is issued for `localhost`
by the CA in HARNIS_TEST_TLS_CA (CI creates both; see the `postgres-tls` job):

    HARNIS_TEST_TLS_DSN=postgresql://postgres:postgres@localhost:5432/postgres
    HARNIS_TEST_TLS_CA=/path/ca.crt  HARNIS_TEST_TLS_OTHER_CA=/path/other-ca.crt
"""
import os
from urllib.parse import urlsplit, urlunsplit

import pytest

DSN = os.environ.get("HARNIS_TEST_TLS_DSN")
CA = os.environ.get("HARNIS_TEST_TLS_CA")
OTHER_CA = os.environ.get("HARNIS_TEST_TLS_OTHER_CA")

pytestmark = pytest.mark.skipif(not (DSN and CA and OTHER_CA),
                                reason="set HARNIS_TEST_TLS_DSN, HARNIS_TEST_TLS_CA and HARNIS_TEST_TLS_OTHER_CA")


def _drivers():
    from harnis import pg

    out = []
    for name in pg.DRIVERS:
        try:
            out.append(pytest.param(pg._load(name), id=name))
        except ImportError:
            out.append(pytest.param(None, id=name, marks=pytest.mark.skip(reason=f"{name} not installed")))
    return out


def _dsn(sslmode: str, rootcert: str | None = None, host: str = "localhost") -> str:
    u = urlsplit(DSN)
    netloc = u.netloc.rsplit("@", 1)
    hostport = netloc[-1].replace("localhost", host, 1) if "localhost" in netloc[-1] else netloc[-1]
    query = f"sslmode={sslmode}" + (f"&sslrootcert={rootcert}" if rootcert else "")
    return urlunsplit((u.scheme, (netloc[0] + "@" if len(netloc) == 2 else "") + hostport, u.path, query, ""))


def _encrypted(conn) -> bool:
    return bool(conn.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").fetchone()[0])


@pytest.mark.parametrize("drv", _drivers())
def test_verify_full_connects_encrypted(drv):
    with drv.connect(_dsn("verify-full", CA)) as conn:
        assert _encrypted(conn)


@pytest.mark.parametrize("drv", _drivers())
def test_require_encrypts_without_checking_the_certificate(drv):
    with drv.connect(_dsn("require")) as conn:
        assert _encrypted(conn)


@pytest.mark.parametrize("drv", _drivers())
def test_untrusted_certificate_authority_is_refused(drv):
    with pytest.raises(drv.Error):
        drv.connect(_dsn("verify-full", OTHER_CA)).close()


@pytest.mark.parametrize("drv", _drivers())
def test_hostname_must_match_the_certificate(drv):
    # The certificate names `localhost`; 127.0.0.1 is the same server, a different name.
    with pytest.raises(drv.Error):
        drv.connect(_dsn("verify-full", CA, host="127.0.0.1")).close()


@pytest.mark.parametrize("drv", _drivers())
def test_verify_ca_accepts_any_name_signed_by_the_ca(drv):
    with drv.connect(_dsn("verify-ca", CA, host="127.0.0.1")) as conn:
        assert _encrypted(conn)


@pytest.mark.parametrize("drv", _drivers())
def test_pool_and_tenant_transactions_over_tls(drv):
    from harnis.db import tenant_tx

    pool = drv.ConnectionPool(_dsn("verify-full", CA), min_size=1, max_size=2,
                              kwargs={"row_factory": drv.dict_row}, open=True)
    try:
        with tenant_tx("acme", pool=pool) as conn:
            row = conn.execute("SELECT current_setting('app.tenant_id') AS t, "
                               "(SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()) AS ssl").fetchone()
        assert row == {"t": "acme", "ssl": True}
    finally:
        pool.close()
