# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Console configuration endpoint, security headers, and turning the console off."""
import fakeredis
from fastapi.testclient import TestClient

from harnis.api import create_app
from harnis.auth import Authenticator, OIDCVerifier
from harnis.config import Settings
from harnis.llm.providers import MockProvider
from harnis.llm.router import LLMRouter

IDP = "https://idp.example.com"
DISCO = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": "https://tokens.example.net/token",
         "jwks_uri": IDP + "/jwks", "end_session_endpoint": IDP + "/logout"}


def app_with(tmp_path, fetch=None, **kw):
    s = Settings(_env_file=None, workspaces_dir=str(tmp_path), **kw)
    auth = None
    if s.auth_mode == "oidc":
        auth = Authenticator(s, None, OIDCVerifier(s, fetch_json=fetch or (lambda url: DISCO)))
    return create_app(s, store=object(), redis=fakeredis.FakeRedis(), router=LLMRouter([MockProvider()]), auth=auth)


def test_local_development_offers_dev_token(tmp_path):
    with TestClient(app_with(tmp_path, env="development")) as c:
        cfg = c.get("/v1/auth/config").json()
        assert cfg == {"auth_mode": "local", "version": cfg["version"], "dev_token": True, "oidc": None}


def test_oidc_console_config_from_discovery(tmp_path):
    app = app_with(tmp_path, auth_mode="oidc", oidc_issuer=IDP, oidc_audience="harnis-api",
                   oidc_console_client_id="console", oidc_console_extra_params={"audience": "harnis-api"})
    with TestClient(app) as c:
        cfg = c.get("/v1/auth/config").json()
        assert cfg["dev_token"] is False
        o = cfg["oidc"]
        assert o["client_id"] == "console" and o["authorization_endpoint"] == IDP + "/authorize"
        assert o["token"] == "access_token" and o["extra_params"] == {"audience": "harnis-api"}
        csp = c.get("/").headers["content-security-policy"]
        assert "https://tokens.example.net" in csp  # the browser may call the token endpoint
        assert "script-src 'self';" in csp and "'unsafe-inline'" not in csp


def test_oidc_without_console_client_has_no_sso_button(tmp_path):
    app = app_with(tmp_path, auth_mode="oidc", oidc_issuer=IDP, oidc_audience="harnis-api")
    with TestClient(app) as c:
        assert c.get("/v1/auth/config").json()["oidc"] is None


def test_unreachable_idp_is_reported_not_fatal(tmp_path):
    def down(url):
        raise OSError("connection refused")

    app = app_with(tmp_path, fetch=down, auth_mode="oidc", oidc_issuer=IDP, oidc_audience="harnis-api",
                   oidc_console_client_id="console")
    with TestClient(app) as c:
        assert "could not be reached" in c.get("/v1/auth/config").json()["oidc"]["error"]
        assert c.get("/").status_code == 200


def test_security_headers_everywhere_and_hsts_in_production(tmp_path):
    with TestClient(app_with(tmp_path)) as c:
        r = c.get("/health")
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
        assert "content-security-policy" not in r.headers  # /docs keeps working
        assert "strict-transport-security" not in r.headers
        assert c.get("/static/console.js").headers["content-type"].startswith(("text/javascript", "application/javascript"))
    prod = app_with(tmp_path, env="production", jwt_secret="x" * 40, llm_providers="anthropic",
                    database_url="postgresql://harnis_app:a-long-random-password@db:5432/harnis")
    with TestClient(prod) as c:
        assert "max-age" in c.get("/health").headers["strict-transport-security"]


def test_console_can_be_disabled(tmp_path):
    with TestClient(app_with(tmp_path, console_enabled=False)) as c:
        assert c.get("/").json()["docs"] == "/docs"
        assert c.get("/static/console.js").status_code == 404


def test_env_must_be_spelled_exactly_and_default_db_passwords_are_refused_in_production():
    import pytest
    from harnis.config import Settings

    strong = dict(jwt_secret="x" * 40, llm_providers="anthropic",
                  database_url="postgresql://harnis_app:a-long-random-password@db:5432/harnis")
    for bad in ("prod", "staging", ""):
        with pytest.raises(ValueError, match="ENV must be"):
            Settings(_env_file=None, env=bad, **strong)
    assert Settings(_env_file=None, env=" Production ", **strong).env == "production"
    with pytest.raises(ValueError, match="default or well-known password"):
        Settings(_env_file=None, env="production", jwt_secret="x" * 40, llm_providers="anthropic")


def test_maintenance_job_starts_in_production_without_the_api_secrets():
    """The Helm CronJob loads ENV=production but not JWT_SECRET: it runs as COMPONENT=job."""
    import pytest
    from harnis.config import Settings

    with pytest.raises(ValueError):  # as the API it refuses to start (no strong secret, mock provider, ...)
        Settings(_env_file=None, env="production")
    assert Settings(_env_file=None, env="production", component="job").component == "job"
    with pytest.raises(ValueError, match="COMPONENT"):
        Settings(_env_file=None, component="worker")
    cron = open("deploy/helm/harnis/templates/maintenance-cronjob.yaml").read()
    assert 'name: COMPONENT' in cron and '"job"' in cron
