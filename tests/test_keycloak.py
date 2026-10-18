# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Single sign-on against a REAL Keycloak with the local "harnis" realm
(deploy/keycloak/harnis-realm.json, started by `python tasks.py sso-up`).

Skipped unless KEYCLOAK_URL is set, e.g.

    KEYCLOAK_URL=http://127.0.0.1:8080 python -m pytest tests/test_keycloak.py

  * Tokens from the password grant (local-only "harnis-check" client) map to
    the right Harnis user, tenant and role through a Harnis app served in-process.
  * The browser test signs in through the real Keycloak login page with the
    console's authorization code + PKCE flow and signs out through Keycloak's
    end_session endpoint. The console's redirect URI must be registered in the
    realm, so the app is served on the fixed port KEYCLOAK_TEST_APP_PORT
    (default 8011; http://127.0.0.1:8011/* is a redirect URI of the
    harnis-console client in the realm file).
"""
import importlib.util
import json
import os
import socket
from pathlib import Path
from urllib import request as urlrequest

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.keycloak]

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "").rstrip("/")
APP_PORT = int(os.environ.get("KEYCLOAK_TEST_APP_PORT", "8011"))

if not KEYCLOAK_URL:
    pytest.skip("KEYCLOAK_URL not set (start Keycloak with `python tasks.py sso-up`)", allow_module_level=True)


def _load_helper():
    path = Path(__file__).resolve().parent.parent / "scripts" / "keycloak_local.py"
    spec = importlib.util.spec_from_file_location("keycloak_local", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kc = _load_helper()
_NO_PROXY = urlrequest.build_opener(urlrequest.ProxyHandler({}))


@pytest.fixture(scope="module")
def keycloak():
    try:
        kc.wait(KEYCLOAK_URL, timeout=10)
    except TimeoutError as exc:
        pytest.skip(str(exc))
    return KEYCLOAK_URL


def oidc_overrides(url: str) -> dict:
    """The settings `keycloak_local.py env` writes to .env, as Settings kwargs."""
    return {k.lower(): v for k, v in kc.oidc_settings(url).items()}


def get_me(base: str, token: str) -> dict:
    req = urlrequest.Request(base + "/me", headers={"Authorization": "Bearer " + token})
    with _NO_PROXY.open(req, timeout=10) as r:
        return json.loads(r.read())


# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def served_app(keycloak, tmp_path_factory, app_pool):
    import redis

    from .test_console import harnis_app, serve

    r = redis.Redis.from_url(os.getenv("TEST_REDIS_URL", "redis://127.0.0.1:6379/15"))
    try:
        r.ping()
    except Exception:
        pytest.skip("Redis not reachable (run `python tasks.py up`)")
    app = harnis_app(tmp_path_factory.mktemp("kc"), app_pool, r, **oidc_overrides(keycloak))
    with serve(app) as url:
        yield url


@pytest.mark.parametrize("user, role, tenant", [
    ("alice", "user", "acme"),
    ("rita", "reviewer", "acme"),
    ("adam", "admin", "acme"),
    ("gina", "admin", "globex"),
    ("ops", "platform-admin", "platform"),
])
def test_keycloak_tokens_map_to_harnis_roles(served_app, keycloak, user, role, tenant):
    me = get_me(served_app, kc.token(keycloak, user))
    assert me == {"user_id": user, "tenant_id": tenant, "roles": [role], "via": "oidc"}


def test_keycloak_id_token_is_not_accepted_as_api_token(served_app, keycloak):
    """The ID token's audience is the client, not harnis-api."""
    from urllib.error import HTTPError

    with pytest.raises(HTTPError) as exc:
        get_me(served_app, kc.token(keycloak, "adam", which="id_token"))
    assert exc.value.code == 401


# ---------------------------------------------------------------------------
# The console in a real browser against the real Keycloak login page
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    try:
        with sync_api.sync_playwright() as p:
            b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_EXECUTABLE") or None)
            yield b
            b.close()
    except Exception as exc:  # no browser installed
        pytest.skip(f"Chromium not available: {exc}")


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.mark.browser
def test_console_sso_with_keycloak_login_page(browser, keycloak, tmp_path, app_pool, redis_client, monkeypatch):
    from playwright.sync_api import expect

    from . import test_console

    if not _port_free(APP_PORT):
        pytest.skip(f"port {APP_PORT} is busy (set KEYCLOAK_TEST_APP_PORT to a port registered in the realm)")
    # serve() picks a random port; the redirect URI registered in Keycloak needs a fixed one.
    monkeypatch.setattr(test_console, "free_port", lambda: APP_PORT)
    app = test_console.harnis_app(tmp_path, app_pool, redis_client, **oidc_overrides(keycloak))

    ctx = browser.new_context()
    page = ctx.new_page()
    errors: list[str] = []
    # Only the Harnis console's own errors count (CSP violations show up here).
    page.on("console", lambda m: errors.append(m.text)
            if m.type == "error" and page.url.startswith(f"http://127.0.0.1:{APP_PORT}") else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        with test_console.serve(app) as url:
            assert url == f"http://127.0.0.1:{APP_PORT}"
            resp = page.goto(url + "/")
            assert keycloak in resp.headers["content-security-policy"]  # token endpoint allowed
            page.click("#sso")

            # The real Keycloak login page for the harnis realm.
            page.wait_for_url(keycloak + "/realms/harnis/protocol/openid-connect/auth*")
            page.fill("#username", "adam")
            page.fill("#password", kc.LOCAL_PASSWORD)
            page.click("#kc-login")

            page.wait_for_url(url + "/**", timeout=15000)
            expect(page.locator(".topbar")).to_contain_text("adam", timeout=15000)
            expect(page.locator(".topbar")).to_contain_text("admin")
            expect(page.locator(".topbar")).to_contain_text("acme")
            expect(page.locator(".nav")).to_contain_text("API keys")  # tenant admin
            assert "code=" not in page.url

            # Sign out: Keycloak end_session (with id_token_hint, so no confirmation
            # page), then back to the console's sign-in screen.
            page.click("#signOut")
            page.wait_for_url(url + "/**", timeout=15000)
            expect(page.locator("#sso")).to_be_visible(timeout=15000)

            # The Keycloak session really ended: SSO asks for the password again.
            page.click("#sso")
            page.wait_for_url(keycloak + "/realms/harnis/protocol/openid-connect/auth*")
            expect(page.locator("#username")).to_be_visible()
    finally:
        ctx.close()
    assert not test_console.console_errors(errors), errors
