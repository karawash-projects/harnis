# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""keycloak_local: helpers for the local Keycloak single sign-on setup.

LOCAL TESTING ONLY. It talks to the "harnis" realm imported from
deploy/keycloak/harnis-realm.json (started by `python tasks.py sso-up`), whose
users have well-known passwords and whose "harnis-check" client allows the
password grant. Never point it at a real identity provider.

Standalone: Python 3.9+ standard library only (tasks.py runs it before the
virtualenv may exist). Subcommands:

  env    --port 8080                     print the .env settings for AUTH_MODE=oidc
  wait   --url http://127.0.0.1:8080     wait until the realm answers
  tokens --url ... --user adam           print an access token (password grant)
  check  --url ... --api http://127.0.0.1:8000 [harnis_check args]
                                         run scripts/harnis_check.py with Keycloak tokens
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REALM = "harnis"
AUDIENCE = "harnis-api"
CONSOLE_CLIENT = "harnis-console"
CHECK_CLIENT = "harnis-check"  # password grant, local testing only
LOCAL_PASSWORD = "harnis-local-only"  # every test user in the realm; local testing only
DEFAULT_URL = "http://127.0.0.1:8080"
ROLE_MAP = {"harnis-users": "user", "harnis-reviewers": "reviewer",
            "harnis-admins": "admin", "platform-ops": "platform-admin"}
# Test users: username -> (Harnis role, tenant)
USERS = {"alice": ("user", "acme"), "rita": ("reviewer", "acme"), "adam": ("admin", "acme"),
         "gina": ("admin", "globex"), "ops": ("platform-admin", "platform")}

# Requests to the local Keycloak must not go through an HTTP(S) proxy.
_OPENER = urlrequest.build_opener(urlrequest.ProxyHandler({}))


def base_url(port: int | str = 8080) -> str:
    return f"http://127.0.0.1:{port}"


def issuer(url: str = DEFAULT_URL) -> str:
    return url.rstrip("/") + "/realms/" + REALM


def oidc_settings(url: str = DEFAULT_URL) -> Dict[str, str]:
    """The Harnis settings (.env keys) for AUTH_MODE=oidc against the local realm."""
    return {
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": issuer(url),
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_USER_CLAIM": "preferred_username",
        "OIDC_TENANT_CLAIM": "tenant_id",
        "OIDC_ROLES_CLAIM": "groups",
        "OIDC_ROLE_MAP": json.dumps(ROLE_MAP, separators=(",", ":")),
        "OIDC_CONSOLE_CLIENT_ID": CONSOLE_CLIENT,
    }


def _get_json(url: str, timeout: float = 5) -> dict:
    with _OPENER.open(urlrequest.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
        return json.loads(r.read())


def discovery(url: str = DEFAULT_URL) -> dict:
    return _get_json(issuer(url) + "/.well-known/openid-configuration")


def wait(url: str = DEFAULT_URL, timeout: float = 180) -> dict:
    """Wait for the realm's discovery document; returns it. Raises TimeoutError."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            disco = discovery(url)
            if disco.get("issuer") == issuer(url):
                return disco
            last = f"issuer is {disco.get('issuer')!r}, expected {issuer(url)!r} (check KC_HOSTNAME)"
        except (OSError, ValueError) as exc:  # URLError and HTTPError are OSErrors
            last = str(exc)
        time.sleep(2)
    raise TimeoutError(f"Keycloak realm {REALM!r} not ready at {url} after {timeout:.0f}s: {last}")


def token(url: str, user: str, password: str = LOCAL_PASSWORD, client_id: str = CHECK_CLIENT,
          which: str = "access_token") -> str:
    """Password grant through the local-only harnis-check client."""
    data = urlparse.urlencode({"grant_type": "password", "client_id": client_id, "username": user,
                               "password": password, "scope": "openid"}).encode()
    req = urlrequest.Request(issuer(url) + "/protocol/openid-connect/token", data=data, method="POST",
                             headers={"Content-Type": "application/x-www-form-urlencoded",
                                      "Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=15) as r:
            body = json.loads(r.read())
    except urlerror.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Keycloak refused the password grant for {user!r}: HTTP {exc.code} {detail}") from exc
    return body[which]


def check_command(url: str, api: str, extra: Optional[List[str]] = None, password: str = LOCAL_PASSWORD,
                  python: str = sys.executable) -> List[str]:
    """The harnis_check.py command line with tokens for adam (admin of acme),
    gina (admin of globex) and ops (platform-admin)."""
    return [python, os.path.join(ROOT, "scripts", "harnis_check.py"), "--api", api,
            "--admin-token", token(url, "adam", password),
            "--other-admin-token", token(url, "gina", password),
            "--reviewer-token", token(url, "rita", password),
            "--platform-token", token(url, "ops", password), *(extra or [])]


def run_check(url: str, api: str, extra: Optional[List[str]] = None, password: str = LOCAL_PASSWORD) -> int:
    cmd = check_command(url, api, extra, password)
    shown = [("<token>" if i > 0 and cmd[i - 1].endswith("-token") else c) for i, c in enumerate(cmd)]
    print("> " + " ".join(shown), flush=True)
    return subprocess.run(cmd, cwd=ROOT).returncode


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Local Keycloak helpers (LOCAL TESTING ONLY)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("env", help="print the .env settings for AUTH_MODE=oidc")
    e.add_argument("--port", default=os.environ.get("KEYCLOAK_PORT", "8080"))
    e.add_argument("--url", help="Keycloak base URL (overrides --port)")
    e.add_argument("--json", action="store_true", help="print a JSON object instead of KEY=value lines")

    w = sub.add_parser("wait", help="wait for the realm discovery document")
    w.add_argument("--url", default=DEFAULT_URL)
    w.add_argument("--timeout", type=float, default=180)

    t = sub.add_parser("tokens", help="print an access token (password grant via harnis-check)")
    t.add_argument("--url", default=DEFAULT_URL)
    t.add_argument("--user", default="adam", help="alice, rita, adam, gina or ops")
    t.add_argument("--password", default=LOCAL_PASSWORD)
    t.add_argument("--id-token", action="store_true", help="print the ID token instead")

    c = sub.add_parser("check", help="run scripts/harnis_check.py with Keycloak-issued tokens")
    c.add_argument("--url", default=DEFAULT_URL)
    c.add_argument("--api", default=os.environ.get("HARNIS_API", "http://127.0.0.1:8000"))
    c.add_argument("--password", default=LOCAL_PASSWORD)

    a, rest = ap.parse_known_args(argv)
    if rest and a.cmd != "check":
        ap.error(f"unrecognized arguments: {' '.join(rest)}")
    if rest and rest[0] == "--":
        rest = rest[1:]
    try:
        if a.cmd == "env":
            values = oidc_settings(a.url or base_url(a.port))
            print(json.dumps(values, indent=2) if a.json else "\n".join(f"{k}={v}" for k, v in values.items()))
        elif a.cmd == "wait":
            wait(a.url, a.timeout)
            print(f"Keycloak realm {REALM!r} is ready: {issuer(a.url)}")
        elif a.cmd == "tokens":
            print(token(a.url, a.user, a.password, which="id_token" if a.id_token else "access_token"))
        elif a.cmd == "check":
            wait(a.url, 30)
            return run_check(a.url, a.api, rest, a.password)
    except (TimeoutError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
