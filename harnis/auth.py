# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Authentication. Every request resolves to a `Principal` (user, tenant, roles).
The tenant always comes from verified credentials, never from a request body,
path or header the client controls.

Three kinds of credentials, all sent as `Authorization: Bearer ...`:

  * AUTH_MODE=oidc   JWTs from your identity provider (Okta, Entra ID, Auth0,
                     Keycloak, Google, ...), verified against the provider's
                     JWKS. Claim names and role mapping are configurable.
  * AUTH_MODE=local  HS256 JWTs signed with JWT_SECRET (development, or when an
                     internal gateway mints tokens). `python -m harnis.auth mint`.
  * API keys         `hrn_<key id>_<secret>` for CI and service accounts, created
                     by a tenant admin (POST /v1/admin/api-keys). Accepted in both
                     modes. Only a SHA-256 of the secret is stored.

Roles
  user            run sessions
  reviewer        approve or deny actions in the tenant
  admin           tenant admin (implies user and reviewer): prompts, API keys, audit log
  platform-admin  manage tenants across the platform; implies nothing inside a tenant
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, get_settings

TENANT_ROLES = {"user", "reviewer", "admin"}
ROLES = TENANT_ROLES | {"platform-admin"}
# Tenant and user ids end up in Redis keys and workspace folder names, so keep
# them to characters that are safe on every filesystem.
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DERIVED = re.compile(r"-[0-9a-f]{10}$")
API_KEY_PREFIX = "hrn_"
_API_KEY = re.compile(r"^hrn_([a-f0-9]{16})_([A-Za-z0-9_-]{32,64})$")


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    via: str = "jwt"  # jwt | oidc | api_key
    # For API keys: the user who created the key. Separation of duties treats
    # a key and its creator as the same person.
    owner: str | None = None

    def identities(self) -> set[str]:
        return {self.user_id} | ({self.owner} if self.owner else set())

    def has(self, role: str) -> bool:
        if role == "platform-admin":
            return "platform-admin" in self.roles
        return role in self.roles or "admin" in self.roles


def safe_id(value: str) -> str:
    """Use the value as-is when it is already a safe id; otherwise derive a
    stable one (IdP subjects like `auth0|5f2...` or e-mail addresses)."""
    value = str(value)
    # A value that already looks like a derived id is derived again, so a
    # literal claim can never equal another user's derived id.
    if _ID.match(value) and not _DERIVED.search(value):
        return value
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")[:40] or "id"
    return f"{slug}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


# ---------------------------------------------------------------------------
# Local (HS256) tokens
# ---------------------------------------------------------------------------
def mint_token(user_id: str, tenant_id: str, roles: list[str], ttl_seconds: int = 8 * 3600) -> str:
    if not (_ID.match(user_id) and _ID.match(tenant_id)):
        raise ValueError("user and tenant ids: letters, digits, '_', '.', '-' (max 64)")
    unknown = set(roles) - ROLES
    if unknown:
        raise ValueError(f"unknown roles: {unknown}")
    s = get_settings()
    now = int(time.time())
    claims = {"sub": user_id, "tenant_id": tenant_id, "roles": roles, "iss": s.jwt_issuer,
              "aud": s.jwt_audience, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(claims, s.jwt_secret, algorithm="HS256")


def _decode_local(token: str, s: Settings) -> Principal:
    try:
        claims = jwt.decode(token, s.jwt_secret, algorithms=["HS256"],  # pinned, never from the header
                            audience=s.jwt_audience, issuer=s.jwt_issuer,
                            options={"require": ["exp", "sub", "tenant_id", "iss", "aud"]})
    except jwt.PyJWTError as exc:
        raise _unauthorized(f"invalid token: {exc}") from exc
    if not (_ID.match(str(claims["sub"])) and _ID.match(str(claims["tenant_id"]))):
        raise _unauthorized("invalid token: malformed subject or tenant")
    roles = frozenset(r for r in claims.get("roles", []) if r in ROLES)
    return Principal(user_id=claims["sub"], tenant_id=claims["tenant_id"], roles=roles, via="jwt")


# ---------------------------------------------------------------------------
# OIDC
# ---------------------------------------------------------------------------
def _claim(claims: dict[str, Any], path: str) -> Any:
    """Read a claim by dotted path, e.g. `realm_access.roles` (Keycloak).
    A key that itself contains dots (namespaced Auth0 claims such as
    `https://example.com/roles`) is matched first as a whole."""
    if path in claims:
        return claims[path]
    cur: Any = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class OIDCVerifier:
    """Verifies IdP-issued JWTs. Signing keys come from the JWKS URL (configured
    or discovered from `<issuer>/.well-known/openid-configuration`) and are
    cached; an unknown `kid` triggers one refresh (key rotation)."""

    def __init__(self, s: Settings, fetch_json: Callable[[str], dict[str, Any]] | None = None):
        if not (s.oidc_issuer and s.oidc_audience):
            raise RuntimeError("AUTH_MODE=oidc needs OIDC_ISSUER and OIDC_AUDIENCE")
        self.s = s
        self.algorithms = [a.strip() for a in s.oidc_algorithms.split(",") if a.strip()]
        if any(a.upper().startswith("HS") or a.lower() == "none" for a in self.algorithms):
            raise RuntimeError("OIDC_ALGORITHMS must be asymmetric (RS*/ES*/PS*/EdDSA)")
        self._fetch = fetch_json or self._http_get_json
        self._jwks_url = s.oidc_jwks_url or None
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._disco: dict[str, Any] | None = None
        self._disco_at = 0.0
        self.role_map: dict[str, str] = json.loads(s.oidc_role_map) if s.oidc_role_map else {}

    @staticmethod
    def _http_get_json(url: str) -> dict[str, Any]:
        import httpx

        r = httpx.get(url, timeout=10, follow_redirects=False)
        r.raise_for_status()
        return r.json()

    def discovery(self) -> dict[str, Any]:
        """The IdP's discovery document (cached like the keys)."""
        if self._disco is None or time.time() - self._disco_at > self.s.oidc_jwks_cache_seconds:
            disco = self._fetch(self.s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration")
            if disco.get("issuer", "").rstrip("/") != self.s.oidc_issuer.rstrip("/"):
                raise RuntimeError("OIDC discovery document issuer does not match OIDC_ISSUER")
            self._disco, self._disco_at = disco, time.time()
        return self._disco

    def _jwks(self, force: bool = False) -> dict[str, Any]:
        if self._keys and not force and time.time() - self._fetched_at < self.s.oidc_jwks_cache_seconds:
            return self._keys
        if self._jwks_url is None:
            self._jwks_url = self.discovery()["jwks_uri"]
        data = self._fetch(self._jwks_url)
        keys = {}
        for jwk in data.get("keys", []):
            if jwk.get("use", "sig") != "sig" or "kid" not in jwk:
                continue
            try:
                keys[jwk["kid"]] = jwt.PyJWK(jwk)
            except jwt.PyJWTError:
                continue  # key type/algorithm we don't support
        self._keys, self._fetched_at = keys, time.time()
        return keys

    def _key_for(self, token: str) -> Any:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise _unauthorized(f"invalid token: {exc}") from exc
        keys = self._jwks()
        if kid not in keys:
            # Rate-limit forced refreshes so garbage kids can't hammer the IdP.
            if time.time() - self._fetched_at > 30:
                keys = self._jwks(force=True)
        if kid not in keys:
            raise _unauthorized("invalid token: unknown signing key")
        return keys[kid]

    def verify(self, token: str) -> Principal:
        s = self.s
        key = self._key_for(token)
        try:
            claims = jwt.decode(token, key, algorithms=self.algorithms, audience=s.oidc_audience,
                                issuer=s.oidc_issuer, leeway=s.oidc_leeway_seconds,
                                options={"require": ["exp", "iss", "aud", "sub"]})
        except jwt.PyJWTError as exc:
            raise _unauthorized(f"invalid token: {exc}") from exc
        user = _claim(claims, s.oidc_user_claim)
        if not user:
            raise _unauthorized(f"invalid token: missing user claim {s.oidc_user_claim!r}")
        tenant = _claim(claims, s.oidc_tenant_claim) or s.oidc_default_tenant
        if not tenant:
            raise _unauthorized(f"invalid token: missing tenant claim {s.oidc_tenant_claim!r} "
                                "(or set OIDC_DEFAULT_TENANT for a single-tenant deployment)")
        raw = _claim(claims, s.oidc_roles_claim) or []
        if isinstance(raw, str):
            raw = raw.replace(",", " ").split()
        roles = set()
        for value in raw:
            mapped = self.role_map.get(str(value), str(value) if not self.role_map else None)
            if mapped in ROLES:
                roles.add(mapped)
        if not roles and s.oidc_default_role in ROLES:
            roles.add(s.oidc_default_role)
        return Principal(user_id=safe_id(user), tenant_id=safe_id(tenant), roles=frozenset(roles), via="oidc")


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
def new_api_key() -> tuple[str, str, str]:
    """Returns (key_id, full key to show once, sha256 hex of the secret to store)."""
    key_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    return key_id, f"{API_KEY_PREFIX}{key_id}_{secret}", hashlib.sha256(secret.encode()).hexdigest()


class Authenticator:
    def __init__(self, settings: Settings, store: Any = None, oidc: OIDCVerifier | None = None):
        self.s = settings
        self.store = store
        self.oidc = oidc
        if settings.auth_mode == "oidc" and self.oidc is None:
            self.oidc = OIDCVerifier(settings)

    def authenticate(self, token: str) -> Principal:
        if token.startswith(API_KEY_PREFIX):
            return self._api_key(token)
        if self.s.auth_mode == "oidc":
            return self.oidc.verify(token)  # type: ignore[union-attr]
        return _decode_local(token, self.s)

    def _api_key(self, token: str) -> Principal:
        m = _API_KEY.match(token)
        if not m or self.store is None:
            raise _unauthorized("invalid API key")
        key_id, secret = m.groups()
        row = self.store.resolve_api_key(key_id)
        expected = row["secret_hash"] if row else hashlib.sha256(b"no such key").hexdigest()
        ok = hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), expected)
        if not row or not ok:
            raise _unauthorized("invalid API key")
        if not row["tenant_active"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant is disabled")
        roles = frozenset(r for r in row["roles"] if r in TENANT_ROLES)
        return Principal(user_id=f"key-{key_id}", tenant_id=row["tenant_id"], roles=roles, via="api_key",
                         owner=row.get("created_by"))


def decode_token(token: str) -> Principal:
    """Verify a local (HS256) token. Kept for scripts and tests; the API uses
    `Authenticator`, which also handles OIDC and API keys."""
    return _decode_local(token, get_settings())


_bearer = HTTPBearer(auto_error=False)


def current_principal(request: Request,
                      creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None:
        raise _unauthorized("missing bearer token")
    auth: Authenticator | None = getattr(request.app.state, "auth", None)
    return auth.authenticate(creds.credentials) if auth else decode_token(creds.credentials)


def require_role(role: str):
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if not p.has(role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role '{role}'")
        return p

    return dep


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a local (HS256) token for development")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--user", required=True)
    m.add_argument("--tenant", required=True)
    m.add_argument("--roles", default="user", help="comma-separated: user,reviewer,admin,platform-admin")
    m.add_argument("--ttl", type=int, default=8 * 3600)
    a = ap.parse_args()
    if get_settings().auth_mode != "local":
        raise SystemExit("AUTH_MODE is not 'local': get tokens from your identity provider or use an API key")
    print(mint_token(a.user, a.tenant, [r for r in a.roles.split(",") if r], a.ttl))


if __name__ == "__main__":
    main()
