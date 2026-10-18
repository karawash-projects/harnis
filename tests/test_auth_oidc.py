# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""OIDC verification against a fake identity provider with real RSA/EC keys."""
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException

from harnis.auth import Authenticator, OIDCVerifier, Principal, safe_id
from harnis.config import Settings

ISSUER = "https://idp.example.com/"
AUD = "harnis-api"


class FakeIdP:
    def __init__(self):
        self.keys = {"k1": rsa.generate_private_key(public_exponent=65537, key_size=2048)}
        self.fetches = []

    def jwk(self, kid, key):
        pub = key.public_key()
        if isinstance(key, rsa.RSAPrivateKey):
            d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub))
            alg = "RS256"
        else:
            d = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(pub))
            alg = "ES256"
        return {**d, "kid": kid, "use": "sig", "alg": alg}

    def fetch(self, url):
        self.fetches.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": ISSUER, "jwks_uri": "https://idp.example.com/keys"}
        return {"keys": [self.jwk(k, v) for k, v in self.keys.items()]}

    def token(self, kid="k1", alg="RS256", **claims):
        now = int(time.time())
        base = {"iss": ISSUER, "aud": AUD, "sub": "auth0|5f2c9a", "iat": now, "exp": now + 300,
                "tenant_id": "acme", "roles": ["reviewer"]}
        base.update(claims)
        base = {k: v for k, v in base.items() if v is not None}
        return jwt.encode(base, self.keys[kid], algorithm=alg, headers={"kid": kid})


def settings(**kw):
    return Settings(_env_file=None, auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUD, **kw)


@pytest.fixture
def idp():
    return FakeIdP()


def test_valid_token_maps_to_principal(idp):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    p = v.verify(idp.token())
    assert p.tenant_id == "acme" and p.roles == frozenset({"reviewer"}) and p.via == "oidc"
    assert p.user_id == safe_id("auth0|5f2c9a") and "|" not in p.user_id
    assert idp.fetches[0].endswith("/.well-known/openid-configuration")


@pytest.mark.parametrize("bad", [
    {"aud": "someone-else"}, {"iss": "https://evil.example.com/"}, {"exp": int(time.time()) - 3600},
])
def test_wrong_audience_issuer_or_expired(idp, bad):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    with pytest.raises(HTTPException) as e:
        v.verify(idp.token(**bad))
    assert e.value.status_code == 401


def test_forged_signature_and_hs256_confusion_rejected(idp):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode({"iss": ISSUER, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60, "tenant_id": "acme"},
                        other, algorithm="RS256", headers={"kid": "k1"})
    with pytest.raises(HTTPException):
        v.verify(forged)
    # Classic alg confusion: HS256 signed with the public key as the secret.
    pub_pem = idp.keys["k1"].public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(Exception):
        confused = jwt.encode({"iss": ISSUER, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60},
                              pub_pem, algorithm="HS256", headers={"kid": "k1"})
        v.verify(confused)


def test_symmetric_algorithms_refused_in_config():
    with pytest.raises(RuntimeError):
        OIDCVerifier(settings(oidc_algorithms="RS256,HS256"), fetch_json=lambda u: {})


def test_key_rotation_refreshes_jwks(idp, monkeypatch):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    v.verify(idp.token())
    idp.keys["k2"] = ec.generate_private_key(ec.SECP256R1())
    v._fetched_at -= 60  # allow the rate-limited refresh
    p = v.verify(idp.token(kid="k2", alg="ES256"))
    assert p.tenant_id == "acme"


def test_unknown_kid_refresh_is_rate_limited(idp):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    v.verify(idp.token())
    n = len(idp.fetches)
    idp.keys["k9"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException):
        v.verify(idp.token(kid="k9"))
    assert len(idp.fetches) == n  # no refetch within 30s of the last one


def test_discovery_issuer_mismatch_refused(idp):
    v = OIDCVerifier(settings(), fetch_json=lambda url: {"issuer": "https://other/", "jwks_uri": "x"})
    with pytest.raises(RuntimeError):
        v.verify(idp.token())


def test_role_mapping_nested_claims_and_default_tenant(idp):
    s = settings(oidc_roles_claim="realm_access.roles", oidc_tenant_claim="org.id",
                 oidc_role_map=json.dumps({"harnis-approvers": "reviewer", "harnis-admins": "admin"}),
                 oidc_default_role="")
    v = OIDCVerifier(s, fetch_json=idp.fetch)
    p = v.verify(idp.token(roles=None, tenant_id=None, realm_access={"roles": ["harnis-approvers", "offline"]},
                           org={"id": "globex"}))
    assert p.roles == frozenset({"reviewer"}) and p.tenant_id == "globex"
    # Unmapped role names are ignored when a map is configured.
    p = v.verify(idp.token(roles=None, tenant_id=None, realm_access={"roles": ["admin"]}, org={"id": "globex"}))
    assert p.roles == frozenset()
    # Single-tenant deployment: tenant from config when the claim is absent.
    v2 = OIDCVerifier(settings(oidc_default_tenant="acme"), fetch_json=idp.fetch)
    assert v2.verify(idp.token(tenant_id=None)).tenant_id == "acme"


def test_missing_tenant_is_rejected(idp):
    v = OIDCVerifier(settings(), fetch_json=idp.fetch)
    with pytest.raises(HTTPException):
        v.verify(idp.token(tenant_id=None))


def test_default_role_and_space_separated_roles(idp):
    v = OIDCVerifier(settings(oidc_roles_claim="scope"), fetch_json=idp.fetch)
    assert v.verify(idp.token(scope="openid reviewer")).roles == frozenset({"reviewer"})
    assert v.verify(idp.token(scope="openid")).roles == frozenset({"user"})


def test_local_tokens_rejected_in_oidc_mode(idp):
    from harnis.auth import mint_token

    a = Authenticator(settings(), store=None, oidc=OIDCVerifier(settings(), fetch_json=idp.fetch))
    with pytest.raises(HTTPException):
        a.authenticate(mint_token("alice", "acme", ["admin"]))
    assert isinstance(a.authenticate(idp.token()), Principal)


def test_platform_admin_does_not_imply_tenant_roles():
    p = Principal("ops", "acme", frozenset({"platform-admin"}))
    assert p.has("platform-admin") and not p.has("user") and not p.has("reviewer")
    a = Principal("boss", "acme", frozenset({"admin"}))
    assert a.has("reviewer") and a.has("user") and not a.has("platform-admin")


@pytest.mark.parametrize("raw", ["auth0|5f2c9a", "jane.doe@example.com", "a" * 200, "ünïcode"])
def test_safe_id_is_stable_and_safe(raw):
    from harnis.auth import _ID
    assert safe_id(raw) == safe_id(raw) and _ID.match(safe_id(raw))
    assert safe_id("plain-id") == "plain-id"


def test_derived_ids_never_collide_with_literal_ids():
    from harnis.auth import safe_id

    derived = safe_id("auth0|5f2c9e")
    assert derived != "auth0|5f2c9e" and safe_id(derived) != derived  # a literal equal to it is re-derived
    assert safe_id("alice") == "alice" and safe_id("alice") == safe_id("alice")
