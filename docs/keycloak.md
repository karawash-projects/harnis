# Single sign-on locally with Keycloak

This sets up a real identity provider on your machine so you can try Harnis with
`AUTH_MODE=oidc` before connecting it to your company's IdP: console sign-in
with SSO (authorization code + PKCE), role mapping from groups, the tenant from
a token claim, and the feature check with IdP-issued tokens.

> **For local testing only.** The realm has test users with a published
> password, the Keycloak admin is `admin` / `admin`, Keycloak runs in dev mode
> with a throwaway database, and the `harnis-check` client allows the password
> grant. Never copy any of these into a real deployment.

## Start it

```bash
python tasks.py up          # Postgres, Redis, ... (once)
python tasks.py sso-up      # Keycloak + realm "harnis"; .env switched to AUTH_MODE=oidc
python tasks.py dev         # restart the API so it picks up the new .env
```

`sso-up` starts the `keycloak` service (compose profile `sso`, image
`quay.io/keycloak/keycloak:26.7.5`) on `http://127.0.0.1:8080` (`KEYCLOAK_PORT`
in `.env`; a free port is picked if 8080 is taken), imports
`deploy/keycloak/harnis-realm.json`, waits for the realm, and writes these
settings to `.env` (also printed by `python scripts/keycloak_local.py env`):

```bash
AUTH_MODE=oidc
OIDC_ISSUER=http://127.0.0.1:8080/realms/harnis
OIDC_AUDIENCE=harnis-api
OIDC_USER_CLAIM=preferred_username
OIDC_TENANT_CLAIM=tenant_id
OIDC_ROLES_CLAIM=groups
OIDC_ROLE_MAP={"harnis-users":"user","harnis-reviewers":"reviewer","harnis-admins":"admin","platform-ops":"platform-admin"}
OIDC_CONSOLE_CLIENT_ID=harnis-console
```

Your previous values are saved in `.env` as `SSO_PREVIOUS_SETTINGS`.

## Test users

Password for every user: `harnis-local-only` (local testing only).

| User | Keycloak group | Harnis role | Tenant (`tenant_id` attribute) |
|---|---|---|---|
| `alice` | `harnis-users` | `user` | `acme` |
| `rita` | `harnis-reviewers` | `reviewer` | `acme` |
| `adam` | `harnis-admins` | `admin` | `acme` |
| `gina` | `harnis-admins` | `admin` | `globex` |
| `ops` | `platform-ops` | `platform-admin` | `platform` |

Keycloak's admin console is at `http://127.0.0.1:8080/admin` (`admin` / `admin`).

## Sign in to the console

Open `http://127.0.0.1:8000`, click **Sign in with SSO**, and sign in on the
Keycloak page as one of the users above. The console shows the user, tenant and
role. **Sign out** ends the Keycloak session too.

The `harnis-console` client accepts redirects to `http://127.0.0.1:8000/*` and
`http://localhost:8000/*` (and `http://127.0.0.1:8011/*` for the browser test).
If you run the API on another port, add that redirect URI to the client in the
Keycloak admin console.

## Feature check with Keycloak tokens

```bash
python tasks.py sso-check                    # API on http://127.0.0.1:8000
python tasks.py sso-check --only tenancy     # extra args go to scripts/harnis_check.py
```

It gets access tokens for `adam` (admin of acme), `gina` (admin of globex) and
`ops` (platform-admin) through the password grant of the `harnis-check` client
and runs `scripts/harnis_check.py --admin-token ... --other-admin-token ...
--platform-token ...`. A few checks are skipped because they need the JWT secret
of local auth (expired tokens, foreign audiences, disabling a tenant).

Tokens by hand: `python scripts/keycloak_local.py tokens --user rita`.

Tests against the running Keycloak (Postgres and Redis needed; the browser test
also needs Playwright and Chromium, and port 8011 free):

```bash
KEYCLOAK_URL=http://127.0.0.1:8080 python -m pytest tests/test_keycloak.py
```

## Stop it

```bash
python tasks.py sso-down    # removes the Keycloak container, restores AUTH_MODE and OIDC_* in .env
```

Restart `python tasks.py dev` afterwards. The realm is imported fresh the next
time you run `sso-up`.

## Mirroring the realm in your own IdP

What Harnis needs from any identity provider, and how this realm provides it:

| Harnis setting | Needs in the access token | In the `harnis` realm |
|---|---|---|
| `OIDC_ISSUER` | `iss` equal to the issuer; discovery at `<issuer>/.well-known/openid-configuration` | `http://127.0.0.1:8080/realms/harnis` (`KC_HOSTNAME` keeps it stable) |
| `OIDC_AUDIENCE` | `aud` contains the API's audience | audience mapper adding `harnis-api` to access tokens |
| `OIDC_TENANT_CLAIM` | the tenant id, from the IdP, never editable by the user | user attribute `tenant_id` mapped to the `tenant_id` claim; declared in the user profile as **admin-only** (view and edit) so users can't move themselves into another tenant |
| `OIDC_ROLES_CLAIM` + `OIDC_ROLE_MAP` | group or role names | group membership mapper, claim `groups`, plain names (`full.path` off) |
| `OIDC_USER_CLAIM` | a stable user id | `preferred_username` (`sub` is the safer choice where usernames can be renamed or reused) |
| `OIDC_CONSOLE_CLIENT_ID` | a public SPA client, authorization code + PKCE (S256), redirect `https://<host>/`, CORS for the console's origin | `harnis-console`: public, standard flow only, PKCE S256 required, web origins `+` (= its redirect URIs), post-logout redirect URIs set |

Access tokens live 15 minutes; the console signs out when its token expires.

For a single-tenant deployment skip the tenant attribute and set
`OIDC_DEFAULT_TENANT` instead. With Keycloak realm roles instead of groups, use
`OIDC_ROLES_CLAIM=realm_access.roles`.

Do not recreate `harnis-check` in a real IdP: the password grant exists here
only so scripts and tests can get tokens without a browser. For CI against a
real deployment, use a tenant admin's `hrn_` API key with `harnis_check.py
--admin-token`.
