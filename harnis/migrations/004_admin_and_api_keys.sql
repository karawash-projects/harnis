-- 004_admin_and_api_keys.sql: service API keys, tenant lifecycle, platform admin.
--
-- Platform-level operations (listing and creating tenants, resolving an API key
-- before the tenant is known) cannot run inside one tenant's RLS context. They
-- go through a few SECURITY DEFINER functions owned by `harnis_platform`, a
-- NOLOGIN role that RLS policies let through on exactly the tables it needs.
-- The application role can execute those functions and nothing more; the API
-- decides who may call them (role `platform-admin`).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'harnis_platform') THEN
        CREATE ROLE harnis_platform NOLOGIN NOBYPASSRLS;
    END IF;
END $$;

-- Tenants can be switched off without deleting their data.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;

CREATE TABLE IF NOT EXISTS api_keys (
    key_id        text PRIMARY KEY,
    tenant_id     text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name          text NOT NULL,
    secret_hash   text NOT NULL,                 -- sha256 of the random secret, hex
    roles         text[] NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id, created_at DESC);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON api_keys;
CREATE POLICY tenant_isolation ON api_keys FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Platform policies: permissive, OR-ed with tenant_isolation, only for harnis_platform.
DROP POLICY IF EXISTS platform_access ON tenants;
CREATE POLICY platform_access ON tenants FOR ALL
    USING (current_user = 'harnis_platform') WITH CHECK (current_user = 'harnis_platform');
DROP POLICY IF EXISTS platform_access ON api_keys;
CREATE POLICY platform_access ON api_keys FOR ALL
    USING (current_user = 'harnis_platform') WITH CHECK (current_user = 'harnis_platform');
DROP POLICY IF EXISTS platform_audit ON audit_log;
CREATE POLICY platform_audit ON audit_log FOR INSERT
    WITH CHECK (current_user = 'harnis_platform');

GRANT SELECT, INSERT, UPDATE ON tenants TO harnis_platform;
GRANT SELECT, UPDATE ON api_keys TO harnis_platform;
GRANT INSERT ON audit_log TO harnis_platform;
GRANT USAGE ON SEQUENCE audit_log_event_id_seq TO harnis_platform;

-- Tenant admins manage their own keys through ordinary RLS-scoped queries.
GRANT SELECT, INSERT, UPDATE ON api_keys TO harnis_app;

-- ---------------------------------------------------------------------------
-- Platform functions
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION harnis_resolve_api_key(p_key_id text)
RETURNS TABLE (tenant_id text, secret_hash text, roles text[], tenant_active boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    -- Record use at most once a minute per key.
    UPDATE api_keys k SET last_used_at = now()
     WHERE k.key_id = p_key_id AND k.revoked_at IS NULL
       AND (k.last_used_at IS NULL OR k.last_used_at < now() - interval '1 minute');
    RETURN QUERY
        SELECT k.tenant_id, k.secret_hash, k.roles, t.active
          FROM api_keys k JOIN tenants t ON t.tenant_id = k.tenant_id
         WHERE k.key_id = p_key_id
           AND k.revoked_at IS NULL
           AND (k.expires_at IS NULL OR k.expires_at > now());
END $$;

CREATE OR REPLACE FUNCTION harnis_admin_list_tenants()
RETURNS TABLE (tenant_id text, name text, allowed_providers text[], max_cost_usd_per_turn numeric,
               active boolean, created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
    SELECT tenant_id, name, allowed_providers, max_cost_usd_per_turn, active, created_at
      FROM tenants ORDER BY tenant_id;
$$;

CREATE OR REPLACE FUNCTION harnis_admin_upsert_tenant(
    p_tenant_id text, p_name text, p_allowed_providers text[], p_max_cost numeric,
    p_active boolean, p_actor text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    -- NULL arguments keep the current value (or the default for a new tenant).
    -- p_max_cost = 0 removes the tenant's own cost cap (the platform default applies).
    INSERT INTO tenants (tenant_id, name, allowed_providers, max_cost_usd_per_turn, active)
    VALUES (p_tenant_id, coalesce(p_name, p_tenant_id),
            coalesce(p_allowed_providers, ARRAY['anthropic','openai','gemini','nova','mock']),
            nullif(p_max_cost, 0), coalesce(p_active, true))
    ON CONFLICT (tenant_id) DO UPDATE SET
        name = coalesce(p_name, tenants.name),
        allowed_providers = coalesce(p_allowed_providers, tenants.allowed_providers),
        max_cost_usd_per_turn = CASE WHEN p_max_cost IS NULL THEN tenants.max_cost_usd_per_turn
                                     ELSE nullif(p_max_cost, 0) END,
        active = coalesce(p_active, tenants.active);
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (p_tenant_id, p_actor, 'tenant_upserted',
            jsonb_build_object('allowed_providers', p_allowed_providers, 'active', p_active,
                               'max_cost_usd_per_turn', p_max_cost));
END $$;

ALTER FUNCTION harnis_resolve_api_key(text) OWNER TO harnis_platform;
ALTER FUNCTION harnis_admin_list_tenants() OWNER TO harnis_platform;
ALTER FUNCTION harnis_admin_upsert_tenant(text, text, text[], numeric, boolean, text) OWNER TO harnis_platform;
REVOKE ALL ON FUNCTION harnis_resolve_api_key(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_admin_list_tenants() FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_admin_upsert_tenant(text, text, text[], numeric, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_resolve_api_key(text) TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_admin_list_tenants() TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_admin_upsert_tenant(text, text, text[], numeric, boolean, text) TO harnis_app;
