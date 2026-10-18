-- 005_provider_wildcard.sql: '*' in tenants.allowed_providers means "every
-- configured provider", including ones added later by plugins. Tenants that
-- still allow the full built-in list move to '*'; deliberately narrowed lists
-- (data residency) are left exactly as they are.

ALTER TABLE tenants ALTER COLUMN allowed_providers SET DEFAULT ARRAY['*'];

ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;
UPDATE tenants SET allowed_providers = ARRAY['*']
 WHERE allowed_providers @> ARRAY['anthropic','openai','gemini','nova','mock']
   AND allowed_providers <@ ARRAY['anthropic','openai','gemini','nova','mock'];
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION harnis_admin_upsert_tenant(
    p_tenant_id text, p_name text, p_allowed_providers text[], p_max_cost numeric,
    p_active boolean, p_actor text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    -- NULL arguments keep the current value (or the default for a new tenant).
    -- p_max_cost = 0 removes the tenant's own cost cap (the platform default applies).
    INSERT INTO tenants (tenant_id, name, allowed_providers, max_cost_usd_per_turn, active)
    VALUES (p_tenant_id, coalesce(p_name, p_tenant_id), coalesce(p_allowed_providers, ARRAY['*']),
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
ALTER FUNCTION harnis_admin_upsert_tenant(text, text, text[], numeric, boolean, text) OWNER TO harnis_platform;
