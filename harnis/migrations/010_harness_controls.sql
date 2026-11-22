-- Harness controls (1.4.0): per-tenant spend caps, wall-clock limit, test gate,
-- and trip wires that act (pause the tenant or freeze writes).
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS max_cost_usd_per_day   numeric(12,4),
    ADD COLUMN IF NOT EXISTS max_cost_usd_per_month numeric(12,4),
    ADD COLUMN IF NOT EXISTS max_turn_seconds       integer,
    ADD COLUMN IF NOT EXISTS require_tests          boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS writes_frozen          boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS tripped_reason         text,
    ADD COLUMN IF NOT EXISTS tripped_at             timestamptz;

DROP FUNCTION IF EXISTS harnis_admin_list_tenants();
CREATE FUNCTION harnis_admin_list_tenants()
RETURNS TABLE (tenant_id text, name text, allowed_providers text[], max_cost_usd_per_turn numeric,
               active boolean, created_at timestamptz,
               max_cost_usd_per_day numeric, max_cost_usd_per_month numeric, max_turn_seconds integer,
               require_tests boolean, writes_frozen boolean, tripped_reason text, tripped_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT t.tenant_id, t.name, t.allowed_providers, t.max_cost_usd_per_turn, t.active, t.created_at,
           t.max_cost_usd_per_day, t.max_cost_usd_per_month, t.max_turn_seconds,
           t.require_tests, t.writes_frozen, t.tripped_reason, t.tripped_at
      FROM tenants t ORDER BY t.tenant_id;
$$;

-- NULL keeps the current value; 0 removes a numeric limit.
CREATE OR REPLACE FUNCTION harnis_admin_set_tenant_controls(
    p_tenant_id text, p_max_day numeric, p_max_month numeric, p_max_seconds integer,
    p_require_tests boolean, p_actor text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    UPDATE tenants SET
        max_cost_usd_per_day   = CASE WHEN p_max_day IS NULL THEN max_cost_usd_per_day ELSE nullif(p_max_day, 0) END,
        max_cost_usd_per_month = CASE WHEN p_max_month IS NULL THEN max_cost_usd_per_month ELSE nullif(p_max_month, 0) END,
        max_turn_seconds       = CASE WHEN p_max_seconds IS NULL THEN max_turn_seconds ELSE nullif(p_max_seconds, 0) END,
        require_tests          = coalesce(p_require_tests, require_tests)
     WHERE tenant_id = p_tenant_id;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (p_tenant_id, p_actor, 'tenant_controls_set',
            jsonb_build_object('max_day', p_max_day, 'max_month', p_max_month,
                               'max_seconds', p_max_seconds, 'require_tests', p_require_tests));
END $$;

-- Clears a trip wire (pause and write freeze). Admin only.
CREATE OR REPLACE FUNCTION harnis_admin_clear_trip(p_tenant_id text, p_actor text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    UPDATE tenants SET active = true, writes_frozen = false, tripped_reason = NULL, tripped_at = NULL
     WHERE tenant_id = p_tenant_id;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (p_tenant_id, p_actor, 'trip_cleared', '{}'::jsonb);
END $$;

-- Called by the running platform for the tenant in whose context it runs.
-- Only ever tightens: freeze writes, or pause the tenant. It never grants.
CREATE OR REPLACE FUNCTION harnis_trip_tenant(p_tenant_id text, p_reason text, p_pause boolean)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_tenant_id IS DISTINCT FROM current_setting('app.tenant_id', true) THEN
        RAISE EXCEPTION 'trip: tenant context mismatch';
    END IF;
    UPDATE tenants SET writes_frozen = true,
                       active = CASE WHEN p_pause THEN false ELSE active END,
                       tripped_reason = left(p_reason, 200),
                       tripped_at = coalesce(tripped_at, now())
     WHERE tenant_id = p_tenant_id;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (p_tenant_id, 'harnis', 'trip_wire', jsonb_build_object('reason', p_reason, 'paused', p_pause));
END $$;

ALTER FUNCTION harnis_admin_list_tenants() OWNER TO harnis_platform;
ALTER FUNCTION harnis_admin_set_tenant_controls(text, numeric, numeric, integer, boolean, text) OWNER TO harnis_platform;
ALTER FUNCTION harnis_admin_clear_trip(text, text) OWNER TO harnis_platform;
ALTER FUNCTION harnis_trip_tenant(text, text, boolean) OWNER TO harnis_platform;
REVOKE ALL ON FUNCTION harnis_admin_list_tenants() FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_admin_set_tenant_controls(text, numeric, numeric, integer, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_admin_clear_trip(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_trip_tenant(text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_admin_list_tenants() TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_admin_set_tenant_controls(text, numeric, numeric, integer, boolean, text) TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_admin_clear_trip(text, text) TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_trip_tenant(text, text, boolean) TO harnis_app;
