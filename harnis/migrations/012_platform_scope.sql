-- Platform-only operations must not be reachable from inside a tenant's context.
--
-- harnis_delete_tenant and harnis_admin_clear_trip take any tenant id and are executable by the
-- application role. The platform API calls them on a connection with no tenant selected; tenant
-- requests always select theirs. Refusing when a tenant is selected means a bug or injection in
-- tenant-scoped code cannot delete another (disabled) tenant or lift its safety freeze.

CREATE OR REPLACE FUNCTION harnis_delete_tenant(p_tenant text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_active boolean;
    n_sessions int;
BEGIN
    IF coalesce(current_setting('app.tenant_id', true), '') <> '' THEN
        RAISE EXCEPTION 'tenant deletion is a platform operation' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT active INTO v_active FROM tenants WHERE tenant_id = p_tenant;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF v_active THEN
        RAISE EXCEPTION 'tenant % is active; disable it before deleting it', p_tenant
              USING ERRCODE = 'object_in_use';
    END IF;
    SELECT count(*) INTO n_sessions FROM sessions WHERE tenant_id = p_tenant;
    DELETE FROM tenants WHERE tenant_id = p_tenant;
    RETURN jsonb_build_object('tenant_id', p_tenant, 'deleted_sessions', n_sessions);
END $$;

CREATE OR REPLACE FUNCTION harnis_admin_clear_trip(p_tenant_id text, p_actor text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF coalesce(current_setting('app.tenant_id', true), '') <> '' THEN
        RAISE EXCEPTION 'clearing a trip is a platform operation' USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE tenants SET active = true, writes_frozen = false, tripped_reason = NULL, tripped_at = NULL
     WHERE tenant_id = p_tenant_id;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (p_tenant_id, p_actor, 'trip_cleared', '{}'::jsonb);
END $$;
