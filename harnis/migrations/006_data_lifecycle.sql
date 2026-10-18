-- 006_data_lifecycle.sql: retention, per-user erasure and tenant deletion.
--
-- The application role can't delete history (the audit log is append-only and
-- sessions are never deleted by normal operation). These operations go through
-- SECURITY DEFINER functions owned by `harnis_lifecycle`, a NOLOGIN role that a
-- permissive RLS policy lets through on the tenant tables. Each function
-- enforces its own scope:
--   * harnis_erase_user: only the tenant in the caller's transaction context
--     (app.tenant_id, set by the API for an authenticated tenant admin);
--   * harnis_delete_tenant: only a disabled tenant, and the API only calls it
--     for platform admins;
--   * harnis_apply_retention: run by the maintenance job.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'harnis_lifecycle') THEN
        CREATE ROLE harnis_lifecycle NOLOGIN NOBYPASSRLS;
    END IF;
END $$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sessions','approvals','prompt_registry','audit_log',
                             'run_metrics','token_ledger','tenants','api_keys']
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS lifecycle_access ON %I', t);
        EXECUTE format(
            'CREATE POLICY lifecycle_access ON %I FOR ALL
               USING (current_user = ''harnis_lifecycle'') WITH CHECK (current_user = ''harnis_lifecycle'')', t);
    END LOOP;
END $$;

GRANT SELECT, DELETE, UPDATE ON sessions, approvals, prompt_registry, audit_log, run_metrics,
    token_ledger, api_keys TO harnis_lifecycle;
GRANT SELECT, DELETE ON tenants TO harnis_lifecycle;
GRANT INSERT ON audit_log TO harnis_lifecycle;
GRANT USAGE ON SEQUENCE audit_log_event_id_seq TO harnis_lifecycle;

-- Platform-level events that outlive a tenant (tenant deletion). No tenant
-- data in here: ids, counts and who did it.
CREATE TABLE IF NOT EXISTS platform_audit (
    event_id    bigserial PRIMARY KEY,
    actor       text NOT NULL,
    event_type  text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON platform_audit TO harnis_app;
GRANT USAGE ON SEQUENCE platform_audit_event_id_seq TO harnis_app;

-- Erase one user's data in the current tenant (right to erasure).
--   * their sessions are deleted (approvals of those sessions cascade);
--   * where their id appears in history kept for accountability or billing
--     (audit log, approvals they decided, prompt and API key authorship),
--     it is replaced by a random pseudonym, the same one everywhere;
--   * token ledger and run metrics rows keep only the deleted session id.
CREATE OR REPLACE FUNCTION harnis_erase_user(p_user text, p_actor text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_tenant text := current_setting('app.tenant_id', true);
    v_alias text := 'erased-' || substr(md5(gen_random_uuid()::text), 1, 12);
    v_sessions text[];
    n_sessions int; n_audit int; n_approvals int; n_other int;
BEGIN
    IF v_tenant IS NULL OR v_tenant = '' THEN
        RAISE EXCEPTION 'harnis_erase_user needs a tenant context';
    END IF;
    IF p_user IS NULL OR p_user = '' THEN
        RAISE EXCEPTION 'user id required';
    END IF;
    SELECT coalesce(array_agg(session_id), '{}') INTO v_sessions
      FROM sessions WHERE tenant_id = v_tenant AND user_id = p_user;
    DELETE FROM sessions WHERE tenant_id = v_tenant AND user_id = p_user;
    GET DIAGNOSTICS n_sessions = ROW_COUNT;
    UPDATE approvals SET requested_by = CASE WHEN requested_by = p_user THEN v_alias ELSE requested_by END,
                         decided_by = CASE WHEN decided_by = p_user THEN v_alias ELSE decided_by END
     WHERE tenant_id = v_tenant AND (requested_by = p_user OR decided_by = p_user);
    GET DIAGNOSTICS n_approvals = ROW_COUNT;
    UPDATE audit_log SET actor = v_alias WHERE tenant_id = v_tenant AND actor = p_user;
    GET DIAGNOSTICS n_audit = ROW_COUNT;
    UPDATE audit_log SET detail = '{}'::jsonb
     WHERE tenant_id = v_tenant AND session_id = ANY(v_sessions) AND detail::text LIKE '%' || p_user || '%';
    UPDATE prompt_registry SET created_by = v_alias WHERE tenant_id = v_tenant AND created_by = p_user;
    GET DIAGNOSTICS n_other = ROW_COUNT;
    UPDATE api_keys SET created_by = v_alias WHERE tenant_id = v_tenant AND created_by = p_user;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (v_tenant, p_actor, 'user_erased',
            jsonb_build_object('alias', v_alias, 'sessions', n_sessions, 'audit_events', n_audit,
                               'approvals', n_approvals));
    RETURN jsonb_build_object('alias', v_alias, 'sessions', v_sessions, 'deleted_sessions', n_sessions,
                              'pseudonymized_audit_events', n_audit, 'pseudonymized_approvals', n_approvals);
END $$;

-- Delete a tenant and everything it owns. The tenant must be disabled first,
-- so deletion is always a deliberate two-step operation.
CREATE OR REPLACE FUNCTION harnis_delete_tenant(p_tenant text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_active boolean;
    n_sessions int;
BEGIN
    SELECT active INTO v_active FROM tenants WHERE tenant_id = p_tenant;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF v_active THEN
        RAISE EXCEPTION 'tenant % is active; disable it before deleting it', p_tenant
              USING ERRCODE = 'object_in_use';
    END IF;
    SELECT count(*) INTO n_sessions FROM sessions WHERE tenant_id = p_tenant;
    -- Every tenant table references tenants(tenant_id) ON DELETE CASCADE.
    DELETE FROM tenants WHERE tenant_id = p_tenant;
    RETURN jsonb_build_object('tenant_id', p_tenant, 'deleted_sessions', n_sessions);
END $$;

-- Retention, for the maintenance job. 0 (or NULL) keeps data forever.
-- Sessions not updated for p_session_days are deleted with their approvals;
-- audit events older than p_audit_days are deleted. Returns the deleted
-- sessions so their workspaces can be removed too.
CREATE OR REPLACE FUNCTION harnis_apply_retention(p_session_days int, p_audit_days int)
RETURNS TABLE (out_tenant_id text, out_session_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF coalesce(p_audit_days, 0) > 0 THEN
        DELETE FROM audit_log a WHERE a.created_at < now() - make_interval(days => p_audit_days);
    END IF;
    IF coalesce(p_session_days, 0) > 0 THEN
        RETURN QUERY
        WITH gone AS (
            DELETE FROM sessions s WHERE s.updated_at < now() - make_interval(days => p_session_days)
                   AND s.status NOT IN ('running', 'awaiting_approval')
            RETURNING s.tenant_id, s.session_id)
        SELECT g.tenant_id, g.session_id FROM gone g;
    END IF;
END $$;

-- Which of these sessions still exist (for sweeping orphaned workspaces).
CREATE OR REPLACE FUNCTION harnis_existing_sessions(p_ids text[])
RETURNS SETOF text
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
    SELECT session_id FROM sessions WHERE session_id = ANY(p_ids);
$$;

ALTER FUNCTION harnis_erase_user(text, text) OWNER TO harnis_lifecycle;
ALTER FUNCTION harnis_delete_tenant(text) OWNER TO harnis_lifecycle;
ALTER FUNCTION harnis_apply_retention(int, int) OWNER TO harnis_lifecycle;
ALTER FUNCTION harnis_existing_sessions(text[]) OWNER TO harnis_lifecycle;

REVOKE ALL ON FUNCTION harnis_erase_user(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_delete_tenant(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_apply_retention(int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_existing_sessions(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_erase_user(text, text) TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_delete_tenant(text) TO harnis_app;

-- Analytics refresh that also works on an unpopulated view (right after a
-- restore, which skips the derived data): CONCURRENTLY needs populated data.
CREATE OR REPLACE FUNCTION refresh_analytics() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF (SELECT ispopulated FROM pg_matviews WHERE schemaname = 'public'
          AND matviewname = 'run_metrics_hourly_mv') THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY run_metrics_hourly_mv;
    ELSE
        REFRESH MATERIALIZED VIEW run_metrics_hourly_mv;
    END IF;
END $$;
ALTER FUNCTION refresh_analytics() OWNER TO harnis_analytics;
REVOKE ALL ON FUNCTION refresh_analytics() FROM PUBLIC;

-- API keys report who created them, so separation of duties can treat a key
-- and its creator as the same person (an admin can't approve their own request
-- with a reviewer key they made).
DROP FUNCTION IF EXISTS harnis_resolve_api_key(text);
CREATE FUNCTION harnis_resolve_api_key(p_key_id text)
RETURNS TABLE (tenant_id text, secret_hash text, roles text[], tenant_active boolean, created_by text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    UPDATE api_keys k SET last_used_at = now()
     WHERE k.key_id = p_key_id AND k.revoked_at IS NULL
       AND (k.last_used_at IS NULL OR k.last_used_at < now() - interval '1 minute');
    RETURN QUERY
        SELECT k.tenant_id, k.secret_hash, k.roles, t.active, k.created_by
          FROM api_keys k JOIN tenants t ON t.tenant_id = k.tenant_id
         WHERE k.key_id = p_key_id
           AND k.revoked_at IS NULL
           AND (k.expires_at IS NULL OR k.expires_at > now());
END $$;
ALTER FUNCTION harnis_resolve_api_key(text) OWNER TO harnis_platform;
REVOKE ALL ON FUNCTION harnis_resolve_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_resolve_api_key(text) TO harnis_app;
