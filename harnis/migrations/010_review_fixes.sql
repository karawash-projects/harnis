-- 010_review_fixes.sql: findings from the pre-production review.
--
--   #30  harnis_erase_user matched the user id with LIKE, so an id containing % or _ acted as a wildcard and blanked
--        audit details of the user's other sessions' events; it now looks for the literal text.
--   M22  erasure left `user_exported` audit rows quoting the user id, and the API keys the user created kept working:
--        harnis_erase_user_residue() scrubs those rows by exact match and revokes the keys. The store calls it in the
--        same transaction as harnis_erase_user.
--   L5   an API key's last_used_at was updated before its secret was checked, so anyone who knew a key id could keep
--        it looking active: harnis_resolve_api_key no longer writes; harnis_touch_api_key() is called after the secret
--        matched.
--   #31  harnis_delete_tenant refuses to run inside a tenant-scoped transaction (it is a platform operation).
-- Idempotent. CREATE OR REPLACE keeps each function's owner and grants.

-- #30 ----------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION harnis_erase_user(p_user text, p_actor text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
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
     WHERE tenant_id = v_tenant AND session_id = ANY(v_sessions) AND position(p_user in detail::text) > 0;
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

-- M22 ----------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION harnis_erase_user_residue(p_user text, p_alias text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_tenant text := current_setting('app.tenant_id', true);
    n_exports int; n_keys int;
BEGIN
    IF v_tenant IS NULL OR v_tenant = '' THEN
        RAISE EXCEPTION 'harnis_erase_user_residue needs a tenant context';
    END IF;
    IF p_user IS NULL OR p_user = '' OR p_alias IS NULL OR p_alias NOT LIKE 'erased-%' THEN
        RAISE EXCEPTION 'user id and an erased-* alias required';
    END IF;
    UPDATE audit_log SET detail = jsonb_set(detail, '{user_id}', to_jsonb(p_alias))
     WHERE tenant_id = v_tenant AND event_type = 'user_exported' AND detail ->> 'user_id' = p_user;
    GET DIAGNOSTICS n_exports = ROW_COUNT;
    UPDATE api_keys SET revoked_at = now()
     WHERE tenant_id = v_tenant AND revoked_at IS NULL AND created_by IN (p_user, p_alias);
    GET DIAGNOSTICS n_keys = ROW_COUNT;
    RETURN jsonb_build_object('scrubbed_export_events', n_exports, 'revoked_api_keys', n_keys);
END $$;
ALTER FUNCTION harnis_erase_user_residue(text, text) OWNER TO harnis_lifecycle;
REVOKE ALL ON FUNCTION harnis_erase_user_residue(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_erase_user_residue(text, text) TO harnis_app;

-- L5 -----------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION harnis_resolve_api_key(p_key_id text)
RETURNS TABLE (tenant_id text, secret_hash text, roles text[], tenant_active boolean, created_by text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    RETURN QUERY
        SELECT k.tenant_id, k.secret_hash, k.roles, t.active, k.created_by
          FROM api_keys k JOIN tenants t ON t.tenant_id = k.tenant_id
         WHERE k.key_id = p_key_id
           AND k.revoked_at IS NULL
           AND (k.expires_at IS NULL OR k.expires_at > now());
END $$;

CREATE OR REPLACE FUNCTION harnis_touch_api_key(p_key_id text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    UPDATE api_keys k SET last_used_at = now()
     WHERE k.key_id = p_key_id AND k.revoked_at IS NULL
       AND (k.last_used_at IS NULL OR k.last_used_at < now() - interval '1 minute');
$$;
ALTER FUNCTION harnis_touch_api_key(text) OWNER TO harnis_platform;
REVOKE ALL ON FUNCTION harnis_touch_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_touch_api_key(text) TO harnis_app;

-- #31 ----------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION harnis_delete_tenant(p_tenant text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_active boolean;
    v_ctx text := current_setting('app.tenant_id', true);
    n_sessions int;
BEGIN
    IF v_ctx IS NOT NULL AND v_ctx <> '' THEN
        RAISE EXCEPTION 'harnis_delete_tenant is a platform operation and cannot run inside a tenant context'
              USING ERRCODE = 'insufficient_privilege';
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
