-- Hardening (1.5.0): ledger partitions with rows in DEFAULT, and complete user erasure.

-- If the DEFAULT partition already holds rows for a month (the job was late), creating that
-- month's partition failed and stopped the whole maintenance run. Move the rows first.
CREATE OR REPLACE FUNCTION ensure_ledger_partitions(months_ahead integer DEFAULT 2)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    m date := date_trunc('month', now())::date;
    i integer;
    part text;
    lo date; hi date;
BEGIN
    FOR i IN 0..months_ahead LOOP
        part := format('token_ledger_%s', to_char(m + make_interval(months => i), 'YYYY_MM'));
        IF to_regclass(part) IS NULL THEN
            lo := m + make_interval(months => i);
            hi := m + make_interval(months => i + 1);
            EXECUTE format('CREATE TABLE %I (LIKE token_ledger INCLUDING DEFAULTS)', part);
            EXECUTE format('INSERT INTO %I SELECT * FROM token_ledger_default WHERE logged_at >= %L AND logged_at < %L',
                           part, lo, hi);
            EXECUTE format('DELETE FROM token_ledger_default WHERE logged_at >= %L AND logged_at < %L', lo, hi);
            EXECUTE format('ALTER TABLE token_ledger ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)', part, lo, hi);
        END IF;
    END LOOP;
END $$;

-- Erasure: also covers sessions created through the user's API keys (and revokes those keys),
-- and matches the user id literally (LIKE treated "_" and "%" as wildcards).
CREATE OR REPLACE FUNCTION harnis_erase_user(p_user text, p_actor text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_tenant text := current_setting('app.tenant_id', true);
    v_alias text := 'erased-' || substr(md5(gen_random_uuid()::text), 1, 12);
    v_sessions text[];
    v_keys text[];
    n_sessions int; n_audit int; n_approvals int; n_other int;
BEGIN
    IF v_tenant IS NULL OR v_tenant = '' THEN
        RAISE EXCEPTION 'harnis_erase_user needs a tenant context';
    END IF;
    IF p_user IS NULL OR p_user = '' THEN
        RAISE EXCEPTION 'user id required';
    END IF;
    SELECT coalesce(array_agg('key-' || key_id), '{}') INTO v_keys
      FROM api_keys WHERE tenant_id = v_tenant AND created_by = p_user;
    SELECT coalesce(array_agg(session_id), '{}') INTO v_sessions
      FROM sessions WHERE tenant_id = v_tenant AND (user_id = p_user OR user_id = ANY(v_keys));
    DELETE FROM sessions WHERE tenant_id = v_tenant AND session_id = ANY(v_sessions);
    GET DIAGNOSTICS n_sessions = ROW_COUNT;
    UPDATE approvals SET requested_by = CASE WHEN requested_by = p_user OR requested_by = ANY(v_keys) THEN v_alias ELSE requested_by END,
                         decided_by = CASE WHEN decided_by = p_user THEN v_alias ELSE decided_by END
     WHERE tenant_id = v_tenant AND (requested_by = p_user OR decided_by = p_user OR requested_by = ANY(v_keys));
    GET DIAGNOSTICS n_approvals = ROW_COUNT;
    UPDATE audit_log SET actor = v_alias WHERE tenant_id = v_tenant AND (actor = p_user OR actor = ANY(v_keys));
    GET DIAGNOSTICS n_audit = ROW_COUNT;
    UPDATE audit_log SET detail = '{}'::jsonb
     WHERE tenant_id = v_tenant AND session_id = ANY(v_sessions) AND strpos(detail::text, p_user) > 0;
    UPDATE prompt_registry SET created_by = v_alias WHERE tenant_id = v_tenant AND created_by = p_user;
    GET DIAGNOSTICS n_other = ROW_COUNT;
    UPDATE api_keys SET created_by = v_alias, revoked_at = coalesce(revoked_at, now())
     WHERE tenant_id = v_tenant AND created_by = p_user;
    INSERT INTO audit_log (tenant_id, actor, event_type, detail)
    VALUES (v_tenant, p_actor, 'user_erased',
            jsonb_build_object('alias', v_alias, 'sessions', n_sessions, 'audit_events', n_audit,
                               'approvals', n_approvals, 'api_keys_revoked', coalesce(array_length(v_keys, 1), 0)));
    RETURN jsonb_build_object('alias', v_alias, 'sessions', v_sessions, 'deleted_sessions', n_sessions,
                              'pseudonymized_audit_events', n_audit, 'pseudonymized_approvals', n_approvals);
END $$;
