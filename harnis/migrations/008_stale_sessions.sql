-- Stale-session reaper.
--
-- A turn that was cut off (the process died or was restarted mid-turn) leaves
-- its session in 'running', and a 'running' session refuses new turns. The
-- maintenance job calls this function to mark such sessions 'failed' so the
-- user can send a new message. It bumps `version`, so a worker that is still
-- alive but very slow can no longer overwrite the result with its checkpoint.
CREATE OR REPLACE FUNCTION harnis_reap_stale_sessions(p_max_age_seconds int)
RETURNS TABLE (out_tenant_id text, out_session_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF coalesce(p_max_age_seconds, 0) <= 0 THEN
        RETURN;
    END IF;
    RETURN QUERY
    WITH reaped AS (
        UPDATE sessions s
           SET status = 'failed',
               version = s.version + 1,
               updated_at = now(),
               state = jsonb_set(jsonb_set(s.state, '{awaiting}', 'null'::jsonb),
                                 '{reply}', to_jsonb('The previous turn was interrupted. Please send your message again.'::text))
         WHERE s.status = 'running'
           AND s.updated_at < now() - make_interval(secs => p_max_age_seconds)
        RETURNING s.tenant_id, s.session_id
    ), logged AS (
        INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)
        SELECT r.tenant_id, r.session_id, 'harnis', 'stale_session_reaped', '{}'::jsonb FROM reaped r
    )
    SELECT r.tenant_id, r.session_id FROM reaped r;
END $$;

ALTER FUNCTION harnis_reap_stale_sessions(int) OWNER TO harnis_lifecycle;
REVOKE ALL ON FUNCTION harnis_reap_stale_sessions(int) FROM PUBLIC;
