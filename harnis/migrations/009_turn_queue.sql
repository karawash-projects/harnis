-- Turn queue (optional: TURN_EXECUTION=queue).
--
-- The API records the work to do and returns; a separate worker process runs
-- the turn. A job is only a pointer: the user's message (already redacted)
-- sits in the session's own state, and an approval decision is read from the
-- approvals table, so the queue holds no message text and no cross-tenant data.
--
-- Workers claim jobs across tenants through one SECURITY DEFINER function that
-- returns only ids. A claim is a lease: a worker that dies lets the lease run
-- out and another worker continues the session from its last checkpoint.
CREATE TABLE IF NOT EXISTS turn_jobs (
    job_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id   text NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    approval_id  uuid,                      -- set when the job resumes a decided approval
    attempts     integer NOT NULL DEFAULT 0,
    claimed_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_turn_jobs_queue ON turn_jobs (created_at);

ALTER TABLE turn_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE turn_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON turn_jobs;
CREATE POLICY tenant_isolation ON turn_jobs FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS lifecycle_access ON turn_jobs;
CREATE POLICY lifecycle_access ON turn_jobs FOR ALL
    USING (current_user = 'harnis_lifecycle') WITH CHECK (current_user = 'harnis_lifecycle');

-- The app role enqueues, renews and finishes jobs inside a tenant context.
GRANT SELECT, INSERT, UPDATE, DELETE ON turn_jobs TO harnis_app;
GRANT SELECT, UPDATE, DELETE ON turn_jobs TO harnis_lifecycle;

CREATE OR REPLACE FUNCTION harnis_claim_turn_job(p_lease_seconds int)
RETURNS TABLE (out_job_id uuid, out_tenant_id text, out_session_id text, out_approval_id uuid, out_attempts int)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    UPDATE turn_jobs j
       SET claimed_at = now(), attempts = j.attempts + 1
     WHERE j.job_id = (SELECT q.job_id FROM turn_jobs q
                        WHERE q.claimed_at IS NULL
                           OR q.claimed_at < now() - make_interval(secs => p_lease_seconds)
                        ORDER BY q.created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1)
    RETURNING j.job_id, j.tenant_id, j.session_id, j.approval_id, j.attempts;
$$;

-- Queue depth and the age of the oldest waiting job, for monitoring.
CREATE OR REPLACE FUNCTION harnis_turn_queue_stats()
RETURNS TABLE (out_queued bigint, out_oldest_seconds double precision)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT count(*), coalesce(extract(epoch FROM now() - min(created_at)), 0)::double precision FROM turn_jobs;
$$;

ALTER FUNCTION harnis_claim_turn_job(int) OWNER TO harnis_lifecycle;
ALTER FUNCTION harnis_turn_queue_stats() OWNER TO harnis_lifecycle;
REVOKE ALL ON FUNCTION harnis_claim_turn_job(int) FROM PUBLIC;
REVOKE ALL ON FUNCTION harnis_turn_queue_stats() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_claim_turn_job(int) TO harnis_app;
GRANT EXECUTE ON FUNCTION harnis_turn_queue_stats() TO harnis_app;

-- The stale-session reaper also drops the jobs of the sessions it fails.
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
    ), purged AS (
        DELETE FROM turn_jobs t USING reaped r WHERE t.session_id = r.session_id
    ), logged AS (
        INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)
        SELECT r.tenant_id, r.session_id, 'harnis', 'stale_session_reaped', '{}'::jsonb FROM reaped r
    )
    SELECT r.tenant_id, r.session_id FROM reaped r;
END $$;
