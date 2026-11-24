-- Scheduled tasks: a message sent to an agent on a schedule, as the person who created it.
--
-- Each run is an ordinary session and turn, so every guard still applies: the same budgets, the same
-- path policy, and every change or command still waits in Approvals (and expires after the usual
-- time if nobody decides). Nothing here lets work skip an approval.
--
-- Schedulers (in the API or a worker) claim due tasks across tenants through one SECURITY DEFINER
-- function; a claim is a short lease so a scheduler that dies lets another one pick the task up.
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    task_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id        text NOT NULL,
    name           text NOT NULL,
    agent          text,
    message        text NOT NULL,
    schedule       jsonb NOT NULL,
    timezone       text NOT NULL DEFAULT 'UTC',
    enabled        boolean NOT NULL DEFAULT true,
    next_run_at    timestamptz,
    claimed_until  timestamptz,
    last_run_at    timestamptz,
    last_status    text,
    last_session_id text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scheduled_due ON scheduled_tasks (next_run_at) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_scheduled_owner ON scheduled_tasks (tenant_id, user_id);

ALTER TABLE scheduled_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON scheduled_tasks;
CREATE POLICY tenant_isolation ON scheduled_tasks FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS lifecycle_access ON scheduled_tasks;
CREATE POLICY lifecycle_access ON scheduled_tasks FOR ALL
    USING (current_user = 'harnis_lifecycle') WITH CHECK (current_user = 'harnis_lifecycle');

GRANT SELECT, INSERT, UPDATE, DELETE ON scheduled_tasks TO harnis_app;
GRANT SELECT, UPDATE ON scheduled_tasks TO harnis_lifecycle;

CREATE OR REPLACE FUNCTION harnis_claim_due_schedules(p_limit int, p_lease_seconds int)
RETURNS TABLE (out_task_id uuid, out_tenant_id text, out_user_id text, out_name text, out_agent text,
               out_message text, out_schedule jsonb, out_timezone text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    UPDATE scheduled_tasks t
       SET claimed_until = now() + make_interval(secs => p_lease_seconds)
     WHERE t.task_id IN (SELECT q.task_id FROM scheduled_tasks q
                          WHERE q.enabled AND q.next_run_at <= now()
                            AND (q.claimed_until IS NULL OR q.claimed_until < now())
                          ORDER BY q.next_run_at
                          FOR UPDATE SKIP LOCKED
                          LIMIT greatest(p_limit, 1))
    RETURNING t.task_id, t.tenant_id, t.user_id, t.name, t.agent, t.message, t.schedule, t.timezone;
$$;

ALTER FUNCTION harnis_claim_due_schedules(int, int) OWNER TO harnis_lifecycle;
REVOKE ALL ON FUNCTION harnis_claim_due_schedules(int, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION harnis_claim_due_schedules(int, int) TO harnis_app;
