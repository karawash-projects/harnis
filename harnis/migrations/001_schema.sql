-- 001_schema.sql — core multi-tenant schema with Row-Level Security.
--
-- Run as the OWNER role (see harnis/migrate.py). The application connects as
-- `harnis_app`, which is neither the table owner nor a superuser, so RLS is
-- enforced on every query it makes. FORCE ROW LEVEL SECURITY additionally
-- applies the policies to the owner, so a mis-configured DATABASE_URL fails
-- closed instead of silently seeing every tenant.
--
-- Tenant context is set per transaction with:
--     SELECT set_config('app.tenant_id', '<tenant>', true);
-- `current_setting('app.tenant_id', true)` returns NULL when unset, and
-- `tenant_id = NULL` is never true, so a missing context returns zero rows.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id          text PRIMARY KEY,
    name               text NOT NULL,
    -- Providers this tenant's data may be sent to (data residency / contracts).
    allowed_providers  text[] NOT NULL DEFAULT ARRAY['anthropic','openai','mock'],
    max_cost_usd_per_turn numeric(10,4),
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id    text PRIMARY KEY,
    tenant_id     text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id       text NOT NULL,
    status        text NOT NULL DEFAULT 'idle'
                  CHECK (status IN ('idle','running','awaiting_approval','completed',
                                    'rejected','escalated','failed')),
    current_node  text NOT NULL DEFAULT 'ingest',
    state         jsonb NOT NULL DEFAULT '{}'::jsonb,
    version       integer NOT NULL DEFAULT 0,   -- optimistic concurrency
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id    text NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    requested_by  text NOT NULL,
    action        jsonb NOT NULL,
    -- SHA-256 of the canonical action. A decision must quote it, so a reviewer
    -- can only ever approve the exact command/diff they were shown.
    action_hash   text NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','approved','denied','expired')),
    decided_by    text,
    decided_at    timestamptz,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_pending ON approvals (tenant_id, status, requested_at);

CREATE TABLE IF NOT EXISTS prompt_registry (
    tenant_id      text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    prompt_key     text NOT NULL,
    version        integer NOT NULL,
    prompt_text    text NOT NULL,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, prompt_key, version)
);

-- Append-only audit trail of security-relevant events.
CREATE TABLE IF NOT EXISTS audit_log (
    event_id    bigserial PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id  text,
    actor       text NOT NULL,
    event_type  text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log (tenant_id, created_at DESC);

-- Per-turn run metrics feeding the analytics view.
CREATE TABLE IF NOT EXISTS run_metrics (
    metric_id      bigserial PRIMARY KEY,
    tenant_id      text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id     text NOT NULL,
    latency_ms     integer NOT NULL,
    cache_hit      boolean NOT NULL DEFAULT false,
    outcome        text NOT NULL,
    steps          integer NOT NULL DEFAULT 0,
    recorded_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_metrics_tenant ON run_metrics (tenant_id, recorded_at);

-- Token ledger, partitioned by month. A DEFAULT partition guarantees inserts
-- never fail when the maintenance job is late; `ensure_ledger_partitions`
-- creates upcoming months (call it from cron / pg_cron).
CREATE TABLE IF NOT EXISTS token_ledger (
    event_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id         text NOT NULL,
    provider           text NOT NULL,
    model              text NOT NULL,
    input_tokens       integer NOT NULL DEFAULT 0,
    output_tokens      integer NOT NULL DEFAULT 0,
    cost_usd           numeric(12,6) NOT NULL DEFAULT 0,
    logged_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, logged_at)
) PARTITION BY RANGE (logged_at);

CREATE TABLE IF NOT EXISTS token_ledger_default PARTITION OF token_ledger DEFAULT;
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_time ON token_ledger (tenant_id, logged_at);

CREATE OR REPLACE FUNCTION ensure_ledger_partitions(months_ahead integer DEFAULT 2)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    m date := date_trunc('month', now())::date;
    i integer;
    part text;
BEGIN
    FOR i IN 0..months_ahead LOOP
        part := format('token_ledger_%s', to_char(m + make_interval(months => i), 'YYYY_MM'));
        IF to_regclass(part) IS NULL THEN
            -- Note: if the DEFAULT partition already holds rows for this range,
            -- they must be moved first; this job runs ahead of time so it doesn't.
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF token_ledger FOR VALUES FROM (%L) TO (%L)',
                part, m + make_interval(months => i), m + make_interval(months => i + 1));
        END IF;
    END LOOP;
END $$;

SELECT ensure_ledger_partitions(2);

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sessions','approvals','prompt_registry','audit_log',
                             'run_metrics','token_ledger','tenants']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I FOR ALL
               USING (tenant_id = current_setting(''app.tenant_id'', true))
               WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))', t);
    END LOOP;
END $$;

-- RLS on a partitioned table applies to queries through the parent. Block
-- direct access to the partitions themselves by never granting on them.

-- ---------------------------------------------------------------------------
-- Analytics.
--
-- Materialized views do NOT support RLS, and a matview must read every
-- tenant's rows to aggregate them. So:
--   * the matview is owned by `harnis_analytics`, a NOLOGIN role nobody can
--     log in as, and the run_metrics policy lets exactly that role read all rows;
--   * the app is never granted the matview itself;
--   * the app reads a security-barrier view whose WHERE clause filters on the
--     tenant context. That view runs with its owner's rights (it has to read
--     the matview), so the WHERE clause *is* the isolation boundary.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS analytics_reader ON run_metrics;
CREATE POLICY analytics_reader ON run_metrics FOR SELECT
    USING (current_user = 'harnis_analytics');
GRANT SELECT ON run_metrics TO harnis_analytics;

DROP MATERIALIZED VIEW IF EXISTS run_metrics_hourly_mv CASCADE;
CREATE MATERIALIZED VIEW run_metrics_hourly_mv AS
SELECT tenant_id,
       date_trunc('hour', recorded_at) AS hour,
       count(*)                                                          AS runs,
       round(avg(latency_ms)::numeric, 1)                                AS avg_latency_ms,
       round(100.0 * count(*) FILTER (WHERE cache_hit) / count(*), 2)    AS cache_hit_pct,
       round(100.0 * count(*) FILTER (WHERE outcome = 'completed') / count(*), 2) AS success_pct,
       count(*) FILTER (WHERE outcome IN ('rejected','failed'))          AS halted
FROM run_metrics
GROUP BY tenant_id, date_trunc('hour', recorded_at)
WITH NO DATA;
CREATE UNIQUE INDEX run_metrics_hourly_mv_pk ON run_metrics_hourly_mv (tenant_id, hour);
ALTER MATERIALIZED VIEW run_metrics_hourly_mv OWNER TO harnis_analytics;

SET ROLE harnis_analytics;
REFRESH MATERIALIZED VIEW run_metrics_hourly_mv;
RESET ROLE;

CREATE OR REPLACE VIEW tenant_analytics_hourly WITH (security_barrier = true) AS
SELECT tenant_id, hour, runs, avg_latency_ms, cache_hit_pct, success_pct, halted
FROM run_metrics_hourly_mv
WHERE tenant_id = current_setting('app.tenant_id', true);
ALTER VIEW tenant_analytics_hourly OWNER TO harnis_analytics;

-- A plain view over an RLS table: security_invoker makes RLS apply to the
-- caller (Postgres 15+). Without it a view runs as its owner and can leak
-- every tenant's rows.
CREATE OR REPLACE VIEW tenant_usage_by_model WITH (security_invoker = true) AS
SELECT tenant_id, provider, model,
       sum(input_tokens)  AS input_tokens,
       sum(output_tokens) AS output_tokens,
       sum(cost_usd)      AS cost_usd,
       count(*)           AS calls
FROM token_ledger
GROUP BY tenant_id, provider, model;

-- Refresh entry point for cron / `python tasks.py maintenance`.
CREATE OR REPLACE FUNCTION refresh_analytics() RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
    REFRESH MATERIALIZED VIEW CONCURRENTLY run_metrics_hourly_mv;
$$;
ALTER FUNCTION refresh_analytics() OWNER TO harnis_analytics;
REVOKE ALL ON FUNCTION refresh_analytics() FROM PUBLIC;
