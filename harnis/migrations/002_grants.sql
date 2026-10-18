-- 002_grants.sql — least-privilege grants for the application role.
-- harnis_app gets only the verbs it needs; no DELETE anywhere, and the audit
-- log is insert/select only so the app cannot rewrite history.

GRANT USAGE ON SCHEMA public TO harnis_app;

GRANT SELECT                 ON tenants         TO harnis_app;
GRANT SELECT, INSERT, UPDATE ON sessions        TO harnis_app;
GRANT SELECT, INSERT, UPDATE ON approvals       TO harnis_app;
GRANT SELECT, INSERT         ON prompt_registry TO harnis_app;
GRANT SELECT, INSERT         ON audit_log       TO harnis_app;
GRANT SELECT, INSERT         ON run_metrics     TO harnis_app;
GRANT SELECT, INSERT         ON token_ledger    TO harnis_app;
GRANT USAGE ON SEQUENCE audit_log_event_id_seq, run_metrics_metric_id_seq TO harnis_app;

GRANT SELECT ON tenant_analytics_hourly TO harnis_app;
GRANT SELECT ON tenant_usage_by_model   TO harnis_app;

-- Explicitly NOT granted: run_metrics_hourly_mv, token_ledger_* partitions,
-- refresh_analytics(), ensure_ledger_partitions().
REVOKE ALL ON FUNCTION ensure_ledger_partitions(integer) FROM PUBLIC;
