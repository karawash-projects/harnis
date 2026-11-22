-- A separate login for platform administration (optional; off until an operator configures and enforces it).
--
-- harnis_platform_ops may run the platform functions and use the platform audit log. By default the
-- application login keeps those rights too, so nothing changes. `python -m harnis.migrate platform-role
-- enforce` removes them from the application login; after that only harnis_platform_ops can create,
-- change or delete tenants, set their controls or lift a trip wire.

GRANT USAGE ON SCHEMA public TO harnis_platform_ops;
GRANT EXECUTE ON FUNCTION harnis_admin_list_tenants() TO harnis_platform_ops;
GRANT EXECUTE ON FUNCTION harnis_admin_upsert_tenant(text, text, text[], numeric, boolean, text) TO harnis_platform_ops;
GRANT EXECUTE ON FUNCTION harnis_admin_set_tenant_controls(text, numeric, numeric, integer, boolean, text) TO harnis_platform_ops;
GRANT EXECUTE ON FUNCTION harnis_admin_clear_trip(text, text) TO harnis_platform_ops;
GRANT EXECUTE ON FUNCTION harnis_delete_tenant(text) TO harnis_platform_ops;
GRANT SELECT, INSERT ON platform_audit TO harnis_platform_ops;
GRANT USAGE ON SEQUENCE platform_audit_event_id_seq TO harnis_platform_ops;
