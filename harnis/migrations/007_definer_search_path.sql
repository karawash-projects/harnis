-- SECURITY DEFINER functions: put the session's temporary schema last.
--
-- PostgreSQL searches the temporary schema (pg_temp) first for relations unless
-- it is listed explicitly, so a role with the default TEMPORARY privilege could
-- shadow a table that a definer function reads. Every definer function already
-- pins its search_path to `public`; this lists pg_temp last, as the PostgreSQL
-- documentation recommends ("Writing SECURITY DEFINER Functions Safely").
DO $$
DECLARE
    f record;
BEGIN
    FOR f IN SELECT p.oid::regprocedure AS sig
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE p.prosecdef AND n.nspname = 'public'
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = public, pg_temp', f.sig);
    END LOOP;
END $$;
