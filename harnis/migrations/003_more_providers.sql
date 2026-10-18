-- 003_more_providers.sql: Gemini and Amazon Nova join the provider list.
--
-- `tenants.allowed_providers` decides which model providers a tenant's data
-- may be sent to. New tenants allow all of them by default. Existing tenants
-- that still have the old default list get the new providers too; tenants with
-- a deliberately narrowed list (e.g. Anthropic only, for data residency) are
-- left exactly as they are.

ALTER TABLE tenants ALTER COLUMN allowed_providers
    SET DEFAULT ARRAY['anthropic','openai','gemini','nova','mock'];

-- FORCE RLS applies to the table owner (the migrator); lift it inside this
-- transaction so the UPDATE sees every tenant. The ALTER takes an exclusive
-- lock, so no other session runs against the table until it is forced again.
ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;
UPDATE tenants
   SET allowed_providers = ARRAY['anthropic','openai','gemini','nova','mock']
 WHERE allowed_providers = ARRAY['anthropic','openai','mock'];
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
