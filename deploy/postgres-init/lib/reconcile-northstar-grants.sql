-- Northstar PostgreSQL privilege reconciliation.
--
-- This file is intentionally not placed directly in docker-entrypoint-initdb.d:
-- the official PostgreSQL image would otherwise execute it without the psql
-- variables below. Invoke it through 010-northstar-roles.sh on a fresh volume
-- or scripts/reconcile-database-grants.sh after every migration.
--
-- Required psql variables:
--   database_name, migrator_role, runtime_role, command_role, backup_role,
--   allow_bootstrap, grant_phase (bootstrap, auto, or exact)
--
-- Keep the assertions and grants in the sibling files. Restore embeds the same
-- grant body in its database-replacement transaction, so post-restore ACLs
-- cannot drift from the ordinary post-migration policy.

BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('northstar-database-role-policy-v1', 0)
);
\ir verify-northstar-grant-boundary.sql
\ir northstar-migration-ledger-manifest.sql
\ir northstar-capability-manifest.sql
\ir apply-northstar-grants.sql
COMMIT;
