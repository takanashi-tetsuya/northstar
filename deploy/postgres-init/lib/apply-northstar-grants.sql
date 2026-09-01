-- Atomic Northstar PostgreSQL ACL/default-privilege policy.
--
-- The caller must already be inside a transaction and must have established
-- the preconditions in verify-northstar-grant-boundary.sql. Required psql
-- variables: database_name, migrator_role, runtime_role, command_role, backup_role.

SELECT pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('northstar-database-role-policy-v1', 0)
);

-- The caller must load the version-controlled capability manifest in this
-- same psql session before entering this transaction.  Do not reconstruct the
-- expected set from current grants: doing so would turn reconciliation into a
-- circular self-attestation.
SELECT pg_catalog.to_regclass('pg_temp.northstar_capability_manifest') IS NOT NULL
  AS northstar_capability_manifest_is_loaded \gset
\if :northstar_capability_manifest_is_loaded
\else
  \echo 'canonical Northstar capability manifest was not loaded'
  \quit 44
\endif

SELECT pg_catalog.to_regclass('pg_temp.northstar_migration_ledger_manifest') IS NOT NULL
  AS northstar_migration_ledger_manifest_is_loaded \gset
\if :northstar_migration_ledger_manifest_is_loaded
\else
  \echo 'canonical Northstar migration ledger manifest was not loaded'
  \quit 44
\endif

-- Reconciliation has three deliberately different lifecycle phases:
--
--   bootstrap  an empty database before sqlx has created application objects;
--   prepare    a stopped legacy database whose 0114/0115 capability boundary
--              has not been installed yet; and
--   exact      a fully migrated database where every current-object grant is
--              rebuilt from the canonical manifest.
--
-- `auto` is reserved for the stopped legacy-role upgrade tool.  It may select
-- bootstrap/prepare/exact from the immutable sqlx ledger, but a partially
-- applied 0114/0115 boundary is always rejected.  In particular, absence of
-- one expected function is never treated as permission to skip attestation.
\if :{?grant_phase}
\else
  \set grant_phase exact
\endif

DROP TABLE IF EXISTS pg_temp.northstar_grant_phase_context;
CREATE TEMPORARY TABLE northstar_grant_phase_context (
  requested_phase pg_catalog.text NOT NULL,
  resolved_phase pg_catalog.text,
  ledger_present pg_catalog.bool NOT NULL DEFAULT false,
  migration_0114 pg_catalog.bool NOT NULL DEFAULT false,
  migration_0115 pg_catalog.bool NOT NULL DEFAULT false
) ON COMMIT DROP;
INSERT INTO pg_temp.northstar_grant_phase_context(requested_phase)
VALUES (pg_catalog.lower(:'grant_phase'));

DO $northstar_grant_phase$
DECLARE
  context pg_temp.northstar_grant_phase_context%ROWTYPE;
  has_application_objects pg_catalog.bool;
  has_pre_boundary_ledger pg_catalog.bool := false;
  has_post_boundary_ledger pg_catalog.bool := false;
  has_boundary_attempt pg_catalog.bool := false;
  ledger_all_successful pg_catalog.bool := true;
  ledger_shape_valid pg_catalog.bool := true;
  ledger_matches_prepare pg_catalog.bool := false;
  ledger_matches_exact pg_catalog.bool := false;
  latest_successful_version pg_catalog.int8;
BEGIN
  SELECT * INTO STRICT context FROM pg_temp.northstar_grant_phase_context;
  IF context.requested_phase NOT IN ('bootstrap','auto','exact') THEN
    RAISE EXCEPTION 'invalid Northstar grant phase: %', context.requested_phase;
  END IF;

  context.ledger_present := pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL;
  IF context.ledger_present THEN
    EXECUTE $sql$
      SELECT COALESCE(pg_catalog.bool_or(version=114 AND success),false),
             COALESCE(pg_catalog.bool_or(version=115 AND success),false),
             COALESCE(pg_catalog.bool_or(version=113 AND success),false),
             COALESCE(pg_catalog.bool_or(version>115 AND success),false),
             COALESCE(pg_catalog.bool_or(version>=114),false),
             COALESCE(pg_catalog.bool_and(success),true),
             pg_catalog.count(*)=pg_catalog.count(DISTINCT version)
               AND COALESCE(pg_catalog.bool_and(
                 version>0 AND description<>''
                 AND pg_catalog.octet_length(checksum)=48
               ),true),
             pg_catalog.max(version) FILTER (WHERE success)
        FROM public._sqlx_migrations
    $sql$
      INTO context.migration_0114,context.migration_0115,
           has_pre_boundary_ledger,has_post_boundary_ledger,
           has_boundary_attempt,ledger_all_successful,ledger_shape_valid,
           latest_successful_version;

    -- The database must match the repository-owned sqlx ledger byte for byte.
    -- Comparing two EXCEPT sets preserves intentional migration-number gaps
    -- (for example 0021) while rejecting missing, unknown, renamed, modified,
    -- failed, or checksum-forged rows.  Never derive the expected set from the
    -- database itself: that would make this security gate self-attesting.
    EXECUTE $sql$
      WITH actual AS (
        SELECT version,description,checksum
          FROM public._sqlx_migrations
         WHERE success
      ), expected AS (
        SELECT version,description,checksum
          FROM pg_temp.northstar_migration_ledger_manifest
      )
      SELECT
        NOT EXISTS (
          (SELECT version,description,checksum FROM actual WHERE version<=113
           EXCEPT
           SELECT version,description,checksum FROM expected WHERE version<=113)
          UNION ALL
          (SELECT version,description,checksum FROM expected WHERE version<=113
           EXCEPT
           SELECT version,description,checksum FROM actual WHERE version<=113)
        )
        AND NOT EXISTS (
          SELECT 1 FROM public._sqlx_migrations WHERE version>113
        ),
        NOT EXISTS (
          (SELECT version,description,checksum FROM actual
           EXCEPT
           SELECT version,description,checksum FROM expected)
          UNION ALL
          (SELECT version,description,checksum FROM expected
           EXCEPT
           SELECT version,description,checksum FROM actual)
        )
    $sql$ INTO ledger_matches_prepare,ledger_matches_exact;
  END IF;

  IF NOT ledger_all_successful THEN
    RAISE EXCEPTION
      'tampered or dirty Northstar migration ledger: every recorded migration must be successful before grant reconciliation';
  END IF;
  IF NOT ledger_shape_valid THEN
    RAISE EXCEPTION
      'tampered Northstar migration ledger: versions must be unique and positive, descriptions non-empty, and every checksum exactly SHA-384';
  END IF;

  IF context.migration_0114 IS DISTINCT FROM context.migration_0115 THEN
    RAISE EXCEPTION
      'partial Northstar capability boundary: migrations 0114 and 0115 must be applied together before grant reconciliation';
  END IF;
  IF has_post_boundary_ledger
     AND NOT (context.migration_0114 AND context.migration_0115) THEN
    RAISE EXCEPTION
      'tampered Northstar migration ledger: a post-0115 migration exists without the complete 0114/0115 boundary';
  END IF;
  IF has_boundary_attempt
     AND NOT (context.migration_0114 AND context.migration_0115) THEN
    RAISE EXCEPTION
      'partial Northstar capability upgrade: the ledger contains 0114-or-later work without the complete 0114/0115 boundary';
  END IF;

  SELECT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname='public'
       AND relation.relname<>'_sqlx_migrations'
       AND relation.relkind IN ('r','p','v','m','S','f')
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_class'::pg_catalog.regclass
            AND dependency.objid=relation.oid AND dependency.deptype='e'
       )
    UNION ALL
    SELECT 1
      FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
     WHERE namespace.nspname='public'
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_proc'::pg_catalog.regclass
            AND dependency.objid=routine.oid AND dependency.deptype='e'
       )
    UNION ALL
    SELECT 1
      FROM pg_catalog.pg_type data_type
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=data_type.typnamespace
     WHERE namespace.nspname='public' AND data_type.typelem=0
       AND ((data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
         OR (data_type.typtype='c' AND EXISTS (
           SELECT 1 FROM pg_catalog.pg_class composite_relation
            WHERE composite_relation.oid=data_type.typrelid
              AND composite_relation.relkind='c'
         )))
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid=data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
  ) INTO has_application_objects;

  context.resolved_phase := CASE context.requested_phase
    WHEN 'bootstrap' THEN 'bootstrap'
    WHEN 'exact' THEN 'exact'
    WHEN 'auto' THEN CASE
      WHEN context.migration_0114 AND context.migration_0115 THEN 'exact'
      WHEN NOT context.ledger_present AND NOT has_application_objects THEN 'bootstrap'
      ELSE 'prepare'
    END
  END;

  IF context.resolved_phase='bootstrap'
     AND (context.ledger_present OR has_application_objects) THEN
    RAISE EXCEPTION
      'bootstrap grant phase requires a genuinely empty database with no sqlx ledger or application objects';
  END IF;
  IF context.resolved_phase='prepare'
     AND (NOT context.ledger_present OR NOT has_application_objects
          OR NOT has_pre_boundary_ledger
          OR NOT ledger_matches_prepare
          OR latest_successful_version<>113
          OR context.migration_0114 OR context.migration_0115) THEN
    RAISE EXCEPTION
      'prepare grant phase requires a stopped migration-0113 database before the 0114/0115 capability boundary';
  END IF;
  IF context.resolved_phase='exact'
     AND (NOT context.migration_0114 OR NOT context.migration_0115
          OR NOT ledger_matches_exact) THEN
    RAISE EXCEPTION
      'exact grant phase requires the complete repository-authenticated migration ledger, including successful migrations 0114 and 0115';
  END IF;

  UPDATE pg_temp.northstar_grant_phase_context
     SET resolved_phase=context.resolved_phase,
         ledger_present=context.ledger_present,
         migration_0114=context.migration_0114,
         migration_0115=context.migration_0115;
END
$northstar_grant_phase$;

SELECT resolved_phase='exact' AS northstar_exact_grant_phase
  FROM pg_temp.northstar_grant_phase_context \gset

\if :northstar_exact_grant_phase

-- Erase arbitrary database/schema grantees before rebuilding the exact
-- owner-issued CONNECT/USAGE rows.  CASCADE removes grant-option descendants;
-- the catalog postcondition below also checks grantor and grantability.
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON DATABASE %I FROM %s CASCADE',
         database.datname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_database database
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   database.datacl,pg_catalog.acldefault('d',database.datdba)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE database.datname=:'database_name'
   AND privilege.grantee<>database.datdba
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %s CASCADE',
         namespace.nspname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_namespace namespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND privilege.grantee<>namespace.nspowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

-- PUBLIC must not inherit the PostgreSQL defaults (CONNECT/TEMP on databases,
-- USAGE on schema public, and EXECUTE on newly-created functions).
REVOKE ALL PRIVILEGES ON DATABASE :"database_name" FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC CASCADE;

-- Reconciliation is convergent: erase every legacy direct grant before
-- rebuilding the exact workload manifests below.
REVOKE ALL PRIVILEGES ON DATABASE :"database_name"
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON SCHEMA public
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;

-- Retired/custom roles are not part of Northstar's database trust boundary.
-- Erase every explicit non-owner relation and column ACL before rebuilding
-- runtime/backup access.  Restricting this to the three known workload names
-- would leave historical grantees able to mutate owner-held authority tables
-- or read SM bearer/IP material.
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I CASCADE',
         namespace.nspname,relation.relname,grantee.rolname
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
  JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND relation.relkind IN ('r','p','v','m','f')
   AND privilege.grantee<>relation.relowner
 ORDER BY 1
\gexec
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I CASCADE',
         namespace.nspname,relation.relname,grantee.rolname
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
  JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND relation.relkind='S'
   AND privilege.grantee<>relation.relowner
 ORDER BY 1
\gexec
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM %I CASCADE',
         pg_catalog.string_agg(
           DISTINCT pg_catalog.quote_ident(attribute.attname),','
           ORDER BY pg_catalog.quote_ident(attribute.attname)
         ),
         namespace.nspname,relation.relname,grantee.rolname
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_attribute AS attribute
    ON attribute.attrelid=relation.oid
   AND attribute.attnum>0 AND NOT attribute.attisdropped
 CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
  JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND relation.relkind IN ('r','p','v','m','f')
   AND privilege.grantee<>relation.relowner
 GROUP BY namespace.nspname,relation.relname,grantee.rolname
 ORDER BY namespace.nspname,relation.relname,grantee.rolname
\gexec

-- Table-level REVOKE does not erase independently granted column ACLs.  A
-- legacy or compromised owner could otherwise leave UPDATE(password_hash) or
-- SELECT(bearer_hash) behind while the relation-level manifest appears clean.
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM PUBLIC, %I, %I, %I CASCADE',
         pg_catalog.string_agg(pg_catalog.quote_ident(attribute.attname),','
                               ORDER BY attribute.attnum),
         namespace.nspname,
         relation.relname,
         :'runtime_role',
         :'command_role',
         :'backup_role'
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_attribute AS attribute
    ON attribute.attrelid=relation.oid
   AND attribute.attnum>0
   AND NOT attribute.attisdropped
 WHERE namespace.nspname='public'
   AND relation.relkind IN ('r','p','v','m','f')
 GROUP BY namespace.nspname,relation.relname
 ORDER BY namespace.nspname,relation.relname
\gexec

GRANT CONNECT ON DATABASE :"database_name"
   TO :"migrator_role", :"runtime_role", :"command_role", :"backup_role";
GRANT USAGE ON SCHEMA public
   TO :"runtime_role", :"command_role", :"backup_role";

-- The runtime role deliberately has no database/schema CREATE privilege and
-- cannot alter ownership or disable triggers.  Current mutable application
-- tables retain DML, but immutable governance journals are reduced below to
-- their exact append/transition surface.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
   TO :"runtime_role";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
   TO :"runtime_role";

-- The two ledgers are startup trust roots, never mutable application state.
SELECT pg_catalog.format(
         'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE %I.%I FROM %I',
         namespace.nspname,
         relation.relname,
         :'runtime_role'
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
 WHERE namespace.nspname = 'public'
   AND relation.relname IN ('_sqlx_migrations','jid_identity_migrations')
   AND relation.relkind IN ('r','p')
\gexec

-- Account authority is mutated only through migration-0108 typed command
-- capabilities.  SELECT remains necessary for authentication/routing, while
-- every direct write privilege (including trigger/reference shortcuts) is
-- removed from the long-lived application identity.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.users FROM :"runtime_role";

-- Release facts are append-only evidence produced by owner-held delete
-- triggers. Runtime may inspect them for startup audit and orphan discovery,
-- but only the reviewed drain capability may consume them.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.mix_delivery_capacity_releases FROM :"runtime_role";
GRANT SELECT ON TABLE public.mix_delivery_capacity_releases TO :"runtime_role";

-- MIX-PAM capacity is projected only by owner-held triggers/capabilities.
-- Runtime may update delivery/reconciliation state on an existing operation,
-- but cannot create or remove a journal row (and therefore cannot bypass exact
-- global/per-account accounting). Counter authority is exactly read-only.
REVOKE INSERT, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.mix_pam_operations FROM :"runtime_role";
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.mix_pam_operation_capacity,
           public.mix_pam_operation_user_capacity
  FROM :"runtime_role";
GRANT SELECT ON TABLE public.mix_pam_operation_capacity,
                      public.mix_pam_operation_user_capacity
  TO :"runtime_role";

-- Upload namespace, slot manifests and recovery queues are database-owned
-- authorities. Runtime receives only the typed migration-0113 capabilities;
-- it cannot read bearer hashes/provider locators or bypass lease/accounting
-- transitions with direct table access.
REVOKE ALL PRIVILEGES
  ON TABLE public.upload_storage_authority,
           public.upload_storage_capacity_ledger,
           public.upload_slots,
           public.upload_storage_jobs,
           public.upload_cleanup_queue
  FROM :"runtime_role", :"command_role";

-- Cluster replay admission and exact C2S route ownership are owner-held
-- authorities.  Redis is only a disposable index; allowing the long-lived
-- runtime identity to read or mutate these rows directly would bypass the
-- replay-capacity trigger and the process/connection fencing capabilities.
REVOKE ALL PRIVILEGES
  ON TABLE public.cluster_signed_envelope_replays,
           public.cluster_signed_envelope_replay_capacity,
           public.cluster_session_routes
  FROM :"runtime_role", :"command_role";

-- Live-route leases, replacement claims and SM resume bearers are owner-held
-- authorities. Runtime can inspect only non-secret reconciliation columns;
-- every transition is one of migration-0114's exact, fenced capabilities.
REVOKE ALL PRIVILEGES
  ON TABLE public.deployment_session_leases,
           public.deployment_session_binding_claims,
           public.sm_resume_sessions
  FROM :"runtime_role", :"command_role";
GRANT SELECT
  ON TABLE public.deployment_session_leases,
           public.deployment_session_binding_claims
  TO :"runtime_role";
GRANT SELECT (
    id,user_id,auth_generation,full_jid,resource,connection_id,
    resume_timeout_seconds,inbound_h,outbound_h,acked_h,available,carbons,
    priority,blocklist_requested,roster_requested,active_privacy_list,
    privacy_requested,user_agent_id,joined_rooms,directed_presence,
    last_presence,resumable,live_lease_until,expires_at,claimed_until,
    created_at,updated_at
  ) ON TABLE public.sm_resume_sessions TO :"runtime_role";

-- XEP-0133 control-plane state is readable where routing/workers require it,
-- but every mutation is an owner-held typed capability.  In particular the
-- service-control watcher uses northstar_admin_service_control_poll() rather
-- than retaining enough UPDATE authority to forge an early restart.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.admin_service_messages,
           public.federation_runtime_rules,
           public.admin_service_control
  FROM :"runtime_role";

-- Neither long-lived login can inspect or forge the XEP-0133 bearer ledger.
-- The command role receives only typed session routines below; the runtime
-- role receives only claim-consuming business routines.
REVOKE ALL PRIVILEGES
  ON TABLE public.admin_command_sessions,
           public.admin_command_capability_authority,
           public.admin_session_cleanup_effects,
           public.admin_session_cleanup_capacity
  FROM :"runtime_role", :"command_role";

-- Immutable histories never rely on an application-set GUC as authority.
-- Remove direct mutation after the broad current-table grant; owner-held,
-- allowlisted capabilities below perform the bounded transitions instead.
SELECT pg_catalog.format(
         'REVOKE %s ON TABLE %I.%I FROM %I',
         CASE
           WHEN relation.relname = 'cluster_muc_delivery_handoffs'
             THEN 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
           WHEN relation.relname = 'governance_export_leases'
             THEN 'DELETE, TRUNCATE, REFERENCES, TRIGGER'
           ELSE 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
         END,
         namespace.nspname,
         relation.relname,
         :'runtime_role'
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
 WHERE namespace.nspname = 'public'
   AND relation.relname IN (
         'audit_log',
         'legal_holds',
         'legal_hold_personal_archives',
         'legal_hold_muc_archives',
         'legal_hold_offline_messages',
         'legal_hold_report_evidence',
         'legal_hold_scopes',
         'legal_hold_offline_snapshots',
         'governance_export_leases',
         'cluster_muc_operations',
         'cluster_muc_delivery_handoffs'
       )
   AND relation.relkind IN ('r', 'p')
\gexec

-- Fail closed for elevated routines. Reconciliation first removes all runtime
-- and backup routine execution, then restores ordinary SECURITY INVOKER
-- routines and the exact reviewed SECURITY DEFINER capability set required by
-- runtime. A newly-added definer is denied until this manifest is changed.
-- A future definer routine is therefore denied until explicitly reviewed.
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public
   FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;

-- Remove every stale explicit routine grantee, not only the three known
-- workload roles. Otherwise a retired login/group role could retain an
-- invoker helper or owner-held capability forever. The reviewed runtime and
-- command rows are rebuilt below from current objects and the manifest.
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %I CASCADE',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         grantee.rolname
       )
  FROM pg_catalog.pg_proc AS routine
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=routine.pronamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(
   COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
 ) AS privilege
  JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND privilege.grantee<>routine.proowner
 ORDER BY 1
\gexec

-- Normalize the explicit owner ACL as well.  PostgreSQL ownership itself is
-- implicit, so an old REVOKE from the owner can leave no ACL row even though
-- the owner can still execute the routine.  The canonical manifest requires a
-- stable owner entry plus at most one workload entry.  All non-owner grants
-- were removed above, making this CASCADE deterministic and safe to rebuild.
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %I CASCADE',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'migrator_role'
       )
  FROM pg_temp.northstar_capability_manifest AS expected
  JOIN pg_catalog.pg_proc AS routine
    ON routine.oid=pg_catalog.to_regprocedure('public.' || expected.signature)
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=routine.pronamespace
 WHERE namespace.nspname='public'
 ORDER BY routine.oid
\gexec
SELECT pg_catalog.format(
         'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO %I',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'migrator_role'
       )
  FROM pg_temp.northstar_capability_manifest AS expected
  JOIN pg_catalog.pg_proc AS routine
    ON routine.oid=pg_catalog.to_regprocedure('public.' || expected.signature)
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=routine.pronamespace
 WHERE namespace.nspname='public' AND routine.prokind='f'
 ORDER BY routine.oid
\gexec
SELECT pg_catalog.format(
         'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO %I',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'runtime_role'
       )
  FROM pg_catalog.pg_proc AS routine
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = routine.pronamespace
 WHERE namespace.nspname = 'public'
   AND routine.prokind='f'
   AND NOT routine.prosecdef
   AND routine.proname NOT LIKE 'northstar_admin_command_%'
   AND routine.proname NOT IN (
         'northstar_protect_admin_session_cleanup_identity',
         'northstar_enqueue_admin_generation_cleanup',
         'northstar_enqueue_admin_exact_session_cleanup'
       )
 ORDER BY routine.oid
\gexec
SELECT pg_catalog.format(
         'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO %I',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'runtime_role'
       )
  FROM pg_catalog.pg_proc AS routine
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = routine.pronamespace
 JOIN (VALUES
       ('northstar_transfer_cluster_muc_outbox(uuid,uuid,uuid,uuid,int8,uuid,int8,text)'),
       ('northstar_purge_released_hold_offline_snapshots(int4,int4)'),
       ('northstar_purge_audit_log(int4,int4)'),
       ('northstar_purge_governance_export_leases(int4,int4)'),
       ('northstar_purge_cluster_muc_history(int4,int4)'),
       ('northstar_release_legal_hold(uuid,uuid,text,uuid)'),
       ('northstar_user_register(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,bytea,bool,int4,uuid)'),
       ('northstar_user_create_bootstrap_admin(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
       ('northstar_user_clear_scram_sha1()'),
       ('northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
       ('northstar_user_change_password_api(uuid,text,int8,bytea,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,uuid)'),
       ('northstar_user_change_password_stream(uuid,int8,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
       ('northstar_user_set_status_api(uuid,int8,bytea,uuid,bool,bool)'),
       ('northstar_user_bump_roster_version(uuid)'),
       ('northstar_user_consume_recovery_generation(uuid,int8,bytea)'),
       ('northstar_user_quiesce_deletion(uuid,int8)'),
       ('northstar_user_delete_quiesced(uuid,text)'),
       ('northstar_admin_command_authorize_claim(text,uuid,text,int8,text,bytea)'),
       ('northstar_admin_command_create_user(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text)'),
       ('northstar_admin_command_reset_user_password(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text,text)'),
       ('northstar_admin_command_user_lifecycle(text,uuid,text,int8,text,bytea,uuid,text,text,text,text,bool,text)'),
       ('northstar_admin_command_issue_delete_cleanup(text,uuid,text,int8,text,bytea,uuid,text,text)'),
       ('northstar_claim_admin_session_cleanup(uuid,int4)'),
       ('northstar_renew_admin_session_cleanup(uuid,uuid,uuid,int4)'),
       ('northstar_retry_admin_session_cleanup(uuid,uuid,uuid,text)'),
       ('northstar_complete_admin_session_cleanup(uuid,uuid,uuid)'),
       ('northstar_admin_session_cleanup_target_current(uuid,uuid,uuid)'),
       ('northstar_admin_session_cleanup_snapshot()'),
       ('northstar_admin_command_delete_user(text,uuid,text,int8,text,bytea,uuid,text,bool,text)'),
       ('northstar_admin_command_replace_users(text,uuid,text,int8,text,bytea,uuid[],text)'),
       ('northstar_admin_command_record_announcement(text,uuid,text,int8,text,bytea,int4,int4,text)'),
       ('northstar_admin_command_set_service_message(text,uuid,text,int8,text,bytea,text,text,text)'),
       ('northstar_admin_command_replace_federation_rules(text,uuid,text,int8,text,bytea,text,text[],text)'),
       ('northstar_admin_command_service_control(text,uuid,text,int8,text,bytea,text,int4,text,bool,text)'),
       ('northstar_admin_service_control_poll()'),
       ('northstar_session_delete_expired_live_leases()'),
       ('northstar_session_capacity_reconcile_lock()'),
       ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
       ('northstar_session_finalize_binding(uuid,uuid,text)'),
       ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
       ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
       ('northstar_session_release_live(uuid)'),
       ('northstar_session_refresh_live(uuid[],int8)'),
       ('northstar_session_cleanup_live(int8)'),
       ('northstar_session_extend_live(uuid,int8)'),
       ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)'),
       ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)'),
       ('northstar_sm_remove_memberships(uuid,uuid,jsonb)'),
       ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)'),
       ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)'),
       ('northstar_sm_claim_authority(uuid,uuid)'),
       ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)'),
       ('northstar_sm_release_claim(uuid,uuid)'),
       ('northstar_sm_revoke(uuid)'),
       ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)'),
       ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)'),
       ('northstar_sm_count(text,uuid,int8,text)'),
       ('northstar_sm_finalize_teardown(uuid,uuid)'),
       ('northstar_sm_lock_suspended(uuid)'),
       ('northstar_sm_advance_suspended(uuid,int8,int8)'),
       ('northstar_sm_expire_before_generation(uuid,int8)'),
       ('northstar_sm_privacy_list_in_use(uuid,text)'),
       ('northstar_sm_privacy_state(uuid)'),
       ('northstar_session_capability_catalog_healthy(text)'),
       ('northstar_mix_delivery_capacity_drain()'),
       ('northstar_mix_delivery_capacity_reconcile()'),
       ('northstar_mix_pam_account_capacity_lock(uuid,text)'),
       ('northstar_mix_pam_operation_insert(uuid,uuid,text,text,text,text,text,text,bytea,uuid,bool,text,text,text[],int8,text)'),
       ('northstar_mix_pam_operation_prune(int8)'),
       ('northstar_mix_pam_capacity_reconcile()'),
       ('northstar_upload_bootstrap_authority(text,bytea)'),
       ('northstar_upload_bind_capacity_policy(int8,int8,int8)'),
       ('northstar_upload_capacity_lock()'),
       ('northstar_upload_active_slot_count(uuid)'),
       ('northstar_upload_public_slot_count()'),
       ('northstar_upload_renew_claim(uuid,uuid,int8)'),
       ('northstar_upload_authority_probe(text,bytea,int8,int8,int8,int8,int8)'),
       ('northstar_upload_dead_letters_page(text,int8,uuid,int4)'),
       ('northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'),
       ('northstar_upload_claim_cleanup(uuid)'),
       ('northstar_upload_cleanup_quiescent(uuid,uuid,int8)'),
       ('northstar_upload_defer_cleanup(uuid,uuid)'),
       ('northstar_upload_confirm_cleanup_absence(uuid,uuid,bool,int8)'),
       ('northstar_upload_fail_cleanup(uuid,uuid,text)'),
       ('northstar_upload_complete_cleanup(uuid,uuid)'),
       ('northstar_upload_claim_storage_jobs(uuid)'),
       ('northstar_upload_complete_storage_job(int8,uuid)'),
       ('northstar_upload_confirm_stage_absence(int8,uuid,bool,int8)'),
       ('northstar_upload_fail_storage_job(int8,uuid,text)'),
       ('northstar_upload_defer_storage_job(int8,uuid)'),
       ('northstar_upload_claim_promotion_job(uuid,uuid,int8,uuid)'),
       ('northstar_upload_defer_promotion_job(uuid,uuid,int8,uuid)'),
       ('northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)'),
       ('northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)'),
       ('northstar_upload_release_claim(uuid,uuid)'),
       ('northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)'),
       ('northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)'),
       ('northstar_upload_claim_is_live(uuid,uuid)'),
       ('northstar_upload_begin_promotion(uuid,uuid,int8,uuid)'),
       ('northstar_upload_attempt_committed(uuid,uuid,text,text,text,bytea,int8,int8)'),
       ('northstar_upload_record_replay(uuid,bytea,bytea,int8)'),
       ('northstar_upload_public_file(uuid)'),
       ('northstar_upload_claim_scrub()'),
       ('northstar_upload_finish_scrub(uuid,uuid,text)'),
       ('northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)'),
       ('northstar_upload_capacity_reconciliation()'),
       ('northstar_upload_queue_snapshot()'),
       ('northstar_upload_policy_binding_matches(int8,int8,int8)'),
       ('northstar_upload_admit_expired_cleanup()'),
       ('northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)'),
       ('northstar_upload_capability_catalog_healthy(text)'),
       ('northstar_admit_cluster_envelope_replay(text,text,uuid,int8,text,int8,text,uuid,int8,text,int8,uuid,bytea,text,timestamptz)'),
       ('northstar_cleanup_cluster_envelope_replays(int4)'),
       ('northstar_cluster_replay_capacity_healthy()'),
       ('northstar_claim_cluster_session_route(text,text,text,text,uuid,int8,uuid,uuid,uuid,int4)'),
       ('northstar_refresh_cluster_session_route(text,text,text,uuid,int8,uuid,int4)'),
       ('northstar_release_cluster_session_route(text,text,text,uuid,int8,uuid)'),
       ('northstar_cluster_session_route(text,text)'),
       ('northstar_cluster_session_nodes_for_bare(text,text)'),
       ('northstar_cleanup_cluster_session_routes(int4)'),
       ('northstar_cluster_session_authority_healthy()')
      ) AS allowed(signature)
   ON routine.oid = pg_catalog.to_regprocedure('public.' || allowed.signature)
 WHERE namespace.nspname = 'public'
   AND routine.prokind='f'
   AND routine.prosecdef
\gexec

SELECT pg_catalog.format(
         'GRANT EXECUTE ON ROUTINE %I.%I(%s) TO %I',
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'command_role'
       )
  FROM pg_catalog.pg_proc AS routine
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = routine.pronamespace
 JOIN (VALUES
       ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
       ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
       ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
       ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
       ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
       ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
       ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
       ('northstar_admin_command_cleanup()')
      ) AS allowed(signature)
   ON routine.oid = pg_catalog.to_regprocedure('public.' || allowed.signature)
 WHERE namespace.nspname = 'public'
   AND routine.prokind='f'
   AND routine.prosecdef
\gexec

-- The backup identity can read a consistent logical snapshot but cannot write,
-- execute application routines, allocate sequence values, or create objects.
GRANT SELECT ON ALL TABLES IN SCHEMA public
   TO :"backup_role";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public
   TO :"backup_role";

-- PostgreSQL has no "ALL TYPES IN SCHEMA" form, so reconcile explicitly-created
-- domains and types with safely-quoted generated statements. Standalone
-- composite types are included; table/view row types and generated array types
-- follow their parent objects and are excluded.
-- First erase every non-owner ACL, including PUBLIC, retired roles and
-- delegated WITH GRANT OPTION chains.  A plain REVOKE without CASCADE is not a
-- convergent repair: PostgreSQL rejects it while a downstream grant depends on
-- the grant option being removed.
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %s CASCADE',
         CASE WHEN data_type.typtype = 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,
         data_type.typname,
         CASE
           WHEN privilege.grantee=0 THEN 'PUBLIC'
           ELSE pg_catalog.quote_ident(grantee.rolname)
         END
       )
  FROM pg_catalog.pg_type AS data_type
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=data_type.typnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(
   COALESCE(data_type.typacl,pg_catalog.acldefault('T',data_type.typowner))
 ) AS privilege
  LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND data_type.typelem=0
   AND (
     (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     ))
   )
   AND privilege.grantee<>data_type.typowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid=data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
 ORDER BY 1
\gexec

-- Ownership grants are implicit and can therefore disappear from typacl after
-- a historical REVOKE without changing effective owner authority.  Normalize
-- that row explicitly so catalog attestation has one deterministic shape.
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %I CASCADE',
         CASE WHEN data_type.typtype='d' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,
         data_type.typname,
         :'migrator_role'
       )
  FROM pg_catalog.pg_type AS data_type
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=data_type.typnamespace
 WHERE namespace.nspname='public'
   AND data_type.typelem=0
   AND (
     (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     ))
   )
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid=data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
 ORDER BY data_type.oid
\gexec
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON %s %I.%I FROM PUBLIC, %I, %I, %I CASCADE',
         CASE WHEN data_type.typtype = 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,
         data_type.typname,
         :'runtime_role',
         :'command_role',
         :'backup_role'
       )
  FROM pg_catalog.pg_type AS data_type
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = data_type.typnamespace
 WHERE namespace.nspname = 'public'
   AND data_type.typelem = 0
   AND (
     (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     ))
   )
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid = 'pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid = data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
 ORDER BY data_type.oid
\gexec
SELECT pg_catalog.format(
         'GRANT USAGE ON %s %I.%I TO %I',
         CASE WHEN data_type.typtype='d' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,
         data_type.typname,
         :'migrator_role'
       )
  FROM pg_catalog.pg_type AS data_type
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=data_type.typnamespace
 WHERE namespace.nspname='public'
   AND data_type.typelem=0
   AND (
     (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     ))
   )
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid=data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
 ORDER BY data_type.oid
\gexec
SELECT pg_catalog.format(
         'GRANT USAGE ON %s %I.%I TO %I, %I',
         CASE WHEN data_type.typtype = 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,
         data_type.typname,
         :'runtime_role',
         :'backup_role'
       )
  FROM pg_catalog.pg_type AS data_type
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = data_type.typnamespace
 WHERE namespace.nspname = 'public'
   AND data_type.typelem = 0
   AND (
     (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     ))
   )
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid = 'pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid = data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
 ORDER BY data_type.oid
\gexec

-- Future migration output is owner-only until this file is run again after
-- the migration transaction.  Global and schema default ACLs are additive in
-- PostgreSQL, so both scopes must be converged; revoking only the public-schema
-- row cannot neutralize a stale global grant.  No workload identity receives
-- a default privilege.  Current objects are granted explicitly above only
-- after the 0114/0115 ledger boundary is complete.
SELECT DISTINCT pg_catalog.format(
         'ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE ALL PRIVILEGES ON %s FROM %s CASCADE',
         owner.rolname,
         CASE WHEN default_acl.defaclnamespace=0 THEN ''
              ELSE pg_catalog.format(' IN SCHEMA %I',namespace.nspname) END,
         CASE default_acl.defaclobjtype
           WHEN 'r' THEN 'TABLES'
           WHEN 'S' THEN 'SEQUENCES'
           WHEN 'f' THEN 'FUNCTIONS'
           WHEN 'T' THEN 'TYPES'
           WHEN 'n' THEN 'SCHEMAS'
         END,
         CASE
           WHEN privilege.grantee=0 THEN 'PUBLIC'
           ELSE pg_catalog.quote_ident(grantee.rolname)
         END
       )
  FROM pg_catalog.pg_default_acl AS default_acl
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=default_acl.defaclrole
  LEFT JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=default_acl.defaclnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) AS privilege
  LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE (default_acl.defaclnamespace=0 OR namespace.nspname='public')
   AND default_acl.defaclobjtype IN ('r','S','f','T','n')
   AND (default_acl.defaclobjtype<>'n' OR default_acl.defaclnamespace=0)
   AND privilege.grantee<>default_acl.defaclrole
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

-- Materialize PostgreSQL's implicit PUBLIC routine/type defaults as explicit
-- denials at global scope, then erase any additive public-schema rows.  The
-- repeated known-role revokes are intentional: they make an empty catalog and
-- a previously delegated catalog converge to the same owner-only result.
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TABLES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TYPES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON SCHEMAS FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;

-- Schema-scoped defaults are additive to the global defaults.  Canonical
-- Northstar policy has no additive public-schema row at all, including an
-- owner-only row left by an old ALTER DEFAULT PRIVILEGES command.
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM :"migrator_role" CASCADE;

-- Exact-phase transactional postconditions prove that the elevated
-- capability and immutable-history boundaries stayed canonical.
SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'public'
            AND relation.relname IN (
                  'audit_log','legal_holds','legal_hold_personal_archives',
                  'legal_hold_muc_archives','legal_hold_offline_messages',
                  'legal_hold_report_evidence','legal_hold_scopes',
                  'legal_hold_offline_snapshots','cluster_muc_operations',
                  'cluster_muc_delivery_handoffs'
                )
            AND (
              (relation.relname='cluster_muc_delivery_handoffs'
                AND pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'INSERT'))
              OR pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'UPDATE')
              OR pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'DELETE')
              OR pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'TRUNCATE')
              OR pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'REFERENCES')
              OR pg_catalog.has_table_privilege(:'runtime_role', relation.oid, 'TRIGGER')
            )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=relation.relnamespace
          WHERE namespace.nspname='public'
            AND relation.relname='governance_export_leases'
            AND (
              pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
            )
       ) AS northstar_runtime_handoff_history_is_read_only \gset
\if :northstar_runtime_handoff_history_is_read_only
\else
  \echo 'runtime must not update/delete immutable history directly'
  \quit 31
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=relation.relnamespace
          WHERE namespace.nspname='public'
            AND relation.relname IN ('_sqlx_migrations','jid_identity_migrations')
            AND (
              NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
              OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
            )
       ) AS northstar_runtime_migration_ledgers_are_read_only \gset
\if :northstar_runtime_migration_ledgers_are_read_only
\else
  \echo 'runtime migration-ledger privileges exceed read-only access'
  \quit 35
\endif

SELECT relation.oid IS NOT NULL
       AND pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AS northstar_runtime_users_is_read_only
  FROM (SELECT pg_catalog.to_regclass('public.users') AS oid) relation
\gset
\if :northstar_runtime_users_is_read_only
\else
  \echo 'runtime users-table privileges must be exactly read-only'
  \quit 37
\endif

SELECT relation.oid IS NOT NULL
       AND pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AS northstar_runtime_mix_release_journal_is_read_only
  FROM (
    SELECT pg_catalog.to_regclass(
      'public.mix_delivery_capacity_releases'
    ) AS oid
  ) relation
\gset
\if :northstar_runtime_mix_release_journal_is_read_only
\else
  \echo 'runtime MIX release-journal privileges must be exactly read-only'
  \quit 44
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM (VALUES
             ('mix_pam_operation_capacity'),
             ('mix_pam_operation_user_capacity')
           ) AS authority(name)
           CROSS JOIN LATERAL (
             SELECT pg_catalog.to_regclass('public.' || authority.name) AS oid
           ) AS relation
          WHERE relation.oid IS NULL
             OR NOT pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(
                  :'runtime_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(
                  :'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(
                  :'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(
                  :'runtime_role',relation.oid,'REFERENCES')
       ) AS northstar_runtime_mix_pam_counters_are_read_only \gset
\if :northstar_runtime_mix_pam_counters_are_read_only
\else
  \echo 'runtime MIX-PAM counter privileges must be exactly read-only'
  \quit 45
\endif

SELECT relation.oid IS NOT NULL
       AND pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
       AND pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AND NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
       AND NOT pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       AS northstar_runtime_mix_pam_operations_are_capability_owned
  FROM (
    SELECT pg_catalog.to_regclass('public.mix_pam_operations') AS oid
  ) relation
\gset
\if :northstar_runtime_mix_pam_operations_are_capability_owned
\else
  \echo 'runtime MIX-PAM operation insert/delete privileges must be capability-only'
  \quit 46
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM (VALUES
             ('upload_storage_authority'),
             ('upload_storage_capacity_ledger'),
             ('upload_slots'),
             ('upload_storage_jobs'),
             ('upload_cleanup_queue')
           ) AS protected(name)
           CROSS JOIN LATERAL (
             SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
           ) AS relation
          WHERE relation.oid IS NULL
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'SELECT')
       ) AS northstar_runtime_upload_authorities_are_capability_only \gset
\if :northstar_runtime_upload_authorities_are_capability_only
\else
  \echo 'runtime upload authorities must be capability-only'
  \quit 38
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM (VALUES
             ('cluster_signed_envelope_replays'),
             ('cluster_signed_envelope_replay_capacity'),
             ('cluster_session_routes')
           ) AS protected(name)
           CROSS JOIN LATERAL (
             SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
           ) AS relation
          WHERE relation.oid IS NULL
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       ) AS northstar_runtime_cluster_authorities_are_private \gset
\if :northstar_runtime_cluster_authorities_are_private
\else
  \echo 'runtime cluster replay/session authorities must be capability-only'
  \quit 44
\endif

SELECT
  pg_catalog.has_table_privilege(
    :'runtime_role','public.deployment_session_leases','SELECT')
  AND pg_catalog.has_table_privilege(
    :'runtime_role','public.deployment_session_binding_claims','SELECT')
  AND NOT EXISTS (
    SELECT 1 FROM (VALUES
      ('deployment_session_leases'),('deployment_session_binding_claims'),
      ('sm_resume_sessions')
    ) protected(name)
    CROSS JOIN LATERAL (
      SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
    ) relation
    WHERE relation.oid IS NULL
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
       OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
       OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
  )
  AND NOT pg_catalog.has_table_privilege(
    :'runtime_role','public.sm_resume_sessions','SELECT')
  AND NOT pg_catalog.has_column_privilege(
    :'runtime_role','public.sm_resume_sessions','token_hash','SELECT')
  AND NOT pg_catalog.has_column_privilege(
    :'runtime_role','public.sm_resume_sessions','claim_token','SELECT')
  AND NOT pg_catalog.has_column_privilege(
    :'runtime_role','public.sm_resume_sessions','peer_ip','SELECT')
  AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.unnest(ARRAY[
      'id','user_id','auth_generation','full_jid','resource','connection_id',
      'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available',
      'carbons','priority','blocklist_requested','roster_requested',
      'active_privacy_list','privacy_requested','user_agent_id','joined_rooms',
      'directed_presence','last_presence','resumable','live_lease_until',
      'expires_at','claimed_until','created_at','updated_at'
    ]::TEXT[]) safe(column_name)
    WHERE NOT pg_catalog.has_column_privilege(
      :'runtime_role','public.sm_resume_sessions',safe.column_name,'SELECT')
  )
  AND NOT EXISTS (
    SELECT 1 FROM (VALUES
      ('deployment_session_leases'),('deployment_session_binding_claims'),
      ('sm_resume_sessions')
    ) protected(name)
    CROSS JOIN LATERAL (
      SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
    ) relation
    WHERE relation.oid IS NULL
       OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'SELECT')
       OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'DELETE')
       OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'SELECT')
       OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'UPDATE')
  ) AS northstar_runtime_session_authorities_are_capability_only \gset
\if :northstar_runtime_session_authorities_are_capability_only
\else
  \echo 'runtime session leases and SM bearer state violate capability-only ACLs'
  \quit 46
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM (VALUES
             ('admin_service_messages'),
             ('federation_runtime_rules'),
             ('admin_service_control')
           ) AS protected(name)
           CROSS JOIN LATERAL (
             SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
           ) AS relation
          WHERE relation.oid IS NULL
             OR NOT pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       ) AS northstar_runtime_xep0133_state_is_read_only \gset
\if :northstar_runtime_xep0133_state_is_read_only
\else
  \echo 'runtime XEP-0133 control-state privileges must be exactly read-only'
  \quit 41
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM (VALUES
             ('admin_command_sessions'),
             ('admin_command_capability_authority'),
             ('admin_session_cleanup_effects'),
             ('admin_session_cleanup_capacity')
           ) AS protected(name)
           CROSS JOIN LATERAL (
             SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
           ) AS relation
          WHERE relation.oid IS NULL
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(:'runtime_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'SELECT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(:'runtime_role',relation.oid,'REFERENCES')
       ) AS northstar_runtime_admin_effect_ledger_is_private \gset
\if :northstar_runtime_admin_effect_ledger_is_private
\else
  \echo 'runtime XEP-0133 bearer/effect ledgers must be accessible only through typed capabilities'
  \quit 42
\endif

SELECT NOT EXISTS (
         SELECT 1 FROM (VALUES
           ('northstar_protect_admin_session_cleanup_identity()'),
           ('northstar_enqueue_admin_generation_cleanup(uuid,uuid,int8,text)'),
           ('northstar_enqueue_admin_exact_session_cleanup(uuid,uuid,int8,text,uuid)')
         ) private_helper(signature)
         CROSS JOIN LATERAL (
           SELECT pg_catalog.to_regprocedure('public.' || private_helper.signature) AS oid
         ) routine
         WHERE routine.oid IS NULL
            OR pg_catalog.has_function_privilege(:'runtime_role',routine.oid,'EXECUTE')
       ) AS northstar_runtime_admin_effect_issuers_are_private \gset
\if :northstar_runtime_admin_effect_issuers_are_private
\else
  \echo 'runtime must not execute internal administrator cleanup issuer helpers'
  \quit 43
\endif

SELECT NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relkind IN ('r','p','v','m','f','S')
           AND (
             pg_catalog.has_table_privilege(:'command_role',relation.oid,'SELECT')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'INSERT')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'UPDATE')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'DELETE')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'TRUNCATE')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'REFERENCES')
             OR pg_catalog.has_table_privilege(:'command_role',relation.oid,'TRIGGER')
             OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'SELECT')
             OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'INSERT')
             OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'UPDATE')
             OR pg_catalog.has_any_column_privilege(:'command_role',relation.oid,'REFERENCES')
           )
       ) AS northstar_command_role_has_no_relation_access \gset
\if :northstar_command_role_has_no_relation_access
\else
  \echo 'command role must not have relation or column privileges'
  \quit 38
\endif

SELECT NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc routine
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
         WHERE namespace.nspname='public' AND routine.prosecdef
           AND pg_catalog.has_function_privilege(:'command_role',routine.oid,'EXECUTE')
           AND NOT EXISTS (
             SELECT 1 FROM (VALUES
               ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
               ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
               ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
               ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
               ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
               ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
               ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
               ('northstar_admin_command_cleanup()')
             ) allowed(signature)
             WHERE pg_catalog.to_regprocedure('public.' || allowed.signature)=routine.oid
           )
       ) AND NOT EXISTS (
         SELECT 1 FROM (VALUES
           ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
           ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
           ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
           ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
           ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
           ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
           ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
           ('northstar_admin_command_cleanup()')
         ) allowed(signature)
         LEFT JOIN pg_catalog.pg_proc routine
           ON routine.oid=pg_catalog.to_regprocedure('public.' || allowed.signature)
         WHERE routine.oid IS NULL OR routine.prokind<>'f' OR NOT routine.prosecdef
           OR NOT pg_catalog.has_function_privilege(:'command_role',routine.oid,'EXECUTE')
       ) AS northstar_command_definer_allowlist_is_exact \gset
\if :northstar_command_definer_allowlist_is_exact
\else
  \echo 'command role SECURITY DEFINER execution does not match exact session manifest'
  \quit 39
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS sequence
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=sequence.relnamespace
          WHERE namespace.nspname='public'
            AND sequence.relkind='S'
            AND CASE
                  WHEN sequence.relkind='S' THEN
                    pg_catalog.has_sequence_privilege(
                      :'runtime_role',sequence.oid,'UPDATE'
                    )
                  ELSE FALSE
                END
       ) AS northstar_runtime_cannot_set_sequence_values \gset
\if :northstar_runtime_cannot_set_sequence_values
\else
  \echo 'runtime must not receive sequence UPDATE/setval authority'
  \quit 36
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
          WHERE namespace.nspname = 'public'
            AND routine.prosecdef
            AND pg_catalog.has_function_privilege(
                  :'runtime_role', routine.oid, 'EXECUTE'
                )
            AND NOT EXISTS (
                  SELECT 1
                    FROM (VALUES
                      ('northstar_transfer_cluster_muc_outbox(uuid,uuid,uuid,uuid,int8,uuid,int8,text)'),
                      ('northstar_purge_released_hold_offline_snapshots(int4,int4)'),
                      ('northstar_purge_audit_log(int4,int4)'),
                      ('northstar_purge_governance_export_leases(int4,int4)'),
                      ('northstar_purge_cluster_muc_history(int4,int4)'),
                      ('northstar_release_legal_hold(uuid,uuid,text,uuid)'),
                      ('northstar_user_register(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,bytea,bool,int4,uuid)'),
                      ('northstar_user_create_bootstrap_admin(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
                      ('northstar_user_clear_scram_sha1()'),
                      ('northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
                      ('northstar_user_change_password_api(uuid,text,int8,bytea,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,uuid)'),
                      ('northstar_user_change_password_stream(uuid,int8,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
                      ('northstar_user_set_status_api(uuid,int8,bytea,uuid,bool,bool)'),
                      ('northstar_user_bump_roster_version(uuid)'),
                      ('northstar_user_consume_recovery_generation(uuid,int8,bytea)'),
                      ('northstar_user_quiesce_deletion(uuid,int8)'),
                      ('northstar_user_delete_quiesced(uuid,text)'),
                      ('northstar_admin_command_authorize_claim(text,uuid,text,int8,text,bytea)'),
                      ('northstar_admin_command_create_user(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text)'),
                      ('northstar_admin_command_reset_user_password(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text,text)'),
                      ('northstar_admin_command_user_lifecycle(text,uuid,text,int8,text,bytea,uuid,text,text,text,text,bool,text)'),
                      ('northstar_admin_command_issue_delete_cleanup(text,uuid,text,int8,text,bytea,uuid,text,text)'),
                      ('northstar_claim_admin_session_cleanup(uuid,int4)'),
                      ('northstar_renew_admin_session_cleanup(uuid,uuid,uuid,int4)'),
                      ('northstar_retry_admin_session_cleanup(uuid,uuid,uuid,text)'),
                      ('northstar_complete_admin_session_cleanup(uuid,uuid,uuid)'),
                      ('northstar_admin_session_cleanup_target_current(uuid,uuid,uuid)'),
                      ('northstar_admin_session_cleanup_snapshot()'),
                      ('northstar_admin_command_delete_user(text,uuid,text,int8,text,bytea,uuid,text,bool,text)'),
                      ('northstar_admin_command_replace_users(text,uuid,text,int8,text,bytea,uuid[],text)'),
                      ('northstar_admin_command_record_announcement(text,uuid,text,int8,text,bytea,int4,int4,text)'),
                      ('northstar_admin_command_set_service_message(text,uuid,text,int8,text,bytea,text,text,text)'),
                      ('northstar_admin_command_replace_federation_rules(text,uuid,text,int8,text,bytea,text,text[],text)'),
                      ('northstar_admin_command_service_control(text,uuid,text,int8,text,bytea,text,int4,text,bool,text)'),
                      ('northstar_admin_service_control_poll()'),
                      ('northstar_session_delete_expired_live_leases()'),
                      ('northstar_session_capacity_reconcile_lock()'),
                      ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
                      ('northstar_session_finalize_binding(uuid,uuid,text)'),
                      ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
                      ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
                      ('northstar_session_release_live(uuid)'),
                      ('northstar_session_refresh_live(uuid[],int8)'),
                      ('northstar_session_cleanup_live(int8)'),
                      ('northstar_session_extend_live(uuid,int8)'),
                      ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)'),
                      ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)'),
                      ('northstar_sm_remove_memberships(uuid,uuid,jsonb)'),
                      ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)'),
                      ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)'),
                      ('northstar_sm_claim_authority(uuid,uuid)'),
                      ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)'),
                      ('northstar_sm_release_claim(uuid,uuid)'),
                      ('northstar_sm_revoke(uuid)'),
                      ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)'),
                      ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)'),
                      ('northstar_sm_count(text,uuid,int8,text)'),
                      ('northstar_sm_finalize_teardown(uuid,uuid)'),
                      ('northstar_sm_lock_suspended(uuid)'),
                      ('northstar_sm_advance_suspended(uuid,int8,int8)'),
                      ('northstar_sm_expire_before_generation(uuid,int8)'),
                      ('northstar_sm_privacy_list_in_use(uuid,text)'),
                      ('northstar_sm_privacy_state(uuid)'),
                      ('northstar_session_capability_catalog_healthy(text)'),
                      ('northstar_mix_delivery_capacity_drain()'),
                      ('northstar_mix_delivery_capacity_reconcile()'),
                      ('northstar_mix_pam_account_capacity_lock(uuid,text)'),
                      ('northstar_mix_pam_operation_insert(uuid,uuid,text,text,text,text,text,text,bytea,uuid,bool,text,text,text[],int8,text)'),
                      ('northstar_mix_pam_operation_prune(int8)'),
                      ('northstar_mix_pam_capacity_reconcile()'),
                      ('northstar_upload_bootstrap_authority(text,bytea)'),
                      ('northstar_upload_bind_capacity_policy(int8,int8,int8)'),
                      ('northstar_upload_capacity_lock()'),
                      ('northstar_upload_active_slot_count(uuid)'),
                      ('northstar_upload_public_slot_count()'),
                      ('northstar_upload_renew_claim(uuid,uuid,int8)'),
                      ('northstar_upload_authority_probe(text,bytea,int8,int8,int8,int8,int8)'),
                      ('northstar_upload_dead_letters_page(text,int8,uuid,int4)'),
                      ('northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'),
                      ('northstar_upload_claim_cleanup(uuid)'),
                      ('northstar_upload_cleanup_quiescent(uuid,uuid,int8)'),
                      ('northstar_upload_defer_cleanup(uuid,uuid)'),
                      ('northstar_upload_confirm_cleanup_absence(uuid,uuid,bool,int8)'),
                      ('northstar_upload_fail_cleanup(uuid,uuid,text)'),
                      ('northstar_upload_complete_cleanup(uuid,uuid)'),
                      ('northstar_upload_claim_storage_jobs(uuid)'),
                      ('northstar_upload_complete_storage_job(int8,uuid)'),
                      ('northstar_upload_confirm_stage_absence(int8,uuid,bool,int8)'),
                      ('northstar_upload_fail_storage_job(int8,uuid,text)'),
                      ('northstar_upload_defer_storage_job(int8,uuid)'),
                      ('northstar_upload_claim_promotion_job(uuid,uuid,int8,uuid)'),
                      ('northstar_upload_defer_promotion_job(uuid,uuid,int8,uuid)'),
                      ('northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)'),
                      ('northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)'),
                      ('northstar_upload_release_claim(uuid,uuid)'),
                      ('northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)'),
                      ('northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)'),
                      ('northstar_upload_claim_is_live(uuid,uuid)'),
                      ('northstar_upload_begin_promotion(uuid,uuid,int8,uuid)'),
                      ('northstar_upload_attempt_committed(uuid,uuid,text,text,text,bytea,int8,int8)'),
                      ('northstar_upload_record_replay(uuid,bytea,bytea,int8)'),
                      ('northstar_upload_public_file(uuid)'),
                      ('northstar_upload_claim_scrub()'),
                      ('northstar_upload_finish_scrub(uuid,uuid,text)'),
                      ('northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)'),
                      ('northstar_upload_capacity_reconciliation()'),
                      ('northstar_upload_queue_snapshot()'),
                      ('northstar_upload_policy_binding_matches(int8,int8,int8)'),
                      ('northstar_upload_admit_expired_cleanup()'),
                      ('northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)'),
                      ('northstar_upload_capability_catalog_healthy(text)'),
                      ('northstar_admit_cluster_envelope_replay(text,text,uuid,int8,text,int8,text,uuid,int8,text,int8,uuid,bytea,text,timestamptz)'),
                      ('northstar_cleanup_cluster_envelope_replays(int4)'),
                      ('northstar_cluster_replay_capacity_healthy()'),
                      ('northstar_claim_cluster_session_route(text,text,text,text,uuid,int8,uuid,uuid,uuid,int4)'),
                      ('northstar_refresh_cluster_session_route(text,text,text,uuid,int8,uuid,int4)'),
                      ('northstar_release_cluster_session_route(text,text,text,uuid,int8,uuid)'),
                      ('northstar_cluster_session_route(text,text)'),
                      ('northstar_cluster_session_nodes_for_bare(text,text)'),
                      ('northstar_cleanup_cluster_session_routes(int4)'),
                      ('northstar_cluster_session_authority_healthy()')
                    ) AS allowed(signature)
                   WHERE pg_catalog.to_regprocedure('public.' || allowed.signature)=routine.oid
                )
       )
       AND (
         NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_proc routine
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
           WHERE namespace.nspname='public' AND routine.prosecdef
         )
         OR NOT EXISTS (
         SELECT 1 FROM (VALUES
           ('northstar_transfer_cluster_muc_outbox(uuid,uuid,uuid,uuid,int8,uuid,int8,text)'),
           ('northstar_purge_released_hold_offline_snapshots(int4,int4)'),
           ('northstar_purge_audit_log(int4,int4)'),
           ('northstar_purge_governance_export_leases(int4,int4)'),
           ('northstar_purge_cluster_muc_history(int4,int4)'),
           ('northstar_release_legal_hold(uuid,uuid,text,uuid)'),
           ('northstar_user_register(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,bytea,bool,int4,uuid)'),
           ('northstar_user_create_bootstrap_admin(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
           ('northstar_user_clear_scram_sha1()'),
           ('northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
           ('northstar_user_change_password_api(uuid,text,int8,bytea,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,uuid)'),
           ('northstar_user_change_password_stream(uuid,int8,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
           ('northstar_user_set_status_api(uuid,int8,bytea,uuid,bool,bool)'),
           ('northstar_user_bump_roster_version(uuid)'),
           ('northstar_user_consume_recovery_generation(uuid,int8,bytea)'),
           ('northstar_user_quiesce_deletion(uuid,int8)'),
           ('northstar_user_delete_quiesced(uuid,text)'),
           ('northstar_admin_command_authorize_claim(text,uuid,text,int8,text,bytea)'),
           ('northstar_admin_command_create_user(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text)'),
           ('northstar_admin_command_reset_user_password(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text,text)'),
           ('northstar_admin_command_user_lifecycle(text,uuid,text,int8,text,bytea,uuid,text,text,text,text,bool,text)'),
           ('northstar_admin_command_issue_delete_cleanup(text,uuid,text,int8,text,bytea,uuid,text,text)'),
           ('northstar_claim_admin_session_cleanup(uuid,int4)'),
           ('northstar_renew_admin_session_cleanup(uuid,uuid,uuid,int4)'),
           ('northstar_retry_admin_session_cleanup(uuid,uuid,uuid,text)'),
           ('northstar_complete_admin_session_cleanup(uuid,uuid,uuid)'),
           ('northstar_admin_session_cleanup_target_current(uuid,uuid,uuid)'),
           ('northstar_admin_session_cleanup_snapshot()'),
           ('northstar_admin_command_delete_user(text,uuid,text,int8,text,bytea,uuid,text,bool,text)'),
           ('northstar_admin_command_replace_users(text,uuid,text,int8,text,bytea,uuid[],text)'),
           ('northstar_admin_command_record_announcement(text,uuid,text,int8,text,bytea,int4,int4,text)'),
           ('northstar_admin_command_set_service_message(text,uuid,text,int8,text,bytea,text,text,text)'),
           ('northstar_admin_command_replace_federation_rules(text,uuid,text,int8,text,bytea,text,text[],text)'),
           ('northstar_admin_command_service_control(text,uuid,text,int8,text,bytea,text,int4,text,bool,text)'),
           ('northstar_admin_service_control_poll()'),
           ('northstar_session_delete_expired_live_leases()'),
           ('northstar_session_capacity_reconcile_lock()'),
           ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
           ('northstar_session_finalize_binding(uuid,uuid,text)'),
           ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
           ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
           ('northstar_session_release_live(uuid)'),
           ('northstar_session_refresh_live(uuid[],int8)'),
           ('northstar_session_cleanup_live(int8)'),
           ('northstar_session_extend_live(uuid,int8)'),
           ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)'),
           ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)'),
           ('northstar_sm_remove_memberships(uuid,uuid,jsonb)'),
           ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)'),
           ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)'),
           ('northstar_sm_claim_authority(uuid,uuid)'),
           ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)'),
           ('northstar_sm_release_claim(uuid,uuid)'),
           ('northstar_sm_revoke(uuid)'),
           ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)'),
           ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)'),
           ('northstar_sm_count(text,uuid,int8,text)'),
           ('northstar_sm_finalize_teardown(uuid,uuid)'),
           ('northstar_sm_lock_suspended(uuid)'),
           ('northstar_sm_advance_suspended(uuid,int8,int8)'),
           ('northstar_sm_expire_before_generation(uuid,int8)'),
           ('northstar_sm_privacy_list_in_use(uuid,text)'),
           ('northstar_sm_privacy_state(uuid)'),
           ('northstar_session_capability_catalog_healthy(text)'),
           ('northstar_mix_delivery_capacity_drain()'),
           ('northstar_mix_delivery_capacity_reconcile()'),
           ('northstar_mix_pam_account_capacity_lock(uuid,text)'),
           ('northstar_mix_pam_operation_insert(uuid,uuid,text,text,text,text,text,text,bytea,uuid,bool,text,text,text[],int8,text)'),
           ('northstar_mix_pam_operation_prune(int8)'),
           ('northstar_mix_pam_capacity_reconcile()'),
           ('northstar_upload_bootstrap_authority(text,bytea)'),
           ('northstar_upload_bind_capacity_policy(int8,int8,int8)'),
           ('northstar_upload_capacity_lock()'),
           ('northstar_upload_active_slot_count(uuid)'),
           ('northstar_upload_public_slot_count()'),
           ('northstar_upload_renew_claim(uuid,uuid,int8)'),
           ('northstar_upload_authority_probe(text,bytea,int8,int8,int8,int8,int8)'),
           ('northstar_upload_dead_letters_page(text,int8,uuid,int4)'),
           ('northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'),
           ('northstar_upload_claim_cleanup(uuid)'),
           ('northstar_upload_cleanup_quiescent(uuid,uuid,int8)'),
           ('northstar_upload_defer_cleanup(uuid,uuid)'),
           ('northstar_upload_confirm_cleanup_absence(uuid,uuid,bool,int8)'),
           ('northstar_upload_fail_cleanup(uuid,uuid,text)'),
           ('northstar_upload_complete_cleanup(uuid,uuid)'),
           ('northstar_upload_claim_storage_jobs(uuid)'),
           ('northstar_upload_complete_storage_job(int8,uuid)'),
           ('northstar_upload_confirm_stage_absence(int8,uuid,bool,int8)'),
           ('northstar_upload_fail_storage_job(int8,uuid,text)'),
           ('northstar_upload_defer_storage_job(int8,uuid)'),
           ('northstar_upload_claim_promotion_job(uuid,uuid,int8,uuid)'),
           ('northstar_upload_defer_promotion_job(uuid,uuid,int8,uuid)'),
           ('northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)'),
           ('northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)'),
           ('northstar_upload_release_claim(uuid,uuid)'),
           ('northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)'),
           ('northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)'),
           ('northstar_upload_claim_is_live(uuid,uuid)'),
           ('northstar_upload_begin_promotion(uuid,uuid,int8,uuid)'),
           ('northstar_upload_attempt_committed(uuid,uuid,text,text,text,bytea,int8,int8)'),
           ('northstar_upload_record_replay(uuid,bytea,bytea,int8)'),
           ('northstar_upload_public_file(uuid)'),
           ('northstar_upload_claim_scrub()'),
           ('northstar_upload_finish_scrub(uuid,uuid,text)'),
           ('northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)'),
           ('northstar_upload_capacity_reconciliation()'),
           ('northstar_upload_queue_snapshot()'),
           ('northstar_upload_policy_binding_matches(int8,int8,int8)'),
           ('northstar_upload_admit_expired_cleanup()'),
           ('northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)'),
           ('northstar_upload_capability_catalog_healthy(text)'),
           ('northstar_admit_cluster_envelope_replay(text,text,uuid,int8,text,int8,text,uuid,int8,text,int8,uuid,bytea,text,timestamptz)'),
           ('northstar_cleanup_cluster_envelope_replays(int4)'),
           ('northstar_cluster_replay_capacity_healthy()'),
           ('northstar_claim_cluster_session_route(text,text,text,text,uuid,int8,uuid,uuid,uuid,int4)'),
           ('northstar_refresh_cluster_session_route(text,text,text,uuid,int8,uuid,int4)'),
           ('northstar_release_cluster_session_route(text,text,text,uuid,int8,uuid)'),
           ('northstar_cluster_session_route(text,text)'),
           ('northstar_cluster_session_nodes_for_bare(text,text)'),
           ('northstar_cleanup_cluster_session_routes(int4)'),
           ('northstar_cluster_session_authority_healthy()')
         ) AS allowed(signature)
         LEFT JOIN pg_catalog.pg_proc AS routine
           ON routine.oid=pg_catalog.to_regprocedure('public.' || allowed.signature)
        WHERE routine.oid IS NULL OR NOT routine.prosecdef
           OR NOT pg_catalog.has_function_privilege(
                :'runtime_role',routine.oid,'EXECUTE'
              )
         )
       ) AS northstar_runtime_definer_allowlist_is_exact \gset
\if :northstar_runtime_definer_allowlist_is_exact
\else
  \echo 'runtime SECURITY DEFINER execution does not match the exact capability manifest'
  \quit 32
\endif

-- Authoritative three-way comparison.  The grant statements above remain
-- intentionally fail-closed, while this postcondition is driven by the
-- independent, version-controlled manifest loaded by the caller.  It proves
-- the full catalog set as well as each workload's exact EXECUTE set without
-- relying on numeric counts or on the grants being inspected.
SELECT NOT EXISTS (
         SELECT 1
           FROM pg_temp.northstar_capability_manifest AS expected
           LEFT JOIN pg_catalog.pg_proc AS routine
             ON routine.oid=pg_catalog.to_regprocedure(
                  'public.' || expected.signature
                )
          WHERE routine.oid IS NULL OR routine.prokind<>'f' OR NOT routine.prosecdef
             OR pg_catalog.pg_get_userbyid(routine.proowner)<>:'migrator_role'
             OR routine.proconfig IS DISTINCT FROM
                  ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
             OR pg_catalog.has_function_privilege(
                  :'runtime_role',routine.oid,'EXECUTE'
                ) IS DISTINCT FROM (expected.workload='runtime')
             OR pg_catalog.has_function_privilege(
                  :'command_role',routine.oid,'EXECUTE'
                ) IS DISTINCT FROM (expected.workload='command')
             OR pg_catalog.has_function_privilege(
                  :'backup_role',routine.oid,'EXECUTE'
                )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_temp.northstar_capability_manifest AS expected
           JOIN pg_catalog.pg_proc AS routine
             ON routine.oid=pg_catalog.to_regprocedure(
                  'public.' || expected.signature
                )
          WHERE (SELECT pg_catalog.count(*)
                   FROM pg_catalog.aclexplode(COALESCE(
                     routine.proacl,
                     pg_catalog.acldefault('f',routine.proowner)
                   )) privilege)
                  <>CASE WHEN expected.workload='private' THEN 1 ELSE 2 END
             OR EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                 routine.proacl,
                 pg_catalog.acldefault('f',routine.proowner)
               )) privilege
                WHERE privilege.privilege_type<>'EXECUTE'
                   OR privilege.is_grantable
                   OR privilege.grantor<>routine.proowner
             )
             OR NOT EXISTS (
               SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                 routine.proacl,
                 pg_catalog.acldefault('f',routine.proowner)
               )) privilege
                 WHERE privilege.grantee=routine.proowner
                   AND privilege.grantor=routine.proowner
                   AND privilege.privilege_type='EXECUTE'
                  AND NOT privilege.is_grantable
             )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=routine.pronamespace
           WHERE namespace.nspname='public' AND routine.prosecdef
             AND routine.prokind<>'f'
        ) AND NOT EXISTS (
          SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid=routine.pronamespace
           WHERE namespace.nspname='public' AND routine.prosecdef
             AND NOT EXISTS (
              SELECT 1
                FROM pg_temp.northstar_capability_manifest AS expected
               WHERE pg_catalog.to_regprocedure(
                       'public.' || expected.signature
                     )=routine.oid
            )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=routine.pronamespace
          WHERE namespace.nspname='public'
            AND pg_catalog.has_function_privilege(
                  :'command_role',routine.oid,'EXECUTE'
                )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_temp.northstar_capability_manifest AS expected
               WHERE expected.workload='command'
                 AND pg_catalog.to_regprocedure(
                       'public.' || expected.signature
                     )=routine.oid
            )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=routine.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
              routine.proacl,
              pg_catalog.acldefault('f',routine.proowner)
            )
          ) AS privilege
          WHERE namespace.nspname='public' AND routine.prosecdef
            AND privilege.grantee=0
            AND privilege.privilege_type='EXECUTE'
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=routine.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
              routine.proacl,
              pg_catalog.acldefault('f',routine.proowner)
            )
          ) AS privilege
          LEFT JOIN pg_temp.northstar_capability_manifest AS expected
            ON pg_catalog.to_regprocedure(
                 'public.' || expected.signature
               )=routine.oid
           WHERE namespace.nspname='public' AND routine.prosecdef
             AND privilege.grantee<>routine.proowner
             AND NOT COALESCE((
               (expected.workload='runtime' AND NOT privilege.is_grantable
                AND privilege.grantor=routine.proowner
                AND privilege.privilege_type='EXECUTE'
                AND privilege.grantee=(
                SELECT oid FROM pg_catalog.pg_roles
                 WHERE rolname=:'runtime_role'
              )) OR
               (expected.workload='command' AND NOT privilege.is_grantable
                AND privilege.grantor=routine.proowner
                AND privilege.privilege_type='EXECUTE'
                AND privilege.grantee=(
                SELECT oid FROM pg_catalog.pg_roles
                 WHERE rolname=:'command_role'
               ))
            ),FALSE)
       ) AS northstar_canonical_capability_manifest_is_exact \gset
\if :northstar_canonical_capability_manifest_is_exact
\else
  \echo 'catalog/runtime/command capability sets drifted from the canonical manifest'
  \quit 45
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
          WHERE namespace.nspname = 'public'
            AND pg_catalog.has_function_privilege(
                  :'backup_role', routine.oid, 'EXECUTE'
                )
       )
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(
                routine.proacl,
                pg_catalog.acldefault('f', routine.proowner)
              )
           ) AS privilege
          WHERE namespace.nspname = 'public'
            AND privilege.grantee = 0
            AND privilege.privilege_type = 'EXECUTE'
       ) AS northstar_backup_and_public_have_no_routine_execution \gset
\if :northstar_backup_and_public_have_no_routine_execution
\else
  \echo 'backup and PUBLIC must not execute application routines'
  \quit 33
\endif

-- No historical role may survive reconciliation as an unmodelled relation,
-- column or type grantee.  Check grantor, grant option and privilege kind as
-- well as the grantee identity; accepting merely the right grantee name would
-- still permit a delegated or overpowered ACL.
SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p','v','m','S','f')
            AND privilege.grantee<>relation.relowner
             AND NOT COALESCE(
               privilege.grantor=relation.relowner
               AND NOT privilege.is_grantable
               AND (
                 (relation.relkind IN ('r','p','v','m','f')
                  AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
                  AND privilege.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE'))
                 OR
                 (relation.relkind IN ('r','p','v','m','f')
                  AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
                  AND privilege.privilege_type='SELECT')
                 OR
                 (relation.relkind='S'
                  AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
                  AND privilege.privilege_type IN ('USAGE','SELECT'))
                 OR
                 (relation.relkind='S'
                  AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
                  AND privilege.privilege_type='SELECT')
               ),FALSE
             )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=relation.relnamespace
           JOIN pg_catalog.pg_attribute AS attribute
             ON attribute.attrelid=relation.oid
            AND attribute.attnum>0 AND NOT attribute.attisdropped
          CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p','v','m','f')
            AND privilege.grantee<>relation.relowner
             AND NOT COALESCE(
               relation.relname='sm_resume_sessions'
               AND privilege.grantor=relation.relowner
               AND NOT privilege.is_grantable
               AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
               AND privilege.privilege_type='SELECT'
               AND attribute.attname=ANY(ARRAY[
                 'id','user_id','auth_generation','full_jid','resource','connection_id',
                 'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available','carbons',
                 'priority','blocklist_requested','roster_requested','active_privacy_list',
                 'privacy_requested','user_agent_id','joined_rooms','directed_presence',
                 'last_presence','resumable','live_lease_until','expires_at','claimed_until',
                 'created_at','updated_at'
               ]::pg_catalog.text[]),FALSE
             )
        ) AND NOT EXISTS (
          SELECT expected.attname
            FROM pg_catalog.unnest(ARRAY[
              'id','user_id','auth_generation','full_jid','resource','connection_id',
              'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available','carbons',
              'priority','blocklist_requested','roster_requested','active_privacy_list',
              'privacy_requested','user_agent_id','joined_rooms','directed_presence',
              'last_presence','resumable','live_lease_until','expires_at','claimed_until',
              'created_at','updated_at'
            ]::pg_catalog.text[]) AS expected(attname)
           WHERE NOT EXISTS (
             SELECT 1
               FROM pg_catalog.pg_class AS relation
               JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid=relation.oid
                AND attribute.attname=expected.attname
                AND attribute.attnum>0 AND NOT attribute.attisdropped
              CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
              WHERE namespace.nspname='public'
                AND relation.relname='sm_resume_sessions'
                AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
                AND privilege.grantor=relation.relowner
                AND privilege.privilege_type='SELECT'
                AND NOT privilege.is_grantable
           )
        ) AND NOT EXISTS (
          SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=data_type.typnamespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(data_type.typacl,pg_catalog.acldefault('T',data_type.typowner))
           ) AS privilege
           WHERE namespace.nspname='public'
             AND data_type.typelem=0
             AND (
               (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
               OR (data_type.typtype='c' AND EXISTS (
                 SELECT 1 FROM pg_catalog.pg_class composite_relation
                  WHERE composite_relation.oid=data_type.typrelid
                    AND composite_relation.relkind='c'
               ))
             )
             AND NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_depend AS dependency
                WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
                  AND dependency.objid=data_type.oid
                  AND (dependency.deptype='e'
                    OR (dependency.deptype='i' AND data_type.typtype<>'c'))
             )
             AND NOT COALESCE(
               privilege.grantor=data_type.typowner
               AND NOT privilege.is_grantable
               AND privilege.privilege_type='USAGE'
               AND privilege.grantee IN (
                 data_type.typowner,
                 (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role'),
                 (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
               ),FALSE
             )
        ) AND NOT EXISTS (
          SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=data_type.typnamespace
           WHERE namespace.nspname='public'
             AND data_type.typelem=0
             AND (
               (data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
               OR (data_type.typtype='c' AND EXISTS (
                 SELECT 1 FROM pg_catalog.pg_class composite_relation
                  WHERE composite_relation.oid=data_type.typrelid
                    AND composite_relation.relkind='c'
               ))
             )
             AND NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_depend AS dependency
                WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
                  AND dependency.objid=data_type.oid
                  AND (dependency.deptype='e'
                    OR (dependency.deptype='i' AND data_type.typtype<>'c'))
             )
             AND EXISTS (
               SELECT required.grantee
                 FROM (VALUES
                   (data_type.typowner),
                   ((SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')),
                   ((SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role'))
                 ) AS required(grantee)
                WHERE NOT EXISTS (
                  SELECT 1 FROM pg_catalog.aclexplode(
                    COALESCE(data_type.typacl,pg_catalog.acldefault('T',data_type.typowner))
                  ) AS privilege
                   WHERE privilege.grantee=required.grantee
                     AND privilege.grantor=data_type.typowner
                     AND privilege.privilege_type='USAGE'
                     AND NOT privilege.is_grantable
                )
             )
        ) AS northstar_relation_grantee_set_is_exact \gset
\if :northstar_relation_grantee_set_is_exact
\else
  \echo 'relation/column/type ACL differs from the canonical grantee and privilege sets'
  \quit 46
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc routine
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            routine.proacl,pg_catalog.acldefault('f',routine.proowner)
          )) privilege
           LEFT JOIN pg_temp.northstar_capability_manifest expected
             ON pg_catalog.to_regprocedure('public.' || expected.signature)=routine.oid
          WHERE namespace.nspname='public'
            AND privilege.grantee<>routine.proowner
            AND NOT COALESCE(
              privilege.grantor=routine.proowner
              AND NOT privilege.is_grantable
              AND privilege.privilege_type='EXECUTE'
              AND (
                (privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
                  AND (NOT routine.prosecdef OR expected.workload='runtime'))
                OR
                (privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'command_role')
                  AND expected.workload='command')
              ),false
            )
       ) AS northstar_routine_grantee_set_is_exact \gset
\if :northstar_routine_grantee_set_is_exact
\else
  \echo 'routine ACL differs from the owner/runtime/command execution manifest'
  \quit 51
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_database database
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            database.datacl,pg_catalog.acldefault('d',database.datdba)
          )) privilege
          WHERE database.datname=:'database_name'
            AND privilege.grantee<>database.datdba
            AND NOT COALESCE(
              privilege.grantor=database.datdba
              AND NOT privilege.is_grantable
              AND privilege.privilege_type='CONNECT'
              AND privilege.grantee IN (
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role'),
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'command_role'),
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
              ),false
            )
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_namespace namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
          )) privilege
          WHERE namespace.nspname='public'
            AND privilege.grantee<>namespace.nspowner
            AND NOT COALESCE(
              privilege.grantor=namespace.nspowner
              AND NOT privilege.is_grantable
              AND privilege.privilege_type='USAGE'
              AND privilege.grantee IN (
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role'),
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'command_role'),
                (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
              ),false
            )
       ) AS northstar_database_schema_acl_set_is_exact \gset
\if :northstar_database_schema_acl_set_is_exact
\else
  \echo 'database/schema ACL differs from the owner-issued CONNECT/USAGE manifest'
  \quit 50
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_default_acl default_acl
           LEFT JOIN pg_catalog.pg_namespace namespace
             ON namespace.oid=default_acl.defaclnamespace
          WHERE namespace.nspname='public'
       )
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_default_acl default_acl
           JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
          WHERE default_acl.defaclnamespace=0
            AND (
              owner.rolname<>:'migrator_role'
              OR default_acl.defaclobjtype NOT IN ('r','S','f','T','n')
              OR EXISTS (
                SELECT privilege.privilege_type
                  FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                 WHERE privilege.grantee<>default_acl.defaclrole
                    OR privilege.grantor<>default_acl.defaclrole
                    OR privilege.is_grantable
                    OR NOT EXISTS (
                      SELECT 1
                        FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                          default_acl.defaclobjtype,default_acl.defaclrole
                        )) built_in
                       WHERE built_in.grantee=default_acl.defaclrole
                         AND built_in.grantor=default_acl.defaclrole
                         AND built_in.privilege_type=privilege.privilege_type
                         AND NOT built_in.is_grantable
                    )
              )
              OR EXISTS (
                SELECT built_in.privilege_type
                  FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                    default_acl.defaclobjtype,default_acl.defaclrole
                  )) built_in
                 WHERE built_in.grantee=default_acl.defaclrole
                   AND built_in.grantor=default_acl.defaclrole
                   AND NOT built_in.is_grantable
                   AND NOT EXISTS (
                     SELECT 1
                       FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                      WHERE privilege.grantee=default_acl.defaclrole
                        AND privilege.grantor=default_acl.defaclrole
                        AND privilege.privilege_type=built_in.privilege_type
                        AND NOT privilege.is_grantable
                   )
              )
            )
       )
       -- PostgreSQL's hard-wired defaults grant PUBLIC EXECUTE on routines and
       -- PUBLIC USAGE on types.  Absence of these two override rows is unsafe,
       -- not equivalent to an owner-only catalog.
       AND NOT EXISTS (
         SELECT required.object_type
           FROM (VALUES ('f'::"char"),('T'::"char")) required(object_type)
          WHERE NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_default_acl default_acl
             WHERE default_acl.defaclrole=(
                     SELECT oid FROM pg_catalog.pg_roles
                      WHERE rolname=:'migrator_role'
                   )
               AND default_acl.defaclnamespace=0
               AND default_acl.defaclobjtype=required.object_type
               AND NOT EXISTS (
                 SELECT 1
                   FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                  WHERE privilege.grantee<>default_acl.defaclrole
                     OR privilege.grantor<>default_acl.defaclrole
                     OR privilege.is_grantable
               )
          )
       ) AS northstar_default_acl_set_is_exact \gset
\if :northstar_default_acl_set_is_exact
\else
  \echo 'global/public default privileges are not owner-only for the canonical migrator'
  \quit 34
\endif

\else

-- Bootstrap/prepare is deliberately capability-free.  Workload identities do
-- not receive CONNECT, schema USAGE, object ACLs, type USAGE or EXECUTE before
-- the 0114/0115 boundary has committed.  This permits the migrator to install
-- the remaining migrations without exposing a future capability to a live
-- runtime, command issuer or backup process.
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON DATABASE %I FROM %s CASCADE',
         database.datname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_database database
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   database.datacl,pg_catalog.acldefault('d',database.datdba)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE database.datname=:'database_name'
   AND privilege.grantee<>database.datdba
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec
SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %s CASCADE',
         namespace.nspname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_namespace namespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND privilege.grantee<>namespace.nspowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

REVOKE ALL PRIVILEGES ON DATABASE :"database_name" FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON DATABASE :"database_name"
  FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON SCHEMA public
  FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
  FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
  FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC CASCADE;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public
  FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;

SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %s CASCADE',
         namespace.nspname,routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_proc routine
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   routine.proacl,pg_catalog.acldefault('f',routine.proowner)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND privilege.grantee<>routine.proowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %s CASCADE',
         CASE WHEN relation.relkind='S' THEN 'SEQUENCE' ELSE 'TABLE' END,
         namespace.nspname,relation.relname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND relation.relkind IN ('r','p','v','m','S','f')
   AND privilege.grantee<>relation.relowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM %s CASCADE',
         pg_catalog.string_agg(DISTINCT pg_catalog.quote_ident(attribute.attname),','
                               ORDER BY pg_catalog.quote_ident(attribute.attname)),
         namespace.nspname,relation.relname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_attribute attribute
    ON attribute.attrelid=relation.oid
   AND attribute.attnum>0 AND NOT attribute.attisdropped
 CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public'
   AND relation.relkind IN ('r','p','v','m','f')
   AND privilege.grantee<>relation.relowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 GROUP BY namespace.nspname,relation.relname,privilege.grantee,grantee.rolname
 ORDER BY namespace.nspname,relation.relname,privilege.grantee
\gexec

SELECT DISTINCT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %s CASCADE',
         CASE WHEN data_type.typtype='d' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,data_type.typname,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_type data_type
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=data_type.typnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
 )) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE namespace.nspname='public' AND data_type.typelem=0
   AND ((data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
     OR (data_type.typtype='c' AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_class composite_relation
        WHERE composite_relation.oid=data_type.typrelid
          AND composite_relation.relkind='c'
     )))
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_depend dependency
      WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
        AND dependency.objid=data_type.oid
        AND (dependency.deptype='e'
          OR (dependency.deptype='i' AND data_type.typtype<>'c'))
   )
   AND privilege.grantee<>data_type.typowner
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

-- Remove every global or public-schema default entry not belonging to its
-- owner, including unknown grantees and delegated WITH GRANT OPTION chains.
SELECT DISTINCT pg_catalog.format(
         'ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE ALL PRIVILEGES ON %s FROM %s CASCADE',
         owner.rolname,
         CASE WHEN default_acl.defaclnamespace=0 THEN ''
              ELSE pg_catalog.format(' IN SCHEMA %I',namespace.nspname) END,
         CASE default_acl.defaclobjtype
           WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
           WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES'
           WHEN 'n' THEN 'SCHEMAS' END,
         CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
              ELSE pg_catalog.quote_ident(grantee.rolname) END
       )
  FROM pg_catalog.pg_default_acl default_acl
  JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
  LEFT JOIN pg_catalog.pg_namespace namespace
    ON namespace.oid=default_acl.defaclnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) privilege
  LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
 WHERE (default_acl.defaclnamespace=0 OR namespace.nspname='public')
   AND default_acl.defaclobjtype IN ('r','S','f','T','n')
   AND (default_acl.defaclobjtype<>'n' OR default_acl.defaclnamespace=0)
   AND privilege.grantee<>default_acl.defaclrole
   AND (privilege.grantee=0 OR grantee.oid IS NOT NULL)
 ORDER BY 1
\gexec

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role"
  REVOKE ALL PRIVILEGES ON SCHEMAS FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC, :"runtime_role", :"command_role", :"backup_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM :"migrator_role" CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_role" IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TYPES FROM :"migrator_role" CASCADE;

-- A pre-boundary database may contain only already-defined manifest routines.
-- Origin 0114 is forbidden until its successful ledger row exists.  Existing
-- definers remain owner-only and hardened, so migration can replace them but
-- no live workload can invoke them during the upgrade window.
SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc routine
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
           LEFT JOIN pg_temp.northstar_capability_manifest expected
             ON pg_catalog.to_regprocedure('public.' || expected.signature)=routine.oid
          WHERE namespace.nspname='public' AND routine.prosecdef
            AND (expected.signature IS NULL OR expected.origin='0114'
              OR routine.prokind<>'f'
              OR pg_catalog.pg_get_userbyid(routine.proowner)<>:'migrator_role'
              OR routine.proconfig IS DISTINCT FROM
                   ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
              OR EXISTS (
                SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                  routine.proacl,pg_catalog.acldefault('f',routine.proowner)
                )) privilege
                 WHERE privilege.grantee<>routine.proowner
                    OR privilege.grantor<>routine.proowner
                    OR privilege.is_grantable
              ))
       ) AS northstar_pre_boundary_definers_are_bounded \gset
\if :northstar_pre_boundary_definers_are_bounded
\else
  \echo 'pre-boundary SECURITY DEFINER catalog is partial, tampered, or exposed'
  \quit 48
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_database database
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            database.datacl,pg_catalog.acldefault('d',database.datdba)
          )) privilege
          WHERE database.datname=:'database_name'
            AND privilege.grantee<>database.datdba
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_namespace namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
          )) privilege
          WHERE namespace.nspname='public'
            AND privilege.grantee<>namespace.nspowner
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) privilege
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p','v','m','S','f')
            AND privilege.grantee<>relation.relowner
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
           JOIN pg_catalog.pg_attribute attribute
             ON attribute.attrelid=relation.oid
            AND attribute.attnum>0 AND NOT attribute.attisdropped
          CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
          WHERE namespace.nspname='public'
            AND privilege.grantee<>relation.relowner
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc routine
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            routine.proacl,pg_catalog.acldefault('f',routine.proowner)
          )) privilege
          WHERE namespace.nspname='public'
            AND privilege.grantee<>routine.proowner
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_type data_type
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=data_type.typnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
            data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
          )) privilege
          WHERE namespace.nspname='public' AND data_type.typelem=0
            AND ((data_type.typrelid=0 AND data_type.typtype IN ('b','d','e','r','m'))
              OR (data_type.typtype='c' AND EXISTS (
                SELECT 1 FROM pg_catalog.pg_class composite_relation
                 WHERE composite_relation.oid=data_type.typrelid
                   AND composite_relation.relkind='c'
              )))
            AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend dependency
               WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
                 AND dependency.objid=data_type.oid
                 AND (dependency.deptype='e'
                   OR (dependency.deptype='i' AND data_type.typtype<>'c'))
            )
            AND privilege.grantee<>data_type.typowner
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_default_acl default_acl
           JOIN pg_catalog.pg_namespace namespace
             ON namespace.oid=default_acl.defaclnamespace
          WHERE namespace.nspname='public'
       ) AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_default_acl default_acl
           JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
          WHERE default_acl.defaclnamespace=0
            AND (owner.rolname<>:'migrator_role'
              OR default_acl.defaclobjtype NOT IN ('r','S','f','T','n')
              OR EXISTS (
                SELECT 1 FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                 WHERE privilege.grantee<>default_acl.defaclrole
                    OR privilege.grantor<>default_acl.defaclrole
                    OR privilege.is_grantable
                    OR NOT EXISTS (
                      SELECT 1 FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                        default_acl.defaclobjtype,default_acl.defaclrole
                      )) built_in
                       WHERE built_in.grantee=default_acl.defaclrole
                         AND built_in.grantor=default_acl.defaclrole
                         AND built_in.privilege_type=privilege.privilege_type
                         AND NOT built_in.is_grantable
                    )
              )
              OR EXISTS (
                SELECT 1 FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                  default_acl.defaclobjtype,default_acl.defaclrole
                )) built_in
                 WHERE built_in.grantee=default_acl.defaclrole
                   AND built_in.grantor=default_acl.defaclrole
                   AND NOT built_in.is_grantable
                   AND NOT EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                      WHERE privilege.grantee=default_acl.defaclrole
                        AND privilege.grantor=default_acl.defaclrole
                        AND privilege.privilege_type=built_in.privilege_type
                        AND NOT privilege.is_grantable
                   )
              ))
       ) AND NOT EXISTS (
         SELECT required.object_type
           FROM (VALUES ('f'::"char"),('T'::"char")) required(object_type)
          WHERE NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_default_acl default_acl
             WHERE default_acl.defaclrole=(
                     SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'migrator_role'
                   )
               AND default_acl.defaclnamespace=0
               AND default_acl.defaclobjtype=required.object_type
               AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                  WHERE privilege.grantee<>default_acl.defaclrole
                     OR privilege.grantor<>default_acl.defaclrole
                     OR privilege.is_grantable
               )
          )
       ) AS northstar_pre_boundary_acl_set_is_owner_only \gset
\if :northstar_pre_boundary_acl_set_is_owner_only
\else
  \echo 'bootstrap/prepare ACL convergence did not produce an owner-only catalog'
  \quit 49
\endif

\endif
