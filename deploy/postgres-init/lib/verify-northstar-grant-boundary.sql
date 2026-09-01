-- Northstar PostgreSQL grant-policy preconditions.
--
-- Required psql variables:
--   database_name, migrator_role, runtime_role, command_role, backup_role, allow_bootstrap

\set ON_ERROR_STOP on

SELECT current_database() = :'database_name' AS northstar_database_matches \gset
\if :northstar_database_matches
\else
  \echo 'refusing to reconcile grants in an unexpected database'
  \quit 20
\endif

SELECT EXISTS (
         SELECT 1
          FROM pg_catalog.pg_roles
          WHERE rolname = current_user
            AND (
              rolname = :'migrator_role'
              OR (:'allow_bootstrap'::pg_catalog.bool AND rolsuper)
            )
       ) AS northstar_grant_actor_allowed \gset
\if :northstar_grant_actor_allowed
\else
  \echo 'grant reconciliation requires the migrator role (or an explicitly allowed bootstrap session)'
  \quit 21
\endif

SELECT count(*) = 4 AS northstar_target_roles_exist
  FROM pg_catalog.pg_roles
 WHERE rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role') \gset
\if :northstar_target_roles_exist
\else
  \echo 'one or more Northstar database roles do not exist'
  \quit 22
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_roles
          WHERE rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
            AND (
              NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
              OR rolbypassrls OR rolinherit
              OR rolvaliduntil IS DISTINCT FROM
                   'infinity'::pg_catalog.timestamptz
              OR rolconfig IS NOT NULL
            )
       ) AS northstar_target_roles_are_unprivileged \gset
\if :northstar_target_roles_are_unprivileged
\else
  \echo 'a Northstar workload role has forbidden cluster-level privileges'
  \quit 23
\endif

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_auth_members AS membership
           JOIN pg_catalog.pg_roles AS granted
             ON granted.oid = membership.roleid
           JOIN pg_catalog.pg_roles AS member
             ON member.oid = membership.member
          WHERE granted.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
             OR member.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
       ) AS northstar_target_roles_have_no_memberships \gset
\if :northstar_target_roles_have_no_memberships
\else
  \echo 'Northstar workload roles must not participate in role memberships'
  \quit 28
\endif

SELECT (SELECT rolconnlimit=4 FROM pg_catalog.pg_roles WHERE rolname=:'migrator_role')
       AND (SELECT rolconnlimit=64 FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
       AND (SELECT rolconnlimit=8 FROM pg_catalog.pg_roles WHERE rolname=:'command_role')
       AND (SELECT rolconnlimit=2 FROM pg_catalog.pg_roles WHERE rolname=:'backup_role')
       AS northstar_workload_connection_limits_are_bounded \gset
\if :northstar_workload_connection_limits_are_bounded
\else
  \echo 'workload CONNECTION LIMIT policy must be migrator=4, runtime=64, commands=8, backup=2'
  \quit 29
\endif

SELECT pg_catalog.pg_get_userbyid(datdba) = :'migrator_role'
         AS northstar_database_owner_matches
  FROM pg_catalog.pg_database
 WHERE datname = current_database() \gset
\if :northstar_database_owner_matches
\else
  \echo 'the migrator role must own the Northstar database before grants are reconciled'
  \quit 24
\endif

SELECT pg_catalog.pg_get_userbyid(nspowner) = :'migrator_role'
         AS northstar_schema_owner_matches
  FROM pg_catalog.pg_namespace
 WHERE nspname = 'public' \gset
\if :northstar_schema_owner_matches
\else
  \echo 'the migrator role must own schema public before grants are reconciled'
  \quit 25
\endif

-- A migration must not silently create application relations or routines as a
-- different owner. Extension members are excluded because their ownership is
-- managed by PostgreSQL and the extension itself.
SELECT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           JOIN pg_catalog.pg_roles AS owner
             ON owner.oid = relation.relowner
          WHERE namespace.nspname = 'public'
            AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'i', 'I')
            AND owner.rolname <> :'migrator_role'
            AND NOT EXISTS (
                  SELECT 1
                    FROM pg_catalog.pg_depend AS dependency
                   WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                     AND dependency.objid = relation.oid
                     AND dependency.deptype = 'e'
                )
       ) AS northstar_foreign_relation_owners \gset
\if :northstar_foreign_relation_owners
  \echo 'a public application relation is not owned by the migrator role'
  \quit 26
\endif

SELECT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
           JOIN pg_catalog.pg_roles AS owner
             ON owner.oid = routine.proowner
          WHERE namespace.nspname = 'public'
            AND owner.rolname <> :'migrator_role'
            AND NOT EXISTS (
                  SELECT 1
                    FROM pg_catalog.pg_depend AS dependency
                   WHERE dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                     AND dependency.objid = routine.oid
                     AND dependency.deptype = 'e'
                )
       ) AS northstar_foreign_routine_owners \gset
\if :northstar_foreign_routine_owners
  \echo 'a public application routine is not owned by the migrator role'
  \quit 27
\endif

SELECT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_type AS data_type
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=data_type.typnamespace
           JOIN pg_catalog.pg_roles AS owner ON owner.oid=data_type.typowner
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
            AND owner.rolname<>:'migrator_role'
            AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend AS dependency
               WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
                 AND dependency.objid=data_type.oid
                 AND (dependency.deptype='e'
                   OR (dependency.deptype='i' AND data_type.typtype<>'c'))
            )
       ) AS northstar_foreign_type_owners \gset
\if :northstar_foreign_type_owners
  \echo 'a public application type/domain is not owned by the migrator role'
  \quit 47
\endif
