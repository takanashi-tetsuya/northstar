#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Audit or upgrade an existing Northstar PostgreSQL volume. The default mode is
# read-only audit. Mutations require --apply; disabling the legacy xmpp login
# requires a second, explicit switch and is guarded against removing the last
# usable superuser.

umask 077
readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly grants_sql="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
readonly capability_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-capability-manifest.sql"
readonly migration_ledger_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
readonly bootstrap_role='northstar_bootstrap'
readonly migrator_role='northstar_migrator'
readonly runtime_role='northstar_runtime'
readonly command_role='northstar_commands'
readonly backup_role='northstar_backup'
readonly database_name='xmpp'

mode='audit'
demote_legacy=false
database_host="${PGHOST:-postgres}"
database_port="${PGPORT:-5432}"
connection_user="${PGUSER:-$bootstrap_role}"
connection_password_file="${POSTGRES_CONNECTION_PASSWORD_FILE:-}"
bootstrap_password_file="${POSTGRES_BOOTSTRAP_PASSWORD_FILE:-/run/secrets/postgres_bootstrap_password}"
migrator_password_file="${NORTHSTAR_MIGRATOR_PASSWORD_FILE:-/run/secrets/northstar_migrator_password}"
runtime_password_file="${NORTHSTAR_RUNTIME_PASSWORD_FILE:-/run/secrets/northstar_runtime_password}"
command_password_file="${NORTHSTAR_COMMAND_PASSWORD_FILE:-/run/secrets/northstar_command_password}"
backup_password_file="${NORTHSTAR_BACKUP_PASSWORD_FILE:-/run/secrets/northstar_backup_password}"

connection_password=''
bootstrap_password=''
migrator_password=''
runtime_password=''
command_password=''
backup_password=''

clear_secrets() {
  unset PGPASSWORD
  unset connection_password bootstrap_password migrator_password runtime_password command_password backup_password
  unset NORTHSTAR_BOOTSTRAP_PASSWORD NORTHSTAR_MIGRATOR_PASSWORD
  unset NORTHSTAR_RUNTIME_PASSWORD NORTHSTAR_BACKUP_PASSWORD
  unset NORTHSTAR_COMMAND_PASSWORD
}
trap clear_secrets EXIT

fail() {
  printf 'database role reconciliation failed: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/reconcile-database-roles.sh [OPTIONS]

Modes:
  --audit                    Read-only drift audit (default)
  --apply                    Create/reconcile roles, ownership and grants
  --demote-legacy-xmpp       With --apply, make legacy role xmpp NOLOGIN and
                             remove its cluster privileges after safety checks

Connection and secret files:
  --host HOST                PostgreSQL host (default: PGHOST or postgres)
  --port PORT                PostgreSQL port (default: PGPORT or 5432)
  --connect-as ROLE          Existing bootstrap superuser; use xmpp for the
                             first pass over a legacy Compose volume
  --connection-password-file FILE
                             Password for --connect-as. Defaults to
                             postgres_bootstrap_password for northstar_bootstrap
                             and legacy postgres_password for xmpp.
  --bootstrap-password-file FILE
                             New/dedicated northstar_bootstrap password; never
                             reused as the legacy connection password
  --migrator-password-file FILE
  --runtime-password-file FILE
  --command-password-file FILE
  --backup-password-file FILE

Secret values are read from files, passed through process environment, and are
never placed in command arguments or output. On a legacy first pass, explicitly
pass the old postgres_password as --connection-password-file and the new
postgres_bootstrap_password as --bootstrap-password-file. Then reconnect as
northstar_bootstrap before using --demote-legacy-xmpp.
EOF
}

read_secret() {
  local path=$1
  local label=$2
  local size
  local value

  [[ -f "$path" && ! -L "$path" && -r "$path" ]] \
    || fail "$label must be a readable regular non-symbolic-link file"
  size=$(wc -c < "$path")
  (( size <= 4096 )) || fail "$label must not exceed 4096 bytes"
  value=$(<"$path")
  [[ ${#value} -ge 32 ]] || fail "$label must contain at least 32 characters"
  LC_ALL=C grep -Eq '^[[:graph:]]+$' "$path" \
    || fail "$label must contain one line of printable, non-whitespace ASCII"
  if ! printf '%s' "$value" | cmp -s - "$path" \
    && ! printf '%s\n' "$value" | cmp -s - "$path"; then
    fail "$label must contain exactly one value with at most one trailing newline"
  fi
  printf '%s' "$value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit) mode='audit'; shift ;;
    --apply) mode='apply'; shift ;;
    --demote-legacy-xmpp) demote_legacy=true; shift ;;
    --host) database_host=${2:?missing host}; shift 2 ;;
    --port) database_port=${2:?missing port}; shift 2 ;;
    --connect-as) connection_user=${2:?missing role}; shift 2 ;;
    --connection-password-file) connection_password_file=${2:?missing file}; shift 2 ;;
    --bootstrap-password-file) bootstrap_password_file=${2:?missing file}; shift 2 ;;
    --migrator-password-file) migrator_password_file=${2:?missing file}; shift 2 ;;
    --runtime-password-file) runtime_password_file=${2:?missing file}; shift 2 ;;
    --command-password-file) command_password_file=${2:?missing file}; shift 2 ;;
    --backup-password-file) backup_password_file=${2:?missing file}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ "$database_port" =~ ^[1-9][0-9]{0,4}$ ]] \
  && (( database_port <= 65535 )) || fail 'port must be between 1 and 65535'
[[ "$connection_user" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
  || fail 'connection role is not a safe PostgreSQL identifier'
[[ -r "$grants_sql" ]] || fail 'the shared grant policy is missing'
[[ -r "$capability_manifest_sql" ]] || fail 'the canonical capability manifest is missing'
[[ -r "$migration_ledger_manifest_sql" ]] || fail 'the canonical migration ledger manifest is missing'
for required_command in cmp grep psql tail wc; do
  command -v "$required_command" >/dev/null \
    || fail "required command is unavailable: $required_command"
done

if [[ "$demote_legacy" == true && "$mode" != 'apply' ]]; then
  fail '--demote-legacy-xmpp requires --apply'
fi

if [[ -z "$connection_password_file" ]]; then
  case "$connection_user" in
    northstar_bootstrap)
      connection_password_file=$bootstrap_password_file
      ;;
    xmpp)
      connection_password_file='/run/secrets/postgres_password'
      ;;
    *)
      fail '--connection-password-file is required for a non-standard bootstrap role'
      ;;
  esac
fi

connection_password=$(read_secret "$connection_password_file" 'connection password')
export PGPASSWORD="$connection_password"

psql_command=(
  psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1
  --host "$database_host" --port "$database_port"
  --username "$connection_user" --dbname "$database_name"
  --set=database_name="$database_name"
  --set=bootstrap_role="$bootstrap_role"
  --set=migrator_role="$migrator_role"
  --set=runtime_role="$runtime_role"
  --set=command_role="$command_role"
  --set=backup_role="$backup_role"
  --set=allow_bootstrap=true
  --set=grant_phase=auto
  --set=capability_manifest_sql="$capability_manifest_sql"
  --set=migration_ledger_manifest_sql="$migration_ledger_manifest_sql"
)

verify_connection_authority() {
  "${psql_command[@]}" --tuples-only --no-align <<'PSQL'
SELECT CASE
         WHEN EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles
            WHERE rolname = current_user AND rolsuper
         ) THEN 'ok'
         ELSE 'denied'
       END;
PSQL
}

audit_roles() {
  local findings
  local legacy_login
  local unexpected_superusers

  findings=$("${psql_command[@]}" --quiet --tuples-only --no-align <<'PSQL'
\i :capability_manifest_sql
\i :migration_ledger_manifest_sql
WITH expected_roles(role_name, must_be_superuser, must_inherit, connection_limit) AS (
  VALUES
    (:'bootstrap_role'::pg_catalog.text, true, true, -1),
    (:'migrator_role'::pg_catalog.text, false, false, 4),
    (:'runtime_role'::pg_catalog.text, false, false, 64),
    (:'command_role'::pg_catalog.text, false, false, 8),
    (:'backup_role'::pg_catalog.text, false, false, 2)
), actual_migration AS (
  SELECT version,description,success,checksum
    FROM public._sqlx_migrations
), findings AS (
  SELECT 'repository migration ledger differs by version, description, success, or SHA-384 checksum' AS finding
   WHERE EXISTS (
     SELECT 1 FROM actual_migration
      WHERE NOT success OR version<=0 OR description=''
         OR pg_catalog.octet_length(checksum)<>48
   ) OR EXISTS (
     (SELECT version,description,checksum
        FROM actual_migration WHERE success
      EXCEPT
      SELECT version,description,checksum
        FROM pg_temp.northstar_migration_ledger_manifest)
     UNION ALL
     (SELECT version,description,checksum
        FROM pg_temp.northstar_migration_ledger_manifest
      EXCEPT
      SELECT version,description,checksum
        FROM actual_migration WHERE success)
   ) OR (SELECT pg_catalog.count(*) FROM actual_migration)
        <> (SELECT pg_catalog.count(DISTINCT version) FROM actual_migration)
  UNION ALL
  SELECT 'missing role: ' || expected.role_name AS finding
    FROM expected_roles AS expected
    LEFT JOIN pg_catalog.pg_roles AS actual
      ON actual.rolname = expected.role_name
   WHERE actual.oid IS NULL
  UNION ALL
  SELECT 'invalid attributes on role: ' || expected.role_name
    FROM expected_roles AS expected
    JOIN pg_catalog.pg_roles AS actual
      ON actual.rolname = expected.role_name
   WHERE NOT actual.rolcanlogin
      OR actual.rolsuper <> expected.must_be_superuser
      OR actual.rolinherit <> expected.must_inherit
      OR actual.rolconnlimit <> expected.connection_limit
       OR (
         NOT expected.must_be_superuser
         AND (
           actual.rolcreatedb OR actual.rolcreaterole OR actual.rolreplication
           OR actual.rolbypassrls
           OR actual.rolvaliduntil IS DISTINCT FROM
                'infinity'::pg_catalog.timestamptz
           OR actual.rolconfig IS NOT NULL
         )
       )
  UNION ALL
  SELECT 'workload role participates in membership: ' ||
         granted.rolname || ' -> ' || member.rolname
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
   WHERE granted.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
      OR member.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
  UNION ALL
  SELECT 'database owner is not ' || :'migrator_role'
    FROM pg_catalog.pg_database
   WHERE datname = current_database()
     AND pg_catalog.pg_get_userbyid(datdba) <> :'migrator_role'
  UNION ALL
  SELECT 'schema public owner is not ' || :'migrator_role'
    FROM pg_catalog.pg_namespace
   WHERE nspname = 'public'
     AND pg_catalog.pg_get_userbyid(nspowner) <> :'migrator_role'
  UNION ALL
  SELECT 'PUBLIC retains database privilege: ' || privilege.privilege_type
    FROM pg_catalog.pg_database AS database
   CROSS JOIN LATERAL pg_catalog.aclexplode(
     COALESCE(
       database.datacl,
       pg_catalog.acldefault('d', database.datdba)
     )
   ) AS privilege
   WHERE database.datname = current_database()
     AND privilege.grantee = 0
  UNION ALL
  SELECT 'PUBLIC retains schema privilege: ' || privilege.privilege_type
    FROM pg_catalog.pg_namespace AS namespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(
     COALESCE(
       namespace.nspacl,
       pg_catalog.acldefault('n', namespace.nspowner)
     )
   ) AS privilege
   WHERE namespace.nspname = 'public'
     AND privilege.grantee = 0
  UNION ALL
  SELECT 'unexpected database ACL: ' ||
         COALESCE(grantee.rolname,'PUBLIC') || ':' || privilege.privilege_type
    FROM pg_catalog.pg_database database
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
     database.datacl,pg_catalog.acldefault('d',database.datdba)
   )) privilege
    LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
   WHERE database.datname=current_database()
     AND privilege.grantee<>database.datdba
     AND NOT COALESCE(
       privilege.grantor=database.datdba AND NOT privilege.is_grantable
       AND privilege.privilege_type='CONNECT'
       AND grantee.rolname IN (:'runtime_role',:'command_role',:'backup_role'),false
     )
  UNION ALL
  SELECT 'unexpected public-schema ACL: ' ||
         COALESCE(grantee.rolname,'PUBLIC') || ':' || privilege.privilege_type
    FROM pg_catalog.pg_namespace namespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
     namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
   )) privilege
    LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=privilege.grantee
   WHERE namespace.nspname='public'
     AND privilege.grantee<>namespace.nspowner
     AND NOT COALESCE(
       privilege.grantor=namespace.nspowner AND NOT privilege.is_grantable
       AND privilege.privilege_type='USAGE'
       AND grantee.rolname IN (:'runtime_role',:'command_role',:'backup_role'),false
     )
  UNION ALL
  SELECT 'unexpected global/public default ACL: ' || owner.rolname || ':' ||
         default_acl.defaclobjtype::pg_catalog.text
    FROM pg_catalog.pg_default_acl default_acl
    JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
    LEFT JOIN pg_catalog.pg_namespace namespace
      ON namespace.oid=default_acl.defaclnamespace
   WHERE namespace.nspname='public'
      OR (default_acl.defaclnamespace=0 AND (
        owner.rolname<>:'migrator_role'
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
        )
      ))
  UNION ALL
  SELECT 'missing owner-only global default ACL override: ' ||
         required.object_type::pg_catalog.text
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
  UNION ALL
  SELECT 'PUBLIC retains relation privilege: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(relation.relname) || ':' || privilege.privilege_type
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
   WHERE namespace.nspname = 'public'
     AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
     AND privilege.grantee = 0
  UNION ALL
  SELECT 'PUBLIC retains routine EXECUTE: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(routine.proname)
    FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = routine.pronamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(
     COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))
   ) AS privilege
   WHERE namespace.nspname = 'public'
     AND privilege.grantee = 0
     AND privilege.privilege_type = 'EXECUTE'
  UNION ALL
  SELECT 'public relation not owned by migrator: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(relation.relname)
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
   WHERE namespace.nspname = 'public'
     AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'i', 'I')
     AND owner.rolname <> :'migrator_role'
     AND NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_depend AS dependency
        WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
          AND dependency.objid = relation.oid
          AND dependency.deptype = 'e'
     )
  UNION ALL
  SELECT 'public routine not owned by migrator: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(routine.proname)
    FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = routine.pronamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = routine.proowner
   WHERE namespace.nspname = 'public'
     AND owner.rolname <> :'migrator_role'
     AND NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_depend AS dependency
        WHERE dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
          AND dependency.objid = routine.oid
          AND dependency.deptype = 'e'
     )
  UNION ALL
  SELECT 'public type/domain not owned by migrator: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(data_type.typname)
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
  UNION ALL
  SELECT 'runtime role can create database objects'
    FROM pg_catalog.pg_roles AS runtime_role
    JOIN pg_catalog.pg_database AS database
      ON database.datname = current_database()
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = 'public'
   WHERE runtime_role.rolname = :'runtime_role'
     AND (
       pg_catalog.has_database_privilege(runtime_role.oid, database.oid, 'CREATE')
       OR pg_catalog.has_schema_privilege(runtime_role.oid, namespace.oid, 'CREATE')
     )
  UNION ALL
  SELECT role.rolname || ' is missing CONNECT or schema USAGE'
    FROM pg_catalog.pg_roles AS role
    JOIN pg_catalog.pg_database AS database
      ON database.datname = current_database()
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = 'public'
   WHERE role.rolname IN (:'runtime_role', :'command_role', :'backup_role')
     AND (
       NOT pg_catalog.has_database_privilege(role.oid, database.oid, 'CONNECT')
       OR NOT pg_catalog.has_schema_privilege(role.oid, namespace.oid, 'USAGE')
     )
  UNION ALL
  SELECT 'runtime relation capability set differs from the exact table manifest'
    FROM pg_catalog.pg_roles runtime_role
   WHERE runtime_role.rolname=:'runtime_role'
     AND EXISTS (
       (SELECT relation.relname,
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'SELECT'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'INSERT'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'UPDATE'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'DELETE'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'TRUNCATE')
                 OR pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'REFERENCES')
                 OR pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'TRIGGER')
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relkind IN ('r','p')
           AND NOT EXISTS (
             SELECT 1 FROM pg_catalog.pg_depend dependency
              WHERE dependency.classid='pg_catalog.pg_class'::pg_catalog.regclass
                AND dependency.objid=relation.oid AND dependency.deptype='e'
           )
        EXCEPT
        SELECT expected.relation_name,expected.can_select,expected.can_insert,
               expected.can_update,expected.can_delete,FALSE
          FROM pg_temp.northstar_runtime_relation_manifest expected)
       UNION ALL
       (SELECT expected.relation_name,expected.can_select,expected.can_insert,
               expected.can_update,expected.can_delete,FALSE
          FROM pg_temp.northstar_runtime_relation_manifest expected
        EXCEPT
        SELECT relation.relname,
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'SELECT'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'INSERT'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'UPDATE'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'DELETE'),
               pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'TRUNCATE')
                 OR pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'REFERENCES')
                 OR pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'TRIGGER')
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relkind IN ('r','p')
           AND NOT EXISTS (
             SELECT 1 FROM pg_catalog.pg_depend dependency
              WHERE dependency.classid='pg_catalog.pg_class'::pg_catalog.regclass
                AND dependency.objid=relation.oid AND dependency.deptype='e'
           ))
     )
  UNION ALL
  SELECT 'runtime SM projection column ACL is incomplete'
   WHERE EXISTS (
     SELECT expected.attname
       FROM pg_catalog.unnest(ARRAY[
         'id','user_id','auth_generation','full_jid','resource','connection_id',
         'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available','carbons',
         'priority','blocklist_requested','roster_requested','active_privacy_list',
         'privacy_requested','user_agent_id','joined_rooms','directed_presence',
         'last_presence','resumable','live_lease_until','expires_at','claimed_until',
         'created_at','updated_at'
       ]::pg_catalog.text[]) expected(attname)
      WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
          JOIN pg_catalog.pg_attribute attribute
            ON attribute.attrelid=relation.oid AND attribute.attname=expected.attname
           AND attribute.attnum>0 AND NOT attribute.attisdropped
         CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
         WHERE namespace.nspname='public' AND relation.relname='sm_resume_sessions'
           AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
           AND privilege.grantor=relation.relowner
           AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable
      )
   )
  UNION ALL
  SELECT 'runtime role is missing required sequence privileges'
    FROM pg_catalog.pg_roles AS runtime_role
   WHERE runtime_role.rolname = :'runtime_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS sequence
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = sequence.relnamespace
         WHERE namespace.nspname = 'public'
           AND sequence.relkind = 'S'
           AND CASE
                 WHEN sequence.relkind='S' THEN (
                   NOT pg_catalog.has_sequence_privilege(runtime_role.oid, sequence.oid, 'USAGE')
                   OR NOT pg_catalog.has_sequence_privilege(runtime_role.oid, sequence.oid, 'SELECT')
                   OR pg_catalog.has_sequence_privilege(runtime_role.oid, sequence.oid, 'UPDATE')
                 )
                 ELSE FALSE
               END
     )
  UNION ALL
  SELECT 'runtime role is missing required routine EXECUTE'
    FROM pg_catalog.pg_roles AS runtime_role
   WHERE runtime_role.rolname = :'runtime_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_proc AS routine
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = 'public'
          AND ((NOT routine.prosecdef
                AND routine.proname NOT LIKE 'northstar_admin_command_%'
                AND routine.proname NOT IN (
                  'northstar_protect_admin_session_cleanup_identity',
                  'northstar_enqueue_admin_generation_cleanup',
                  'northstar_enqueue_admin_exact_session_cleanup'
                ))
               OR routine.oid IN (
            SELECT pg_catalog.to_regprocedure('public.' || allowed.signature)
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
                ('northstar_admin_service_control_poll()')
              ) AS allowed(signature)
          ))
          AND NOT pg_catalog.has_function_privilege(
                runtime_role.oid,
                routine.oid,
                'EXECUTE'
              )
     )
  UNION ALL
  SELECT 'runtime role can execute a non-allowlisted SECURITY DEFINER routine'
    FROM pg_catalog.pg_roles AS runtime_role
   WHERE runtime_role.rolname = :'runtime_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_proc AS routine
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = 'public'
          AND routine.prosecdef
          AND routine.oid NOT IN (
            SELECT pg_catalog.to_regprocedure('public.' || allowed.signature)
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
                ('northstar_admin_service_control_poll()')
              ) AS allowed(signature)
          )
          AND routine.oid NOT IN (
            SELECT pg_catalog.to_regprocedure('public.' || capability.signature)
              FROM pg_temp.northstar_capability_manifest AS capability
             WHERE capability.workload='runtime'
          )
          AND pg_catalog.has_function_privilege(
                runtime_role.oid,
                routine.oid,
                'EXECUTE'
              )
     )
  UNION ALL
  SELECT role.rolname || ' retains CREATE or TEMPORARY privilege'
    FROM pg_catalog.pg_roles AS role
    JOIN pg_catalog.pg_database AS database
      ON database.datname = current_database()
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = 'public'
   WHERE role.rolname IN (:'runtime_role', :'command_role', :'backup_role')
     AND (
       pg_catalog.has_database_privilege(role.oid, database.oid, 'CREATE')
       OR pg_catalog.has_database_privilege(role.oid, database.oid, 'TEMPORARY')
       OR pg_catalog.has_schema_privilege(role.oid, namespace.oid, 'CREATE')
     )
  UNION ALL
  SELECT 'command role has application relation privilege'
    FROM pg_catalog.pg_roles AS command_role
   WHERE command_role.rolname = :'command_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS relation
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r','p','v','m','f')
          AND (
            pg_catalog.has_table_privilege(command_role.oid,relation.oid,'SELECT')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'INSERT')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'UPDATE')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'DELETE')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'REFERENCES')
            OR pg_catalog.has_table_privilege(command_role.oid,relation.oid,'TRIGGER')
            OR pg_catalog.has_any_column_privilege(command_role.oid,relation.oid,'SELECT')
            OR pg_catalog.has_any_column_privilege(command_role.oid,relation.oid,'INSERT')
            OR pg_catalog.has_any_column_privilege(command_role.oid,relation.oid,'UPDATE')
            OR pg_catalog.has_any_column_privilege(command_role.oid,relation.oid,'REFERENCES')
          )
     )
  UNION ALL
  SELECT 'command role has application sequence privilege'
    FROM pg_catalog.pg_roles AS command_role
   WHERE command_role.rolname = :'command_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS sequence
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=sequence.relnamespace
         WHERE namespace.nspname='public' AND sequence.relkind='S'
           AND CASE
                 WHEN sequence.relkind='S' THEN (
                   pg_catalog.has_sequence_privilege(command_role.oid,sequence.oid,'USAGE')
                   OR pg_catalog.has_sequence_privilege(command_role.oid,sequence.oid,'SELECT')
                   OR pg_catalog.has_sequence_privilege(command_role.oid,sequence.oid,'UPDATE')
                 )
                 ELSE FALSE
               END
     )
  UNION ALL
  SELECT 'command role does not have the exact session capability set'
    FROM pg_catalog.pg_roles AS command_role
   WHERE command_role.rolname = :'command_role'
     AND (
       EXISTS (
         SELECT 1
           FROM (VALUES
             ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
             ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
             ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
             ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
             ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
             ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
             ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
             ('northstar_admin_command_cleanup()')
           ) AS required(signature)
          WHERE pg_catalog.to_regprocedure('public.' || required.signature) IS NULL
             OR NOT pg_catalog.has_function_privilege(
                    command_role.oid,
                    pg_catalog.to_regprocedure('public.' || required.signature),
                    'EXECUTE')
       )
       OR EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid=routine.pronamespace
          WHERE namespace.nspname='public'
            AND pg_catalog.has_function_privilege(command_role.oid,routine.oid,'EXECUTE')
            AND routine.oid NOT IN (
              SELECT pg_catalog.to_regprocedure('public.' || allowed.signature)
                FROM (VALUES
                  ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
                  ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
                  ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
                  ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
                  ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
                  ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
                  ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
                  ('northstar_admin_command_cleanup()')
                ) AS allowed(signature)
            )
            AND routine.oid NOT IN (
              SELECT pg_catalog.to_regprocedure('public.' || capability.signature)
                FROM pg_temp.northstar_capability_manifest AS capability
               WHERE capability.workload='command'
            )
       )
     )
  UNION ALL
  SELECT 'backup role has write privilege on application relations'
    FROM pg_catalog.pg_roles AS backup_role
   WHERE backup_role.rolname = :'backup_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS relation
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (
            pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'INSERT')
            OR pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'UPDATE')
            OR pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'DELETE')
            OR pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'TRUNCATE')
            OR pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'REFERENCES')
            OR pg_catalog.has_table_privilege(backup_role.oid, relation.oid, 'TRIGGER')
            OR pg_catalog.has_any_column_privilege(backup_role.oid, relation.oid, 'INSERT')
            OR pg_catalog.has_any_column_privilege(backup_role.oid, relation.oid, 'UPDATE')
            OR pg_catalog.has_any_column_privilege(backup_role.oid, relation.oid, 'REFERENCES')
          )
     )
  UNION ALL
  SELECT 'backup role is missing required relation SELECT'
    FROM pg_catalog.pg_roles AS backup_role
   WHERE backup_role.rolname = :'backup_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS relation
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND NOT pg_catalog.has_table_privilege(
            backup_role.oid,
            relation.oid,
            'SELECT'
          )
     )
  UNION ALL
  SELECT 'backup role is missing required sequence SELECT'
    FROM pg_catalog.pg_roles AS backup_role
   WHERE backup_role.rolname = :'backup_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS sequence
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = sequence.relnamespace
         WHERE namespace.nspname = 'public'
           AND sequence.relkind = 'S'
           AND CASE
                 WHEN sequence.relkind='S' THEN NOT pg_catalog.has_sequence_privilege(
                   backup_role.oid,
                   sequence.oid,
                   'SELECT'
                 )
                 ELSE FALSE
               END
     )
  UNION ALL
  SELECT 'backup role can execute application routines'
    FROM pg_catalog.pg_roles AS backup_role
   WHERE backup_role.rolname = :'backup_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_proc AS routine
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = 'public'
          AND pg_catalog.has_function_privilege(
            backup_role.oid,
            routine.oid,
            'EXECUTE'
          )
     )
  UNION ALL
  SELECT 'backup role can allocate sequence values'
    FROM pg_catalog.pg_roles AS backup_role
   WHERE backup_role.rolname = :'backup_role'
     AND EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS sequence
         JOIN pg_catalog.pg_namespace AS namespace
           ON namespace.oid = sequence.relnamespace
         WHERE namespace.nspname = 'public'
           AND sequence.relkind = 'S'
           AND CASE
                 WHEN sequence.relkind='S' THEN (
                   pg_catalog.has_sequence_privilege(backup_role.oid, sequence.oid, 'USAGE')
                   OR pg_catalog.has_sequence_privilege(backup_role.oid, sequence.oid, 'UPDATE')
                 )
                 ELSE FALSE
               END
      )
  UNION ALL
  SELECT 'unexpected explicit relation ACL grantee: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(relation.relname) || ':' ||
         COALESCE(pg_catalog.quote_ident(grantee.rolname),'PUBLIC') || ':' ||
         privilege.privilege_type
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS privilege
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
   WHERE namespace.nspname='public'
     AND relation.relkind IN ('r','p','v','m','S','f')
     AND privilege.grantee<>relation.relowner
     AND NOT COALESCE(
       privilege.grantor=relation.relowner
       AND NOT privilege.is_grantable
       AND (
         (relation.relkind IN ('r','p')
          AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')
          AND EXISTS (
            SELECT 1
              FROM pg_temp.northstar_runtime_relation_manifest expected
             WHERE expected.relation_name=relation.relname
               AND CASE privilege.privilege_type
                     WHEN 'SELECT' THEN expected.can_select
                     WHEN 'INSERT' THEN expected.can_insert
                     WHEN 'UPDATE' THEN expected.can_update
                     WHEN 'DELETE' THEN expected.can_delete
                     ELSE FALSE
                   END
          ))
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
  UNION ALL
  SELECT 'unexpected explicit column ACL grantee: ' ||
         pg_catalog.quote_ident(namespace.nspname) || '.' ||
         pg_catalog.quote_ident(relation.relname) || '.' ||
         pg_catalog.quote_ident(attribute.attname) || ':' ||
         COALESCE(pg_catalog.quote_ident(grantee.rolname),'PUBLIC') || ':' ||
         privilege.privilege_type
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid=relation.oid
     AND attribute.attnum>0 AND NOT attribute.attisdropped
   CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
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
  UNION ALL
  SELECT 'routine ACL differs from the owner/runtime/command execution manifest'
   WHERE EXISTS (
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
          ),FALSE
        )
   )
  UNION ALL
  SELECT 'type/domain ACL differs from the owner/runtime/backup USAGE manifest'
   WHERE EXISTS (
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
   ) OR EXISTS (
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
        AND EXISTS (
          SELECT required.grantee
            FROM (VALUES
              (data_type.typowner),
              ((SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role')),
              ((SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'backup_role'))
            ) required(grantee)
           WHERE NOT EXISTS (
             SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
               data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
             )) privilege
              WHERE privilege.grantee=required.grantee
                AND privilege.grantor=data_type.typowner
                AND privilege.privilege_type='USAGE'
                AND NOT privilege.is_grantable
           )
        )
   )
  UNION ALL
  SELECT 'canonical SECURITY DEFINER capability manifest drifted'
   WHERE EXISTS (
     SELECT 1
       FROM pg_temp.northstar_capability_manifest AS expected
       LEFT JOIN pg_catalog.pg_proc AS routine
         ON routine.oid=pg_catalog.to_regprocedure('public.' || expected.signature)
      WHERE routine.oid IS NULL OR NOT routine.prosecdef
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
   ) OR EXISTS (
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
   ) OR EXISTS (
     SELECT 1
       FROM pg_catalog.pg_proc AS routine
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid=routine.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
      ) AS privilege
      WHERE namespace.nspname='public' AND routine.prosecdef
        AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
   ) OR EXISTS (
     SELECT 1
       FROM pg_catalog.pg_proc AS routine
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid=routine.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
      ) AS privilege
      LEFT JOIN pg_temp.northstar_capability_manifest AS expected
        ON pg_catalog.to_regprocedure('public.' || expected.signature)=routine.oid
      WHERE namespace.nspname='public' AND routine.prosecdef
        AND privilege.grantee<>routine.proowner
        AND NOT COALESCE((
          (expected.workload='runtime'
           AND privilege.grantor=routine.proowner
           AND privilege.privilege_type='EXECUTE'
           AND NOT privilege.is_grantable
           AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles
             WHERE rolname=:'runtime_role'))
          OR
          (expected.workload='command'
            AND privilege.grantor=routine.proowner
            AND privilege.privilege_type='EXECUTE'
            AND NOT privilege.is_grantable
            AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles
              WHERE rolname=:'command_role'))
        ),FALSE)
   )
)
SELECT finding FROM findings ORDER BY finding;
PSQL
  )

  unexpected_superusers=$("${psql_command[@]}" --tuples-only --no-align <<'PSQL'
SELECT rolname
  FROM pg_catalog.pg_roles
 WHERE rolsuper AND rolcanlogin AND rolname <> :'bootstrap_role'
 ORDER BY rolname;
PSQL
  )

  legacy_login=$("${psql_command[@]}" --tuples-only --no-align <<'PSQL'
SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'xmpp' AND rolcanlogin
);
PSQL
  )

  if [[ -n "$unexpected_superusers" ]]; then
    unexpected_superusers=${unexpected_superusers//$'\n'/,}
    printf 'warning: additional login superuser(s) remain: %s\n' \
      "$unexpected_superusers" >&2
  fi
  if [[ "$legacy_login" == 't' ]]; then
    printf '%s\n' \
      'warning: legacy database role xmpp can still log in; use the guarded explicit demotion after credential cutover' >&2
  fi
  if [[ -n "$findings" ]]; then
    printf '%s\n' "$findings" >&2
    return 4
  fi
  printf '%s\n' 'Northstar database role audit passed.'
}

authority=$(verify_connection_authority | tail -n 1)
[[ "$authority" == 'ok' ]] || fail 'the connected role is not a PostgreSQL superuser'

if [[ "$mode" == 'audit' ]]; then
  audit_roles
  exit $?
fi

bootstrap_password=$(read_secret "$bootstrap_password_file" 'postgres_bootstrap_password')
migrator_password=$(read_secret "$migrator_password_file" 'northstar_migrator_password')
runtime_password=$(read_secret "$runtime_password_file" 'northstar_runtime_password')
command_password=$(read_secret "$command_password_file" 'northstar_command_password')
backup_password=$(read_secret "$backup_password_file" 'northstar_backup_password')

export NORTHSTAR_BOOTSTRAP_PASSWORD="$bootstrap_password"
export NORTHSTAR_MIGRATOR_PASSWORD="$migrator_password"
export NORTHSTAR_RUNTIME_PASSWORD="$runtime_password"
export NORTHSTAR_COMMAND_PASSWORD="$command_password"
export NORTHSTAR_BACKUP_PASSWORD="$backup_password"

"${psql_command[@]}" <<'PSQL'
\getenv bootstrap_password NORTHSTAR_BOOTSTRAP_PASSWORD
\getenv migrator_password NORTHSTAR_MIGRATOR_PASSWORD
\getenv runtime_password NORTHSTAR_RUNTIME_PASSWORD
\getenv command_password NORTHSTAR_COMMAND_PASSWORD
\getenv backup_password NORTHSTAR_BACKUP_PASSWORD

BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('northstar-database-role-policy-v1', 0)
);
SET LOCAL password_encryption = 'scram-sha-256';

SELECT pg_catalog.format(
         'CREATE ROLE %I LOGIN PASSWORD %L SUPERUSER CREATEDB CREATEROLE NOREPLICATION',
         :'bootstrap_role', :'bootstrap_password'
       )
 WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :'bootstrap_role'
       ) \gexec
SELECT pg_catalog.format(
  'ALTER ROLE %I LOGIN PASSWORD %L INHERIT SUPERUSER CREATEDB CREATEROLE NOREPLICATION CONNECTION LIMIT -1',
  :'bootstrap_role', :'bootstrap_password'
) \gexec

SELECT pg_catalog.format(
         'CREATE ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 VALID UNTIL ''infinity''',
         :'migrator_role', :'migrator_password'
       )
 WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :'migrator_role'
       ) \gexec
SELECT pg_catalog.format(
         'CREATE ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64 VALID UNTIL ''infinity''',
         :'runtime_role', :'runtime_password'
       )
 WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :'runtime_role'
       ) \gexec
SELECT pg_catalog.format(
         'CREATE ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 VALID UNTIL ''infinity''',
         :'command_role', :'command_password'
       )
 WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :'command_role'
       ) \gexec
SELECT pg_catalog.format(
         'CREATE ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 VALID UNTIL ''infinity''',
         :'backup_role', :'backup_password'
       )
 WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :'backup_role'
       ) \gexec

SELECT pg_catalog.format(
  'ALTER ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 VALID UNTIL ''infinity''',
  :'migrator_role', :'migrator_password'
) \gexec
SELECT pg_catalog.format(
  'ALTER ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64 VALID UNTIL ''infinity''',
  :'runtime_role', :'runtime_password'
) \gexec
SELECT pg_catalog.format(
  'ALTER ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 VALID UNTIL ''infinity''',
  :'command_role', :'command_password'
) \gexec
SELECT pg_catalog.format(
  'ALTER ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 VALID UNTIL ''infinity''',
  :'backup_role', :'backup_password'
) \gexec

SELECT pg_catalog.format('ALTER ROLE %I RESET ALL',role_name)
  FROM (VALUES
    (:'migrator_role'),(:'runtime_role'),(:'command_role'),(:'backup_role')
  ) AS workload(role_name)
 ORDER BY role_name
\gexec

SELECT pg_catalog.format('REVOKE %I FROM %I', granted.rolname, member.rolname)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
  JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
 WHERE granted.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
    OR member.rolname IN (:'migrator_role', :'runtime_role', :'command_role', :'backup_role')
 ORDER BY granted.rolname, member.rolname
\gexec

ALTER DATABASE :"database_name" OWNER TO :"migrator_role";
ALTER SCHEMA public OWNER TO :"migrator_role";

SELECT pg_catalog.format(
         'ALTER %s %I.%I OWNER TO %I',
         CASE relation.relkind
           WHEN 'S' THEN 'SEQUENCE'
           WHEN 'v' THEN 'VIEW'
           WHEN 'm' THEN 'MATERIALIZED VIEW'
           WHEN 'f' THEN 'FOREIGN TABLE'
           ELSE 'TABLE'
         END,
         namespace.nspname,
         relation.relname,
         :'migrator_role'
       )
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
 WHERE namespace.nspname = 'public'
   AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
   AND pg_catalog.pg_get_userbyid(relation.relowner) <> :'migrator_role'
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
            AND dependency.objid = relation.oid
            AND dependency.deptype = 'e'
       )
 -- PostgreSQL requires an OWNED BY sequence to have the same owner as its
 -- owning table. Move tables first; their dependent sequences then already
 -- match (or can be reconciled safely by the generated sequence statement).
 ORDER BY CASE WHEN relation.relkind = 'S' THEN 1 ELSE 0 END, relation.oid
\gexec

SELECT pg_catalog.format(
         'ALTER %s %I.%I(%s) OWNER TO %I',
         CASE routine.prokind
           WHEN 'p' THEN 'PROCEDURE'
           WHEN 'a' THEN 'AGGREGATE'
           ELSE 'FUNCTION'
         END,
         namespace.nspname,
         routine.proname,
         pg_catalog.pg_get_function_identity_arguments(routine.oid),
         :'migrator_role'
       )
  FROM pg_catalog.pg_proc AS routine
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = routine.pronamespace
 WHERE namespace.nspname = 'public'
   AND pg_catalog.pg_get_userbyid(routine.proowner) <> :'migrator_role'
   AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend AS dependency
          WHERE dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
            AND dependency.objid = routine.oid
            AND dependency.deptype = 'e'
       )
 ORDER BY routine.oid
\gexec

SELECT pg_catalog.format(
         'ALTER %s %I.%I OWNER TO %I',
         CASE WHEN data_type.typtype='d' THEN 'DOMAIN' ELSE 'TYPE' END,
         namespace.nspname,data_type.typname,:'migrator_role'
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
   AND pg_catalog.pg_get_userbyid(data_type.typowner)<>:'migrator_role'
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_depend AS dependency
      WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
        AND dependency.objid=data_type.oid
        AND (dependency.deptype='e'
          OR (dependency.deptype='i' AND data_type.typtype<>'c'))
   )
 ORDER BY data_type.oid
\gexec
COMMIT;
PSQL

"${psql_command[@]}" --file "$grants_sql"

if [[ "$demote_legacy" == true ]]; then
  [[ "$connection_user" != 'xmpp' ]] \
    || fail 'reconnect as northstar_bootstrap before demoting the legacy xmpp role'
  "${psql_command[@]}" <<'PSQL'
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('northstar-database-role-policy-v1', 0)
);
SELECT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'xmpp'
       ) AS northstar_legacy_exists \gset
\if :northstar_legacy_exists
  SELECT current_user <> 'xmpp'
         AND (
           NOT EXISTS (
             SELECT 1 FROM pg_catalog.pg_roles
              WHERE rolname = 'xmpp' AND rolsuper
           )
           OR EXISTS (
             SELECT 1 FROM pg_catalog.pg_roles
              WHERE rolsuper AND rolcanlogin AND rolname <> 'xmpp'
           )
  ) AS northstar_safe_to_demote \gset
  \if :northstar_safe_to_demote
    SELECT pg_catalog.format('REVOKE %I FROM %I', granted.rolname, member.rolname)
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
      JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
     WHERE granted.rolname = 'xmpp' OR member.rolname = 'xmpp'
     ORDER BY granted.rolname, member.rolname
    \gexec
    ALTER ROLE xmpp NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 0 PASSWORD NULL;
  \else
    \echo 'refusing to demote the current or last login superuser'
    \quit 40
  \endif
\endif
COMMIT;
PSQL
fi

capability_ledger_present=$("${psql_command[@]}" --tuples-only --no-align \
  --command="SELECT pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL")
capability_boundary_complete=false
if [[ "$capability_ledger_present" == t ]]; then
  capability_boundary_complete=$("${psql_command[@]}" --tuples-only --no-align \
    --command="SELECT pg_catalog.count(*)=2 FROM public._sqlx_migrations WHERE success AND version IN (114,115)")
fi
if [[ "$capability_boundary_complete" == t ]]; then
  audit_roles
else
  printf '%s\n' \
    'Northstar roles prepared with owner-only ACLs; run migrations through 0115, then exact grant reconciliation before starting any workload.'
fi
