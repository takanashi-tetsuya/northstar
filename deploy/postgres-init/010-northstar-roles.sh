#!/usr/bin/env bash

# docker-entrypoint.sh sources non-executable *.sh files. Re-execute in a child
# so strict shell options, readonly variables, and traps cannot leak into the
# PostgreSQL image's parent entrypoint when a filesystem loses executable bits.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  bash "${BASH_SOURCE[0]}"
  return
fi

set -Eeuo pipefail
set +x

# Runs only while the official PostgreSQL image initializes a fresh volume.
# POSTGRES_USER must be the container-only bootstrap role; application and
# maintenance services receive separate credentials.

readonly bootstrap_role='northstar_bootstrap'
readonly migrator_role='northstar_migrator'
readonly runtime_role='northstar_runtime'
readonly command_role='northstar_commands'
readonly backup_role='northstar_backup'
readonly database_name="${POSTGRES_DB:-xmpp}"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly grants_sql="$script_dir/lib/reconcile-northstar-grants.sql"

bootstrap_password=''
migrator_password=''
runtime_password=''
command_password=''
backup_password=''

clear_secrets() {
  unset PGPASSWORD
  unset bootstrap_password migrator_password runtime_password command_password backup_password
  unset NORTHSTAR_BOOTSTRAP_PASSWORD NORTHSTAR_MIGRATOR_PASSWORD
  unset NORTHSTAR_RUNTIME_PASSWORD NORTHSTAR_BACKUP_PASSWORD
  unset NORTHSTAR_COMMAND_PASSWORD
}
trap clear_secrets EXIT

fail() {
  printf 'Northstar PostgreSQL initialization failed: %s\n' "$1" >&2
  exit 1
}

read_secret() {
  local path=$1
  local label=$2
  local size
  local value

  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular, non-symbolic-link file"
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

[[ "${POSTGRES_USER:-}" == "$bootstrap_role" ]] \
  || fail "POSTGRES_USER must be $bootstrap_role on a fresh volume"
[[ "$database_name" == 'xmpp' ]] \
  || fail 'POSTGRES_DB must be xmpp for the production role policy'
[[ -r "$grants_sql" ]] || fail 'the shared grant policy is missing'
for required_command in cmp grep psql wc; do
  command -v "$required_command" >/dev/null \
    || fail "required command is unavailable: $required_command"
done

bootstrap_password=$(read_secret \
  "${POSTGRES_PASSWORD_FILE:-/run/secrets/postgres_bootstrap_password}" \
  'postgres_bootstrap_password')
migrator_password=$(read_secret \
  "${NORTHSTAR_MIGRATOR_PASSWORD_FILE:-/run/secrets/northstar_migrator_password}" \
  'northstar_migrator_password')
runtime_password=$(read_secret \
  "${NORTHSTAR_RUNTIME_PASSWORD_FILE:-/run/secrets/northstar_runtime_password}" \
  'northstar_runtime_password')
command_password=$(read_secret \
  "${NORTHSTAR_COMMAND_PASSWORD_FILE:-/run/secrets/northstar_command_password}" \
  'northstar_command_password')
backup_password=$(read_secret \
  "${NORTHSTAR_BACKUP_PASSWORD_FILE:-/run/secrets/northstar_backup_password}" \
  'northstar_backup_password')

# Export only to the local psql child. \getenv moves each value into a psql
# variable and psql's :'name' quoting turns it into a safe SQL literal. Secret
# values never enter argv or stdout.
export NORTHSTAR_BOOTSTRAP_PASSWORD="$bootstrap_password"
export NORTHSTAR_MIGRATOR_PASSWORD="$migrator_password"
export NORTHSTAR_RUNTIME_PASSWORD="$runtime_password"
export NORTHSTAR_COMMAND_PASSWORD="$command_password"
export NORTHSTAR_BACKUP_PASSWORD="$backup_password"
export PGPASSWORD="$bootstrap_password"

psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --username "$bootstrap_role" --dbname "$database_name" \
  --set=database_name="$database_name" \
  --set=bootstrap_role="$bootstrap_role" \
  --set=migrator_role="$migrator_role" \
  --set=runtime_role="$runtime_role" \
  --set=command_role="$command_role" \
  --set=backup_role="$backup_role" <<'PSQL'
\getenv migrator_password NORTHSTAR_MIGRATOR_PASSWORD
\getenv runtime_password NORTHSTAR_RUNTIME_PASSWORD
\getenv command_password NORTHSTAR_COMMAND_PASSWORD
\getenv backup_password NORTHSTAR_BACKUP_PASSWORD
\getenv bootstrap_password NORTHSTAR_BOOTSTRAP_PASSWORD

SELECT current_user = :'bootstrap_role'
       AND EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles
          WHERE rolname = current_user AND rolsuper
       ) AS northstar_bootstrap_is_superuser \gset
\if :northstar_bootstrap_is_superuser
\else
  \echo 'fresh-volume role setup must run as the dedicated bootstrap superuser'
  \quit 30
\endif

BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('northstar-database-role-policy-v1', 0)
);
SET LOCAL password_encryption = 'scram-sha-256';

-- initdb creates the bootstrap role before this script. Rewrite its verifier
-- under the explicit SCRAM policy as well, without changing its privileges.
SELECT pg_catalog.format(
  'ALTER ROLE %I PASSWORD %L', :'bootstrap_role', :'bootstrap_password'
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

-- Role-level GUCs (especially search_path) survive ALTER ROLE unless reset
-- explicitly.  They are outside the application DSN and can otherwise change
-- catalog resolution or disable safety timeouts before pool pinning runs.
SELECT pg_catalog.format('ALTER ROLE %I RESET ALL',role_name)
  FROM (VALUES
    (:'migrator_role'),(:'runtime_role'),(:'command_role'),(:'backup_role')
  ) AS workload(role_name)
 ORDER BY role_name
\gexec

SELECT pg_catalog.format('REVOKE %I FROM %I CASCADE', granted.rolname, member.rolname)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
  JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
 WHERE granted.rolname IN (
         :'bootstrap_role', :'migrator_role', :'runtime_role',
         :'command_role', :'backup_role'
       )
    OR member.rolname IN (
         :'bootstrap_role', :'migrator_role', :'runtime_role',
         :'command_role', :'backup_role'
       )
 ORDER BY granted.rolname, member.rolname
\gexec

-- Restore uses one bounded catalog/control session outside the target database.
-- Converge the dedicated cluster's maintenance database to one owner and one
-- explicit non-owner CONNECT grant; do not inherit PostgreSQL's PUBLIC default
-- or preserve arbitrary legacy grantees.
ALTER DATABASE postgres OWNER TO :"bootstrap_role";
ALTER DATABASE postgres WITH ALLOW_CONNECTIONS true CONNECTION LIMIT -1 IS_TEMPLATE false;
REVOKE ALL PRIVILEGES ON DATABASE postgres FROM PUBLIC;
SELECT pg_catalog.format(
         'REVOKE ALL PRIVILEGES ON DATABASE postgres FROM %I CASCADE',
         grantee.rolname
       )
  FROM pg_catalog.pg_database AS database
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   database.datacl,pg_catalog.acldefault('d',database.datdba)
 )) AS privilege
  JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=privilege.grantee
 WHERE database.datname='postgres'
   AND privilege.grantee<>database.datdba
 GROUP BY grantee.rolname
 ORDER BY grantee.rolname
\gexec
GRANT CONNECT ON DATABASE postgres TO :"migrator_role";

ALTER DATABASE :"database_name" OWNER TO :"migrator_role";
ALTER SCHEMA public OWNER TO :"migrator_role";
COMMIT;
PSQL

psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --username "$bootstrap_role" --dbname "$database_name" \
  --set=database_name="$database_name" \
  --set=migrator_role="$migrator_role" \
  --set=runtime_role="$runtime_role" \
  --set=command_role="$command_role" \
  --set=backup_role="$backup_role" \
  --set=allow_bootstrap=true \
  --set=grant_phase=bootstrap \
  --file "$grants_sql"

printf '%s\n' 'Northstar PostgreSQL workload roles and least-privilege grants initialized.'
