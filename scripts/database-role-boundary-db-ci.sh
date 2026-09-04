#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Destructive, database-backed acceptance test for the PostgreSQL role boundary.
# This is intentionally restricted to an empty, loopback-only CI service. It
# exercises the legacy-volume reconciliation path, the real migration binary,
# post-migration ACL reconciliation, and negative privilege probes.

umask 077

readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly database_host="${PGHOST:-127.0.0.1}"
readonly database_port="${PGPORT:-5432}"
readonly control_role='northstar_ci_control'
readonly legacy_role='xmpp'
readonly bootstrap_role='northstar_bootstrap'
readonly migrator_role='northstar_migrator'
readonly runtime_role='northstar_runtime'
readonly command_role='northstar_commands'
readonly backup_role='northstar_backup'
readonly stale_grantee_role='northstar_ci_stale_grantee'
readonly delegated_grantee_role='northstar_ci_delegated_grantee'
readonly database_name='xmpp'
readonly phase_fixture_database='northstar_ci_grant_phase_fixture'

readonly control_password="${NORTHSTAR_CI_CONTROL_PASSWORD:-}"
readonly legacy_password='northstar-ci-legacy-password-00000001'
readonly bootstrap_password='northstar-ci-bootstrap-password-00000001'
readonly migrator_password='northstar-ci-migrator-password-00000001'
readonly runtime_password='northstar-ci-runtime-password-00000001'
readonly command_password='northstar-ci-command-password-00000001'
readonly backup_password='northstar-ci-backup-password-00000001'

runtime_dir=''
tmp_root="${TMPDIR:-/tmp}"
tmp_root=${tmp_root%/}
database_is_managed=false
phase_fixture_database_created=false
denial_probe=0

fail() {
  printf 'database role CI acceptance failed: %s\n' "$1" >&2
  exit 1
}

[[ "${CI:-}" == 'true' && "${NORTHSTAR_DATABASE_ROLE_CI:-}" == 'true' ]] \
  || fail 'refusing destructive test outside an explicitly enabled CI job'
case "$database_host" in
  127.0.0.1|localhost|::1) ;;
  *) fail 'the destructive CI fixture must use a loopback PostgreSQL service' ;;
esac
[[ "$database_port" =~ ^[1-9][0-9]{0,4}$ ]] \
  && (( database_port <= 65535 )) || fail 'invalid PostgreSQL port'
[[ ${#control_password} -ge 32 ]] \
  || fail 'NORTHSTAR_CI_CONTROL_PASSWORD must contain at least 32 characters'

for command in bash cargo chmod grep install mktemp psql python3 rm sed sha384sum; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

runtime_dir="$(mktemp -d "$tmp_root/northstar-database-role-ci.XXXXXX")"
chmod 0700 "$runtime_dir"
readonly marker="northstar-database-role-ci-$PPID-$$-$RANDOM-$RANDOM"

control_psql() {
  PGPASSWORD="$control_password" psql \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host "$database_host" --port "$database_port" \
    --username "$control_role" "$@"
}

psql_as() {
  local role=$1
  local password=$2
  shift 2
  PGPASSWORD="$password" psql \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host "$database_host" --port "$database_port" \
    --username "$role" --dbname "$database_name" "$@"
}

cleanup() {
  local original_status=$?
  local cleanup_status=0
  local marker_state='f:f'

  trap - EXIT
  set +e
  if [[ "$database_is_managed" == true ]]; then
    marker_state=$(control_psql --dbname=postgres --tuples-only --no-align \
      --set=expected_marker="$marker" <<'PSQL'
WITH fixture AS (
  SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname='xmpp') AS database_exists,
    COALESCE((
      SELECT pg_catalog.shobj_description(database.oid,'pg_database')=:'expected_marker'
        FROM pg_catalog.pg_database AS database WHERE database.datname='xmpp'
    ),false) AS database_marked,
    COALESCE((
      SELECT owner.rolname='xmpp'
        FROM pg_catalog.pg_database AS database
        JOIN pg_catalog.pg_roles AS owner ON owner.oid=database.datdba
       WHERE database.datname='xmpp'
    ),false) AS database_owned_by_legacy,
    EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='xmpp') AS role_exists,
    COALESCE((
      SELECT pg_catalog.shobj_description(role.oid,'pg_authid')=:'expected_marker'
        FROM pg_catalog.pg_roles AS role WHERE role.rolname='xmpp'
    ),false) AS role_marked
)
SELECT (database_exists OR role_exists)::pg_catalog.text || ':' ||
       (
         (NOT database_exists AND NOT role_exists)
         OR (role_exists AND role_marked AND (
               NOT database_exists OR database_marked OR database_owned_by_legacy
             ))
       )::pg_catalog.text
  FROM fixture;
PSQL
    )
    if [[ "$marker_state" == 't:t' ]]; then
      if [[ "$phase_fixture_database_created" == true ]]; then
        if control_psql --dbname=postgres \
          --command="DROP DATABASE IF EXISTS northstar_ci_grant_phase_fixture WITH (FORCE);"; then
          phase_fixture_database_created=false
        else
          cleanup_status=1
        fi
      fi
      control_psql --dbname=postgres <<'PSQL' || cleanup_status=1
-- The fixture deliberately transfers the maintenance database to bootstrap
-- and grants migrator its only maintenance capability.  Return those
-- cluster-global objects to the external CI controller before dropping the
-- fixture roles; otherwise cleanup either leaks ACLs or fails on ownership.
ALTER DATABASE postgres OWNER TO northstar_ci_control;
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
GRANT CONNECT, TEMPORARY ON DATABASE postgres TO PUBLIC;
SELECT (
  database_owner.rolname='northstar_ci_control'
  AND database.datallowconn
  AND database.datconnlimit=-1
  AND NOT database.datistemplate
  AND pg_catalog.count(*) FILTER (
        WHERE privilege.grantee=database.datdba
          AND privilege.grantor=database.datdba
          AND privilege.privilege_type IN ('CONNECT','CREATE','TEMPORARY')
          AND NOT privilege.is_grantable
      )=3
  AND pg_catalog.count(*) FILTER (
        WHERE privilege.grantee=0
          AND privilege.grantor=database.datdba
          AND privilege.privilege_type IN ('CONNECT','TEMPORARY')
          AND NOT privilege.is_grantable
      )=2
  AND pg_catalog.count(*)=5
) AS northstar_maintenance_database_restored
  FROM pg_catalog.pg_database AS database
  JOIN pg_catalog.pg_roles AS database_owner ON database_owner.oid=database.datdba
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   database.datacl,pg_catalog.acldefault('d',database.datdba)
 )) AS privilege
 WHERE database.datname='postgres'
 GROUP BY database.oid,database_owner.rolname
\gset
\if :northstar_maintenance_database_restored
\else
  \echo 'failed to restore the disposable CI maintenance database boundary'
  \quit 41
\endif
-- Preserve the ownership marker until the cluster-global maintenance state
-- has been restored and verified. A failed cleanup can then be retried safely.
DROP DATABASE IF EXISTS xmpp WITH (FORCE);
DROP ROLE IF EXISTS northstar_backup;
DROP ROLE IF EXISTS northstar_runtime;
DROP ROLE IF EXISTS northstar_commands;
DROP ROLE IF EXISTS northstar_migrator;
DROP ROLE IF EXISTS northstar_bootstrap;
DROP ROLE IF EXISTS northstar_ci_stale_grantee;
DROP ROLE IF EXISTS northstar_ci_delegated_grantee;
DROP ROLE IF EXISTS xmpp;
PSQL
    elif [[ "$marker_state" != 'f:t' ]]; then
      printf '%s\n' \
        'refusing database cleanup because the isolated CI ownership marker is absent or inconsistent' >&2
      cleanup_status=1
    fi
  fi

  if [[ -f "${privilege_matrix_file:-}" ]]; then
    python3 - "${privilege_matrix_file}" "$project_dir/privilege-matrix.json" <<'PY' || true
import json, sys
try:
    records = []
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line.strip()))
    with open(sys.argv[2], 'w', encoding='utf-8') as f:
        json.dump({"probes": records, "total": len(records)}, f, indent=2)
except Exception:
    pass
PY
  fi

  case "$runtime_dir" in
    "$tmp_root"/northstar-database-role-ci.*)
      rm -rf -- "$runtime_dir" || cleanup_status=1
      ;;
    *)
      printf 'refusing cleanup of unexpected temporary path: %s\n' "$runtime_dir" >&2
      cleanup_status=1
      ;;
  esac

  unset PGPASSWORD NORTHSTAR_CI_LEGACY_PASSWORD NORTHSTAR_CI_DATABASE_MARKER
  if (( original_status != 0 )); then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

write_secret() {
  local path=$1
  local value=$2
  install -m 0600 /dev/null "$path"
  printf '%s\n' "$value" >"$path"
}

readonly privilege_matrix_file="$runtime_dir/privilege-matrix.jsonl"
: >"$privilege_matrix_file"

record_privilege_probe() {
  local role="$1" database="$2" schema="$3" object="$4" privilege="$5" expected="$6" actual="$7" sqlstate="$8" classification="$9"
  printf '{"role":"%s","database":"%s","schema":"%s","object":"%s","privilege":"%s","expected":"%s","actual":"%s","sqlstate":"%s","classification":"%s"}\n' \
    "$role" "$database" "$schema" "$object" "$privilege" "$expected" "$actual" "$sqlstate" "$classification" >>"$privilege_matrix_file"
}

print_role_diagnostic() {
  local classification="$1" role="$2" database="$3" schema="$4" object="$5" privilege="$6" expected="$7" actual="$8" sqlstate="$9"
  printf '[WORKLOAD_ROLE_DIAGNOSTIC]\n' >&2
  printf '  role: %s\n' "$role" >&2
  printf '  database: %s\n' "$database" >&2
  printf '  schema: %s\n' "$schema" >&2
  printf '  object: %s\n' "$object" >&2
  printf '  privilege: %s\n' "$privilege" >&2
  printf '  expected: %s\n' "$expected" >&2
  printf '  actual: %s\n' "$actual" >&2
  printf '  SQLSTATE: %s\n' "$sqlstate" >&2
  printf '  classification: %s\n' "$classification" >&2
}

parse_sql_metadata() {
  local sql="$1"
  local schema="public" object="unknown" privilege="UNKNOWN"
  if [[ "$sql" =~ ALTER[[:space:]]+TABLE[[:space:]]+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+) ]]; then
    schema="${BASH_REMATCH[1]}"
    object="${BASH_REMATCH[2]}"
    privilege="ALTER"
  elif [[ "$sql" =~ UPDATE[[:space:]]+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+) ]]; then
    schema="${BASH_REMATCH[1]}"
    object="${BASH_REMATCH[2]}"
    privilege="UPDATE"
  elif [[ "$sql" =~ DELETE[[:space:]]+FROM[[:space:]]+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+) ]]; then
    schema="${BASH_REMATCH[1]}"
    object="${BASH_REMATCH[2]}"
    privilege="DELETE"
  elif [[ "$sql" =~ INSERT[[:space:]]+INTO[[:space:]]+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+) ]]; then
    schema="${BASH_REMATCH[1]}"
    object="${BASH_REMATCH[2]}"
    privilege="INSERT"
  elif [[ "$sql" =~ CREATE[[:space:]]+TEMPORARY ]]; then
    schema="pg_temp"
    object="temp_table"
    privilege="CREATE_TEMP"
  elif [[ "$sql" =~ CREATE[[:space:]]+TABLE ]]; then
    schema="public"
    object="table"
    privilege="CREATE"
  elif [[ "$sql" =~ SELECT[[:space:]]+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+) ]]; then
    schema="${BASH_REMATCH[1]}"
    object="${BASH_REMATCH[2]}"
    privilege="EXECUTE"
  elif [[ "$sql" =~ SET[[:space:]]+ROLE ]]; then
    schema="pg_catalog"
    object="role"
    privilege="SET_ROLE"
  fi
  printf '%s\t%s\t%s' "$schema" "$object" "$privilege"
}

expect_insufficient_privilege() {
  local role=$1
  local password=$2
  local label=$3
  local sql=$4
  local output
  local status
  local schema object privilege
  IFS=$'\t' read -r schema object privilege < <(parse_sql_metadata "$sql")

  denial_probe=$((denial_probe + 1))
  output="$runtime_dir/denial-$denial_probe.log"
  set +e
  PGPASSWORD="$password" psql \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --host "$database_host" --port "$database_port" \
    --username "$role" --dbname "$database_name" \
    --command "$sql" >"$output" 2>&1
  status=$?
  set -e
  if (( status == 0 )); then
    print_role_diagnostic "SHOULD_DENY_BUT_ALLOWED" "$role" "$database_name" "$schema" "$object" "$privilege" "DENY (42501)" "ALLOWED (00000)" "00000"
    record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "42501" "00000" "00000" "SHOULD_DENY_BUT_ALLOWED"
    fail "$label unexpectedly succeeded as $role"
  fi
  local actual_sqlstate
  actual_sqlstate="$(sed -nE 's/.*ERROR:[[:space:]]+([0-9A-Z]{5}):.*/\1/p' "$output" | head -n 1)"
  [[ -n "$actual_sqlstate" ]] || actual_sqlstate="UNKNOWN"

  if ! grep -Eq 'ERROR:[[:space:]]+42501:' "$output"; then
    print_role_diagnostic "UNEXPECTED_SQLSTATE" "$role" "$database_name" "$schema" "$object" "$privilege" "42501" "$actual_sqlstate" "$actual_sqlstate"
    record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "42501" "$actual_sqlstate" "$actual_sqlstate" "UNEXPECTED_SQLSTATE"
    printf 'unexpected denial result for %s:\n' "$label" >&2
    sed -E 's/(password=)[^[:space:]]+/\1[REDACTED]/gi' "$output" >&2
    fail "$label failed for a reason other than insufficient_privilege"
  fi
  record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "42501" "42501" "42501" "DENIED_AS_EXPECTED"
}

expect_sqlstate() {
  local role=$1
  local password=$2
  local expected_state=$3
  local label=$4
  local sql=$5
  local output
  local status
  local schema object privilege
  IFS=$'\t' read -r schema object privilege < <(parse_sql_metadata "$sql")

  denial_probe=$((denial_probe + 1))
  output="$runtime_dir/sqlstate-$denial_probe.log"
  set +e
  PGPASSWORD="$password" psql \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 --set=VERBOSITY=verbose \
    --host "$database_host" --port "$database_port" \
    --username "$role" --dbname "$database_name" \
    --command "$sql" >"$output" 2>&1
  status=$?
  set -e
  if (( status == 0 )); then
    print_role_diagnostic "SHOULD_DENY_BUT_ALLOWED" "$role" "$database_name" "$schema" "$object" "$privilege" "DENY ($expected_state)" "ALLOWED (00000)" "00000"
    record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "$expected_state" "00000" "00000" "SHOULD_DENY_BUT_ALLOWED"
    fail "$label unexpectedly succeeded as $role"
  fi
  local actual_sqlstate
  actual_sqlstate="$(sed -nE 's/.*ERROR:[[:space:]]+([0-9A-Z]{5}):.*/\1/p' "$output" | head -n 1)"
  [[ -n "$actual_sqlstate" ]] || actual_sqlstate="UNKNOWN"

  if ! grep -Eq "ERROR:[[:space:]]+${expected_state}:" "$output"; then
    print_role_diagnostic "UNEXPECTED_SQLSTATE" "$role" "$database_name" "$schema" "$object" "$privilege" "$expected_state" "$actual_sqlstate" "$actual_sqlstate"
    record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "$expected_state" "$actual_sqlstate" "$actual_sqlstate" "UNEXPECTED_SQLSTATE"
    printf 'unexpected SQLSTATE result for %s:\n' "$label" >&2
    sed -E 's/(password=)[^[:space:]]+/\1[REDACTED]/gi' "$output" >&2
    fail "$label failed with an unexpected SQLSTATE"
  fi
  record_privilege_probe "$role" "$database_name" "$schema" "$object" "$privilege" "$expected_state" "$expected_state" "$expected_state" "DENIED_AS_EXPECTED"
}

cd "$project_dir"

# Refuse the destructive, relatively expensive database fixture before it
# starts if a migration changed without regenerating the repository authority.
# Otherwise the eventual exact-grant error misleadingly looks like a database
# ACL defect even though its expected ledger was stale at checkout time.
python3 scripts/generate-database-migration-ledger.py --check \
  || fail 'repository migration ledger is stale'

# The service owns only database postgres. Refuse to reuse any cluster that
# already has fixture/application identities or the target database.
fixture_conflicts=$(control_psql --dbname=postgres --tuples-only --no-align <<'PSQL'
SELECT
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database
    WHERE datname IN ('xmpp','northstar_ci_grant_phase_fixture'))
  +
  (
    SELECT pg_catalog.count(*)
      FROM pg_catalog.pg_roles
     WHERE rolname IN (
       'xmpp', 'northstar_bootstrap', 'northstar_migrator',
       'northstar_runtime', 'northstar_commands', 'northstar_backup',
       'northstar_ci_stale_grantee', 'northstar_ci_delegated_grantee'
     )
  );
PSQL
)
[[ "$fixture_conflicts" == '0' ]] \
  || fail 'the CI PostgreSQL service is not empty; refusing role/database collision'

# This fixture rewrites cluster-global owner/config/ACL state on the standard
# maintenance database. It is safe only on the disposable official-image
# service whose exact semantic default is restored during cleanup; absence of
# Northstar role names alone does not make an arbitrary shared cluster safe.
maintenance_database_is_disposable=$(control_psql --dbname=postgres \
  --tuples-only --no-align <<'PSQL'
SELECT (
  database_owner.rolname='northstar_ci_control'
  AND database.datallowconn
  AND database.datconnlimit=-1
  AND NOT database.datistemplate
  AND pg_catalog.count(*) FILTER (
        WHERE privilege.grantee=database.datdba
          AND privilege.grantor=database.datdba
          AND privilege.privilege_type IN ('CONNECT','CREATE','TEMPORARY')
          AND NOT privilege.is_grantable
      )=3
  AND pg_catalog.count(*) FILTER (
        WHERE privilege.grantee=0
          AND privilege.grantor=database.datdba
          AND privilege.privilege_type IN ('CONNECT','TEMPORARY')
          AND NOT privilege.is_grantable
      )=2
  AND pg_catalog.count(*)=5
)
  FROM pg_catalog.pg_database AS database
  JOIN pg_catalog.pg_roles AS database_owner ON database_owner.oid=database.datdba
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
   database.datacl,pg_catalog.acldefault('d',database.datdba)
 )) AS privilege
 WHERE database.datname='postgres'
 GROUP BY database.oid,database_owner.rolname;
PSQL
)
[[ "$maintenance_database_is_disposable" == 't' ]] \
  || fail 'the CI PostgreSQL maintenance database is not the disposable canonical service; refusing cluster-global mutation'

# Build a legacy Compose-like state: xmpp is both login superuser and database
# owner. Password values enter psql only through environment variables.
export NORTHSTAR_CI_LEGACY_PASSWORD="$legacy_password"
export NORTHSTAR_CI_DATABASE_MARKER="$marker"
database_is_managed=true
control_psql --dbname=postgres <<'PSQL'
\getenv legacy_password NORTHSTAR_CI_LEGACY_PASSWORD
\getenv database_marker NORTHSTAR_CI_DATABASE_MARKER
BEGIN;
SELECT pg_catalog.format(
  'CREATE ROLE xmpp LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %L',
  :'legacy_password'
) \gexec
COMMENT ON ROLE xmpp IS :'database_marker';
COMMIT;
CREATE DATABASE xmpp OWNER xmpp;
COMMENT ON DATABASE xmpp IS :'database_marker';
PSQL
unset NORTHSTAR_CI_LEGACY_PASSWORD NORTHSTAR_CI_DATABASE_MARKER

# Reconstruct a genuine stopped pre-capability-upgrade database.  The phase
# gate intentionally rejects an arbitrary populated schema without an sqlx
# ledger: that shape cannot be distinguished from a partial/tampered install.
# Checksums use sqlx's SHA-384 migration checksum so the real migration command
# can subsequently verify 0001..0113 and apply the remainder.
psql_as "$legacy_role" "$legacy_password" <<'PSQL'
CREATE TABLE public._sqlx_migrations (
  version BIGINT PRIMARY KEY,
  description TEXT NOT NULL,
  installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
  success BOOLEAN NOT NULL,
  checksum BYTEA NOT NULL,
  execution_time BIGINT NOT NULL
);
PSQL
for migration_path in "$project_dir"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name=${migration_path##*/}
  migration_version=${migration_name%%_*}
  (( 10#$migration_version <= 113 )) || continue
  migration_description=${migration_name#*_}
  migration_description=${migration_description%.sql}
  migration_description=${migration_description//_/ }
  migration_checksum=$(sha384sum "$migration_path")
  migration_checksum=${migration_checksum%% *}
  psql_as "$legacy_role" "$legacy_password" \
    --set=migration_path="$migration_path" \
    --set=migration_version="$((10#$migration_version))" \
    --set=migration_description="$migration_description" \
    --set=migration_checksum="$migration_checksum" <<'PSQL'
\i :migration_path
INSERT INTO public._sqlx_migrations(
  version,description,success,checksum,execution_time
) VALUES (
  :'migration_version'::pg_catalog.int8,:'migration_description',true,
  pg_catalog.decode(:'migration_checksum','hex'),0
);
PSQL
done

# Include additional owner-coupled legacy objects so reconciliation proves
# more than role creation. The SERIAL sequence also exercises
# table-before-sequence transfer.
psql_as "$legacy_role" "$legacy_password" <<'PSQL'
CREATE TABLE public.northstar_ci_legacy_probe (
  id BIGSERIAL PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE FUNCTION public.northstar_ci_legacy_probe_function()
RETURNS INTEGER LANGUAGE sql AS $$ SELECT 1 $$;
PSQL

readonly legacy_password_file="$runtime_dir/legacy-password"
readonly bootstrap_password_file="$runtime_dir/bootstrap-password"
readonly migrator_password_file="$runtime_dir/migrator-password"
readonly runtime_password_file="$runtime_dir/runtime-password"
readonly command_password_file="$runtime_dir/command-password"
readonly backup_password_file="$runtime_dir/backup-password"
readonly migrator_url_file="$runtime_dir/migrator-database-url"

write_secret "$legacy_password_file" "$legacy_password"
write_secret "$bootstrap_password_file" "$bootstrap_password"
write_secret "$migrator_password_file" "$migrator_password"
write_secret "$runtime_password_file" "$runtime_password"
write_secret "$command_password_file" "$command_password"
write_secret "$backup_password_file" "$backup_password"
write_secret "$migrator_url_file" \
  "postgres://northstar_migrator:${migrator_password}@127.0.0.1:${database_port}/xmpp"

# Exercise the explicit existing-volume upgrade using the old superuser, then
# reconnect through the new bootstrap boundary before the guarded legacy cutover.
bash scripts/reconcile-database-roles.sh --apply \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$legacy_role" \
  --connection-password-file "$legacy_password_file" \
  --bootstrap-password-file "$bootstrap_password_file" \
  --migrator-password-file "$migrator_password_file" \
  --runtime-password-file "$runtime_password_file" \
  --command-password-file "$command_password_file" \
  --backup-password-file "$backup_password_file"

bash scripts/reconcile-database-roles.sh --apply --demote-legacy-xmpp \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
  --connection-password-file "$bootstrap_password_file" \
  --bootstrap-password-file "$bootstrap_password_file" \
  --migrator-password-file "$migrator_password_file" \
  --runtime-password-file "$runtime_password_file" \
  --command-password-file "$command_password_file" \
  --backup-password-file "$backup_password_file"

# Auto/prepare must leave every workload at zero capability until the boundary
# migrations commit.  Catalog inspection is performed through the isolated
# control connection because those workloads intentionally cannot connect yet.
pre_boundary_workloads_are_unprivileged=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_roles role
    JOIN pg_catalog.pg_database database ON database.datname=current_database()
    JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
   WHERE role.rolname IN ('northstar_runtime','northstar_commands','northstar_backup')
     AND (pg_catalog.has_database_privilege(role.oid,database.oid,'CONNECT')
       OR pg_catalog.has_schema_privilege(role.oid,namespace.oid,'USAGE'))
) AND NOT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
    CROSS JOIN pg_catalog.pg_roles role
   WHERE namespace.nspname='public'
     AND role.rolname IN ('northstar_runtime','northstar_commands','northstar_backup')
     AND CASE
           WHEN relation.relkind='S' THEN
             pg_catalog.has_sequence_privilege(role.oid,relation.oid,'SELECT')
           ELSE
             pg_catalog.has_any_column_privilege(
               role.oid,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES'
             )
         END
) AND NOT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
    CROSS JOIN pg_catalog.pg_roles role
   WHERE namespace.nspname='public'
     AND role.rolname IN ('northstar_runtime','northstar_commands','northstar_backup')
     AND pg_catalog.has_function_privilege(role.oid,routine.oid,'EXECUTE')
);
PSQL
)
[[ "$pre_boundary_workloads_are_unprivileged" == t ]] \
  || fail 'legacy prepare phase exposed a workload capability before migrations 0114/0115'

# Exercise a genuinely empty bootstrap database, then poison its ledger with a
# one-sided and a post-boundary-without-boundary state. Both malformed shapes
# must fail before any grant can be installed.
# Mark cleanup ownership before issuing CREATE DATABASE.  PostgreSQL can commit
# the command even if the client loses the acknowledgement; DROP IF EXISTS is
# therefore the only crash-safe cleanup contract for this fixed fixture name.
phase_fixture_database_created=true
control_psql --dbname=postgres \
  --command="CREATE DATABASE northstar_ci_grant_phase_fixture OWNER northstar_migrator;"
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" \
  --command="ALTER SCHEMA public OWNER TO northstar_migrator;"
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" \
  --set=database_name="$phase_fixture_database" \
  --set=migrator_role="$migrator_role" --set=runtime_role="$runtime_role" \
  --set=command_role="$command_role" --set=backup_role="$backup_role" \
  --set=allow_bootstrap=false --set=grant_phase=bootstrap \
  --file="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
fresh_bootstrap_is_owner_only=$(control_psql --dbname="$phase_fixture_database" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles role
  JOIN pg_catalog.pg_database database ON database.datname=current_database()
  JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
  WHERE role.rolname IN ('northstar_runtime','northstar_commands','northstar_backup')
    AND (pg_catalog.has_database_privilege(role.oid,database.oid,'CONNECT')
      OR pg_catalog.has_schema_privilege(role.oid,namespace.oid,'USAGE'))
);
PSQL
)
[[ "$fresh_bootstrap_is_owner_only" == t ]] \
  || fail 'fresh bootstrap phase granted a workload capability'
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" <<'PSQL'
CREATE TABLE public._sqlx_migrations (
  version BIGINT PRIMARY KEY, description TEXT NOT NULL,
  installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL,
  checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL
);
INSERT INTO public._sqlx_migrations
VALUES (114,'partial boundary',now(),true,'\x00',0);
PSQL
set +e
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" \
  --set=database_name="$phase_fixture_database" \
  --set=migrator_role="$migrator_role" --set=runtime_role="$runtime_role" \
  --set=command_role="$command_role" --set=backup_role="$backup_role" \
  --set=allow_bootstrap=false --set=grant_phase=auto \
  --file="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql" \
  >"$runtime_dir/partial-boundary.log" 2>&1
partial_boundary_status=$?
set -e
(( partial_boundary_status != 0 )) \
  || fail 'one-sided migration 0114/0115 boundary was accepted'
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" \
  --command="UPDATE public._sqlx_migrations SET version=116, description='tampered post-boundary';"
set +e
PGPASSWORD="$migrator_password" psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
  --host "$database_host" --port "$database_port" --username "$migrator_role" \
  --dbname="$phase_fixture_database" \
  --set=database_name="$phase_fixture_database" \
  --set=migrator_role="$migrator_role" --set=runtime_role="$runtime_role" \
  --set=command_role="$command_role" --set=backup_role="$backup_role" \
  --set=allow_bootstrap=false --set=grant_phase=auto \
  --file="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql" \
  >"$runtime_dir/tampered-boundary.log" 2>&1
tampered_boundary_status=$?
set -e
(( tampered_boundary_status != 0 )) \
  || fail 'post-0115 ledger row without the capability boundary was accepted'
control_psql --dbname=postgres \
  --command="DROP DATABASE northstar_ci_grant_phase_fixture WITH (FORCE);"
phase_fixture_database_created=false

legacy_ownership_transferred=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT
  (
    SELECT pg_catalog.count(*) = 2
       AND pg_catalog.bool_and(owner.rolname = 'northstar_migrator')
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
     WHERE namespace.nspname = 'public'
       AND relation.relname IN (
         'northstar_ci_legacy_probe', 'northstar_ci_legacy_probe_id_seq'
       )
  )
  AND (
    SELECT owner.rolname = 'northstar_migrator'
      FROM pg_catalog.pg_proc AS routine
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
      JOIN pg_catalog.pg_roles AS owner ON owner.oid = routine.proowner
     WHERE namespace.nspname = 'public'
       AND routine.proname = 'northstar_ci_legacy_probe_function'
  );
PSQL
)
[[ "$legacy_ownership_transferred" == 't' ]] \
  || fail 'legacy relation, owned sequence, or routine ownership was not transferred'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP FUNCTION public.northstar_ci_legacy_probe_function();
DROP TABLE public.northstar_ci_legacy_probe;
PSQL

# The real Northstar migration command must apply the complete on-disk chain as
# northstar_migrator. It also runs the domain-scoped identity canonicalization.
NORTHSTAR_DISABLE_DOTENV=true \
XMPP_DOMAIN=ci.northstar.invalid \
MIGRATOR_DATABASE_URL_FILE="$migrator_url_file" \
  cargo run --quiet --locked --bin rust-xmpp-server -- migrate

control_psql --dbname=postgres <<'PSQL'
CREATE ROLE northstar_ci_stale_grantee NOLOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE northstar_ci_delegated_grantee NOLOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
PSQL

# Seed representative historical drift. Reconciliation must remove direct and
# default privileges rather than merely layering the current grants on top.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
GRANT CONNECT, TEMPORARY ON DATABASE xmpp
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT USAGE, CREATE ON SCHEMA public
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT EXECUTE ON FUNCTION public.northstar_user_clear_scram_sha1()
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT UPDATE ON TABLE public.deployment_session_leases
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT SELECT(token_hash,peer_ip) ON TABLE public.sm_resume_sessions
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON public._sqlx_migrations, public.jid_identity_migrations TO northstar_runtime;
GRANT TRUNCATE, REFERENCES, TRIGGER ON public.audit_log TO northstar_runtime;
GRANT INSERT(username), UPDATE(is_admin), REFERENCES(id)
  ON public.users TO northstar_runtime;
GRANT INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON public.admin_service_messages,
     public.federation_runtime_rules,
     public.admin_service_control
  TO northstar_runtime;
GRANT UPDATE(body) ON public.admin_service_messages TO northstar_runtime;
GRANT UPDATE(domain) ON public.federation_runtime_rules TO northstar_runtime;
GRANT UPDATE(execute_at) ON public.admin_service_control TO northstar_runtime;
GRANT SELECT(bearer_hash)
  ON public.admin_command_sessions TO northstar_runtime, northstar_commands;
GRANT UPDATE ON ALL SEQUENCES IN SCHEMA public TO northstar_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator IN SCHEMA public
  GRANT UPDATE ON SEQUENCES TO northstar_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator IN SCHEMA public
  GRANT UPDATE ON TABLES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator IN SCHEMA public
  GRANT UPDATE ON SEQUENCES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator IN SCHEMA public
  GRANT USAGE ON TYPES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT UPDATE ON TABLES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT UPDATE ON SEQUENCES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT EXECUTE ON FUNCTIONS TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT USAGE ON TYPES TO northstar_ci_stale_grantee WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT CREATE ON SCHEMAS TO northstar_ci_stale_grantee WITH GRANT OPTION;
CREATE DOMAIN public.northstar_ci_acl_domain AS pg_catalog.text;
CREATE TYPE public.northstar_ci_acl_composite AS (value pg_catalog.text);
GRANT USAGE ON DOMAIN public.northstar_ci_acl_domain
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
GRANT USAGE ON TYPE public.northstar_ci_acl_composite
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
-- CREATE OR REPLACE preserves ACLs. Simulate a historical owner REVOKE so the
-- reconciler must explicitly recreate the canonical owner EXECUTE row.
REVOKE ALL PRIVILEGES ON FUNCTION public.northstar_upload_queue_snapshot()
  FROM northstar_migrator CASCADE;
PSQL

# A dependent grant is the critical CASCADE regression: REVOKE ... RESTRICT
# would abort the whole transaction rather than converge the catalog. Cover
# both object ACL dependencies and PostgreSQL 16+ role-membership grant chains.
control_psql --dbname="$database_name" <<'PSQL'
GRANT northstar_runtime TO northstar_ci_stale_grantee WITH ADMIN OPTION;
SET ROLE northstar_ci_stale_grantee;
GRANT northstar_runtime TO northstar_ci_delegated_grantee;
RESET ROLE;
SET ROLE northstar_ci_stale_grantee;
GRANT CONNECT ON DATABASE xmpp TO northstar_ci_delegated_grantee;
GRANT USAGE ON SCHEMA public TO northstar_ci_delegated_grantee;
GRANT EXECUTE ON FUNCTION public.northstar_user_clear_scram_sha1()
  TO northstar_ci_delegated_grantee;
GRANT UPDATE ON TABLE public.deployment_session_leases
  TO northstar_ci_delegated_grantee;
GRANT SELECT(token_hash) ON TABLE public.sm_resume_sessions
  TO northstar_ci_delegated_grantee;
GRANT USAGE ON DOMAIN public.northstar_ci_acl_domain
  TO northstar_ci_delegated_grantee;
GRANT USAGE ON TYPE public.northstar_ci_acl_composite
  TO northstar_ci_delegated_grantee;
RESET ROLE;
PSQL

pre_reconcile_audit="$runtime_dir/pre-reconcile-audit.log"
set +e
bash scripts/reconcile-database-roles.sh --audit \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
  --connection-password-file "$bootstrap_password_file" \
  >"$pre_reconcile_audit" 2>&1
pre_reconcile_status=$?
set -e
if (( pre_reconcile_status != 4 )); then
  sed -E 's/(password=)[^[:space:]]+/\1[REDACTED]/gi' \
    "$pre_reconcile_audit" >&2
  fail 'role audit failed as infrastructure instead of reporting canonical drift'
fi
if ! grep -Fq 'canonical SECURITY DEFINER capability manifest drifted' \
  "$pre_reconcile_audit"; then
  sed -E 's/(password=)[^[:space:]]+/\1[REDACTED]/gi' \
    "$pre_reconcile_audit" >&2
  fail 'canonical verifier did not report the seeded stale routine grantee'
fi
if ! grep -Eq 'unexpected explicit (relation|column) ACL grantee' \
  "$pre_reconcile_audit"; then
  sed -E 's/(password=)[^[:space:]]+/\1[REDACTED]/gi' \
    "$pre_reconcile_audit" >&2
  fail 'canonical verifier did not report the seeded stale relation grantee'
fi

bash scripts/reconcile-database-roles.sh --apply \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
  --connection-password-file "$bootstrap_password_file" \
  --bootstrap-password-file "$bootstrap_password_file" \
  --migrator-password-file "$migrator_password_file" \
  --runtime-password-file "$runtime_password_file" \
  --command-password-file "$command_password_file" \
  --backup-password-file "$backup_password_file"

# The ordinary grants job remains independently idempotent after role-policy
# convergence, while only the role reconciler is allowed to repair membership.
MIGRATOR_DATABASE_URL_FILE="$migrator_url_file" \
  bash scripts/reconcile-database-grants.sh

protected_membership_removed=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted ON granted.oid=membership.roleid
    JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member
   WHERE granted.rolname IN (
     'northstar_bootstrap','northstar_migrator','northstar_runtime',
     'northstar_commands','northstar_backup'
   ) OR member.rolname IN (
     'northstar_bootstrap','northstar_migrator','northstar_runtime',
     'northstar_commands','northstar_backup'
   )
);
PSQL
)
[[ "$protected_membership_removed" == 't' ]] \
  || fail 'role reconciliation retained a protected role membership or delegated grant chain'

stale_definer_grant_removed=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT pg_catalog.has_function_privilege(
  'northstar_ci_stale_grantee',
  'public.northstar_user_clear_scram_sha1()','EXECUTE'
)
 AND NOT pg_catalog.has_function_privilege(
   'northstar_ci_delegated_grantee',
   'public.northstar_user_clear_scram_sha1()','EXECUTE'
 );
PSQL
)
[[ "$stale_definer_grant_removed" == 't' ]] \
  || fail 'grant reconciliation retained a stale SECURITY DEFINER grantee'
stale_relation_grants_removed=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT pg_catalog.has_table_privilege(
         'northstar_ci_stale_grantee','public.deployment_session_leases','UPDATE'
       )
   AND NOT pg_catalog.has_column_privilege(
         'northstar_ci_stale_grantee','public.sm_resume_sessions',
         'token_hash','SELECT'
       )
   AND NOT pg_catalog.has_column_privilege(
         'northstar_ci_stale_grantee','public.sm_resume_sessions',
         'peer_ip','SELECT'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_ci_delegated_grantee','public.deployment_session_leases','UPDATE'
       )
   AND NOT pg_catalog.has_column_privilege(
         'northstar_ci_delegated_grantee','public.sm_resume_sessions','token_hash','SELECT'
       )
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_acl_domain','USAGE'
       )
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_delegated_grantee','public.northstar_ci_acl_domain','USAGE'
       )
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_acl_composite','USAGE'
       )
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_delegated_grantee','public.northstar_ci_acl_composite','USAGE'
       );
PSQL
)
[[ "$stale_relation_grants_removed" == 't' ]] \
  || fail 'grant reconciliation retained a stale relation or sensitive-column grantee'
database_schema_defaults_converged=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles role
  JOIN pg_catalog.pg_database database ON database.datname=current_database()
  JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
  WHERE role.rolname IN ('northstar_ci_stale_grantee','northstar_ci_delegated_grantee')
    AND (pg_catalog.has_database_privilege(role.oid,database.oid,'CONNECT')
      OR pg_catalog.has_database_privilege(role.oid,database.oid,'CREATE')
      OR pg_catalog.has_database_privilege(role.oid,database.oid,'TEMPORARY')
      OR pg_catalog.has_schema_privilege(role.oid,namespace.oid,'USAGE')
      OR pg_catalog.has_schema_privilege(role.oid,namespace.oid,'CREATE'))
) AND NOT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_default_acl default_acl
    JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
    LEFT JOIN pg_catalog.pg_namespace namespace
      ON namespace.oid=default_acl.defaclnamespace
   WHERE (default_acl.defaclnamespace=0 OR namespace.nspname='public')
     AND (owner.rolname<>'northstar_migrator'
       OR default_acl.defaclobjtype NOT IN ('r','S','f','T','n')
       OR EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
          WHERE privilege.grantee<>default_acl.defaclrole
             OR privilege.grantor<>default_acl.defaclrole
             OR privilege.is_grantable
       ))
);
PSQL
)
[[ "$database_schema_defaults_converged" == t ]] \
  || fail 'database/schema/default ACL reconciliation retained a stale or delegated chain'

canonical_acl_rebuilt=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
WITH snapshot_acl AS (
  SELECT routine.proowner,privilege.*
    FROM pg_catalog.pg_proc routine
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
     routine.proacl,pg_catalog.acldefault('f',routine.proowner)
   )) privilege
   WHERE routine.oid='public.northstar_upload_queue_snapshot()'::pg_catalog.regprocedure
), domain_acl AS (
  SELECT data_type.typowner,privilege.*
    FROM pg_catalog.pg_type data_type
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
     data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
   )) privilege
   WHERE data_type.oid='public.northstar_ci_acl_domain'::pg_catalog.regtype
), composite_acl AS (
  SELECT data_type.typowner,privilege.*
    FROM pg_catalog.pg_type data_type
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
     data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
   )) privilege
   WHERE data_type.oid='public.northstar_ci_acl_composite'::pg_catalog.regtype
)
SELECT (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(
                 privilege_type='EXECUTE' AND NOT is_grantable
                 AND grantor=proowner
                 AND grantee IN (
                   proowner,
                   (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime')
                 )
               )
               AND pg_catalog.bool_or(grantee=proowner)
               AND pg_catalog.bool_or(grantee=(
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
               ))
          FROM snapshot_acl)
   AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(
                 privilege_type='USAGE' AND NOT is_grantable
                 AND grantor=typowner
                 AND grantee IN (
                   typowner,
                   (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'),
                   (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup')
                 )
               )
               AND pg_catalog.bool_or(grantee=typowner)
               AND pg_catalog.bool_or(grantee=(
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
               ))
               AND pg_catalog.bool_or(grantee=(
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup'
               ))
          FROM domain_acl)
   AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(
                 privilege_type='USAGE' AND NOT is_grantable
                 AND grantor=typowner
                 AND grantee IN (
                   typowner,
                   (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'),
                   (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup')
                 )
               )
               AND pg_catalog.bool_or(grantee=typowner)
               AND pg_catalog.bool_or(grantee=(
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
               ))
               AND pg_catalog.bool_or(grantee=(
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup'
               ))
          FROM composite_acl);
PSQL
)
[[ "$canonical_acl_rebuilt" == 't' ]] \
  || fail 'grant reconciliation did not rebuild canonical owner/runtime/type ACLs'

# Objects created after reconciliation remain owner-only.  Migrations execute
# while workloads are stopped; a subsequent exact reconciliation grants each
# current object explicitly.  No global/schema default may pre-authorize a
# future object or preserve a retired/delegated chain.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
CREATE TABLE public.northstar_ci_default_table(id pg_catalog.int8 GENERATED BY DEFAULT AS IDENTITY);
CREATE FUNCTION public.northstar_ci_default_function()
RETURNS pg_catalog.int4 LANGUAGE sql AS $$ SELECT 1 $$;
CREATE DOMAIN public.northstar_ci_default_domain AS pg_catalog.text;
CREATE TYPE public.northstar_ci_default_composite AS (value pg_catalog.text);
CREATE SCHEMA northstar_ci_default_schema;
PSQL
default_acl_converged=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT pg_catalog.has_table_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_default_table','UPDATE')
   AND NOT pg_catalog.has_sequence_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_default_table_id_seq','UPDATE')
   AND NOT pg_catalog.has_function_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_default_function()','EXECUTE')
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_default_domain','USAGE')
   AND NOT pg_catalog.has_type_privilege(
         'northstar_ci_stale_grantee','public.northstar_ci_default_composite','USAGE')
   AND NOT pg_catalog.has_function_privilege(
         'northstar_runtime','public.northstar_ci_default_function()','EXECUTE')
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_proc routine
     CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
     )) privilege
     WHERE routine.oid='public.northstar_ci_default_function()'::pg_catalog.regprocedure
       AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
   )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime','public.northstar_ci_default_table','SELECT')
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime','public.northstar_ci_default_table','INSERT')
   AND NOT pg_catalog.has_table_privilege(
         'northstar_backup','public.northstar_ci_default_table','SELECT')
   AND NOT pg_catalog.has_sequence_privilege(
         'northstar_runtime','public.northstar_ci_default_table_id_seq','USAGE')
   AND NOT pg_catalog.has_sequence_privilege(
         'northstar_backup','public.northstar_ci_default_table_id_seq','SELECT')
   AND NOT pg_catalog.has_type_privilege(
         'northstar_runtime','public.northstar_ci_default_domain','USAGE')
   AND NOT pg_catalog.has_type_privilege(
         'northstar_backup','public.northstar_ci_default_domain','USAGE')
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_type data_type
     CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
       data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
     )) privilege
     WHERE data_type.oid='public.northstar_ci_default_domain'::pg_catalog.regtype
       AND privilege.grantee=0 AND privilege.privilege_type='USAGE'
   )
   AND NOT pg_catalog.has_type_privilege(
         'northstar_runtime','public.northstar_ci_default_composite','USAGE')
   AND NOT pg_catalog.has_type_privilege(
         'northstar_backup','public.northstar_ci_default_composite','USAGE')
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_type data_type
     CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
       data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
     )) privilege
      WHERE data_type.oid='public.northstar_ci_default_composite'::pg_catalog.regtype
        AND privilege.grantee=0 AND privilege.privilege_type='USAGE'
   )
   AND NOT pg_catalog.has_schema_privilege(
         'northstar_ci_stale_grantee','northstar_ci_default_schema','USAGE')
   AND NOT pg_catalog.has_schema_privilege(
         'northstar_ci_stale_grantee','northstar_ci_default_schema','CREATE');
PSQL
)
[[ "$default_acl_converged" == 't' ]] \
  || fail 'future objects inherited a workload, PUBLIC, stale, or delegated default ACL'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP FUNCTION public.northstar_ci_default_function();
DROP TABLE public.northstar_ci_default_table;
DROP DOMAIN public.northstar_ci_default_domain;
DROP TYPE public.northstar_ci_default_composite;
DROP SCHEMA northstar_ci_default_schema;
DROP DOMAIN public.northstar_ci_acl_domain;
DROP TYPE public.northstar_ci_acl_composite;
PSQL

# PostgreSQL omits pg_default_acl rows whose ACL is exactly the built-in
# default. For routines and types that means PUBLIC regains EXECUTE/USAGE. An
# audit which inspects only rows that happen to exist therefore fails open.
# Deliberately restore both built-ins, prove the protective rows disappear,
# require the audit to reject the catalog, then reconcile them back.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE northstar_migrator
  GRANT USAGE ON TYPES TO PUBLIC;
PSQL
built_in_override_rows_disappeared=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT pg_catalog.count(*)=0
  FROM pg_catalog.pg_default_acl default_acl
  JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
 WHERE owner.rolname='northstar_migrator'
   AND default_acl.defaclnamespace=0
   AND default_acl.defaclobjtype IN ('f','T');
PSQL
)
[[ "$built_in_override_rows_disappeared" == t ]] \
  || fail 'fixture could not restore PostgreSQL built-in routine/type defaults'
missing_default_audit="$runtime_dir/missing-default-overrides-audit.log"
set +e
bash scripts/reconcile-database-roles.sh --audit \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
  --connection-password-file "$bootstrap_password_file" \
  >"$missing_default_audit" 2>&1
missing_default_audit_status=$?
set -e
(( missing_default_audit_status != 0 )) \
  || fail 'audit accepted disappeared owner-only routine/type default ACL overrides'
grep -Fq 'missing owner-only global default ACL override' "$missing_default_audit" \
  || fail 'audit did not identify disappeared built-in-default override rows'
MIGRATOR_DATABASE_URL_FILE="$migrator_url_file" \
  bash scripts/reconcile-database-grants.sh
safe_default_overrides_restored=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(NOT EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
          WHERE privilege.grantee<>default_acl.defaclrole
             OR privilege.grantor<>default_acl.defaclrole
             OR privilege.is_grantable
       ))
  FROM pg_catalog.pg_default_acl default_acl
  JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
 WHERE owner.rolname='northstar_migrator'
   AND default_acl.defaclnamespace=0
   AND default_acl.defaclobjtype IN ('f','T');
PSQL
)
[[ "$safe_default_overrides_restored" == t ]] \
  || fail 'reconciliation did not restore owner-only routine/type default ACL overrides'

# The repository ledger is a release trust root, not a best-effort migration
# counter. Exercise each fail-closed class independently and restore the exact
# version-1 row between probes so a later failure cannot mask another class.
ledger_v1_checksum=$(sha384sum "$project_dir/migrations/0001_initial.sql")
ledger_v1_checksum=${ledger_v1_checksum%% *}
expect_ledger_audit_failure() {
  local label="$1" log="$runtime_dir/ledger-$1-audit.log" status
  set +e
  bash scripts/reconcile-database-roles.sh --audit \
    --allow-external-superuser "$control_role" \
    --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
    --connection-password-file "$bootstrap_password_file" >"$log" 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail "$label migration-ledger corruption was accepted"
  grep -Fq 'repository migration ledger differs by version, description, success, or SHA-384 checksum' \
    "$log" || fail "$label migration-ledger corruption was not identified by the audit"
}

psql_as "$migrator_role" "$migrator_password" \
  --command="DELETE FROM public._sqlx_migrations WHERE version=1"
expect_ledger_audit_failure missing
psql_as "$migrator_role" "$migrator_password" \
  --set=ledger_checksum="$ledger_v1_checksum" <<'PSQL'
INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time)
VALUES (1,'initial',true,pg_catalog.decode(:'ledger_checksum','hex'),0);
PSQL

psql_as "$migrator_role" "$migrator_password" <<'PSQL'
INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time)
VALUES (9223372036854775807,'unknown migration',true,pg_catalog.decode(repeat('44',48),'hex'),0);
PSQL
expect_ledger_audit_failure unknown
psql_as "$migrator_role" "$migrator_password" \
  --command="DELETE FROM public._sqlx_migrations WHERE version=9223372036854775807"

psql_as "$migrator_role" "$migrator_password" \
  --command="UPDATE public._sqlx_migrations SET success=false WHERE version=1"
expect_ledger_audit_failure failed
psql_as "$migrator_role" "$migrator_password" \
  --command="UPDATE public._sqlx_migrations SET success=true WHERE version=1"

psql_as "$migrator_role" "$migrator_password" <<'PSQL'
UPDATE public._sqlx_migrations
   SET description='tampered initial',checksum=pg_catalog.decode(repeat('55',48),'hex')
 WHERE version=1;
PSQL
expect_ledger_audit_failure tampered
psql_as "$migrator_role" "$migrator_password" \
  --set=ledger_checksum="$ledger_v1_checksum" <<'PSQL'
UPDATE public._sqlx_migrations
   SET description='initial',checksum=pg_catalog.decode(:'ledger_checksum','hex')
 WHERE version=1;
PSQL

session_catalog_healthy=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT public.northstar_session_capability_catalog_healthy('public')")
[[ "$session_catalog_healthy" == 't' ]] \
  || fail 'session authority catalog reports non-canonical relation/column ACLs'

# Startup health must inspect direct ACL rows, not only the current workload's
# effective privilege. An alien role with EXECUTE (especially WITH GRANT
# OPTION) invalidates the capability boundary until the grant is removed.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
GRANT EXECUTE ON FUNCTION public.northstar_sm_privacy_state(uuid)
  TO northstar_ci_stale_grantee WITH GRANT OPTION;
PSQL
alien_execute_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$alien_execute_rejected" == 't' ]] \
  || fail 'alien EXECUTE grant did not make startup capability health fail closed'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
REVOKE ALL PRIVILEGES ON FUNCTION public.northstar_sm_privacy_state(uuid)
  FROM northstar_ci_stale_grantee;
PSQL

# Trigger health is an exact manifest: preserving the name while substituting
# another function must be rejected, just like a disabled/conditional/extra
# trigger. Restore the canonical trigger before continuing the fixture.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
CREATE FUNCTION public.northstar_ci_substitute_session_capacity()
RETURNS trigger LANGUAGE plpgsql
SET search_path TO pg_catalog, public, pg_temp AS $$
BEGIN
  RETURN NEW;
END
$$;
DROP TRIGGER deployment_session_leases_capacity_insert
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON public.deployment_session_leases FOR EACH ROW
EXECUTE FUNCTION public.northstar_ci_substitute_session_capacity();
PSQL
substituted_trigger_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$substituted_trigger_rejected" == 't' ]] \
  || fail 'same-name session trigger function substitution was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP TRIGGER deployment_session_leases_capacity_insert
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON public.deployment_session_leases FOR EACH ROW
EXECUTE FUNCTION public.northstar_session_capacity_insert();
DROP FUNCTION public.northstar_ci_substitute_session_capacity();
PSQL
session_catalog_restored=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT public.northstar_session_capability_catalog_healthy('public')")
[[ "$session_catalog_restored" == 't' ]] \
  || fail 'canonical session trigger manifest was not restored'

# A same-name/same-function trigger is still not canonical when UPDATE OF,
# arguments, constraint metadata or deferral semantics drift.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP TRIGGER deployment_session_leases_capacity_update
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_update
AFTER UPDATE OF connection_id ON public.deployment_session_leases
FOR EACH ROW EXECUTE FUNCTION public.northstar_session_capacity_update();
PSQL
update_column_manifest_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$update_column_manifest_rejected" == 't' ]] \
  || fail 'same-name trigger with a reduced UPDATE OF column set was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP TRIGGER deployment_session_leases_capacity_update
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_update
AFTER UPDATE OF lease_id,connection_id,user_id,full_jid
ON public.deployment_session_leases
FOR EACH ROW EXECUTE FUNCTION public.northstar_session_capacity_update();
DROP TRIGGER deployment_session_leases_capacity_insert
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON public.deployment_session_leases FOR EACH ROW
EXECUTE FUNCTION public.northstar_session_capacity_insert('unexpected');
PSQL
trigger_argument_manifest_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$trigger_argument_manifest_rejected" == 't' ]] \
  || fail 'same-name trigger with TG_ARGV data was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP TRIGGER deployment_session_leases_capacity_insert
  ON public.deployment_session_leases;
CREATE CONSTRAINT TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON public.deployment_session_leases
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION public.northstar_session_capacity_insert();
PSQL
constraint_trigger_manifest_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$constraint_trigger_manifest_rejected" == 't' ]] \
  || fail 'constraint/deferrable trigger substitution was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP TRIGGER deployment_session_leases_capacity_insert
  ON public.deployment_session_leases;
CREATE TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON public.deployment_session_leases FOR EACH ROW
EXECUTE FUNCTION public.northstar_session_capacity_insert();
PSQL
exact_trigger_catalog_restored=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT public.northstar_session_capability_catalog_healthy('public')")
[[ "$exact_trigger_catalog_restored" == 't' ]] \
  || fail 'exact trigger catalog was not restored after malicious fixtures'

# Trigger-function authority is part of the trigger manifest too.  These
# capacity guards deliberately remain SECURITY INVOKER: they run inside an
# owner-held capability statement and must not become independently elevated.
# Their fixed path is equally important because the body calls schema-local
# capacity helpers by unqualified name.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
ALTER FUNCTION public.northstar_session_capacity_insert() SECURITY DEFINER;
PSQL
trigger_function_mode_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$trigger_function_mode_rejected" == 't' ]] \
  || fail 'SECURITY DEFINER promotion of an invoker capacity trigger was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
ALTER FUNCTION public.northstar_session_capacity_insert() SECURITY INVOKER;
ALTER FUNCTION public.northstar_session_capacity_insert() RESET search_path;
PSQL
trigger_function_path_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT NOT public.northstar_session_capability_catalog_healthy('public')")
[[ "$trigger_function_path_rejected" == 't' ]] \
  || fail 'unfixed capacity trigger search_path was not rejected'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
ALTER FUNCTION public.northstar_session_capacity_insert()
  SET search_path TO pg_catalog, public, pg_temp;
PSQL
exact_trigger_function_catalog_restored=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command \
  "SELECT public.northstar_session_capability_catalog_healthy('public')")
[[ "$exact_trigger_function_catalog_restored" == 't' ]] \
  || fail 'exact trigger-function authority catalog was not restored'

# Execute the real migration chain in a schema containing both whitespace and
# an embedded quote while the fully-populated public installation remains as a
# decoy. Formatting-only tests cannot detect an accidental public. reference.
quoted_migration_driver="$runtime_dir/quoted-schema-migration.sql"
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
CREATE SCHEMA "northstar ci ""quoted" AUTHORIZATION northstar_migrator;
PSQL
for migration_path in "$project_dir"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
  {
    printf '%s\n' '\set ON_ERROR_STOP on'
    printf '%s\n' 'SET search_path TO "northstar ci ""quoted";'
    printf '%s\n' '\i :migration_path'
  } >"$quoted_migration_driver"
  if [[ "$(sed -n '1p' "$migration_path")" == '-- no-transaction' ]]; then
    psql_as "$migrator_role" "$migrator_password" \
      --set=migration_path="$migration_path" --file "$quoted_migration_driver"
  else
    # Match SQLx's per-migration transaction boundary.  In particular, the
    # 0126/0128 accounting cut-overs require their table locks and authority
    # replacement to commit atomically, while explicitly non-transactional
    # concurrent-index migrations above remain outside a transaction block.
    psql_as "$migrator_role" "$migrator_password" --single-transaction \
      --set=migration_path="$migration_path" --file "$quoted_migration_driver"
  fi
done
quoted_schema_chain_ok=$(psql_as "$migrator_role" "$migrator_password" \
  --tuples-only --no-align <<'PSQL'
WITH probes AS (
  SELECT pg_catalog.to_regclass('"northstar ci ""quoted".users') IS NOT NULL
           AND pg_catalog.to_regclass('"northstar ci ""quoted".users')
                 IS DISTINCT FROM pg_catalog.to_regclass('public.users')
           AS users_isolated,
    (
     SELECT routine.proconfig=ARRAY[
              'search_path=pg_catalog, "northstar ci ""quoted", pg_temp'
            ]::pg_catalog.text[]
       FROM pg_catalog.pg_proc routine
      WHERE routine.oid=pg_catalog.to_regprocedure(
        '"northstar ci ""quoted".northstar_upload_queue_snapshot()'
      )
    ) AS upload_path_isolated,
    (
     SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
              trigger.tgenabled='O' AND NOT trigger.tgisinternal
              AND function_namespace.nspname='northstar ci "quoted'
              AND routine.prokind='f' AND NOT routine.prosecdef
              AND routine.proconfig=ARRAY[
                    'search_path=pg_catalog, "northstar ci ""quoted", pg_temp'
                  ]::pg_catalog.text[]
            )
       FROM pg_catalog.pg_trigger trigger
       JOIN pg_catalog.pg_class relation ON relation.oid=trigger.tgrelid
       JOIN pg_catalog.pg_namespace relation_namespace
         ON relation_namespace.oid=relation.relnamespace
       JOIN pg_catalog.pg_proc routine ON routine.oid=trigger.tgfoid
       JOIN pg_catalog.pg_namespace function_namespace
         ON function_namespace.oid=routine.pronamespace
      WHERE relation_namespace.nspname='northstar ci "quoted'
        AND trigger.tgname IN (
          'deployment_session_leases_capacity_insert',
          'deployment_session_leases_capacity_delete',
          'deployment_session_leases_capacity_update',
          'sm_resume_sessions_deployment_capacity_insert',
          'sm_resume_sessions_deployment_capacity_delete'
        )
    ) AS trigger_catalog_isolated
)
SELECT CASE
         WHEN users_isolated AND upload_path_isolated
              AND trigger_catalog_isolated THEN 't'
         ELSE pg_catalog.format(
           'f users=%s upload_path=%s triggers=%s',
           users_isolated,upload_path_isolated,
           trigger_catalog_isolated
         )
       END
  FROM probes;
PSQL
)
if [[ "$quoted_schema_chain_ok" != 't' ]]; then
  printf 'quoted-schema migration diagnostics: %s\n' "$quoted_schema_chain_ok" >&2
  fail 'real quoted-schema migration chain escaped into the populated public decoy'
fi
# The catalog health capability deliberately treats an owner session as the
# single-owner development profile.  Query the production-shaped public decoy
# through the runtime identity, not the migrator used to inspect the private
# quoted schema, so its exact runtime grants are evaluated in the right mode.
public_decoy_healthy=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align \
  --command="SELECT public.northstar_session_capability_catalog_healthy('public')")
[[ "$public_decoy_healthy" == 't' ]] \
  || fail 'quoted-schema migration changed the production public authority catalog'
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
DROP SCHEMA "northstar ci ""quoted" CASCADE;
PSQL

bash scripts/reconcile-database-roles.sh --audit \
  --allow-external-superuser "$control_role" \
  --host "$database_host" --port "$database_port" --connect-as "$bootstrap_role" \
  --connection-password-file "$bootstrap_password_file"

# Compare the successful sqlx ledger to every checked-in migration rather than
# assuming contiguous numbering (version 0021 is intentionally absent).
expected_versions=''
for migration_path in migrations/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name=${migration_path##*/}
  migration_version=${migration_name%%_*}
  expected_versions+="$((10#$migration_version))"$'\n'
done
expected_versions=${expected_versions%$'\n'}
actual_versions=$(psql_as "$migrator_role" "$migrator_password" \
  --tuples-only --no-align --command \
  'SELECT version FROM public._sqlx_migrations WHERE success ORDER BY version')
[[ "$actual_versions" == "$expected_versions" ]] \
  || fail 'the successful sqlx ledger does not exactly match migrations on disk'
expected_latest="${expected_versions##*$'\n'}"
[[ "${actual_versions%%$'\n'*}" == '1' && "${actual_versions##*$'\n'}" == "$expected_latest" ]] \
  || fail "the real migration chain did not span versions 0001 through $(printf '%04d' "$expected_latest")"

# Cluster attributes, ownership, and role-membership invariants are checked by
# an independent control connection rather than by the roles under test.
role_boundary_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
WITH workload AS (
  SELECT *
    FROM pg_catalog.pg_roles
   WHERE rolname IN ('northstar_migrator', 'northstar_runtime', 'northstar_commands', 'northstar_backup')
), protected_role AS (
  SELECT oid,rolname FROM pg_catalog.pg_roles
   WHERE rolname IN (
     'northstar_bootstrap','northstar_migrator','northstar_runtime',
     'northstar_commands','northstar_backup'
   )
), forbidden_membership AS (
  SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
   WHERE granted.oid IN (SELECT oid FROM protected_role)
      OR member.oid IN (SELECT oid FROM protected_role)
)
SELECT
  (SELECT pg_catalog.count(*) = 4 FROM workload)
  AND (SELECT pg_catalog.count(*) = 5 FROM protected_role)
  AND NOT EXISTS (
    SELECT 1 FROM workload
     WHERE NOT rolcanlogin OR rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole
        OR rolreplication OR rolbypassrls
        OR rolvaliduntil IS DISTINCT FROM 'infinity'::pg_catalog.timestamptz
        OR rolconfig IS NOT NULL
  )
  AND NOT EXISTS (SELECT 1 FROM forbidden_membership)
  AND (SELECT rolconnlimit = 4 FROM workload WHERE rolname = 'northstar_migrator')
  AND (SELECT rolconnlimit = 64 FROM workload WHERE rolname = 'northstar_runtime')
  AND (SELECT rolconnlimit = 8 FROM workload WHERE rolname = 'northstar_commands')
  AND (SELECT rolconnlimit = 2 FROM workload WHERE rolname = 'northstar_backup')
  AND (
    SELECT pg_catalog.pg_get_userbyid(datdba) = 'northstar_migrator'
      FROM pg_catalog.pg_database WHERE datname = current_database()
  )
  AND (
    SELECT pg_catalog.pg_get_userbyid(nspowner) = 'northstar_migrator'
      FROM pg_catalog.pg_namespace WHERE nspname = 'public'
  )
  AND NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'i', 'I')
       AND pg_catalog.pg_get_userbyid(relation.relowner) <> 'northstar_migrator'
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_class'::pg_catalog.regclass
            AND dependency.objid=relation.oid AND dependency.deptype='e'
       )
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
     WHERE namespace.nspname='public'
       AND pg_catalog.pg_get_userbyid(routine.proowner)<>'northstar_migrator'
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_proc'::pg_catalog.regclass
            AND dependency.objid=routine.oid AND dependency.deptype='e'
       )
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_type data_type
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=data_type.typnamespace
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
       AND pg_catalog.pg_get_userbyid(data_type.typowner)<>'northstar_migrator'
       AND NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
            AND dependency.objid=data_type.oid
            AND (dependency.deptype='e'
              OR (dependency.deptype='i' AND data_type.typtype<>'c'))
       )
  )
  AND EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
     WHERE rolname = 'xmpp' AND NOT rolcanlogin AND NOT rolsuper
  );
PSQL
)
[[ "$role_boundary_ok" == 't' ]] || fail 'role attributes or ownership boundary drifted'

# Load the independent, version-controlled capability manifest.  The database
# catalog and all three workload grant sets are compared as sets; no numeric
# count is allowed to become a second, stale source of truth.
security_definer_boundary_ok=$(control_psql --dbname="$database_name" \
  --quiet --tuples-only --no-align <<'PSQL'
\i deploy/postgres-init/lib/northstar-capability-manifest.sql
WITH expected(signature) AS (
  SELECT signature FROM pg_temp.northstar_capability_manifest
), resolved AS (
  SELECT signature,
         pg_catalog.to_regprocedure('public.' || signature) AS oid
    FROM expected
), all_routines AS (
  SELECT routine.*
    FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
   WHERE namespace.nspname = 'public'
), actual AS (
  SELECT * FROM all_routines WHERE prosecdef
), public_execute AS (
  SELECT DISTINCT routine.oid
    FROM all_routines AS routine
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        routine.proacl,
        pg_catalog.acldefault('f', routine.proowner)
      )
    ) AS privilege
   WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
)
SELECT (SELECT pg_catalog.count(oid) FROM resolved) =
         (SELECT pg_catalog.count(*) FROM expected)
   AND (SELECT pg_catalog.count(*) FROM actual) =
         (SELECT pg_catalog.count(*) FROM expected)
   AND NOT EXISTS (
     SELECT 1 FROM resolved
      WHERE oid IS NULL OR NOT EXISTS (SELECT 1 FROM actual WHERE actual.oid = resolved.oid)
   )
   AND NOT EXISTS (
     SELECT 1 FROM actual
      WHERE pg_catalog.pg_get_userbyid(proowner) <> 'northstar_migrator'
         OR NOT (
           proconfig = ARRAY['search_path=pg_catalog, public, pg_temp']
         )
   )
   AND NOT EXISTS (
     SELECT 1 FROM all_routines
      WHERE pg_catalog.has_function_privilege('northstar_backup', oid, 'EXECUTE')
   )
   AND NOT EXISTS (
     SELECT 1 FROM all_routines AS routine
      WHERE pg_catalog.has_function_privilege(
              'northstar_commands',routine.oid,'EXECUTE'
            )
        AND NOT EXISTS (
          SELECT 1
            FROM pg_temp.northstar_capability_manifest AS expected_capability
           WHERE expected_capability.workload='command'
             AND pg_catalog.to_regprocedure(
                   'public.' || expected_capability.signature
                 )=routine.oid
        )
   )
   AND NOT EXISTS (
     SELECT 1
       FROM pg_temp.northstar_capability_manifest AS expected_capability
       JOIN resolved ON resolved.signature=expected_capability.signature
      WHERE pg_catalog.has_function_privilege(
              'northstar_runtime',resolved.oid,'EXECUTE'
            ) IS DISTINCT FROM (expected_capability.workload='runtime')
         OR pg_catalog.has_function_privilege(
              'northstar_commands',resolved.oid,'EXECUTE'
            ) IS DISTINCT FROM (expected_capability.workload='command')
         OR pg_catalog.has_function_privilege(
              'northstar_backup',resolved.oid,'EXECUTE'
            )
   )
   AND NOT EXISTS (
     SELECT 1
       FROM pg_temp.northstar_capability_manifest AS expected_capability
       JOIN resolved ON resolved.signature=expected_capability.signature
       JOIN actual AS routine ON routine.oid=resolved.oid
      WHERE (SELECT pg_catalog.count(*)
               FROM pg_catalog.aclexplode(COALESCE(
                 routine.proacl,pg_catalog.acldefault('f',routine.proowner)
               )) privilege)
              <>CASE WHEN expected_capability.workload='private' THEN 1 ELSE 2 END
         OR EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.privilege_type<>'EXECUTE'
               OR privilege.is_grantable
         )
         OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.grantee=routine.proowner
              AND privilege.privilege_type='EXECUTE'
              AND NOT privilege.is_grantable
         )
   )
   AND NOT EXISTS (
     SELECT 1
       FROM actual AS routine
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
      ) AS privilege
      LEFT JOIN pg_temp.northstar_capability_manifest AS expected_capability
        ON pg_catalog.to_regprocedure(
             'public.' || expected_capability.signature
           )=routine.oid
      WHERE privilege.grantee<>routine.proowner
        AND NOT COALESCE((
          (expected_capability.workload='runtime' AND NOT privilege.is_grantable
           AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles
             WHERE rolname='northstar_runtime'))
          OR
          (expected_capability.workload='command' AND NOT privilege.is_grantable
            AND privilege.grantee=(SELECT oid FROM pg_catalog.pg_roles
              WHERE rolname='northstar_commands'))
        ),FALSE)
   )
   AND NOT EXISTS (SELECT 1 FROM public_execute);
PSQL
)
if [[ "$security_definer_boundary_ok" != 't' ]]; then
  control_psql --dbname="$database_name" --quiet --tuples-only --no-align <<'PSQL' >&2
\i deploy/postgres-init/lib/northstar-capability-manifest.sql
WITH expected AS (
  SELECT signature,workload,
         pg_catalog.to_regprocedure('public.' || signature) AS oid
    FROM pg_temp.northstar_capability_manifest
), all_routines AS (
  SELECT routine.*
    FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
   WHERE namespace.nspname='public'
), findings AS (
  SELECT 'missing/unsafe definer: ' || expected.signature AS finding
    FROM expected LEFT JOIN all_routines routine ON routine.oid=expected.oid
   WHERE routine.oid IS NULL OR NOT routine.prosecdef
      OR pg_catalog.pg_get_userbyid(routine.proowner)<>'northstar_migrator'
      OR routine.proconfig IS DISTINCT FROM
           ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
  UNION ALL
  SELECT 'unexpected definer: ' || routine.oid::pg_catalog.regprocedure::pg_catalog.text
    FROM all_routines routine
   WHERE routine.prosecdef
     AND NOT EXISTS (SELECT 1 FROM expected WHERE expected.oid=routine.oid)
  UNION ALL
  SELECT 'unexpected PUBLIC routine execute: ' ||
         routine.oid::pg_catalog.regprocedure::pg_catalog.text
    FROM all_routines routine
   WHERE EXISTS (
     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
     )) privilege
      WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
   )
  UNION ALL
  SELECT 'definer ACL cardinality mismatch: ' || expected.signature
    FROM expected JOIN all_routines routine ON routine.oid=expected.oid
   WHERE (
     SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(COALESCE(
       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
     ))
   )<>CASE WHEN expected.workload='private' THEN 1 ELSE 2 END
  UNION ALL
  SELECT 'definer ACL contains non-EXECUTE or grant option: ' || expected.signature
    FROM expected JOIN all_routines routine ON routine.oid=expected.oid
   WHERE EXISTS (
     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
     )) privilege
      WHERE privilege.privilege_type<>'EXECUTE' OR privilege.is_grantable
   )
  UNION ALL
  SELECT 'definer ACL lacks owner EXECUTE: ' || expected.signature
    FROM expected JOIN all_routines routine ON routine.oid=expected.oid
   WHERE NOT EXISTS (
     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
     )) privilege
      WHERE privilege.grantee=routine.proowner
        AND privilege.privilege_type='EXECUTE'
        AND NOT privilege.is_grantable
   )
  UNION ALL
  SELECT 'definer execution grant mismatch: ' || expected.signature
    FROM expected JOIN all_routines routine ON routine.oid=expected.oid
   WHERE pg_catalog.has_function_privilege(
           'northstar_runtime',routine.oid,'EXECUTE'
         ) IS DISTINCT FROM (expected.workload='runtime')
      OR pg_catalog.has_function_privilege(
           'northstar_commands',routine.oid,'EXECUTE'
         ) IS DISTINCT FROM (expected.workload='command')
      OR pg_catalog.has_function_privilege('northstar_backup',routine.oid,'EXECUTE')
)
SELECT finding FROM findings ORDER BY finding;
PSQL
  fail 'SECURITY DEFINER schema, owner, or execution allowlist drifted'
fi

handoff_history_acl_ok=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
SELECT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'SELECT'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'INSERT'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'UPDATE'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'DELETE'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'TRUNCATE'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'REFERENCES'
       )
   AND NOT pg_catalog.has_table_privilege(
         'northstar_runtime', 'public.cluster_muc_delivery_handoffs', 'TRIGGER'
       );
PSQL
)
[[ "$handoff_history_acl_ok" == 't' ]] \
  || fail 'cluster MUC handoff history is not runtime read-only'

users_acl_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
SELECT pg_catalog.has_table_privilege('northstar_runtime','public.users','SELECT')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','INSERT')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','UPDATE')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','DELETE')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','TRUNCATE')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','REFERENCES')
   AND NOT pg_catalog.has_table_privilege('northstar_runtime','public.users','TRIGGER')
   AND NOT pg_catalog.has_any_column_privilege('northstar_runtime','public.users','INSERT')
   AND NOT pg_catalog.has_any_column_privilege('northstar_runtime','public.users','UPDATE')
   AND NOT pg_catalog.has_any_column_privilege('northstar_runtime','public.users','REFERENCES');
PSQL
)
[[ "$users_acl_ok" == 't' ]] || fail 'users table is not runtime read-only'

upload_authority_acl_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
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
    ) relation
   WHERE relation.oid IS NULL
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'SELECT')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'SELECT')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'SELECT')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_commands',relation.oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_commands',relation.oid,'SELECT')
      OR pg_catalog.has_any_column_privilege('northstar_commands',relation.oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_commands',relation.oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_commands',relation.oid,'REFERENCES')
);
PSQL
)
[[ "$upload_authority_acl_ok" == 't' ]] \
  || fail 'upload authority/recovery tables are not capability-only'

# Migrations 0112-0114 add three owner-held authority families.  Validate
# relation and column ACLs as sets, including the intentionally narrow SM
# snapshot projection.  This is independent of routine EXECUTE verification.
cluster_session_authority_acl_ok=$(control_psql --dbname="$database_name" \
  --tuples-only --no-align <<'PSQL'
WITH protected(name,runtime_read) AS (
  VALUES
    ('upload_storage_authority','none'),
    ('upload_storage_capacity_ledger','none'),
    ('upload_slots','none'),
    ('upload_storage_jobs','none'),
    ('upload_cleanup_queue','none'),
    ('cluster_signed_envelope_replays','none'),
    ('cluster_signed_envelope_replay_capacity','none'),
    ('cluster_session_routes','none'),
    ('deployment_session_leases','table'),
    ('deployment_session_binding_claims','table'),
    ('sm_resume_sessions','columns')
), resolved AS (
  SELECT protected.*,
         pg_catalog.to_regclass('public.' || protected.name) AS oid
    FROM protected
), expected_sm_column(name) AS (
  VALUES
    ('id'),('user_id'),('auth_generation'),('full_jid'),('resource'),
    ('connection_id'),('resume_timeout_seconds'),('inbound_h'),('outbound_h'),
    ('acked_h'),('available'),('carbons'),('priority'),
    ('blocklist_requested'),('roster_requested'),('active_privacy_list'),
    ('privacy_requested'),('user_agent_id'),('joined_rooms'),
    ('directed_presence'),('last_presence'),('resumable'),('live_lease_until'),
    ('expires_at'),('claimed_until'),('created_at'),('updated_at')
), actual_sm_column(name) AS (
  SELECT attribute.attname::pg_catalog.text
    FROM pg_catalog.pg_attribute AS attribute
   WHERE attribute.attrelid='public.sm_resume_sessions'::pg_catalog.regclass
     AND attribute.attnum>0 AND NOT attribute.attisdropped
     AND pg_catalog.has_column_privilege(
           'northstar_runtime',attribute.attrelid,attribute.attnum,'SELECT'
         )
)
SELECT NOT EXISTS (
  SELECT 1 FROM resolved
   WHERE oid IS NULL
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_runtime',oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',oid,'REFERENCES')
      OR (runtime_read='none' AND (
            pg_catalog.has_table_privilege('northstar_runtime',oid,'SELECT')
            OR pg_catalog.has_any_column_privilege(
                 'northstar_runtime',oid,'SELECT'
               )))
      OR (runtime_read='table' AND NOT pg_catalog.has_table_privilege(
            'northstar_runtime',oid,'SELECT'
          ))
      OR (runtime_read='columns' AND pg_catalog.has_table_privilege(
            'northstar_runtime',oid,'SELECT'
          ))
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'SELECT')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_commands',oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_commands',oid,'SELECT')
      OR pg_catalog.has_any_column_privilege('northstar_commands',oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_commands',oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_commands',oid,'REFERENCES')
      OR NOT pg_catalog.has_table_privilege('northstar_backup',oid,'SELECT')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_backup',oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_backup',oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_backup',oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_backup',oid,'REFERENCES')
) AND NOT EXISTS (
  SELECT name FROM expected_sm_column
  EXCEPT SELECT name FROM actual_sm_column
) AND NOT EXISTS (
  SELECT name FROM actual_sm_column
  EXCEPT SELECT name FROM expected_sm_column
) AND NOT pg_catalog.has_column_privilege(
  'northstar_runtime','public.sm_resume_sessions','token_hash','SELECT'
) AND NOT pg_catalog.has_column_privilege(
  'northstar_runtime','public.sm_resume_sessions','claim_token','SELECT'
) AND NOT pg_catalog.has_column_privilege(
  'northstar_runtime','public.sm_resume_sessions','peer_ip','SELECT'
) AND NOT EXISTS (
  SELECT 1
    FROM resolved
    JOIN pg_catalog.pg_class AS relation ON relation.oid=resolved.oid
   CROSS JOIN LATERAL pg_catalog.aclexplode(
     COALESCE(relation.relacl,pg_catalog.acldefault('r',relation.relowner))
   ) AS privilege
   WHERE privilege.grantee=0
) AND NOT EXISTS (
  SELECT 1
    FROM resolved
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid=resolved.oid
     AND attribute.attnum>0 AND NOT attribute.attisdropped
   CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
   WHERE privilege.grantee=0
);
PSQL
)
[[ "$cluster_session_authority_acl_ok" == 't' ]] \
  || fail '0112-0114 authority table/column ACL manifest drifted'
for secret_column in token_hash claim_token peer_ip; do
  expect_insufficient_privilege "$runtime_role" "$runtime_password" \
    "runtime SM ${secret_column} column read" \
    "SELECT ${secret_column} FROM public.sm_resume_sessions LIMIT 1"
done

for ip_policy in exact subnet; do
  null_ip_claim_status=$(psql_as "$runtime_role" "$runtime_password" \
    --tuples-only --no-align --command="
      SELECT status FROM public.northstar_sm_claim(
        decode(repeat('00',32),'hex'),
        '00000000-0000-0000-0000-000000000001'::pg_catalog.uuid,
        NULL::pg_catalog.inet,
        NULL::pg_catalog.uuid,
        '${ip_policy}',FALSE,
        '00000000-0000-0000-0000-000000000002'::pg_catalog.uuid,
        30
      )")
  [[ "$null_ip_claim_status" == 'rejected' ]] \
    || fail "SM ${ip_policy} IP policy accepted a NULL claimant address"
done

# Runtime receives only fixed-cardinality, locator-free facts from typed
# routines. Raw reads and mutations of all five upload authorities stay denied.
psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align <<'PSQL' >/dev/null
SELECT pg_catalog.count(*) FROM public.northstar_upload_capacity_reconciliation();
SELECT pg_catalog.count(*) FROM public.northstar_upload_queue_snapshot();
SELECT pg_catalog.count(*) FROM public.northstar_upload_public_file(
  '00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
);
PSQL
for upload_relation in \
  upload_storage_authority upload_storage_capacity_ledger upload_slots \
  upload_storage_jobs upload_cleanup_queue
do
  expect_insufficient_privilege "$runtime_role" "$runtime_password" \
    "runtime raw ${upload_relation} read" \
    "SELECT 1 FROM public.${upload_relation} LIMIT 1"
  expect_insufficient_privilege "$runtime_role" "$runtime_password" \
    "runtime raw ${upload_relation} mutation" \
    "DELETE FROM public.${upload_relation} WHERE false"
done

xep0133_state_acl_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1
    FROM (VALUES
      ('admin_service_messages'),
      ('federation_runtime_rules'),
      ('admin_service_control')
    ) AS protected(name)
    CROSS JOIN LATERAL (
      SELECT pg_catalog.to_regclass('public.' || protected.name) AS oid
    ) relation
   WHERE relation.oid IS NULL
      OR NOT pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'SELECT')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'INSERT')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'UPDATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'DELETE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'TRUNCATE')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'REFERENCES')
      OR pg_catalog.has_table_privilege('northstar_runtime',relation.oid,'TRIGGER')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'INSERT')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'UPDATE')
      OR pg_catalog.has_any_column_privilege('northstar_runtime',relation.oid,'REFERENCES')
);
PSQL
)
[[ "$xep0133_state_acl_ok" == 't' ]] \
  || fail 'XEP-0133 service/federation/control state is not runtime read-only'

expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct users INSERT' \
  "INSERT INTO public.users(id,username,password_hash) VALUES('00000000-0000-0000-0000-000000000011','runtime-insert-forbidden','invalid')"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct users UPDATE' \
  'UPDATE public.users SET is_admin=TRUE WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct users DELETE' \
  'DELETE FROM public.users WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-message INSERT' \
  "INSERT INTO public.admin_service_messages(kind,body,revision) VALUES('motd','forbidden','00000000-0000-0000-0000-000000000040')"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-message UPDATE' \
  'UPDATE public.admin_service_messages SET body=body WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-message DELETE' \
  'DELETE FROM public.admin_service_messages WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct federation-rule INSERT' \
  "INSERT INTO public.federation_runtime_rules(kind,domain) VALUES('blacklist','forbidden.invalid')"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct federation-rule UPDATE' \
  'UPDATE public.federation_runtime_rules SET domain=domain WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct federation-rule DELETE' \
  'DELETE FROM public.federation_runtime_rules WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-control INSERT' \
  "INSERT INTO public.admin_service_control(singleton,generation,action,status,execute_at,expires_at,requested_generation) VALUES(TRUE,'00000000-0000-0000-0000-000000000041','restart','scheduled',clock_timestamp(),clock_timestamp()+INTERVAL '1 minute',0)"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-control UPDATE' \
  'UPDATE public.admin_service_control SET execute_at=execute_at WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct service-control DELETE' \
  'DELETE FROM public.admin_service_control WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime command-session read' \
  'SELECT id FROM public.admin_command_sessions LIMIT 1'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime command-session INSERT' \
  "INSERT INTO public.admin_command_sessions(id,owner_id,owner_full_jid,owner_auth_generation,node,stage,expires_at,bearer_hash) VALUES('00000000-0000-0000-0000-000000000099','00000000-0000-0000-0000-000000000099','x@ci.northstar.invalid/r',0,'x','form',clock_timestamp(),decode(repeat('00',32),'hex'))"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime command-session UPDATE' \
  'UPDATE public.admin_command_sessions SET stage=stage WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime command-session DELETE' \
  'DELETE FROM public.admin_command_sessions WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime command authority read' \
  'SELECT hmac_key FROM public.admin_command_capability_authority'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime cleanup effect direct read' \
  'SELECT id FROM public.admin_session_cleanup_effects LIMIT 1'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime cleanup effect direct mutation' \
  'UPDATE public.admin_session_cleanup_effects SET status=status WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime cleanup capacity direct mutation' \
  'UPDATE public.admin_session_cleanup_capacity SET queued=queued WHERE false'
expect_insufficient_privilege "$command_role" "$command_password" \
  'command issuer direct session read' \
  'SELECT id FROM public.admin_command_sessions LIMIT 1'
expect_insufficient_privilege "$command_role" "$command_password" \
  'command issuer direct user read' \
  'SELECT id FROM public.users LIMIT 1'
expect_insufficient_privilege "$command_role" "$command_password" \
  'command issuer cleanup effect direct read' \
  'SELECT id FROM public.admin_session_cleanup_effects LIMIT 1'
expect_insufficient_privilege "$command_role" "$command_password" \
  'command issuer private cleanup helper' \
  "SELECT public.northstar_enqueue_admin_generation_cleanup(
     '00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000002',1,'role-ci-user@example.invalid')"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime legacy unclaimed administrator mutation' \
  "SELECT public.northstar_admin_user_lifecycle('00000000-0000-0000-0000-000000000012','role-ci-admin',0,'00000000-0000-0000-0000-000000000013','role-ci-user','disable')"

# Harmless positive command probe: the runtime can execute a reviewed user
# capability even though the underlying table is read-only.  The promotion
# probe proves that merely knowing an account UUID/generation cannot replace
# the exact REST administrator bearer fence.
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command='SELECT public.northstar_user_clear_scram_sha1() >= 0')" == 't' ]] \
  || fail 'reviewed user command capability is unavailable to runtime'

# Build an administrator through the owner-only bootstrap capability, then a
# non-administrator through the real two-role XEP-0133 bearer -> claim ->
# atomic business-command path. Credential bytes are disposable test data.
bootstrap_created=$(psql_as "$migrator_role" "$migrator_password" \
  --tuples-only --no-align <<'PSQL'
SELECT public.northstar_user_create_bootstrap_admin(
  '00000000-0000-0000-0000-000000000012','role-ci-admin',
  '$argon2id$northstar-ci-bootstrap-credential',
  decode(repeat('11',16),'hex'),4096,
  decode(repeat('12',32),'hex'),decode(repeat('13',32),'hex'),
  NULL,NULL,NULL,NULL
);
PSQL
)
[[ "$bootstrap_created" == 't' ]] || fail 'bootstrap account command did not create its fixture'

# A legacy or partially recovered snapshot may have no stored peer address.
# Under exact/subnet policy that absence must fail closed rather than acting as
# a wildcard.  Two independent rows avoid one buggy claim masking the second
# policy behind an already-held claim token. A third, active row exercises the
# SQL capability's snapshot-size boundary without relying on Rust validation.
psql_as "$migrator_role" "$migrator_password" >/dev/null <<'PSQL'
INSERT INTO public.sm_resume_sessions(
  id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
  resume_timeout_seconds,resumable,peer_ip,live_lease_until,expires_at
) VALUES
  ('00000000-0000-0000-0000-000000000050',decode(repeat('a1',32),'hex'),
   '00000000-0000-0000-0000-000000000012',0,
   'role-ci-admin@ci.northstar.invalid/null-ip-exact','null-ip-exact',
   '00000000-0000-0000-0000-000000000051',300,TRUE,NULL,
   clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '5 minutes'),
  ('00000000-0000-0000-0000-000000000052',decode(repeat('a2',32),'hex'),
   '00000000-0000-0000-0000-000000000012',0,
   'role-ci-admin@ci.northstar.invalid/null-ip-subnet','null-ip-subnet',
   '00000000-0000-0000-0000-000000000053',300,TRUE,NULL,
   clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '5 minutes'),
  ('00000000-0000-0000-0000-000000000056',decode(repeat('a3',32),'hex'),
   '00000000-0000-0000-0000-000000000012',0,
   'role-ci-admin@ci.northstar.invalid/snapshot-bounds','snapshot-bounds',
   '00000000-0000-0000-0000-000000000057',300,FALSE,
   '198.51.100.20'::pg_catalog.inet,
   clock_timestamp()+INTERVAL '5 minutes',clock_timestamp()+INTERVAL '5 minutes'),
  ('00000000-0000-0000-0000-000000000058',decode(repeat('a5',32),'hex'),
   '00000000-0000-0000-0000-000000000012',0,
   'role-ci-admin@ci.northstar.invalid/legacy-null-device','legacy-null-device',
   '00000000-0000-0000-0000-000000000059',300,TRUE,
   '198.51.100.22'::pg_catalog.inet,
   clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '5 minutes');
INSERT INTO public.sm_resume_sessions(
  id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
  resume_timeout_seconds,resumable,peer_ip,user_agent_id,
  live_lease_until,expires_at
) VALUES (
  '00000000-0000-0000-0000-000000000064',decode(repeat('a6',32),'hex'),
  '00000000-0000-0000-0000-000000000012',0,
  'role-ci-admin@ci.northstar.invalid/bound-device','bound-device',
  '00000000-0000-0000-0000-000000000065',300,TRUE,
  '198.51.100.23'::pg_catalog.inet,
  '00000000-0000-0000-0000-000000000066'::pg_catalog.uuid,
  clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '5 minutes'
);
PSQL
stored_null_ip_claims_rejected=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align <<'PSQL'
WITH outcomes AS (
  SELECT status FROM public.northstar_sm_claim(
    decode(repeat('a1',32),'hex'),
    '00000000-0000-0000-0000-000000000012',
    '198.51.100.10'::pg_catalog.inet,NULL,'exact',FALSE,
    '00000000-0000-0000-0000-000000000054',30
  )
  UNION ALL
  SELECT status FROM public.northstar_sm_claim(
    decode(repeat('a2',32),'hex'),
    '00000000-0000-0000-0000-000000000012',
    '198.51.100.11'::pg_catalog.inet,NULL,'subnet',FALSE,
    '00000000-0000-0000-0000-000000000055',30
  )
)
SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(status='rejected')
  FROM outcomes;
PSQL
)
[[ "$stored_null_ip_claims_rejected" == 't' ]] \
  || fail 'SM exact/subnet policy accepted a snapshot with NULL stored peer_ip'

legacy_null_device_status=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command="
    SELECT status FROM public.northstar_sm_claim(
      decode(repeat('a5',32),'hex'),
      '00000000-0000-0000-0000-000000000012',NULL::pg_catalog.inet,
      '00000000-0000-0000-0000-000000000062','none',TRUE,
      '00000000-0000-0000-0000-000000000063',30
    )")
[[ "$legacy_null_device_status" == 'rejected' ]] \
  || fail 'SM strict same-device policy accepted a legacy NULL stored device ID'

null_claimant_device_status=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command="
    SELECT status FROM public.northstar_sm_claim(
      decode(repeat('a6',32),'hex'),
      '00000000-0000-0000-0000-000000000012',NULL::pg_catalog.inet,
      NULL::pg_catalog.uuid,'none',TRUE,
      '00000000-0000-0000-0000-000000000067',30
    )")
[[ "$null_claimant_device_status" == 'rejected' ]] \
  || fail 'SM strict same-device policy accepted a NULL claimant device ID'

legacy_compatibility_status=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align --command="
    SELECT status FROM public.northstar_sm_claim(
      decode(repeat('a5',32),'hex'),
      '00000000-0000-0000-0000-000000000012',NULL::pg_catalog.inet,
      NULL::pg_catalog.uuid,'none',FALSE,
      '00000000-0000-0000-0000-000000000068',30
    )")
[[ "$legacy_compatibility_status" == 'claimed' ]] \
  || fail 'SM compatibility mode rejected a legacy NULL stored device ID'

expect_sqlstate "$runtime_role" "$runtime_password" '22023' \
  'runtime SM create capability oversized joined-room snapshot' \
  "SELECT public.northstar_sm_create(
     '00000000-0000-0000-0000-000000000060',decode(repeat('a4',32),'hex'),
     '00000000-0000-0000-0000-000000000012',0,
     'role-ci-admin@ci.northstar.invalid/oversized-create','oversized-create',
     'ci.northstar.invalid','00000000-0000-0000-0000-000000000061',
     300,0,0,0,FALSE,FALSE,0::pg_catalog.int2,FALSE,FALSE,NULL,FALSE,
     '198.51.100.21'::pg_catalog.inet,NULL,
     (SELECT pg_catalog.jsonb_agg('{}'::pg_catalog.jsonb)
        FROM pg_catalog.generate_series(1,257)),
     '[]'::pg_catalog.jsonb,NULL,300,300)"

oversized_snapshot_updates=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align <<'PSQL'
SELECT NOT public.northstar_sm_update_snapshot(
  '00000000-0000-0000-0000-000000000056',
  '00000000-0000-0000-0000-000000000057',0,0,0,FALSE,FALSE,0::pg_catalog.int2,
  FALSE,FALSE,NULL,FALSE,'198.51.100.20'::pg_catalog.inet,NULL,
  (SELECT pg_catalog.jsonb_agg('{}'::pg_catalog.jsonb)
     FROM pg_catalog.generate_series(1,257)),
  '[]'::pg_catalog.jsonb,NULL,FALSE,300,300
);
SELECT NOT public.northstar_sm_update_snapshot(
  '00000000-0000-0000-0000-000000000056',
  '00000000-0000-0000-0000-000000000057',0,0,0,FALSE,FALSE,0::pg_catalog.int2,
  FALSE,FALSE,NULL,FALSE,'198.51.100.20'::pg_catalog.inet,NULL,
  '[]'::pg_catalog.jsonb,
  (SELECT pg_catalog.jsonb_agg('"room@example.invalid"'::pg_catalog.jsonb)
     FROM pg_catalog.generate_series(1,1025)),
  NULL,FALSE,300,300
);
SELECT NOT public.northstar_sm_update_snapshot(
  '00000000-0000-0000-0000-000000000056',
  '00000000-0000-0000-0000-000000000057',0,0,0,FALSE,FALSE,0::pg_catalog.int2,
  FALSE,FALSE,NULL,FALSE,'198.51.100.20'::pg_catalog.inet,NULL,
  '[]'::pg_catalog.jsonb,'[]'::pg_catalog.jsonb,
  pg_catalog.repeat('x',1048577),FALSE,300,300
);
SELECT joined_rooms='[]'::pg_catalog.jsonb
   AND directed_presence='[]'::pg_catalog.jsonb
   AND last_presence IS NULL
  FROM public.sm_resume_sessions
 WHERE id='00000000-0000-0000-0000-000000000056';
PSQL
)
[[ "$oversized_snapshot_updates" == $'t\nt\nt\nt' ]] \
  || fail 'runtime SM snapshot capability accepted or persisted oversized state'
psql_as "$migrator_role" "$migrator_password" --command="
  DELETE FROM public.sm_resume_sessions
   WHERE id IN(
     '00000000-0000-0000-0000-000000000050',
     '00000000-0000-0000-0000-000000000052',
     '00000000-0000-0000-0000-000000000056',
     '00000000-0000-0000-0000-000000000058'
   )" >/dev/null

# The runtime watcher can only advance a migrator/typed-command-created row at
# its database-clock deadline.  It cannot retain UPDATE on the control table.
psql_as "$migrator_role" "$migrator_password" >/dev/null <<'PSQL'
INSERT INTO public.admin_service_control(
  singleton,generation,action,status,execute_at,expires_at,
  requested_by,requested_generation
) VALUES(
  TRUE,'00000000-0000-0000-0000-000000000041','restart','scheduled',
  clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '5 minutes',
  '00000000-0000-0000-0000-000000000012',0
);
PSQL
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT action='restart' AND fired_at IS NOT NULL FROM public.northstar_admin_service_control_poll()")" == 't' ]] \
  || fail 'typed runtime service-control poll did not atomically fire a due generation'
psql_as "$migrator_role" "$migrator_password" \
  --command="DELETE FROM public.admin_service_control WHERE generation='00000000-0000-0000-0000-000000000041'" \
  >/dev/null

command_bearer='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
command_claim='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_session('00000000-0000-0000-0000-000000000020','${command_bearer}','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console','ci.northstar.invalid',0,'http://jabber.org/protocol/admin#add-user','form')")" == 't' ]] \
  || fail 'command issuer could not create the bounded XEP-0133 session'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${command_bearer}','${command_claim}','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'))")" == 'started' ]] \
  || fail 'command issuer could not mint the exact bound execution claim'
non_admin_created=$(psql_as "$runtime_role" "$runtime_password" \
  --tuples-only --no-align <<'PSQL'
SELECT public.northstar_admin_command_create_user(
  repeat('B',64),'00000000-0000-0000-0000-000000000012','role-ci-admin',0,
  'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'),
  '00000000-0000-0000-0000-000000000013','role-ci-user',
  '$argon2id$northstar-ci-user-credential',
  decode(repeat('21',16),'hex'),4096,
  decode(repeat('22',32),'hex'),decode(repeat('23',32),'hex'),
  NULL,NULL,NULL,NULL,
  '<x xmlns="jabber:x:data" type="result"/>'
);
PSQL
)
[[ "$non_admin_created" == 'created' ]] \
  || fail 'reviewed administrative account-create command was unavailable'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${command_bearer}','CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC','00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'))")" == 'completed' ]] \
  || fail 'completed XEP-0133 submission was not idempotently replayed'
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_user(repeat('B',64),'00000000-0000-0000-0000-000000000012','role-ci-admin',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'),'00000000-0000-0000-0000-000000000023','claim-replay','\$argon2id\$claim-replay',decode(repeat('31',16),'hex'),4096,decode(repeat('32',32),'hex'),decode(repeat('33',32),'hex'),NULL,NULL,NULL,NULL,'<x/>')")" == 'unauthorized' ]] \
  || fail 'completed claim was replayable'
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_user(repeat('Z',64),'00000000-0000-0000-0000-000000000012','role-ci-admin',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'),'00000000-0000-0000-0000-000000000024','fake-claim','\$argon2id\$fake-claim',decode(repeat('41',16),'hex'),4096,decode(repeat('42',32),'hex'),decode(repeat('43',32),'hex'),NULL,NULL,NULL,NULL,'<x/>')")" == 'unauthorized' ]] \
  || fail 'forged claim token was accepted'
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_user(repeat('B',64),'00000000-0000-0000-0000-000000000012','role-ci-admin',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('cd',32),'hex'),'00000000-0000-0000-0000-000000000025','cross-target','\$argon2id\$cross-target',decode(repeat('51',16),'hex'),4096,decode(repeat('52',32),'hex'),decode(repeat('53',32),'hex'),NULL,NULL,NULL,NULL,'<x/>')")" == 'unauthorized' ]] \
  || fail 'cross-target claim substitution was accepted'
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_set_service_message(repeat('B',64),'00000000-0000-0000-0000-000000000012','role-ci-admin',0,'http://jabber.org/protocol/admin#set-motd',decode(repeat('ab',32),'hex'),'motd','forbidden','<x/>')")" == 'f' ]] \
  || fail 'cross-command claim substitution was accepted'

# Mint a generation-0 claim now; the concurrent password fence below advances
# the actor to generation 1 and must make this otherwise-valid claim unusable.
stale_bearer='DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'
stale_claim='EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_session('00000000-0000-0000-0000-000000000026','${stale_bearer}','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console','ci.northstar.invalid',0,'http://jabber.org/protocol/admin#announce','form')")" == 't' ]]
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${stale_bearer}','${stale_claim}','00000000-0000-0000-0000-000000000027','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',0,'http://jabber.org/protocol/admin#announce',decode(repeat('de',32),'hex'))")" == 'started' ]]
psql_as "$runtime_role" "$runtime_password" >/dev/null <<'PSQL'
INSERT INTO public.api_sessions(id,user_id,token_hash,expires_at)
VALUES(
  '00000000-0000-0000-0000-000000000014',
  '00000000-0000-0000-0000-000000000013',
  decode(repeat('24',32),'hex'),clock_timestamp()+INTERVAL '1 hour'
);
PSQL
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_user_set_status_api('00000000-0000-0000-0000-000000000013',0,decode(repeat('24',32),'hex'),'00000000-0000-0000-0000-000000000013',NULL,TRUE)")" == '-2' ]] \
  || fail 'non-administrator promotion was not rejected by the command capability'
[[ "$(control_psql --dbname="$database_name" --tuples-only --no-align \
  --command="SELECT NOT is_admin FROM public.users WHERE id='00000000-0000-0000-0000-000000000013'")" == 't' ]] \
  || fail 'non-administrator promotion changed account authority'

# Two transactions racing the same observed generation must produce exactly
# one winner. This is the executable lost-update proof for password/SCRAM and
# auth-generation replacement: the loser observes a stale fence, never a
# second increment or a last-writer-wins credential overwrite.
generation_a="$runtime_dir/generation-a.out"
generation_b="$runtime_dir/generation-b.out"
psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_user_change_password_stream('00000000-0000-0000-0000-000000000012',0,'\$argon2id\$northstar-ci-generation-a-credential',decode(repeat('31',16),'hex'),4096,decode(repeat('32',32),'hex'),decode(repeat('33',32),'hex'),NULL,NULL,NULL,NULL)" \
  >"$generation_a" &
generation_a_pid=$!
psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_user_change_password_stream('00000000-0000-0000-0000-000000000012',0,'\$argon2id\$northstar-ci-generation-b-credential',decode(repeat('41',16),'hex'),4096,decode(repeat('42',32),'hex'),decode(repeat('43',32),'hex'),NULL,NULL,NULL,NULL)" \
  >"$generation_b" &
generation_b_pid=$!
wait "$generation_a_pid"
wait "$generation_b_pid"
generation_a_result=$(<"$generation_a")
generation_b_result=$(<"$generation_b")
[[ ( "$generation_a_result" == 't' && "$generation_b_result" == 'f' ) \
   || ( "$generation_a_result" == 'f' && "$generation_b_result" == 't' ) ]] \
  || fail 'concurrent auth-generation command did not produce one exact winner'
[[ "$(control_psql --dbname="$database_name" --tuples-only --no-align \
  --command="SELECT auth_generation=1 FROM public.users WHERE id='00000000-0000-0000-0000-000000000012'")" == 't' ]] \
  || fail 'concurrent auth-generation command lost or duplicated an update'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${command_bearer}','JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ','00000000-0000-0000-0000-000000000032','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',0,'http://jabber.org/protocol/admin#add-user',decode(repeat('ab',32),'hex'))")" == 'invalid' ]] \
  || fail 'old-generation completed command bearer replayed a cached result'
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_record_announcement('${stale_claim}','00000000-0000-0000-0000-000000000012','role-ci-admin',0,'http://jabber.org/protocol/admin#announce',decode(repeat('de',32),'hex'),1,1,'<x/>')")" == 'f' ]] \
  || fail 'old-generation XEP-0133 claim survived credential rotation'

expired_bearer='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
expired_claim='GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_session('00000000-0000-0000-0000-000000000028','${expired_bearer}','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console','ci.northstar.invalid',1,'http://jabber.org/protocol/admin#announce','form')")" == 't' ]]
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${expired_bearer}','${expired_claim}','00000000-0000-0000-0000-000000000029','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',1,'http://jabber.org/protocol/admin#announce',decode(repeat('ef',32),'hex'))")" == 'started' ]]
psql_as "$migrator_role" "$migrator_password" --command="UPDATE public.admin_command_sessions SET claim_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE operation_id='00000000-0000-0000-0000-000000000029'" >/dev/null
[[ "$(psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_record_announcement('${expired_claim}','00000000-0000-0000-0000-000000000012','role-ci-admin',1,'http://jabber.org/protocol/admin#announce',decode(repeat('ef',32),'hex'),1,1,'<x/>')")" == 'f' ]] \
  || fail 'expired XEP-0133 claim was accepted'

race_bearer='HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH'
race_claim='IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII'
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_create_session('00000000-0000-0000-0000-000000000030','${race_bearer}','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console','ci.northstar.invalid',1,'http://jabber.org/protocol/admin#announce','form')")" == 't' ]]
[[ "$(psql_as "$command_role" "$command_password" --tuples-only --no-align \
  --command="SELECT outcome FROM public.northstar_admin_command_begin_execution('${race_bearer}','${race_claim}','00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000012','role-ci-admin','role-ci-admin@ci.northstar.invalid/console',1,'http://jabber.org/protocol/admin#announce',decode(repeat('fa',32),'hex'))")" == 'started' ]]
race_a="$runtime_dir/command-race-a.out"
race_b="$runtime_dir/command-race-b.out"
psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_record_announcement('${race_claim}','00000000-0000-0000-0000-000000000012','role-ci-admin',1,'http://jabber.org/protocol/admin#announce',decode(repeat('fa',32),'hex'),1,1,'<x/>')" >"$race_a" &
race_a_pid=$!
psql_as "$runtime_role" "$runtime_password" --tuples-only --no-align \
  --command="SELECT public.northstar_admin_command_record_announcement('${race_claim}','00000000-0000-0000-0000-000000000012','role-ci-admin',1,'http://jabber.org/protocol/admin#announce',decode(repeat('fa',32),'hex'),1,1,'<x/>')" >"$race_b" &
race_b_pid=$!
wait "$race_a_pid"
wait "$race_b_pid"
race_a_result=$(<"$race_a")
race_b_result=$(<"$race_b")
[[ ( "$race_a_result" == 't' && "$race_b_result" == 'f' ) \
   || ( "$race_a_result" == 'f' && "$race_b_result" == 't' ) ]] \
  || fail 'concurrent XEP-0133 claim did not produce one exact winner'
[[ "$(control_psql --dbname="$database_name" --tuples-only --no-align \
  --command="SELECT count(*)=1 FROM public.audit_log WHERE actor_id='00000000-0000-0000-0000-000000000012' AND action='admin.announcement.send'")" == 't' ]] \
  || fail 'concurrent XEP-0133 execution produced duplicate audit or mutation'

# Prove the migrator still has the DDL capability needed by future migrations,
# while remaining a non-superuser according to the independent assertion above.
psql_as "$migrator_role" "$migrator_password" <<'PSQL'
CREATE TABLE public.northstar_ci_migrator_probe (id INTEGER PRIMARY KEY);
DROP TABLE public.northstar_ci_migrator_probe;
PSQL

# Immutable history is a fail-closed manifest.  This deliberately replaces the
# former assertion that runtime must hold unrestricted users DML.
immutable_history_acl_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1 FROM (VALUES
    ('audit_log',FALSE),('legal_holds',FALSE),('legal_hold_personal_archives',FALSE),
    ('legal_hold_muc_archives',FALSE),('legal_hold_offline_messages',FALSE),
    ('legal_hold_report_evidence',FALSE),('legal_hold_scopes',FALSE),
    ('legal_hold_offline_snapshots',FALSE),('cluster_muc_operations',FALSE),
    ('cluster_muc_delivery_handoffs',TRUE)
  ) AS immutable(name,deny_insert)
  WHERE pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'UPDATE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'DELETE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'TRUNCATE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'REFERENCES'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'TRIGGER'
        )
     OR (deny_insert AND pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'INSERT'
        ))
) AND NOT pg_catalog.has_table_privilege(
  'northstar_runtime','public.governance_export_leases','DELETE'
 ) AND NOT pg_catalog.has_table_privilege(
  'northstar_runtime','public.governance_export_leases','TRUNCATE'
 ) AND NOT pg_catalog.has_table_privilege(
  'northstar_runtime','public.governance_export_leases','REFERENCES'
 ) AND NOT pg_catalog.has_table_privilege(
  'northstar_runtime','public.governance_export_leases','TRIGGER'
);
PSQL
)
[[ "$immutable_history_acl_ok" == 't' ]] \
  || fail 'runtime immutable-history mutation privilege drifted'

migration_ledger_acl_ok=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
SELECT NOT EXISTS (
  SELECT 1 FROM (VALUES ('_sqlx_migrations'),('jid_identity_migrations')) ledger(name)
  WHERE NOT pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'SELECT'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'INSERT'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'UPDATE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'DELETE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'TRUNCATE'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'REFERENCES'
        )
     OR pg_catalog.has_table_privilege(
          'northstar_runtime',pg_catalog.to_regclass('public.' || name),'TRIGGER'
        )
);
PSQL
)
[[ "$migration_ledger_acl_ok" == 't' ]] \
  || fail 'runtime migration ledgers are not exactly read-only'

runtime_sequence_update_count=$(control_psql --dbname="$database_name" --tuples-only --no-align <<'PSQL'
SELECT pg_catalog.count(*)
 FROM pg_catalog.pg_class sequence
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid=sequence.relnamespace
 WHERE namespace.nspname='public' AND sequence.relkind='S'
   AND CASE
         WHEN sequence.relkind='S' THEN
           pg_catalog.has_sequence_privilege('northstar_runtime',sequence.oid,'UPDATE')
         ELSE FALSE
       END;
PSQL
)
[[ "$runtime_sequence_update_count" == '0' ]] \
  || fail 'runtime can set sequence values'

expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime CREATE in public' \
  'CREATE TABLE public.northstar_ci_runtime_ddl_probe (id INTEGER)'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime TEMPORARY object creation' \
  'CREATE TEMPORARY TABLE northstar_ci_runtime_temp_probe (id INTEGER)'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime ownership change' \
  'ALTER TABLE public.users OWNER TO northstar_runtime'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime trigger disable' \
  'ALTER TABLE public.users DISABLE TRIGGER ALL'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime SQLx migration-ledger forgery' \
  'UPDATE public._sqlx_migrations SET success=FALSE WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime identity migration-ledger forgery' \
  'DELETE FROM public.jid_identity_migrations WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime sequence setval' \
  "SELECT pg_catalog.setval('public.audit_log_id_seq'::pg_catalog.regclass,1,FALSE)"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime role escalation' \
  'SET ROLE northstar_migrator'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime direct handoff history mutation' \
  'DELETE FROM public.cluster_muc_delivery_handoffs WHERE false'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime forged audit retention marker' \
  "BEGIN; INSERT INTO public.audit_log(action,target,details) VALUES('northstar-ci-marker','acl','{}'); SET LOCAL northstar.audit_retention_cleanup='bounded-v1'; DELETE FROM public.audit_log WHERE action='northstar-ci-marker'; ROLLBACK"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime forged hold-snapshot retention marker' \
  "BEGIN; SET LOCAL northstar.hold_snapshot_retention_cleanup='bounded-v1'; DELETE FROM public.legal_hold_offline_snapshots WHERE false; ROLLBACK"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime forged governance-export retention marker' \
  "BEGIN; SET LOCAL northstar.governance_export_cleanup='bounded-v1'; DELETE FROM public.governance_export_leases WHERE false; ROLLBACK"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime forged cluster-MUC retention marker' \
  "BEGIN; SET LOCAL northstar.cluster_muc_retention_cleanup='bounded-v1'; DELETE FROM public.cluster_muc_operations WHERE false; ROLLBACK"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime offline upload authority maintenance' \
  "SELECT public.offline_upgrade_upload_storage_authority_v1_to_v2('northstar-ci-impossible', decode(repeat('00',32),'hex'), decode(repeat('11',32),'hex'), 'ALL_NORTHSTAR_NODES_STOPPED_AND_NAMESPACE_VERIFIED')"
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime upload job capacity trigger execution' \
  'SELECT public.account_upload_storage_job_capacity()'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime upload cleanup capacity trigger execution' \
  'SELECT public.account_upload_cleanup_capacity()'
expect_insufficient_privilege "$runtime_role" "$runtime_password" \
  'runtime cluster MUC fence trigger execution' \
  'SELECT public.fence_cluster_muc_outbox_identity()'

# Backup must support a consistent logical read while lacking write, routine,
# sequence-allocation, and TEMP capabilities.
psql_as "$backup_role" "$backup_password" --tuples-only --no-align <<'PSQL' >/dev/null
SELECT pg_catalog.count(*) FROM public.users;
SELECT pg_catalog.count(*) FROM public._sqlx_migrations;
SELECT pg_catalog.count(*) FROM public.upload_storage_authority;
SELECT pg_catalog.count(*) FROM public.upload_storage_capacity_ledger;
SELECT pg_catalog.count(*) FROM public.upload_slots;
SELECT pg_catalog.count(*) FROM public.upload_storage_jobs;
SELECT pg_catalog.count(*) FROM public.upload_cleanup_queue;
PSQL
expect_insufficient_privilege "$backup_role" "$backup_password" \
  'backup table write' \
  "INSERT INTO public.users (id, username, password_hash) VALUES ('00000000-0000-0000-0000-000000000001', 'northstar-ci-backup-write', 'invalid')"
expect_insufficient_privilege "$backup_role" "$backup_password" \
  'backup application routine execution' \
  "SELECT public.api_json_contains_secret_key('{}'::jsonb)"
expect_insufficient_privilege "$backup_role" "$backup_password" \
  'backup sequence allocation' \
  "SELECT pg_catalog.nextval('public.audit_log_id_seq'::pg_catalog.regclass)"
expect_insufficient_privilege "$backup_role" "$backup_password" \
  'backup TEMPORARY object creation' \
  'CREATE TEMPORARY TABLE northstar_ci_backup_temp_probe (id INTEGER)'

printf '%s\n' \
  'database role CI acceptance passed; immutable history and elevated capabilities are exact'
