#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
[[ $# -eq 3 ]] || {
  echo "usage: $0 DATABASE_DUMP SCRATCH_ROOT UPLOAD_ROWS_OUTPUT" >&2
  exit 2
}

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
database_dump="$1"
scratch_root="$2"
upload_rows_output="$3"
grant_reconcile_sql="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
grant_boundary_sql="$project_dir/deploy/postgres-init/lib/verify-northstar-grant-boundary.sql"
grant_apply_sql="$project_dir/deploy/postgres-init/lib/apply-northstar-grants.sql"
capability_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-capability-manifest.sql"
migration_ledger_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
readonly validation_database='northstar_backup_verify'
readonly migrator_role='northstar_migrator'
readonly runtime_role='northstar_runtime'
readonly command_role='northstar_commands'
readonly backup_role='northstar_backup'

[[ -f "$database_dump" && ! -L "$database_dump" ]] \
  || { echo "database dump must be a regular non-symlink file" >&2; exit 2; }
[[ -d "$scratch_root" && ! -L "$scratch_root" ]] \
  || { echo "local validation scratch root must be a real directory" >&2; exit 2; }
for grant_policy_file in "$grant_reconcile_sql" "$grant_boundary_sql" \
  "$grant_apply_sql" "$capability_manifest_sql" "$migration_ledger_manifest_sql"; do
  [[ -f "$grant_policy_file" && ! -L "$grant_policy_file" && -r "$grant_policy_file" ]] \
    || { echo "database grant policy is missing or unsafe: $grant_policy_file" >&2; exit 1; }
done

for command in createdb initdb pg_ctl pg_restore psql; do
  command -v "$command" >/dev/null \
    || { echo "local dump validation requires PostgreSQL command: $command" >&2; exit 1; }
done

validation_root="$(mktemp -d "$scratch_root/northstar-backup-pg.XXXXXX")"
data_dir="$validation_root/data"
postgres_log="$validation_root/postgres.log"
# Restore plaintext staging can be deeply nested. PostgreSQL's Unix socket
# path is limited to 107 bytes on Linux, so keep the socket in a separate
# private short-lived directory while all database files remain under the
# operator-selected scratch root.
socket_dir="$(mktemp -d /tmp/northstar-backup-pg-socket.XXXXXX)"
chmod 0700 "$socket_dir"
server_started=false

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if [[ "$server_started" == true ]]; then
    pg_ctl -D "$data_dir" -m immediate -w stop >/dev/null 2>&1 || status=1
  fi
  case "$socket_dir" in
    /tmp/northstar-backup-pg-socket.*)
      rmdir -- "$socket_dir" 2>/dev/null || status=1
      ;;
    *)
      echo "refusing to remove unexpected local validation socket path" >&2
      status=1
      ;;
  esac
  case "$validation_root" in
    "$scratch_root"/northstar-backup-pg.*)
      rm -rf --one-file-system -- "$validation_root"
      ;;
    *)
      echo "refusing to remove unexpected local validation path" >&2
      status=1
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

initdb -D "$data_dir" --username=postgres --auth-local=trust --auth-host=reject \
  --no-instructions >/dev/null

# The validation instance is reachable only through its private Unix socket.
# It never connects back to, creates databases in, or mutates the source server.
{
  printf "listen_addresses = ''\n"
  printf "unix_socket_directories = '%s'\n" "${socket_dir//\'/\'\'}"
  printf "fsync = off\n"
  printf "synchronous_commit = off\n"
  printf "full_page_writes = off\n"
} >>"$data_dir/postgresql.conf"

if ! pg_ctl -D "$data_dir" -l "$postgres_log" -w start >/dev/null; then
  echo 'local dump-validation PostgreSQL failed to start' >&2
  tail -n 80 "$postgres_log" >&2 || true
  exit 1
fi
server_started=true

# Validate the dump under the same privilege boundary used by production.
# Restoring as the bootstrap superuser would prove only SQL syntax and could
# hide foreign ownership, an invalid migration ledger, an unregistered table,
# or a drifted SECURITY DEFINER capability until the real database cutover.
psql -h "$socket_dir" -U postgres -d postgres --no-psqlrc --quiet \
  --set ON_ERROR_STOP=1 <<'PSQL'
CREATE ROLE northstar_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4
  VALID UNTIL 'infinity';
CREATE ROLE northstar_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64
  VALID UNTIL 'infinity';
CREATE ROLE northstar_commands LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8
  VALID UNTIL 'infinity';
CREATE ROLE northstar_backup LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2
  VALID UNTIL 'infinity';
PSQL
createdb -h "$socket_dir" -U postgres --owner="$migrator_role" \
  "$validation_database"
psql -h "$socket_dir" -U postgres -d "$validation_database" --no-psqlrc \
  --quiet --set ON_ERROR_STOP=1 \
  --command="ALTER SCHEMA public OWNER TO $migrator_role"
pg_restore -h "$socket_dir" -U "$migrator_role" -d "$validation_database" \
  --no-owner --no-acl --single-transaction "$database_dump"
psql -h "$socket_dir" -U "$migrator_role" -d "$validation_database" \
  --no-psqlrc --quiet --set ON_ERROR_STOP=1 \
  --set database_name="$validation_database" \
  --set migrator_role="$migrator_role" \
  --set runtime_role="$runtime_role" \
  --set command_role="$command_role" \
  --set backup_role="$backup_role" \
  --set allow_bootstrap=false --set grant_phase=exact \
  --file "$grant_reconcile_sql"
psql -h "$socket_dir" -U "$migrator_role" -d "$validation_database" \
  --no-psqlrc --quiet --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --field-separator=$'\t' \
  --command="SELECT id,size,COALESCE(encode(content_sha256,'hex'),'')
             FROM public.upload_slots
             WHERE uploaded AND expires_at > clock_timestamp()
             ORDER BY id" >"$upload_rows_output"

pg_ctl -D "$data_dir" -m fast -w stop >/dev/null
server_started=false
rmdir -- "$socket_dir"
rm -rf --one-file-system -- "$validation_root"
trap - EXIT INT TERM
