#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Run this as northstar_migrator immediately after sqlx migrations. It repairs
# ACLs for existing objects and default privileges for future migration output.

umask 077
readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly grants_sql="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
readonly capability_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-capability-manifest.sql"
readonly migration_ledger_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
readonly pg_runner="$project_dir/scripts/run-postgres.py"
database_url_file="${MIGRATOR_DATABASE_URL_FILE:-/run/secrets/migrator_database_url}"

usage() {
  cat >&2 <<'EOF'
usage: scripts/reconcile-database-grants.sh [--database-url-file FILE]

Re-apply Northstar's runtime and read-only backup ACLs after migrations.
The URL file must authenticate as northstar_migrator to database xmpp.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url-file)
      database_url_file=${2:?missing database URL file}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -f "$database_url_file" && ! -L "$database_url_file" && -r "$database_url_file" ]] \
  || { echo 'migrator database URL must be a readable regular non-symlink file' >&2; exit 1; }
[[ -r "$grants_sql" ]] || { echo 'database grant policy is missing' >&2; exit 1; }
[[ -r "$capability_manifest_sql" ]] \
  || { echo 'database capability manifest is missing' >&2; exit 1; }
[[ -r "$migration_ledger_manifest_sql" ]] \
  || { echo 'database migration ledger manifest is missing' >&2; exit 1; }
[[ -r "$pg_runner" ]] || { echo 'PostgreSQL secret-safe launcher is missing' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 1; }
command -v psql >/dev/null || { echo 'psql is required' >&2; exit 1; }

python3 "$pg_runner" --database-url-file "$database_url_file" -- \
  psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --set=database_name=xmpp \
    --set=migrator_role=northstar_migrator \
    --set=runtime_role=northstar_runtime \
    --set=command_role=northstar_commands \
    --set=backup_role=northstar_backup \
    --set=allow_bootstrap=false \
    --set=grant_phase=exact \
    --file "$grants_sql"

printf '%s\n' 'Northstar database grants reconciled.'
