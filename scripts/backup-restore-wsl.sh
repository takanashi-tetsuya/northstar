#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
postgres_bin="$(pg_config --bindir)"
for command in initdb pg_ctl createdb psql; do
  [[ -x "$postgres_bin/$command" ]] \
    || { echo "required PostgreSQL command is unavailable: $postgres_bin/$command" >&2; exit 1; }
done

work_dir="$(mktemp -d /tmp/northstar-backup-restore.XXXXXX)"
data_dir="$work_dir/postgres"
socket_dir="$work_dir/socket"
backup_root="$work_dir/backups"
source_uploads="$work_dir/source-uploads"
restore_uploads="$work_dir/restore-uploads"
database_role="northstar_restore_it"
database_password='Northstar:test\secret'
password_file="$work_dir/postgres-password"
cluster_started=false

cleanup() {
  if [[ "$cluster_started" == true ]]; then
    "$postgres_bin/pg_ctl" --pgdata "$data_dir" --mode fast --wait stop >/dev/null 2>&1 || true
  fi
  case "$work_dir" in
    /tmp/northstar-backup-restore.*) rm -rf -- "$work_dir" ;;
    *) echo "refusing to clean unexpected test path: $work_dir" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$socket_dir" "$backup_root" "$source_uploads" "$restore_uploads"
printf '%s\n' "$database_password" > "$password_file"
chmod 600 "$password_file"
"$postgres_bin/initdb" \
  --pgdata "$data_dir" \
  --username "$database_role" \
  --pwfile "$password_file" \
  --auth-local scram-sha-256 \
  --auth-host reject \
  --no-locale >/dev/null
"$postgres_bin/pg_ctl" \
  --pgdata "$data_dir" \
  --options="-F -k $socket_dir -c listen_addresses='' -c unix_socket_permissions=0700" \
  --wait start >/dev/null
cluster_started=true

PGPASSWORD="$database_password" "$postgres_bin/createdb" \
  --host "$socket_dir" --username "$database_role" northstar_backup_source
PGPASSWORD="$database_password" "$postgres_bin/createdb" \
  --host "$socket_dir" --username "$database_role" northstar_restore_target

encoded_socket="${socket_dir//\//%2F}"
encoded_password='Northstar%3Atest%5Csecret'
source_database="postgresql://$database_role:$encoded_password@/northstar_backup_source?host=$encoded_socket"
target_database="postgresql://$database_role:$encoded_password@/northstar_restore_target?host=$encoded_socket"
upload_id="0123456789abcdef0123456789abcdef"
upload_body="northstar immutable upload restore probe"
printf '%s' "$upload_body" > "$source_uploads/$upload_id"
upload_size="$(stat -c '%s' "$source_uploads/$upload_id")"

PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
  PGDATABASE=northstar_backup_source "$postgres_bin/psql" \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command='CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, success BOOLEAN NOT NULL);' \
  --command='INSERT INTO _sqlx_migrations VALUES (13, TRUE);' \
  --command='CREATE TABLE backup_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL);' \
  --command="INSERT INTO backup_probe VALUES (1, 'database-restored');" \
  --command='CREATE TABLE upload_slots (id TEXT PRIMARY KEY, size BIGINT NOT NULL, uploaded BOOLEAN NOT NULL);' \
  --command="INSERT INTO upload_slots VALUES ('$upload_id', $upload_size, TRUE);" >/dev/null

DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
  --output "$backup_root" \
  --upload-dir "$source_uploads" >/dev/null
backup_dir="$(find "$backup_root" -mindepth 1 -maxdepth 1 -type d -name 'northstar-*' -print -quit)"
[[ -n "$backup_dir" ]] || { echo "backup test did not create an archive" >&2; exit 1; }
bash "$project_dir/scripts/verify-backup.sh" "$backup_dir" >/dev/null

printf '%s' 'stale upload retained for rollback' > "$restore_uploads/stale.txt"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore WRONG --upload-dir "$restore_uploads" >/dev/null 2>&1; then
  echo "restore accepted an invalid confirmation phrase" >&2
  exit 1
fi

DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE \
  --upload-dir "$restore_uploads" >/dev/null

restored_value="$(PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
  PGDATABASE=northstar_restore_target "$postgres_bin/psql" \
  --no-psqlrc --tuples-only --no-align \
  --command='SELECT value FROM backup_probe WHERE id = 1')"
[[ "$restored_value" == "database-restored" ]] \
  || { echo "restored database probe did not match" >&2; exit 1; }
[[ "$(<"$restore_uploads/$upload_id")" == "$upload_body" ]] \
  || { echo "restored upload content did not match" >&2; exit 1; }
find "$restore_uploads" -mindepth 2 -maxdepth 2 \
  -path '*/.pre-restore.*/stale.txt' -type f -print -quit | grep -q . \
  || { echo "pre-restore upload was not retained" >&2; exit 1; }

echo "backup/restore: private PostgreSQL, checksums, confirmation guard, database data, uploads and rollback retention passed"
