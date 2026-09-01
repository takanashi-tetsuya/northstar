#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
[[ $# -eq 3 ]] || {
  echo "usage: $0 DATABASE_DUMP SCRATCH_ROOT UPLOAD_ROWS_OUTPUT" >&2
  exit 2
}

database_dump="$1"
scratch_root="$2"
upload_rows_output="$3"

[[ -f "$database_dump" && ! -L "$database_dump" ]] \
  || { echo "database dump must be a regular non-symlink file" >&2; exit 2; }
[[ -d "$scratch_root" && ! -L "$scratch_root" ]] \
  || { echo "local validation scratch root must be a real directory" >&2; exit 2; }

for command in createdb initdb pg_ctl pg_restore psql; do
  command -v "$command" >/dev/null \
    || { echo "local dump validation requires PostgreSQL command: $command" >&2; exit 1; }
done

validation_root="$(mktemp -d "$scratch_root/northstar-backup-pg.XXXXXX")"
data_dir="$validation_root/data"
socket_dir="$validation_root/socket"
mkdir -m 0700 "$socket_dir"
server_started=false

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if [[ "$server_started" == true ]]; then
    pg_ctl -D "$data_dir" -m immediate -w stop >/dev/null 2>&1 || status=1
  fi
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

pg_ctl -D "$data_dir" -w start >/dev/null
server_started=true
createdb -h "$socket_dir" -U postgres northstar_backup_verify
pg_restore -h "$socket_dir" -U postgres -d northstar_backup_verify \
  --no-owner --no-acl --single-transaction "$database_dump"
psql -h "$socket_dir" -U postgres -d northstar_backup_verify \
  --no-psqlrc --quiet --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --field-separator=$'\t' \
  --command="SELECT id,size,COALESCE(encode(content_sha256,'hex'),'')
             FROM public.upload_slots
             WHERE uploaded AND expires_at > clock_timestamp()
             ORDER BY id" >"$upload_rows_output"

pg_ctl -D "$data_dir" -m fast -w stop >/dev/null
server_started=false
rm -rf --one-file-system -- "$validation_root"
trap - EXIT INT TERM
