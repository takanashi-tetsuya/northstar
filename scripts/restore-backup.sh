#!/usr/bin/env bash
set -euo pipefail

umask 077
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
backup_dir=""
database_url_file="${DATABASE_URL_FILE:-}"
upload_dir="${UPLOAD_DIR:-$project_dir/data/uploads}"
confirmation=""

usage() {
  echo "usage: $0 BACKUP_DIRECTORY --confirm-restore NORTHSTAR-RESTORE [--database-url-file FILE] [--upload-dir DIR]" >&2
}

[[ $# -gt 0 ]] || { usage; exit 2; }
backup_dir="$1"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm-restore) confirmation="${2:-}"; shift 2 ;;
    --database-url-file) database_url_file="${2:?missing database URL file}"; shift 2 ;;
    --upload-dir) upload_dir="${2:?missing upload directory}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$confirmation" == "NORTHSTAR-RESTORE" ]] \
  || { echo "restore refused: explicit confirmation phrase is required" >&2; exit 2; }

bash "$script_dir/verify-backup.sh" "$backup_dir"
backup_dir="$(cd "$backup_dir" && pwd -P)"
for command in python3 pg_restore psql tar; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done
pg_client=(python3 "$script_dir/run-postgres.py")
if [[ -n "$database_url_file" ]]; then
  pg_client+=(--database-url-file "$database_url_file")
fi
pg_client+=(--)

mkdir -p "$upload_dir"
resolved_upload="$(cd "$upload_dir" && pwd -P)"
[[ "$resolved_upload" != "/" && "$resolved_upload" != "$project_dir" ]] \
  || { echo "refusing broad upload restore target: $resolved_upload" >&2; exit 2; }

extract_dir="$(mktemp -d "$resolved_upload/.northstar-restore.XXXXXX")"
cleanup() {
  [[ ! -d "$extract_dir" ]] && return
  case "$extract_dir" in
    "$resolved_upload"/.northstar-restore.*) rm -rf -- "$extract_dir" ;;
    *) echo "refusing to clean unexpected restore staging path: $extract_dir" >&2 ;;
  esac
}
trap cleanup EXIT
tar --extract --gzip --file="$backup_dir/uploads.tar.gz" --directory="$extract_dir"

echo "Restoring PostgreSQL. Stop Northstar first; active writers are not supported during restore." >&2
"${pg_client[@]}" pg_restore "$backup_dir/database.dump" \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  --single-transaction \
  --file=- \
  | "${pg_client[@]}" psql --no-psqlrc --set ON_ERROR_STOP=1

previous_uploads="$resolved_upload/.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$previous_uploads"
while IFS= read -r -d '' entry; do
  mv -- "$entry" "$previous_uploads/"
done < <(find "$resolved_upload" -mindepth 1 -maxdepth 1 \
  ! -path "$extract_dir" ! -path "$previous_uploads" -print0)
while IFS= read -r -d '' entry; do
  mv -- "$entry" "$resolved_upload/"
done < <(find "$extract_dir" -mindepth 1 -maxdepth 1 -print0)
rmdir "$extract_dir"
trap - EXIT

missing=0
uploaded_rows="$("${pg_client[@]}" psql --no-psqlrc --tuples-only --no-align --field-separator=$'\t' \
  --command='SELECT id, size FROM upload_slots WHERE uploaded ORDER BY id')"
while IFS=$'\t' read -r upload_id expected_size; do
  [[ -n "$upload_id" ]] || continue
  path="$resolved_upload/$upload_id"
  if [[ ! -f "$path" || "$(stat -c '%s' "$path")" != "$expected_size" ]]; then
    echo "restored upload is missing or has the wrong size: $upload_id" >&2
    missing=$((missing + 1))
  fi
done <<< "$uploaded_rows"
(( missing == 0 )) || { echo "restore completed with $missing upload integrity error(s)" >&2; exit 1; }

echo "restore complete: database and $resolved_upload"
echo "previous upload files retained at: $previous_uploads"
