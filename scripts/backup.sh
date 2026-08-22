#!/usr/bin/env bash
set -euo pipefail

umask 077
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output_root="$project_dir/backups"
database_url_file="${DATABASE_URL_FILE:-}"
upload_dir="${UPLOAD_DIR:-$project_dir/data/uploads}"
retention_days=0

usage() {
  echo "usage: $0 [--output DIR] [--database-url-file FILE] [--upload-dir DIR] [--retention-days DAYS]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output_root="${2:?missing output directory}"; shift 2 ;;
    --database-url-file) database_url_file="${2:?missing database URL file}"; shift 2 ;;
    --upload-dir) upload_dir="${2:?missing upload directory}"; shift 2 ;;
    --retention-days) retention_days="${2:?missing retention days}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ "$retention_days" =~ ^[0-9]+$ ]] || { echo "retention days must be a non-negative integer" >&2; exit 2; }
for command in python3 pg_dump pg_restore psql tar sha256sum; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done

pg_client=(python3 "$script_dir/run-postgres.py")
if [[ -n "$database_url_file" ]]; then
  pg_client+=(--database-url-file "$database_url_file")
fi
pg_client+=(--)

mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd -P)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_dir="$output_root/northstar-$timestamp"
[[ ! -e "$final_dir" ]] || { echo "backup already exists: $final_dir" >&2; exit 1; }
staging="$(mktemp -d "$output_root/.northstar-backup.XXXXXX")"
cleanup() {
  [[ ! -d "$staging" ]] && return
  case "$staging" in
    "$output_root"/.northstar-backup.*) rm -rf -- "$staging" ;;
    *) echo "refusing to clean unexpected backup staging path: $staging" >&2 ;;
  esac
}
trap cleanup EXIT

"${pg_client[@]}" pg_dump \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-acl \
  --file="$staging/database.dump"
pg_restore --list "$staging/database.dump" > "$staging/database.contents"

if [[ -d "$upload_dir" ]]; then
  upload_dir="$(cd "$upload_dir" && pwd -P)"
  tar --create --gzip --file="$staging/uploads.tar.gz" \
    --exclude='*.part' \
    --exclude='.pre-restore.*' \
    --exclude='.northstar-restore.*' \
    --directory="$upload_dir" .
else
  tar --create --gzip --file="$staging/uploads.tar.gz" --files-from=/dev/null
fi

database_version="$("${pg_client[@]}" psql --no-psqlrc --tuples-only --no-align --command='SHOW server_version' | tr -d '\r\n')"
migration_count="$("${pg_client[@]}" psql --no-psqlrc --tuples-only --no-align --command='SELECT COUNT(*) FROM _sqlx_migrations WHERE success' | tr -d '\r\n')"
cat > "$staging/manifest.txt" <<EOF
format=northstar-backup-v1
created_at=$timestamp
postgresql_version=$database_version
successful_migrations=$migration_count
database_archive=database.dump
upload_archive=uploads.tar.gz
upload_consistency=immutable-final-files
EOF
(cd "$staging" && sha256sum database.dump database.contents uploads.tar.gz manifest.txt > SHA256SUMS)
touch "$staging/READY"
mv -- "$staging" "$final_dir"
trap - EXIT

if (( retention_days > 0 )); then
  find "$output_root" -mindepth 1 -maxdepth 1 -type d -name 'northstar-*' \
    -mtime "+$retention_days" -exec rm -rf -- {} +
fi

echo "backup complete: $final_dir"
