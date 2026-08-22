#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 BACKUP_DIRECTORY" >&2; exit 2; }
backup_dir="$(cd "$1" && pwd -P)"
for file in READY SHA256SUMS manifest.txt database.dump database.contents uploads.tar.gz; do
  [[ -f "$backup_dir/$file" ]] || { echo "backup is incomplete: missing $file" >&2; exit 1; }
done
grep -qx 'format=northstar-backup-v1' "$backup_dir/manifest.txt" \
  || { echo "unsupported backup format" >&2; exit 1; }
(cd "$backup_dir" && sha256sum --check SHA256SUMS)
pg_restore --list "$backup_dir/database.dump" >/dev/null
archive_listing="$(tar --list --gzip --file="$backup_dir/uploads.tar.gz")"

while IFS= read -r entry; do
  case "$entry" in
    /*|../*|*/../*|*/..) echo "unsafe path in upload archive: $entry" >&2; exit 1 ;;
  esac
done <<< "$archive_listing"

echo "backup verified: $backup_dir"
