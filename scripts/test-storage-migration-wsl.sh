#!/usr/bin/env bash
# Real PostgreSQL 17 + versioned MinIO proof for offline local/S3 cutover.
set -Eeuo pipefail
umask 077

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
source "$project_dir/scripts/lib/isolated-minio-fixture.sh"
for program in cargo cmp curl "${NORTHSTAR_MINIO_ENGINE:-docker}" openssl psql python3 sha256sum; do
  command -v "$program" >/dev/null || { echo "storage migration fixture needs $program" >&2; exit 2; }
done
[[ "$(PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -p "${PGPORT:-5432}" -U xmpp_test -d xmpp_test -Atqc 'SHOW server_version_num')" == 17* ]] || {
  echo 'storage migration fixture requires isolated PostgreSQL 17 at xmpp_test' >&2
  exit 2
}

work_dir="$(mktemp -d /tmp/northstar-storage-migrate.XXXXXXXX)"
schema="northstar_storage_migrate_$(openssl rand -hex 12)"
[[ "$schema" =~ ^northstar_storage_migrate_[a-f0-9]{24}$ ]] || exit 2
cli_pid=''
schema_created=false
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$cli_pid" ]]; then
    kill "$cli_pid" 2>/dev/null || true
    wait "$cli_pid" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    for log in "$work_dir"/*.log; do
      [[ -f "$log" ]] && { echo "fixture diagnostic: ${log##*/}" >&2; tail -n 70 "$log" >&2; }
    done
  fi
  if [[ "$schema_created" == true ]]; then
    PGPASSWORD=xmpp-test-password PGOPTIONS= psql -h 127.0.0.1 -p "${PGPORT:-5432}" -U xmpp_test -d xmpp_test \
      -v ON_ERROR_STOP=1 -q -c "SET client_min_messages=warning; DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null || status=1
  fi
  northstar_minio_stop
  case "$work_dir" in
    /tmp/northstar-storage-migrate.*) rm -rf -- "$work_dir" ;;
    *) status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT

psql_fixture() {
  PGPASSWORD=xmpp-test-password PGOPTIONS="-c search_path=$schema" \
    psql -h 127.0.0.1 -p "${PGPORT:-5432}" -U xmpp_test -d xmpp_test -v ON_ERROR_STOP=1 "$@"
}
query() { psql_fixture -Atqc "$1"; }
s3() {
  python3 "$project_dir/scripts/lib/s3-fixture.py" \
    --endpoint "$NORTHSTAR_MINIO_ENDPOINT" --bucket northstar-migrate-it \
    --access-key-file "$NORTHSTAR_MINIO_ACCESS_KEY_FILE" \
    --secret-key-file "$NORTHSTAR_MINIO_SECRET_KEY_FILE" "$@"
}
namespace_digest() {
  python3 - "$1" "$2" "$NORTHSTAR_MINIO_ENDPOINT" <<'PY'
import hashlib
from pathlib import Path
import sys

backend, root, endpoint = sys.argv[1:]
digest = hashlib.sha256(b'northstar/upload-storage-namespace/v2\0')
def field(value):
    value = value.encode()
    digest.update(len(value).to_bytes(8, 'big'))
    digest.update(value)
field(backend)
if backend == 'local':
    field(str(Path(root).resolve(strict=True)))
else:
    for value in (endpoint, 'us-east-1', 'northstar-migrate-it', 'migration-it'):
        field(value)
    digest.update(bytes((1, 1, 0)))  # path-style, loopback HTTP, no SSE-KMS
print(digest.hexdigest())
PY
}

northstar_minio_start "$work_dir"
s3 create-versioned-bucket
PGPASSWORD=xmpp-test-password PGOPTIONS= psql -h 127.0.0.1 -p "${PGPORT:-5432}" -U xmpp_test -d xmpp_test \
  -v ON_ERROR_STOP=1 -q -c "CREATE SCHEMA \"$schema\"" >/dev/null
schema_created=true

source_root="$work_dir/source-local"
target_root="$work_dir/target-local"
mkdir -m 0700 "$source_root" "$target_root"
upload_id='b1f47d52-4797-41bd-944b-5d16f2585ba1'
user_id='af26cb3c-bc82-4e15-aeba-2edca8772cc9'
openssl rand 131072 >"$source_root/$upload_id"
bytes="$(stat -c %s "$source_root/$upload_id")"
sha="$(sha256sum "$source_root/$upload_id")"
sha="${sha%% *}"
local_digest="$(namespace_digest local "$source_root")"
s3_digest="$(namespace_digest s3 "$source_root")"
forward_run="$(cat /proc/sys/kernel/random/uuid)"
reverse_run="$(cat /proc/sys/kernel/random/uuid)"
missing_target_run="$(cat /proc/sys/kernel/random/uuid)"

export NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$schema"
export UPLOAD_DIR="$source_root" UPLOAD_S3_ENDPOINT="$NORTHSTAR_MINIO_ENDPOINT"
export UPLOAD_S3_BUCKET=northstar-migrate-it UPLOAD_S3_REGION=us-east-1
export UPLOAD_S3_PREFIX=migration-it UPLOAD_S3_PATH_STYLE=true UPLOAD_S3_ALLOW_HTTP=true
export UPLOAD_S3_CREDENTIAL_MODE=files
export UPLOAD_S3_ACCESS_KEY_ID_FILE="$NORTHSTAR_MINIO_ACCESS_KEY_FILE"
export UPLOAD_S3_SECRET_ACCESS_KEY_FILE="$NORTHSTAR_MINIO_SECRET_KEY_FILE"

cargo build --locked --bin rust-xmpp-server
binary="${CARGO_TARGET_DIR:-$project_dir/target}/debug/rust-xmpp-server"
"$binary" migrate >"$work_dir/migrate.log" 2>&1
psql_fixture -q -c 'SELECT northstar_upload_bind_capacity_policy(100000,1000000,1099511627776)' >/dev/null
psql_fixture -q -v user_id="$user_id" -v upload_id="$upload_id" \
  -v bytes="$bytes" -v sha="$sha" -v local_digest="$local_digest" <<'SQL' >/dev/null
INSERT INTO users(id,username,password_hash)
VALUES (:'user_id'::uuid,'migration-fixture','fixture-only');
INSERT INTO upload_storage_authority(storage_backend,namespace_sha256)
VALUES ('local',decode(:'local_digest','hex'));
INSERT INTO upload_slots(id,user_id,filename,content_type,size,token_hash,expires_at,
    uploaded,uploading,content_sha256,completed_at,put_expires_at,
    storage_backend,storage_state,storage_object_key,storage_sha256,storage_size)
VALUES (:'upload_id'::uuid,:'user_id'::uuid,'fixture.bin','application/octet-stream',
    :'bytes'::bigint,decode(repeat('22',32),'hex'),clock_timestamp()+interval '1 day',
    TRUE,FALSE,decode(:'sha','hex'),clock_timestamp(),clock_timestamp()+interval '15 minutes',
    'local','committed',:'upload_id',decode(:'sha','hex'),:'bytes'::bigint);
SQL

# The test-only pause occurs after an attempt is committed to PostgreSQL and
# before object I/O. Kill the process, then make MinIO contain that attempt's
# bytes: this is the indistinguishable "PUT succeeded, acknowledgement lost"
# case. Recovery must retire its key and create a fresh destination identity.
NORTHSTAR_STORAGE_MIGRATION_TEST_PAUSE_AFTER_CLAIM=true \
  "$binary" storage migrate --from local --to s3 --all-nodes-stopped \
  --run-id "$forward_run" >"$work_dir/interrupted.log" 2>&1 &
cli_pid=$!
ambiguous_key=''
for _ in $(seq 1 200); do
  ambiguous_key="$(query "SELECT dest_key FROM upload_storage_migration_attempts WHERE run_id='$forward_run'::uuid ORDER BY created_at LIMIT 1")"
  [[ -n "$ambiguous_key" ]] && break
  if ! kill -0 "$cli_pid" 2>/dev/null; then
    echo 'migration exited before a durable attempt was recorded' >&2
    exit 1
  fi
  sleep 0.1
done
[[ "$ambiguous_key" == "objects/$upload_id/"* ]] || {
  echo 'migration did not journal an S3 attempt before the timeout' >&2
  exit 1
}
kill -KILL "$cli_pid"
wait "$cli_pid" 2>/dev/null || true
cli_pid=''
ambiguous_version="$(s3 put "migration-it/$ambiguous_key" "$source_root/$upload_id")"
[[ -n "$ambiguous_version" ]]
[[ "$(query "SELECT storage_backend FROM upload_storage_authority WHERE singleton")" == local ]]

if UPLOAD_S3_PREFIX=wrong-namespace "$binary" storage migrate --from local --to s3 \
  --all-nodes-stopped --run-id "$forward_run" >"$work_dir/wrong-namespace.log" 2>&1; then
  echo 'migration accepted the wrong S3 namespace' >&2
  exit 1
fi
[[ "$(query "SELECT state FROM upload_storage_migration_runs WHERE run_id='$forward_run'::uuid")" == copying ]]
psql_fixture -q -c "UPDATE upload_storage_migration_items SET claim_expires_at=clock_timestamp()-interval '1 second' WHERE run_id='$forward_run'::uuid AND claim_token IS NOT NULL" >/dev/null
"$binary" storage migrate --from local --to s3 --all-nodes-stopped \
  --run-id "$forward_run" >"$work_dir/forward.log" 2>&1

[[ "$(query "SELECT state FROM upload_storage_migration_runs WHERE run_id='$forward_run'::uuid")" == cutover ]]
[[ "$(query "SELECT storage_backend||'|'||generation FROM upload_storage_authority WHERE singleton")" == 's3|2' ]]
[[ "$(query "SELECT encode(namespace_sha256,'hex') FROM upload_storage_authority WHERE singleton")" == "$s3_digest" ]]
[[ "$(query "SELECT count(*) FROM upload_storage_migration_attempts WHERE run_id='$forward_run'::uuid AND state='retired'")" == 1 ]]
[[ "$(query "SELECT count(*) FROM upload_storage_migration_attempts WHERE run_id='$forward_run'::uuid AND state='verified'")" == 1 ]]
IFS='|' read -r final_key final_version final_sha <<<"$(query "SELECT storage_object_key||'|'||storage_object_version||'|'||encode(storage_sha256,'hex') FROM upload_slots WHERE id='$upload_id'::uuid")"
[[ "$final_key" != "$ambiguous_key" && -n "$final_version" && "$final_sha" == "$sha" ]]
s3 get "migration-it/$ambiguous_key" "$ambiguous_version" "$work_dir/ambiguous.bin" >/dev/null
s3 get "migration-it/$final_key" "$final_version" "$work_dir/forward.bin" >/dev/null
cmp "$source_root/$upload_id" "$work_dir/ambiguous.bin"
cmp "$source_root/$upload_id" "$work_dir/forward.bin"

# A later S3 version must not replace the exact version pinned by PostgreSQL.
printf 'newer unrelated bytes' >"$work_dir/newer.bin"
newer_version="$(s3 put "migration-it/$final_key" "$work_dir/newer.bin")"
[[ "$newer_version" != "$final_version" ]]
export UPLOAD_DIR="$target_root"
if UPLOAD_S3_PREFIX=wrong-namespace "$binary" storage migrate --from s3 --to local \
  --all-nodes-stopped --run-id "$reverse_run" >"$work_dir/wrong-reverse-namespace.log" 2>&1; then
  echo 'reverse migration accepted the wrong source namespace' >&2
  exit 1
fi
[[ "$(query "SELECT count(*) FROM upload_storage_migration_runs WHERE run_id='$reverse_run'::uuid")" == 0 ]]
"$binary" storage migrate --from s3 --to local --all-nodes-stopped \
  --run-id "$reverse_run" >"$work_dir/reverse.log" 2>&1
[[ "$(query "SELECT storage_backend||'|'||generation FROM upload_storage_authority WHERE singleton")" == 'local|3' ]]
[[ "$(query "SELECT encode(namespace_sha256,'hex') FROM upload_storage_authority WHERE singleton")" == "$(namespace_digest local "$target_root")" ]]
[[ "$(query "SELECT storage_backend||'|'||storage_object_key||'|'||encode(storage_sha256,'hex') FROM upload_slots WHERE id='$upload_id'::uuid")" == "local|$upload_id|$sha" ]]
cmp "$source_root/$upload_id" "$target_root/$upload_id"
s3 get "migration-it/$final_key" "$final_version" "$work_dir/retained-source.bin" >/dev/null
cmp "$source_root/$upload_id" "$work_dir/retained-source.bin"

# A destination can disappear after copy verification but before the final
# database transaction. Remove the pinned S3 version at that precise boundary
# and require the cutover to leave both the authority and source slot intact.
NORTHSTAR_STORAGE_MIGRATION_TEST_PAUSE_BEFORE_CUTOVER=true \
  "$binary" storage migrate --from local --to s3 --all-nodes-stopped \
  --run-id "$missing_target_run" >"$work_dir/missing-target.log" 2>&1 &
cli_pid=$!
missing_key=''
missing_version=''
for _ in $(seq 1 200); do
  IFS='|' read -r missing_key missing_version <<<"$(query "SELECT dest_key||'|'||dest_version FROM upload_storage_migration_items WHERE run_id='$missing_target_run'::uuid AND verified_at IS NOT NULL")"
  [[ -n "$missing_key" && -n "$missing_version" ]] && break
  if ! kill -0 "$cli_pid" 2>/dev/null; then
    echo 'migration exited before recording a verified S3 destination' >&2
    exit 1
  fi
  sleep 0.1
done
[[ "$missing_key" == "objects/$upload_id/"* && -n "$missing_version" ]] || {
  echo 'migration did not expose its pinned S3 destination before the timeout' >&2
  exit 1
}
s3 delete-version "migration-it/$missing_key" "$missing_version"
if wait "$cli_pid"; then
  echo 'migration cut over after its verified S3 destination was deleted' >&2
  exit 1
fi
cli_pid=''
[[ "$(query "SELECT state FROM upload_storage_migration_runs WHERE run_id='$missing_target_run'::uuid")" == copying ]]
[[ "$(query "SELECT storage_backend||'|'||generation FROM upload_storage_authority WHERE singleton")" == 'local|3' ]]
[[ "$(query "SELECT storage_backend||'|'||storage_object_key FROM upload_slots WHERE id='$upload_id'::uuid")" == "local|$upload_id" ]]
cmp "$source_root/$upload_id" "$target_root/$upload_id"
echo 'storage migration: interrupted attempt retired; exact versions retained; missing verified destination refused; bidirectional cutover passed'
