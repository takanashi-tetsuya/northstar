#!/usr/bin/env bash
set -euo pipefail

umask 077
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output_root="$project_dir/backups"
database_url_file="${DATABASE_URL_FILE:-}"
upload_dir="${UPLOAD_DIR:-$project_dir/data/uploads}"
retention_days=0
signing_key_file="${BACKUP_SIGNING_KEY_FILE:-}"
require_signature="${BACKUP_REQUIRE_SIGNATURE:-false}"
age_recipient_file="${BACKUP_AGE_RECIPIENT_FILE:-}"
sequence_state_file="${BACKUP_SEQUENCE_STATE_FILE:-}"
northstar_version="${NORTHSTAR_BACKUP_APPLICATION_VERSION:-${NORTHSTAR_VERSION:-unknown}}"
plaintext_staging_root="${BACKUP_PLAINTEXT_STAGING_DIR:-}"
security_policy="${BACKUP_SECURITY_POLICY:-production}"
maintenance_lock_key=735559096281326101
migration_ledger_manifest="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
migration_count=''

usage() {
  cat >&2 <<EOF
usage: $0 [OPTIONS]

Create a Northstar backup with a versioned, monotonic manifest.

Options:
  --output DIR                 Backup destination root
  --database-url-file FILE     PostgreSQL URL secret file
  --upload-dir DIR             Immutable upload-object directory
  --retention-days DAYS        Delete canonical backups older than DAYS
  --sequence-state-file FILE   Persistent generation/sequence state
  --signing-key-file FILE      OpenSSL Ed25519 private key (file only)
  --require-signature          Fail unless a signing key file is configured
  --age-recipient-file FILE    age recipient file; encrypt all payloads
  --plaintext-staging-dir DIR  Private scratch for pre-encryption payloads
  --northstar-version VERSION  Application/build version for the manifest
  --development-insecure-legacy
                               Explicitly allow unsigned/unencrypted development backups
  -h, --help                   Show this help

Environment equivalents:
  BACKUP_SEQUENCE_STATE_FILE, BACKUP_SIGNING_KEY_FILE,
  BACKUP_REQUIRE_SIGNATURE, BACKUP_AGE_RECIPIENT_FILE,
  BACKUP_PLAINTEXT_STAGING_DIR, BACKUP_SECURITY_POLICY,
  NORTHSTAR_BACKUP_APPLICATION_VERSION (or NORTHSTAR_VERSION).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output_root="${2:?missing output directory}"; shift 2 ;;
    --database-url-file) database_url_file="${2:?missing database URL file}"; shift 2 ;;
    --upload-dir) upload_dir="${2:?missing upload directory}"; shift 2 ;;
    --retention-days) retention_days="${2:?missing retention days}"; shift 2 ;;
    --sequence-state-file) sequence_state_file="${2:?missing sequence state file}"; shift 2 ;;
    --signing-key-file) signing_key_file="${2:?missing signing key file}"; shift 2 ;;
    --require-signature) require_signature=true; shift ;;
    --age-recipient-file) age_recipient_file="${2:?missing age recipient file}"; shift 2 ;;
    --plaintext-staging-dir) plaintext_staging_root="${2:?missing plaintext staging directory}"; shift 2 ;;
    --northstar-version) northstar_version="${2:?missing Northstar version}"; shift 2 ;;
    --development-insecure-legacy) security_policy=development-legacy; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

case "$security_policy" in
  production)
    require_signature=true
    ;;
  development-legacy)
    printf '%s\n' \
      'WARNING: development-legacy backup policy permits unauthenticated or unencrypted backups; never use it for production data.' >&2
    ;;
  *)
    echo "BACKUP_SECURITY_POLICY must be production or development-legacy" >&2
    exit 2
    ;;
esac

[[ "$retention_days" =~ ^[0-9]+$ ]] || { echo "retention days must be a non-negative integer" >&2; exit 2; }
case "${require_signature,,}" in
  1|true|yes) require_signature=true ;;
  0|false|no) require_signature=false ;;
  *) echo "BACKUP_REQUIRE_SIGNATURE must be true or false" >&2; exit 2 ;;
esac
[[ "$northstar_version" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$ ]] \
  || { echo "Northstar version is not a safe manifest identifier" >&2; exit 2; }
[[ -f "$migration_ledger_manifest" && ! -L "$migration_ledger_manifest" \
   && -r "$migration_ledger_manifest" ]] \
  || { echo "repository migration ledger manifest is missing" >&2; exit 1; }
for command in chmod grep id mktemp mv python3 pg_dump pg_restore psql rm \
  sha256sum stat tar touch tr; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done
if [[ "$require_signature" == true && -z "$signing_key_file" ]]; then
  echo "backup signature is required but no signing key file was configured" >&2
  exit 2
fi
if [[ "$security_policy" == production ]]; then
  [[ -n "$database_url_file" ]] \
    || { echo "production backup requires --database-url-file" >&2; exit 2; }
  [[ -f "$database_url_file" && ! -L "$database_url_file" && -r "$database_url_file" ]] \
    || { echo "production database URL must be a readable regular non-symlink file" >&2; exit 2; }
  [[ -n "$age_recipient_file" ]] \
    || { echo "production backup requires an age recipient file" >&2; exit 2; }
  [[ -n "$sequence_state_file" ]] \
    || { echo "production backup requires an explicit persistent sequence-state file" >&2; exit 2; }
  [[ -n "$plaintext_staging_root" ]] \
    || { echo "production backup requires an explicit private plaintext staging directory" >&2; exit 2; }
fi
if [[ -n "$signing_key_file" ]]; then
  command -v openssl >/dev/null || { echo "required command is unavailable: openssl" >&2; exit 1; }
  [[ -f "$signing_key_file" && ! -L "$signing_key_file" && -r "$signing_key_file" ]] \
    || { echo "signing key must be a readable regular non-symlink file" >&2; exit 2; }
  key_mode="$(stat -c '%a' "$signing_key_file")"
  (( (8#$key_mode & 077) == 0 )) || [[ "$signing_key_file" == /run/secrets/* ]] \
    || { echo "signing key must not be accessible to group or other users" >&2; exit 2; }
  openssl pkey -in "$signing_key_file" -passin pass: -text -noout 2>/dev/null \
    | grep -q 'ED25519' \
    || { echo "signing key must be an unencrypted OpenSSL Ed25519 private key" >&2; exit 2; }
fi
if [[ -n "$age_recipient_file" ]]; then
  command -v age >/dev/null || { echo "required command is unavailable: age" >&2; exit 1; }
  [[ -f "$age_recipient_file" && ! -L "$age_recipient_file" && -r "$age_recipient_file" ]] \
    || { echo "age recipients must be a readable regular non-symlink file" >&2; exit 2; }
  age --encrypt --recipients-file "$age_recipient_file" /dev/null >/dev/null \
    || { echo "age recipient file is invalid" >&2; exit 2; }
fi

pg_client=(python3 "$script_dir/run-postgres.py")
if [[ -n "$database_url_file" ]]; then
  pg_client+=(--database-url-file "$database_url_file")
fi
pg_client+=(--)

attest_backup_database_role() {
  local result
  result=$("${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align \
    --set ON_ERROR_STOP=1 --command "
WITH role AS (
  SELECT * FROM pg_catalog.pg_roles WHERE rolname=current_user
), app_schema AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace WHERE nspname='public'
)
SELECT current_user='northstar_backup'
   AND (SELECT rolcanlogin AND NOT rolsuper AND NOT rolinherit
          AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
          AND NOT rolbypassrls AND rolconnlimit=2 FROM role)
   AND pg_catalog.pg_get_userbyid(
         (SELECT datdba FROM pg_catalog.pg_database WHERE datname=current_database())
       )<>current_user
   AND pg_catalog.pg_get_userbyid((SELECT nspowner FROM app_schema))<>current_user
   AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')
   AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP')
   AND pg_catalog.has_database_privilege(current_user,current_database(),'CONNECT')
   AND pg_catalog.has_schema_privilege(current_user,(SELECT oid FROM app_schema),'USAGE')
   AND NOT pg_catalog.has_schema_privilege(current_user,(SELECT oid FROM app_schema),'CREATE')
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_auth_members membership, role
      WHERE membership.member=role.oid OR membership.roleid=role.oid
   )
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_class relation
     JOIN app_schema ON app_schema.oid=relation.relnamespace
     WHERE relation.relkind IN ('r','p','v','m','f')
       AND (pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
         OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
         OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
         OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
         OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
         OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
         OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
         OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
         OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES'))
   )
   AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class sequence
      JOIN app_schema ON app_schema.oid=sequence.relnamespace
      WHERE sequence.relkind='S'
        AND CASE
              WHEN sequence.relkind='S' THEN (
                pg_catalog.has_sequence_privilege(current_user,sequence.oid,'USAGE')
                OR pg_catalog.has_sequence_privilege(current_user,sequence.oid,'UPDATE')
              )
              ELSE FALSE
            END
   )
   AND NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_proc routine
     JOIN app_schema ON app_schema.oid=routine.pronamespace
     WHERE pg_catalog.has_function_privilege(current_user,routine.oid,'EXECUTE')
   );")
  [[ "$result" == 't' ]] || {
    echo 'backup PostgreSQL role attestation failed: use the bounded read-only northstar_backup URL; runtime, migrator, owner and writable identities are refused' >&2
    return 1
  }
}

if [[ "$security_policy" == production ]]; then
  attest_backup_database_role
fi

mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd -P)"
resolved_home=""
if [[ -n "${HOME:-}" && -d "$HOME" ]]; then
  resolved_home="$(cd "$HOME" && pwd -P)"
fi
if [[ "$output_root" == "/" || "$output_root" == "$project_dir" ]] \
   || [[ -n "$resolved_home" && "$output_root" == "$resolved_home" ]]; then
  echo "refusing broad backup output directory: $output_root" >&2
  exit 2
fi
if [[ -z "$sequence_state_file" ]]; then
  sequence_state_file="$output_root/.northstar-backup-state"
else
  sequence_state_parent="$(dirname -- "$sequence_state_file")"
  [[ -d "$sequence_state_parent" && ! -L "$sequence_state_parent" ]] \
    || { echo "sequence state parent must be a pre-created real directory" >&2; exit 2; }
  sequence_state_parent="$(cd "$sequence_state_parent" && pwd -P)"
  [[ "$(stat -c '%u:%g' "$sequence_state_parent")" == "$(id -u):$(id -g)" \
     && "$(stat -c '%a' "$sequence_state_parent")" == 700 ]] \
    || { echo "explicit sequence-state parent must be owner-owned mode 0700" >&2; exit 2; }
  sequence_state_file="$sequence_state_parent/$(basename -- "$sequence_state_file")"
fi
if [[ -e "$sequence_state_file" || -L "$sequence_state_file" ]]; then
  [[ -f "$sequence_state_file" && ! -L "$sequence_state_file" ]] \
    || { echo "sequence state must be a regular non-symlink file" >&2; exit 2; }
fi
read -r backup_generation backup_sequence \
  < <(python3 "$script_dir/backup-security.py" reserve-sequence "$sequence_state_file")
[[ -n "$backup_generation" && -n "$backup_sequence" ]] \
  || { echo "failed to reserve a backup sequence" >&2; exit 1; }
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
final_dir="$output_root/northstar-$timestamp"
[[ ! -e "$final_dir" ]] || { echo "backup already exists: $final_dir" >&2; exit 1; }
if [[ -n "$age_recipient_file" ]]; then
  [[ -n "$plaintext_staging_root" ]] || plaintext_staging_root="${TMPDIR:-/tmp}"
  [[ -d "$plaintext_staging_root" && ! -L "$plaintext_staging_root" ]] \
    || { echo "plaintext staging root must be a pre-created real directory" >&2; exit 2; }
  plaintext_staging_root="$(cd "$plaintext_staging_root" && pwd -P)"
  if [[ "$plaintext_staging_root" == "$output_root" \
        || "$plaintext_staging_root" == "$output_root"/* \
        || "$output_root" == "$plaintext_staging_root"/* ]]; then
    echo "encrypted backup plaintext staging must be outside the backup destination" >&2
    exit 2
  fi
fi
validation_staging_root="$plaintext_staging_root"
if [[ -z "$validation_staging_root" ]]; then
  validation_staging_root="${TMPDIR:-/tmp}"
fi
[[ -d "$validation_staging_root" && ! -L "$validation_staging_root" ]] \
  || { echo "local validation scratch root must be a pre-created real directory" >&2; exit 2; }
validation_staging_root="$(cd "$validation_staging_root" && pwd -P)"
staging="$(mktemp -d "$output_root/.northstar-backup.XXXXXX")"
payload_staging="$staging"
private_payload_staging=""
maintenance_session_started=false
maintenance_session_pid=""
maintenance_session_in=""
maintenance_session_out=""

close_maintenance_session() {
  if [[ "$maintenance_session_started" != true ]]; then
    return 0
  fi
  if [[ -e "/proc/$$/fd/$maintenance_session_in" ]]; then
    printf '%s\n' '\q' >&"$maintenance_session_in" || true
    exec {maintenance_session_in}>&- || true
  fi
  if [[ -e "/proc/$$/fd/$maintenance_session_out" ]]; then
    exec {maintenance_session_out}<&- || true
  fi
  wait "$maintenance_session_pid" 2>/dev/null || true
  maintenance_session_started=false
}

maintenance_session_command() {
  local input_file="$1" output_file="$2"
  local token="__NORTHSTAR_BACKUP_DONE_$(python3 -c 'import secrets; print(secrets.token_hex(8))')__"
  [[ -e "/proc/$$/fd/$maintenance_session_in" \
     && -e "/proc/$$/fd/$maintenance_session_out" ]] || return 1
  : >"$output_file"
  {
    cat "$input_file"
    printf '\n\\echo %s\n' "$token"
  } >&"$maintenance_session_in" || return 1
  while IFS= read -r line <&"$maintenance_session_out"; do
    if [[ "$line" == "$token" ]]; then
      return 0
    fi
    printf '%s\n' "$line" >>"$output_file"
  done
  return 1
}

start_maintenance_session() {
  local sql_file="$staging/maintenance-lock.sql" output_file="$staging/maintenance-lock.out"
  coproc BACKUP_DB_SESSION {
    "${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
  }
  maintenance_session_out="${BACKUP_DB_SESSION[0]}"
  maintenance_session_in="${BACKUP_DB_SESSION[1]}"
  maintenance_session_pid="$BACKUP_DB_SESSION_PID"
  maintenance_session_started=true
  cat >"$sql_file" <<SQL
SET application_name TO 'northstar-backup';
SELECT CASE WHEN pg_try_advisory_lock($maintenance_lock_key)
       THEN '__MAINTENANCE_LOCK_OK__' ELSE '__MAINTENANCE_LOCK_BUSY__' END;
SELECT CASE WHEN pg_try_advisory_lock(
                   pg_catalog.hashtextextended(
                     'northstar-database-role-policy-v1',0
                   )
                 )
       THEN '__POLICY_LOCK_OK__' ELSE '__POLICY_LOCK_BUSY__' END;
SQL
  maintenance_session_command "$sql_file" "$output_file"
  grep -qx '__MAINTENANCE_LOCK_OK__' "$output_file" \
    || { echo "another backup or restore holds the PostgreSQL maintenance fence" >&2; return 1; }
  grep -qx '__POLICY_LOCK_OK__' "$output_file" \
    || { echo "a migration or database-grant reconciliation holds the PostgreSQL policy fence" >&2; return 1; }
  rm -- "$sql_file" "$output_file"
}

attest_repository_migration_ledger() {
  local sql_file="$staging/migration-ledger-attestation.sql"
  local result accepted
  python3 - "$migration_ledger_manifest" "$sql_file" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
output = pathlib.Path(sys.argv[2])
row = re.compile(
    r"^\s*\(([0-9]+),'((?:[^']|'')*)',"
    r"pg_catalog\.decode\('([0-9a-f]{96})','hex'\)\)[,;]\s*$",
    re.MULTILINE,
)
rows = row.findall(source)
if not rows:
    raise SystemExit("repository migration ledger manifest contains no rows")
versions = [int(version, 10) for version, _, _ in rows]
gaps = set(range(1, max(versions) + 1)) - set(versions)
if (
    versions != sorted(versions)
    or len(versions) != len(set(versions))
    or any(version <= 0 for version in versions)
    or gaps != {21}
    or any(not description.replace("''", "'").strip() for _, description, _ in rows)
    or source.count("pg_catalog.decode('") != len(rows)
    or source.count("\\set northstar_migration_ledger_manifest_is_loaded true") != 1
):
    raise SystemExit(
        "repository migration ledger manifest is malformed, unexpectedly gapped, or duplicated"
    )
values = ",\n".join(
    f"({version},'{description}',pg_catalog.decode('{checksum}','hex'))"
    for version, description, checksum in rows
)
sql = f"""WITH expected(version,description,checksum) AS (VALUES
{values}
), actual AS (
  SELECT version,description,success,checksum
    FROM public._sqlx_migrations
)
SELECT (
  NOT EXISTS (
    SELECT 1 FROM actual
     WHERE NOT success OR version<=0 OR description=''
        OR pg_catalog.octet_length(checksum)<>48
  )
  AND (SELECT pg_catalog.count(*) FROM actual)
      =(SELECT pg_catalog.count(DISTINCT version) FROM actual)
  AND (SELECT pg_catalog.count(*) FROM actual)
      =(SELECT pg_catalog.count(*) FROM expected)
  AND NOT EXISTS (
    (SELECT version,description,checksum FROM actual WHERE success
     EXCEPT SELECT version,description,checksum FROM expected)
    UNION ALL
    (SELECT version,description,checksum FROM expected
     EXCEPT SELECT version,description,checksum FROM actual WHERE success)
  )
)::pg_catalog.text || '|' || (SELECT pg_catalog.count(*) FROM expected)::pg_catalog.text;
"""
output.write_text(sql, encoding="utf-8", newline="\n")
PY
  chmod 0600 "$sql_file"
  result=$("${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align \
    --set ON_ERROR_STOP=1 --file "$sql_file" | tr -d '\r\n')
  rm -- "$sql_file"
  accepted=${result%%|*}
  migration_count=${result#*|}
  [[ "$accepted" == true && "$migration_count" =~ ^[1-9][0-9]*$ ]] || {
    echo 'backup refused: database migration ledger differs by version, description, success, or SHA-384 checksum' >&2
    return 1
  }
}

cleanup() {
  cleanup_status=$?
  trap - EXIT
  set +e
  close_maintenance_session
  if [[ -n "$private_payload_staging" && -d "$private_payload_staging" ]]; then
    case "$private_payload_staging" in
      "$plaintext_staging_root"/northstar-backup-plaintext.*)
        rm -rf --one-file-system -- "$private_payload_staging"
        ;;
      *) echo "refusing to clean unexpected plaintext staging path" >&2 ;;
    esac
  fi
  if [[ -d "$staging" ]]; then
    case "$staging" in
      "$output_root"/.northstar-backup.*) rm -rf --one-file-system -- "$staging" ;;
      *) echo "refusing to clean unexpected backup staging path: $staging" >&2; cleanup_status=1 ;;
    esac
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
if [[ -n "$age_recipient_file" ]]; then
  private_payload_staging="$(mktemp -d "$plaintext_staging_root/northstar-backup-plaintext.XXXXXX")"
  chmod 0700 "$private_payload_staging"
  payload_staging="$private_payload_staging"
fi

start_maintenance_session
attest_repository_migration_ledger

"${pg_client[@]}" pg_dump \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-acl \
  --file="$payload_staging/database.dump"
pg_restore --list "$payload_staging/database.dump" > "$payload_staging/database.contents"

if [[ -d "$upload_dir" ]]; then
  upload_dir="$(cd "$upload_dir" && pwd -P)"
  tar --create --gzip --file="$payload_staging/uploads.tar.gz" \
    --exclude='*.part' \
    --exclude='.northstar-upload-root' \
    --exclude='.pre-restore.*' \
    --exclude='.northstar-restore.*' \
    --exclude='.northstar-restore-*' \
    --directory="$upload_dir" .
else
  tar --create --gzip --file="$payload_staging/uploads.tar.gz" --files-from=/dev/null
fi
python3 "$script_dir/verify-upload-archive.py" "$payload_staging/uploads.tar.gz"

# Prove that every live upload referenced by the exact database dump is present
# in the captured archive with the authoritative size and digest. Extra archive
# objects are harmless; a missing or changed referenced object blocks READY.
upload_rows="$payload_staging/upload-rows.tsv"
bash "$script_dir/validate-backup-dump-local.sh" \
  "$payload_staging/database.dump" "$validation_staging_root" "$upload_rows"
python3 - "$payload_staging/uploads.tar.gz" "$upload_rows" <<'PY'
import hashlib
import pathlib
import re
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
rows_path = pathlib.Path(sys.argv[2])
uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
required = {}
for number, raw in enumerate(rows_path.read_text(encoding="ascii").splitlines(), 1):
    fields = raw.split("\t")
    if len(fields) != 3 or not uuid_re.fullmatch(fields[0]) or not fields[1].isdigit():
        raise SystemExit(f"invalid upload metadata in dump at row {number}")
    if fields[2] and not re.fullmatch(r"[0-9a-f]{64}", fields[2]):
        raise SystemExit(f"invalid upload digest in dump at row {number}")
    required[fields[0]] = (int(fields[1]), fields[2])

seen = set()
with tarfile.open(archive_path, mode="r:gz") as archive:
    for member in archive:
        name = pathlib.PurePosixPath(member.name).name
        if not member.isfile() or name not in required:
            continue
        if name in seen:
            raise SystemExit(f"duplicate referenced upload object in archive: {name}")
        expected_size, expected_digest = required[name]
        if member.size != expected_size:
            raise SystemExit(f"referenced upload has wrong archived size: {name}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit(f"referenced upload could not be read: {name}")
        digest = hashlib.sha256()
        for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
            digest.update(chunk)
        if expected_digest and digest.hexdigest() != expected_digest:
            raise SystemExit(f"referenced upload has wrong archived digest: {name}")
        seen.add(name)
missing = sorted(required.keys() - seen)
if missing:
    raise SystemExit(f"database dump references missing upload objects: {missing}")
PY
rm -- "$upload_rows"

database_version="$("${pg_client[@]}" psql --no-psqlrc --tuples-only --no-align --command='SHOW server_version' | tr -d '\r\n')"
database_plain_sha256="$(sha256sum "$payload_staging/database.dump" | awk '{print $1}')"
database_contents_plain_sha256="$(sha256sum "$payload_staging/database.contents" | awk '{print $1}')"
upload_plain_sha256="$(sha256sum "$payload_staging/uploads.tar.gz" | awk '{print $1}')"

encryption=none
database_archive=database.dump
database_contents=database.contents
upload_archive=uploads.tar.gz
if [[ -n "$age_recipient_file" ]]; then
  encryption=age
  age --encrypt --recipients-file "$age_recipient_file" \
    --output "$staging/database.dump.age" "$payload_staging/database.dump"
  age --encrypt --recipients-file "$age_recipient_file" \
    --output "$staging/database.contents.age" "$payload_staging/database.contents"
  age --encrypt --recipients-file "$age_recipient_file" \
    --output "$staging/uploads.tar.gz.age" "$payload_staging/uploads.tar.gz"
  database_archive=database.dump.age
  database_contents=database.contents.age
  upload_archive=uploads.tar.gz.age
fi
database_archive_sha256="$(sha256sum "$staging/$database_archive" | awk '{print $1}')"
database_contents_archive_sha256="$(sha256sum "$staging/$database_contents" | awk '{print $1}')"
upload_archive_sha256="$(sha256sum "$staging/$upload_archive" | awk '{print $1}')"

signature=none
signing_key_id=none
if [[ -n "$signing_key_file" ]]; then
  signature=openssl-ed25519
  openssl pkey -in "$signing_key_file" -passin pass: -pubout \
    -out "$staging/.signing-public.pem" 2>/dev/null \
    || { echo "signing key must be an unencrypted OpenSSL private key" >&2; exit 1; }
  openssl pkey -pubin -in "$staging/.signing-public.pem" -text_pub -noout 2>/dev/null \
    | grep -q 'ED25519' \
    || { echo "signing key must use Ed25519" >&2; exit 1; }
  openssl pkey -pubin -in "$staging/.signing-public.pem" -outform DER \
    -out "$staging/.signing-public.der" 2>/dev/null
  signing_key_id="sha256:$(sha256sum "$staging/.signing-public.der" | awk '{print $1}')"
  rm -- "$staging/.signing-public.der"
fi
cat > "$staging/manifest.txt" <<EOF
format=northstar-backup-v2
manifest_version=2
backup_generation=$backup_generation
backup_sequence=$backup_sequence
created_at=$created_at
northstar_version=$northstar_version
postgresql_version=$database_version
successful_migrations=$migration_count
encryption=$encryption
signature=$signature
signing_key_id=$signing_key_id
database_archive=$database_archive
database_archive_sha256=$database_archive_sha256
database_plain_sha256=$database_plain_sha256
database_contents=$database_contents
database_contents_archive_sha256=$database_contents_archive_sha256
database_contents_plain_sha256=$database_contents_plain_sha256
upload_archive=$upload_archive
upload_archive_sha256=$upload_archive_sha256
upload_plain_sha256=$upload_plain_sha256
upload_consistency=immutable-final-files
EOF
python3 "$script_dir/backup-security.py" validate-manifest "$staging/manifest.txt"
checksum_files=("$database_archive" "$database_contents" "$upload_archive" manifest.txt)
if [[ "$signature" == openssl-ed25519 ]]; then
  openssl pkeyutl -sign -rawin -inkey "$signing_key_file" -passin pass: \
    -in "$staging/manifest.txt" -out "$staging/manifest.sig" 2>/dev/null
  checksum_files+=(manifest.sig)
fi
rm -f -- "$staging/.signing-public.pem"
(cd "$staging" && sha256sum "${checksum_files[@]}" > SHA256SUMS)

# READY is a durability statement, not merely a filename. Flush every published
# artifact first, verify the maintenance-fence session is still alive, then
# flush READY and the containing directory before and after atomic publication.
python3 - "$staging" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for entry in root.iterdir():
    if not entry.is_file() or entry.is_symlink():
        continue
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(entry, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
fence_probe_sql="$staging/maintenance-fence-probe.sql"
fence_probe_output="$staging/maintenance-fence-probe.out"
printf '%s\n' "SELECT '__FENCE_ALIVE__';" >"$fence_probe_sql"
maintenance_session_command "$fence_probe_sql" "$fence_probe_output"
grep -qx '__FENCE_ALIVE__' "$fence_probe_output" \
  || { echo "backup maintenance fence disappeared before publication" >&2; exit 1; }
rm -- "$fence_probe_sql" "$fence_probe_output"
touch "$staging/READY"
chmod 0600 "$staging/READY"
python3 - "$staging/READY" "$staging" <<'PY'
import os
import sys

for index, path in enumerate(sys.argv[1:]):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if index == 1:
        flags |= getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY
if [[ -n "$private_payload_staging" ]]; then
  rm -rf --one-file-system -- "$private_payload_staging"
  private_payload_staging=""
fi
mv -- "$staging" "$final_dir"
python3 - "$output_root" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
close_maintenance_session
trap - EXIT

if (( retention_days > 0 )); then
  while IFS= read -r -d '' candidate; do
    name="${candidate##*/}"
    [[ "$name" =~ ^northstar-[0-9]{8}T[0-9]{6}Z$ ]] \
      || { echo "refusing unexpected retention candidate: $candidate" >&2; exit 1; }
    resolved_candidate="$(cd "$candidate" && pwd -P)"
    [[ "$resolved_candidate" == "$output_root/$name" ]] \
      || { echo "refusing retention candidate outside backup root: $candidate" >&2; exit 1; }
    rm -rf --one-file-system -- "$candidate"
  done < <(find "$output_root" -mindepth 1 -maxdepth 1 -type d \
    -name 'northstar-????????T??????Z' -mtime "+$retention_days" -print0)
fi

echo "backup complete: $final_dir"
