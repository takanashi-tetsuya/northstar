#!/usr/bin/env bash
set -euo pipefail
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
postgres_bin="$(pg_config --bindir)"
for command in initdb pg_ctl createdb pg_dump pg_restore psql; do
  [[ -x "$postgres_bin/$command" ]] \
    || { echo "required PostgreSQL command is unavailable: $postgres_bin/$command" >&2; exit 1; }
done
export PATH="$postgres_bin:$PATH"
for command in age age-keygen awk openssl sed sha384sum; do
  command -v "$command" >/dev/null \
    || { echo "required production backup command is unavailable: $command" >&2; exit 1; }
done

work_dir="$(mktemp -d /tmp/northstar-backup-restore.XXXXXX)"
data_dir="$work_dir/postgres"
socket_dir="$work_dir/socket"
backup_root="$work_dir/backups"
source_uploads="$work_dir/source-uploads"
restore_uploads="$work_dir/restore-uploads"
restore_rollback="$work_dir/restore-rollback"
bootstrap_role="northstar_test_bootstrap"
bootstrap_password='Northstar:test\secret'
migrator_role='northstar_migrator'
migrator_password='NorthstarMigratorFixturePassword123456789'
runtime_role='northstar_runtime'
runtime_password='NorthstarRuntimeFixturePassword1234567890'
command_role='northstar_commands'
command_password='NorthstarCommandFixturePassword1234567890'
backup_role='northstar_backup'
backup_password='NorthstarBackupFixturePassword12345678901'
password_file="$work_dir/postgres-password"
cluster_started=false

cleanup() {
  if [[ "$cluster_started" == true ]]; then
    "$postgres_bin/pg_ctl" --pgdata "$data_dir" --mode fast --wait stop >/dev/null 2>&1 || true
  fi
  if [[ "${NORTHSTAR_BACKUP_RESTORE_TEST_KEEP_WORK:-false}" == true ]]; then
    echo "preserved isolated backup/restore fixture: $work_dir" >&2
    return
  fi
  case "$work_dir" in
    /tmp/northstar-backup-restore.*) rm -rf -- "$work_dir" ;;
    *) echo "refusing to clean unexpected test path: $work_dir" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$socket_dir" "$backup_root" "$source_uploads" "$restore_uploads" "$restore_rollback"
mark_upload_root() {
  printf '%s\n' 'northstar-upload-root-v1' >"$1/.northstar-upload-root"
  chmod 0700 "$1"
  chmod 0600 "$1/.northstar-upload-root"
}
mark_rollback_root() {
  printf '%s\n' 'northstar-restore-rollback-v1' >"$1/.northstar-rollback-root"
  chmod 0700 "$1"
  chmod 0600 "$1/.northstar-rollback-root"
}
mark_upload_root "$restore_uploads"
mark_rollback_root "$restore_rollback"
printf '%s\n' "$bootstrap_password" > "$password_file"
chmod 600 "$password_file"
"$postgres_bin/initdb" \
  --pgdata "$data_dir" \
  --username "$bootstrap_role" \
  --pwfile "$password_file" \
  --auth-local scram-sha-256 \
  --auth-host reject \
  --no-locale >/dev/null
"$postgres_bin/pg_ctl" \
  --pgdata "$data_dir" \
  --options="-F -k $socket_dir -c listen_addresses='' -c unix_socket_permissions=0700" \
  --wait start >/dev/null
cluster_started=true

export NORTHSTAR_FIXTURE_MIGRATOR_PASSWORD="$migrator_password"
export NORTHSTAR_FIXTURE_RUNTIME_PASSWORD="$runtime_password"
export NORTHSTAR_FIXTURE_COMMAND_PASSWORD="$command_password"
export NORTHSTAR_FIXTURE_BACKUP_PASSWORD="$backup_password"
PGPASSWORD="$bootstrap_password" PGHOST="$socket_dir" PGUSER="$bootstrap_role" \
  PGDATABASE=postgres "$postgres_bin/psql" --no-psqlrc --set ON_ERROR_STOP=1 <<'PSQL'
\getenv migrator_password NORTHSTAR_FIXTURE_MIGRATOR_PASSWORD
\getenv runtime_password NORTHSTAR_FIXTURE_RUNTIME_PASSWORD
\getenv command_password NORTHSTAR_FIXTURE_COMMAND_PASSWORD
\getenv backup_password NORTHSTAR_FIXTURE_BACKUP_PASSWORD
SELECT format(
  'CREATE ROLE northstar_migrator LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 VALID UNTIL ''infinity''',
  :'migrator_password'
) \gexec
SELECT format(
  'CREATE ROLE northstar_runtime LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64 VALID UNTIL ''infinity''',
  :'runtime_password'
) \gexec
SELECT format(
  'CREATE ROLE northstar_commands LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 VALID UNTIL ''infinity''',
  :'command_password'
) \gexec
SELECT format(
  'CREATE ROLE northstar_backup LOGIN PASSWORD %L NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 VALID UNTIL ''infinity''',
  :'backup_password'
) \gexec
CREATE ROLE northstar_fixture_outsider NOLOGIN NOINHERIT NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
PSQL
unset NORTHSTAR_FIXTURE_MIGRATOR_PASSWORD NORTHSTAR_FIXTURE_RUNTIME_PASSWORD \
  NORTHSTAR_FIXTURE_COMMAND_PASSWORD \
  NORTHSTAR_FIXTURE_BACKUP_PASSWORD

create_restore_database() {
  local database_name="$1"
  [[ "$database_name" =~ ^northstar_[a-z0-9_]+$ ]] || return 2
  PGPASSWORD="$bootstrap_password" "$postgres_bin/createdb" \
    --host "$socket_dir" --username "$bootstrap_role" \
    --owner "$migrator_role" "$database_name"
  PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
    --set ON_ERROR_STOP=1 \
    --command="ALTER SCHEMA public OWNER TO $migrator_role" >/dev/null
}

database_role="$migrator_role"
database_password="$migrator_password"
create_restore_database northstar_backup_source
create_restore_database northstar_restore_target

apply_repository_migrations() {
  local database_name="$1"
  local migration migration_name migration_version migration_description
  local migration_checksum no_transaction expected_count actual_ledger
  PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
    --set ON_ERROR_STOP=1 >/dev/null <<'PSQL'
CREATE TABLE public._sqlx_migrations (
  version BIGINT PRIMARY KEY,
  description TEXT NOT NULL,
  installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
  success BOOLEAN NOT NULL,
  checksum BYTEA NOT NULL,
  execution_time BIGINT NOT NULL
);
PSQL

  expected_count=0
  for migration in "$project_dir"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
    [[ -f "$migration" ]] || { echo 'repository migration fixture is empty' >&2; return 1; }
    migration_name=${migration##*/}
    migration_version=${migration_name%%_*}
    migration_description=${migration_name#*_}
    migration_description=${migration_description%.sql}
    migration_description=${migration_description//_/ }
    migration_checksum=$(sha384sum "$migration")
    migration_checksum=${migration_checksum%% *}
    no_transaction=false
    [[ "$(sed -n '1p' "$migration")" == '-- no-transaction' ]] \
      && no_transaction=true

    if [[ "$no_transaction" == true ]]; then
      PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
        PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
        --set ON_ERROR_STOP=1 --file "$migration" >/dev/null
      PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
        PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
        --set ON_ERROR_STOP=1 --set=migration_version="$((10#$migration_version))" \
        --set=migration_description="$migration_description" \
        --set=migration_checksum="$migration_checksum" >/dev/null <<'PSQL'
INSERT INTO public._sqlx_migrations(
  version,description,success,checksum,execution_time
) VALUES (
  :'migration_version'::pg_catalog.int8,:'migration_description',true,
  pg_catalog.decode(:'migration_checksum','hex'),0
);
PSQL
    else
      PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
        PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
        --set ON_ERROR_STOP=1 --single-transaction \
        --set=migration_path="$migration" \
        --set=migration_version="$((10#$migration_version))" \
        --set=migration_description="$migration_description" \
        --set=migration_checksum="$migration_checksum" >/dev/null <<'PSQL'
\i :migration_path
INSERT INTO public._sqlx_migrations(
  version,description,success,checksum,execution_time
) VALUES (
  :'migration_version'::pg_catalog.int8,:'migration_description',true,
  pg_catalog.decode(:'migration_checksum','hex'),0
);
PSQL
    fi
    expected_count=$((expected_count + 1))
  done

  actual_ledger=$(PGPASSWORD="$migrator_password" PGHOST="$socket_dir" \
    PGUSER="$migrator_role" PGDATABASE="$database_name" "$postgres_bin/psql" \
    --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command="SELECT count(*)::text || '|' || bool_and(success)::text || '|' || bool_and(octet_length(checksum)=48)::text FROM public._sqlx_migrations")
  [[ "$actual_ledger" == "$expected_count|true|true" ]] || {
    echo "repository migration fixture ledger is incomplete: $actual_ledger" >&2
    return 1
  }
}

reconcile_repository_grants() {
  local database_name="$1"
  [[ "$database_name" =~ ^northstar_[a-z0-9_]+$ ]] || return 2
  PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" \
    --no-psqlrc --set ON_ERROR_STOP=1 \
    --set database_name="$database_name" \
    --set migrator_role="$migrator_role" \
    --set runtime_role="$runtime_role" \
    --set command_role="$command_role" \
    --set backup_role="$backup_role" \
    --set allow_bootstrap=false \
    --set grant_phase=exact \
    --file "$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql" \
    >/dev/null
}

# Durable database probes must use the same closed-world schema that production
# grant reconciliation attests.  Test-only tables in public would either make
# exact reconciliation fail or, worse, make a rollback dump impossible to
# reconcile during compensation.  A user plus its vCard gives each fixture a
# foreign-key-backed marker without introducing out-of-band schema objects.
seed_canonical_probe() {
  local database_name="$1" user_id="$2" username="$3" marker="$4"
  [[ "$database_name" =~ ^northstar_[a-z0-9_]+$ ]] || return 2
  [[ "$user_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || return 2
  [[ "$username" =~ ^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$ ]] || return 2
  [[ -n "$marker" && ${#marker} -le 128 \
     && "$marker" != *$'\n'* && "$marker" != *$'\r'* && "$marker" != *'|'* ]] \
    || return 2
  PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
    --single-transaction --set ON_ERROR_STOP=1 --set=probe_user_id="$user_id" \
    --set=probe_username="$username" --set=probe_marker="$marker" \
    >/dev/null <<'PSQL'
INSERT INTO public.users(id,username,password_hash,display_name,is_admin)
VALUES (:'probe_user_id'::pg_catalog.uuid,:'probe_username',
        'fixture-password-hash',:'probe_marker',FALSE);
INSERT INTO public.vcards(user_id,payload)
VALUES (:'probe_user_id'::pg_catalog.uuid,:'probe_marker');
PSQL
}

read_canonical_probe() {
  local database_name="$1" user_id="$2"
  [[ "$database_name" =~ ^northstar_[a-z0-9_]+$ ]] || return 2
  [[ "$user_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || return 2
  PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
    --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --set=probe_user_id="$user_id" \
    --command="SELECT users.display_name || '|' || vcards.payload
                 FROM public.users
                 JOIN public.vcards ON vcards.user_id=users.id
                WHERE users.id=:'probe_user_id'::pg_catalog.uuid"
}

canonical_probe_presence() {
  local database_name="$1" user_id="$2"
  [[ "$database_name" =~ ^northstar_[a-z0-9_]+$ ]] || return 2
  [[ "$user_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || return 2
  PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
    PGDATABASE="$database_name" "$postgres_bin/psql" --no-psqlrc \
    --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --set=probe_user_id="$user_id" \
    --command="SELECT (SELECT count(*) FROM public.users
                         WHERE id=:'probe_user_id'::pg_catalog.uuid)::text
                      || '|' ||
                      (SELECT count(*) FROM public.vcards
                         WHERE user_id=:'probe_user_id'::pg_catalog.uuid)::text"
}

apply_repository_migrations northstar_backup_source

# The long-lived restore target represents an already deployed Northstar
# database.  Keep its pre-cutover sentinel inside the canonical schema so the
# restore's recoverability preflight proves the same lifecycle that operators
# use, rather than succeeding or failing on a test-only public table.
guard_probe_user_id="70000000-0000-4000-8000-000000000001"
guard_probe_marker="unchanged-before-cutover"
apply_repository_migrations northstar_restore_target
seed_canonical_probe northstar_restore_target "$guard_probe_user_id" \
  restore-guard "$guard_probe_marker"
reconcile_repository_grants northstar_restore_target

encoded_socket="${socket_dir//\//%2F}"
source_database="postgresql://$migrator_role:$migrator_password@/northstar_backup_source?host=$encoded_socket"
target_database="postgresql://$migrator_role:$migrator_password@/northstar_restore_target?host=$encoded_socket"
upload_id="01234567-89ab-cdef-0123-456789abcdef"
upload_body="northstar immutable upload restore probe"
source_probe_user_id="11111111-1111-4111-8111-111111111111"
source_probe_marker="database-restored"
printf '%s' "$upload_body" > "$source_uploads/$upload_id"
upload_size="$(stat -c '%s' "$source_uploads/$upload_id")"
upload_digest="$(sha256sum "$source_uploads/$upload_id" | awk '{print $1}')"

seed_canonical_probe northstar_backup_source "$source_probe_user_id" \
  backup-fixture "$source_probe_marker"

# Migrations intentionally leave deployment-wide upload capacity unbound.
# Production startup binds it before accepting slots; this offline fixture
# must establish the same durable authority before seeding its retained object.
PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
  PGDATABASE=northstar_backup_source "$postgres_bin/psql" \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command='SELECT policy_generation,recovery_draining FROM northstar_upload_bind_capacity_policy(100000,1000000,1099511627776);' \
  --command="INSERT INTO upload_slots(id,user_id,filename,content_type,size,token_hash,expires_at,uploaded,uploading,content_sha256,completed_at,put_expires_at,storage_backend,storage_state,storage_object_key,storage_sha256,storage_size) VALUES ('$upload_id','$source_probe_user_id','fixture.bin','application/octet-stream',$upload_size,decode(repeat('22',32),'hex'),clock_timestamp()+INTERVAL '1 day',TRUE,FALSE,decode('$upload_digest','hex'),clock_timestamp(),clock_timestamp()+INTERVAL '15 minutes','local','committed','$upload_id',decode('$upload_digest','hex'),$upload_size);" >/dev/null

reconcile_repository_grants northstar_backup_source

# First exercise the production path: read-only backup identity, file-backed
# URL secrets, Ed25519 authentication, age encryption, monotonic state, a
# NOCREATEDB migrator restore, and atomic post-restore ACL convergence.
production_root="$work_dir/production"
production_backup_root="$production_root/backups"
production_uploads="$production_root/uploads"
production_rollback="$production_root/rollback"
production_scratch="$production_root/scratch"
production_sequence_dir="$production_root/sequence"
production_floor_dir="$production_root/floor"
production_verify_floor_dir="$production_root/verify-floor"
mkdir -p -m 0700 "$production_root" "$production_backup_root" \
  "$production_uploads" "$production_rollback" "$production_scratch" \
  "$production_sequence_dir" "$production_floor_dir" \
  "$production_verify_floor_dir"
mark_upload_root "$production_uploads"
mark_rollback_root "$production_rollback"

production_signing_key="$production_root/signing-ed25519.pem"
production_verify_key="$production_root/signing-ed25519.pub.pem"
production_age_identity="$production_root/age-identity.txt"
production_age_recipients="$production_root/age-recipients.txt"
openssl genpkey -algorithm ED25519 -out "$production_signing_key" 2>/dev/null
openssl pkey -in "$production_signing_key" -pubout \
  -out "$production_verify_key" 2>/dev/null
age-keygen -o "$production_age_identity" >/dev/null 2>&1
age-keygen -y "$production_age_identity" >"$production_age_recipients"
chmod 0600 "$production_signing_key" "$production_verify_key" \
  "$production_age_identity" "$production_age_recipients"

create_restore_database northstar_production_restore_target
production_backup_url_file="$production_root/backup-database-url"
production_restore_url_file="$production_root/restore-database-url"
printf '%s\n' \
  "postgresql://$backup_role:$backup_password@/northstar_backup_source?host=$encoded_socket" \
  >"$production_backup_url_file"
printf '%s\n' \
  "postgresql://$migrator_role:$migrator_password@/northstar_production_restore_target?host=$encoded_socket" \
  >"$production_restore_url_file"
chmod 0600 "$production_backup_url_file" "$production_restore_url_file"

BACKUP_SECURITY_POLICY=production bash "$project_dir/scripts/backup.sh" \
  --database-url-file "$production_backup_url_file" \
  --output "$production_backup_root" \
  --upload-dir "$source_uploads" \
  --sequence-state-file "$production_sequence_dir/current" \
  --signing-key-file "$production_signing_key" \
  --age-recipient-file "$production_age_recipients" \
  --plaintext-staging-dir "$production_scratch" \
  --northstar-version fixture-production >/dev/null
production_backup_dir="$(find "$production_backup_root" -mindepth 1 -maxdepth 1 \
  -type d -name 'northstar-*' -print -quit)"
[[ -n "$production_backup_dir" ]] \
  || { echo "production backup test did not create an archive" >&2; exit 1; }
BACKUP_SECURITY_POLICY=production bash "$project_dir/scripts/verify-backup.sh" \
  "$production_backup_dir" \
  --public-key-file "$production_verify_key" \
  --age-identity-file "$production_age_identity" \
  --rollback-state-file "$production_verify_floor_dir/floor" >/dev/null
BACKUP_SECURITY_POLICY=production bash "$project_dir/scripts/restore-backup.sh" \
  "$production_backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file "$production_restore_url_file" \
  --upload-dir "$production_uploads" \
  --rollback-dir "$production_rollback" \
  --plaintext-staging-dir "$production_scratch" \
  --public-key-file "$production_verify_key" \
  --age-identity-file "$production_age_identity" \
  --rollback-state-file "$production_floor_dir/floor" >/dev/null

production_acl_ok="$(PGPASSWORD="$migrator_password" PGHOST="$socket_dir" \
  PGUSER="$migrator_role" PGDATABASE=northstar_production_restore_target \
  "$postgres_bin/psql" --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
  --command="SELECT pg_get_userbyid(nspowner) = '$migrator_role'
                    AND NOT has_schema_privilege('northstar_fixture_outsider', 'public', 'USAGE')
                    AND has_table_privilege('$runtime_role', 'public.vcards', 'SELECT')
                    AND has_table_privilege('$backup_role', 'public.vcards', 'SELECT')
               FROM pg_namespace WHERE nspname = 'public'")"
[[ "$production_acl_ok" == t && -f "$production_uploads/$upload_id" ]] \
  || { echo "production restore did not converge owner/ACL/upload state" >&2; exit 1; }
if PGPASSWORD="$backup_password" PGHOST="$socket_dir" PGUSER="$backup_role" \
   PGDATABASE=northstar_production_restore_target "$postgres_bin/psql" \
   --no-psqlrc --set ON_ERROR_STOP=1 \
   --command="UPDATE public.vcards SET payload='forbidden'
               WHERE user_id='$source_probe_user_id'::pg_catalog.uuid" >/dev/null 2>&1; then
  echo "production restore granted write access to the backup identity" >&2
  exit 1
fi

# The remaining fault matrix intentionally uses the explicit development policy
# so its fixtures stay plaintext and independently mutable. Production behavior
# has already been exercised above and remains the application default.
export BACKUP_SECURITY_POLICY=development-legacy
DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
  --output "$backup_root" \
  --upload-dir "$source_uploads" >/dev/null
backup_dir="$(find "$backup_root" -mindepth 1 -maxdepth 1 -type d -name 'northstar-*' -print -quit)"
[[ -n "$backup_dir" ]] || { echo "backup test did not create an archive" >&2; exit 1; }
bash "$project_dir/scripts/verify-backup.sh" "$backup_dir" >/dev/null

# Broad retention roots must be rejected before pg_dump or deletion. A valid
# retention run deletes only strict, direct backup directories and leaves
# similarly prefixed foreign paths and links untouched.
for unsafe_output in / "$project_dir" "${HOME:-$project_dir}"; do
  if DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
    --output "$unsafe_output" --upload-dir "$source_uploads" --retention-days 1 \
    >/dev/null 2>&1; then
    echo "backup accepted a broad retention root: $unsafe_output" >&2
    exit 1
  fi
done
retention_root="$work_dir/retention"
mkdir "$retention_root"
mkdir "$retention_root/northstar-20000101T000000Z" "$retention_root/northstar-not-a-backup"
ln -s "$work_dir" "$retention_root/northstar-20000102T000000Z"
touch -d '10 days ago' "$retention_root/northstar-20000101T000000Z" \
  "$retention_root/northstar-not-a-backup" "$retention_root/northstar-20000102T000000Z"
DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
  --output "$retention_root" --upload-dir "$source_uploads" --retention-days 1 >/dev/null
[[ ! -e "$retention_root/northstar-20000101T000000Z" ]] \
  || { echo "strict expired backup directory was not removed" >&2; exit 1; }
[[ -d "$retention_root/northstar-not-a-backup" && -L "$retention_root/northstar-20000102T000000Z" ]] \
  || { echo "retention removed a foreign directory or linked target" >&2; exit 1; }

# Checksums detect accidental corruption, not an attacker who can rewrite the
# archive and its checksum file together. Ensure structural validation still
# rejects a forged upload archive containing a link outside the restore root.
malicious_backup="$work_dir/malicious-backup"
malicious_source="$work_dir/malicious-source"
cp -a -- "$backup_dir" "$malicious_backup"
mkdir "$malicious_source"
ln -s ../../outside-restore "$malicious_source/escape"
tar --create --gzip --file="$malicious_backup/uploads.tar.gz" \
  --directory="$malicious_source" .
(cd "$malicious_backup" && sha256sum database.dump database.contents uploads.tar.gz manifest.txt > SHA256SUMS)
if bash "$project_dir/scripts/verify-backup.sh" "$malicious_backup" >/dev/null 2>&1; then
  echo "backup verification accepted a forged upload symlink" >&2
  exit 1
fi

# Restore path validation must fail before either data plane is touched.  The
# canonical guard row was installed before the fault matrix and remains under
# the exact production grant policy throughout these rejection paths.

# Backup and restore must contend on the same advisory key in their target
# database. PostgreSQL advisory locks are database-scoped, so exercise each job
# against an independent holder in the exact database that job will use.
coproc FIXTURE_MAINTENANCE_FENCE {
  PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
    PGDATABASE=northstar_restore_target "$postgres_bin/psql" \
    --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
}
fence_output_fd="${FIXTURE_MAINTENANCE_FENCE[0]}"
fence_input_fd="${FIXTURE_MAINTENANCE_FENCE[1]}"
fence_process_pid="$FIXTURE_MAINTENANCE_FENCE_PID"
printf '%s\n' \
  'SELECT pg_advisory_lock(735559096281326101);' \
  '\echo __FIXTURE_FENCE_HELD__' >&"$fence_input_fd"
fence_ready=false
while IFS= read -r fence_line <&"$fence_output_fd"; do
  if [[ "$fence_line" == __FIXTURE_FENCE_HELD__ ]]; then
    fence_ready=true
    break
  fi
done
[[ "$fence_ready" == true ]] || { echo "fixture could not acquire maintenance fence" >&2; exit 1; }

fenced_restore_root="$work_dir/fenced-restore"
fenced_rollback_root="$work_dir/fenced-rollback"
mkdir "$fenced_restore_root" "$fenced_rollback_root"
mark_upload_root "$fenced_restore_root"
mark_rollback_root "$fenced_rollback_root"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE \
  --upload-dir "$fenced_restore_root" --rollback-dir "$fenced_rollback_root" \
  >/dev/null 2>&1; then
  echo "restore ignored the shared maintenance fence" >&2
  exit 1
fi
[[ -z "$(find "$fenced_restore_root" -mindepth 1 -maxdepth 1 -name '.northstar-restore-cutover-*' -print -quit)" ]] \
  || { echo "maintenance-fence refusal published partial state" >&2; exit 1; }
printf '%s\n' '\q' >&"$fence_input_fd"
exec {fence_input_fd}>&-
exec {fence_output_fd}<&-
wait "$fence_process_pid"

coproc FIXTURE_BACKUP_MAINTENANCE_FENCE {
  PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
    PGDATABASE=northstar_backup_source "$postgres_bin/psql" \
    --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
}
backup_fence_output_fd="${FIXTURE_BACKUP_MAINTENANCE_FENCE[0]}"
backup_fence_input_fd="${FIXTURE_BACKUP_MAINTENANCE_FENCE[1]}"
backup_fence_process_pid="$FIXTURE_BACKUP_MAINTENANCE_FENCE_PID"
printf '%s\n' \
  'SELECT pg_advisory_lock(735559096281326101);' \
  '\echo __FIXTURE_BACKUP_FENCE_HELD__' >&"$backup_fence_input_fd"
backup_fence_ready=false
while IFS= read -r fence_line <&"$backup_fence_output_fd"; do
  if [[ "$fence_line" == __FIXTURE_BACKUP_FENCE_HELD__ ]]; then
    backup_fence_ready=true
    break
  fi
done
[[ "$backup_fence_ready" == true ]] \
  || { echo "fixture could not acquire backup maintenance fence" >&2; exit 1; }
fenced_backup_root="$work_dir/fenced-backups"
mkdir "$fenced_backup_root"
if DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
  --output "$fenced_backup_root" --upload-dir "$source_uploads" >/dev/null 2>&1; then
  echo "backup ignored the shared maintenance fence" >&2
  exit 1
fi
[[ -z "$(find "$fenced_backup_root" -mindepth 1 -maxdepth 1 -type d -name 'northstar-*' -print -quit)" ]] \
  || { echo "backup maintenance-fence refusal published partial state" >&2; exit 1; }
printf '%s\n' '\q' >&"$backup_fence_input_fd"
exec {backup_fence_input_fd}>&-
exec {backup_fence_output_fd}<&-
wait "$backup_fence_process_pid"

guard_rollback="$work_dir/guard-rollback"
mkdir "$guard_rollback"
for unsafe_upload in / "$project_dir" "${HOME:-$project_dir}"; do
  if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
    "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$unsafe_upload" \
    --rollback-dir "$guard_rollback" >/dev/null 2>&1; then
    echo "restore accepted a broad upload root: $unsafe_upload" >&2
    exit 1
  fi
done
guard_upload="$work_dir/guard-upload"
mkdir "$guard_upload"
for unsafe_rollback in / "$project_dir" "${HOME:-$project_dir}"; do
  if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
    "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$guard_upload" \
    --rollback-dir "$unsafe_rollback" >/dev/null 2>&1; then
    echo "restore accepted a broad rollback root: $unsafe_rollback" >&2
    exit 1
  fi
done
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$guard_upload" \
  --rollback-dir "$guard_rollback" >/dev/null 2>&1; then
  echo "restore accepted upload and rollback roots without ownership markers" >&2
  exit 1
fi
stray_uploads="$work_dir/stray-uploads"
stray_rollback="$work_dir/stray-rollback"
mkdir "$stray_uploads" "$stray_rollback"
printf '%s' 'must remain untouched' >"$stray_uploads/stray.txt"
mkdir "$stray_uploads/stray-directory"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$stray_uploads" \
  --rollback-dir "$stray_rollback" >/dev/null 2>&1; then
  echo "restore accepted foreign upload-root objects" >&2
  exit 1
fi
[[ "$(<"$stray_uploads/stray.txt")" == "must remain untouched" \
   && -d "$stray_uploads/stray-directory" ]] \
  || { echo "foreign upload-root objects changed during rejection" >&2; exit 1; }
real_link_target="$work_dir/link-target"
linked_uploads="$work_dir/linked-uploads"
linked_rollback="$work_dir/linked-rollback"
mkdir "$real_link_target" "$linked_rollback"
ln -s "$real_link_target" "$linked_uploads"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$linked_uploads" \
  --rollback-dir "$linked_rollback" >/dev/null 2>&1; then
  echo "restore accepted a linked upload root" >&2
  exit 1
fi
real_rollback_target="$work_dir/real-rollback-target"
linked_rollback_root="$work_dir/linked-rollback-root"
linked_upload_target="$work_dir/linked-upload-target"
mkdir "$real_rollback_target" "$linked_upload_target"
ln -s "$real_rollback_target" "$linked_rollback_root"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$linked_upload_target" \
  --rollback-dir "$linked_rollback_root" >/dev/null 2>&1; then
  echo "restore accepted a linked rollback root" >&2
  exit 1
fi
overlap_upload="$work_dir/overlap-upload"
overlap_rollback="$overlap_upload/rollback"
mkdir -p "$overlap_rollback"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$overlap_upload" \
  --rollback-dir "$overlap_rollback" >/dev/null 2>&1; then
  echo "restore accepted overlapping upload and rollback roots" >&2
  exit 1
fi
backup_overlap_upload="$work_dir/backup-overlap-upload"
mkdir "$backup_overlap_upload"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$backup_overlap_upload" \
  --rollback-dir "$backup_root" >/dev/null 2>&1; then
  echo "restore accepted a rollback root overlapping the backup tree" >&2
  exit 1
fi
backup_overlap_rollback="$work_dir/backup-overlap-rollback"
mkdir "$backup_overlap_rollback"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$backup_dir" \
  --rollback-dir "$backup_overlap_rollback" >/dev/null 2>&1; then
  echo "restore accepted an upload root overlapping the backup directory" >&2
  exit 1
fi
invalid_env_upload="$work_dir/invalid-env-upload"
invalid_env_rollback="$work_dir/invalid-env-rollback"
mkdir "$invalid_env_upload" "$invalid_env_rollback"
mark_upload_root "$invalid_env_upload"
mark_rollback_root "$invalid_env_rollback"
if NORTHSTAR_RESTORE_TEST_FAIL_AFTER_UPLOAD_MOVES=invalid DATABASE_URL="$target_database" \
  bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE --upload-dir "$invalid_env_upload" \
  --rollback-dir "$invalid_env_rollback" >/dev/null 2>&1; then
  echo "restore accepted an invalid fault-injection boundary" >&2
  exit 1
fi
[[ "$(find "$invalid_env_rollback" -mindepth 1 -maxdepth 1 ! -name '.northstar-rollback-root' -print -quit)" == "" ]] \
  || { echo "invalid restore option created rollback state before rejection" >&2; exit 1; }
extra_marker_upload="$work_dir/extra-marker-upload"
extra_marker_rollback="$work_dir/extra-marker-rollback"
mkdir "$extra_marker_upload" "$extra_marker_rollback"
mark_upload_root "$extra_marker_upload"
mark_rollback_root "$extra_marker_rollback"
printf '%s\n' extra >>"$extra_marker_upload/.northstar-upload-root"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$extra_marker_upload" \
  --rollback-dir "$extra_marker_rollback" >/dev/null 2>&1; then
  echo "restore accepted an upload marker with trailing data" >&2
  exit 1
fi
mark_upload_root "$extra_marker_upload"
printf '%s\n' extra >>"$extra_marker_rollback/.northstar-rollback-root"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE --upload-dir "$extra_marker_upload" \
  --rollback-dir "$extra_marker_rollback" >/dev/null 2>&1; then
  echo "restore accepted a rollback marker with trailing data" >&2
  exit 1
fi
guard_value="$(read_canonical_probe northstar_restore_target "$guard_probe_user_id")"
[[ "$guard_value" == "$guard_probe_marker|$guard_probe_marker" ]] \
  || { echo "path rejection changed the restore target database" >&2; exit 1; }

stale_upload_id="11111111-1111-4111-8111-111111111111"
printf '%s' 'stale upload retained for rollback' > "$restore_uploads/$stale_upload_id"
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore WRONG --upload-dir "$restore_uploads" \
  --rollback-dir "$restore_rollback" >/dev/null 2>&1; then
  echo "restore accepted an invalid confirmation phrase" >&2
  exit 1
fi

# A NOCREATEDB/NOSUPERUSER migrator must never need pg_signal_backend. Keep a
# peer session open, require restore to reject the cutover after installing its
# connection fence, and prove the peer was not terminated.
peer_uploads="$work_dir/peer-fence-uploads"
peer_rollback="$work_dir/peer-fence-rollback"
mkdir "$peer_uploads" "$peer_rollback"
mark_upload_root "$peer_uploads"
mark_rollback_root "$peer_rollback"
coproc FIXTURE_RESTORE_PEER {
  PGPASSWORD="$migrator_password" PGHOST="$socket_dir" PGUSER="$migrator_role" \
    PGDATABASE=northstar_restore_target "$postgres_bin/psql" \
    --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
}
peer_output_fd="${FIXTURE_RESTORE_PEER[0]}"
peer_input_fd="${FIXTURE_RESTORE_PEER[1]}"
peer_process_pid="$FIXTURE_RESTORE_PEER_PID"
printf '%s\n' '\echo __RESTORE_PEER_READY__' >&"$peer_input_fd"
IFS= read -r peer_ready <&"$peer_output_fd"
[[ "$peer_ready" == __RESTORE_PEER_READY__ ]] \
  || { echo "restore peer fixture did not become ready" >&2; exit 1; }
if DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" --confirm-restore NORTHSTAR-RESTORE \
  --upload-dir "$peer_uploads" --rollback-dir "$peer_rollback" \
  >/dev/null 2>&1; then
  echo "restore ignored an existing target database peer" >&2
  exit 1
fi
printf '%s\n' 'SELECT 1;' '\echo __RESTORE_PEER_SURVIVED__' >&"$peer_input_fd"
peer_survived=false
while IFS= read -r peer_line <&"$peer_output_fd"; do
  if [[ "$peer_line" == __RESTORE_PEER_SURVIVED__ ]]; then
    peer_survived=true
    break
  fi
done
[[ "$peer_survived" == true ]] \
  || { echo "restore terminated a peer instead of refusing cleanly" >&2; exit 1; }
printf '%s\n' '\q' >&"$peer_input_fd"
exec {peer_input_fd}>&-
exec {peer_output_fd}<&-
wait "$peer_process_pid"

DATABASE_URL="$target_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE \
  --upload-dir "$restore_uploads" \
  --rollback-dir "$restore_rollback" >/dev/null

restored_value="$(read_canonical_probe northstar_restore_target "$source_probe_user_id")"
[[ "$restored_value" == "$source_probe_marker|$source_probe_marker" ]] \
  || { echo "restored database probe did not match" >&2; exit 1; }
[[ "$(<"$restore_uploads/$upload_id")" == "$upload_body" ]] \
  || { echo "restored upload content did not match" >&2; exit 1; }
find "$restore_rollback" -mindepth 3 -maxdepth 3 \
  -path "*/restore-*/uploads/$stale_upload_id" -type f -print -quit | grep -q . \
  || { echo "pre-restore upload was not retained" >&2; exit 1; }
[[ "$(<"$restore_uploads/.northstar-upload-root")" == "northstar-upload-root-v1" ]] \
  || { echo "restore did not preserve the protected upload-root marker" >&2; exit 1; }

# A structurally valid archive with rewritten checksums must still be rejected
# when a same-size object no longer matches the authoritative database digest.
tampered_backup="$work_dir/tampered-digest-backup"
tampered_uploads="$work_dir/tampered-uploads"
tampered_restore="$work_dir/tampered-restore"
tampered_rollback="$work_dir/tampered-rollback"
cp -a -- "$backup_dir" "$tampered_backup"
mkdir "$tampered_uploads" "$tampered_restore" "$tampered_rollback"
mark_upload_root "$tampered_restore"
mark_rollback_root "$tampered_rollback"
tar --extract --gzip --file="$tampered_backup/uploads.tar.gz" --directory="$tampered_uploads"
python3 -c 'import pathlib,sys; path=pathlib.Path(sys.argv[1]); data=path.read_bytes(); path.write_bytes(bytes((byte ^ 1) for byte in data))' \
  "$tampered_uploads/$upload_id"
[[ "$(stat -c '%s' "$tampered_uploads/$upload_id")" == "$upload_size" ]] \
  || { echo "same-size tamper fixture changed size" >&2; exit 1; }
tar --create --gzip --file="$tampered_backup/uploads.tar.gz" \
  --directory="$tampered_uploads" .
(cd "$tampered_backup" && sha256sum database.dump database.contents uploads.tar.gz manifest.txt > SHA256SUMS)
tampered_sentinel_id="22222222-2222-4222-8222-222222222222"
printf '%s' 'tampered restore target must remain' > "$tampered_restore/$tampered_sentinel_id"
create_restore_database northstar_tampered_target
apply_repository_migrations northstar_tampered_target
tampered_probe_user_id="60000000-0000-4000-8000-000000000005"
tampered_probe_marker="target-unchanged"
seed_canonical_probe northstar_tampered_target "$tampered_probe_user_id" \
  tampered-probe "$tampered_probe_marker"
reconcile_repository_grants northstar_tampered_target
tampered_database="postgresql://$migrator_role:$migrator_password@/northstar_tampered_target?host=$encoded_socket"
if DATABASE_URL="$tampered_database" bash "$project_dir/scripts/restore-backup.sh" \
  "$tampered_backup" --confirm-restore NORTHSTAR-RESTORE \
  --upload-dir "$tampered_restore" --rollback-dir "$tampered_rollback" >/dev/null 2>&1; then
  echo "restore accepted a same-size upload with the wrong database digest" >&2
  exit 1
fi
untouched_value="$(read_canonical_probe northstar_tampered_target \
  "$tampered_probe_user_id")"
[[ "$untouched_value" == "$tampered_probe_marker|$tampered_probe_marker" ]] \
  || { echo "failed restore changed the target database before digest validation" >&2; exit 1; }
[[ "$(<"$tampered_restore/$tampered_sentinel_id")" == "tampered restore target must remain" ]] \
  || { echo "failed restore changed uploads before digest validation" >&2; exit 1; }

# Exercise the post-database, mid-upload-switch compensation path. The restore
# must put both data planes back exactly, including removing objects that exist
# only in the rejected backup.
rollback_restore="$work_dir/rollback-restore"
rollback_retention="$work_dir/rollback-retention"
mkdir "$rollback_restore" "$rollback_retention"
mark_upload_root "$rollback_restore"
mark_rollback_root "$rollback_retention"
rollback_sentinel_id="33333333-3333-4333-8333-333333333333"
printf '%s' 'rollback upload sentinel' > "$rollback_restore/$rollback_sentinel_id"
create_restore_database northstar_rollback_target
apply_repository_migrations northstar_rollback_target
rollback_probe_user_id="60000000-0000-4000-8000-000000000001"
rollback_probe_marker="database-rolled-back"
seed_canonical_probe northstar_rollback_target "$rollback_probe_user_id" \
  rollback-probe "$rollback_probe_marker"
reconcile_repository_grants northstar_rollback_target
rollback_database_url="postgresql://$migrator_role:$migrator_password@/northstar_rollback_target?host=$encoded_socket"
rollback_fault_log="$work_dir/rollback-fault.log"
if NORTHSTAR_RESTORE_TEST_FAIL_AFTER_UPLOAD_MOVES=1 DATABASE_URL="$rollback_database_url" \
  bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE --upload-dir "$rollback_restore" \
  --rollback-dir "$rollback_retention" >"$rollback_fault_log" 2>&1; then
  echo "restore fault injection unexpectedly succeeded" >&2
  exit 1
fi
if ! rollback_value="$(read_canonical_probe northstar_rollback_target \
  "$rollback_probe_user_id")"; then
  echo 'rollback fault injection left the target database unavailable' >&2
  tail -n 160 "$rollback_fault_log" >&2 || true
  exit 1
fi
[[ "$rollback_value" == "$rollback_probe_marker|$rollback_probe_marker" ]] \
  || { echo "database compensation did not restore the pre-cutover data" >&2; exit 1; }
remaining_source_probe="$(canonical_probe_presence northstar_rollback_target \
  "$source_probe_user_id")"
[[ "$remaining_source_probe" == "0|0" ]] \
  || { echo "database compensation retained rows from the rejected backup" >&2; exit 1; }
rollback_upload_rows="$(PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
  PGDATABASE=northstar_rollback_target "$postgres_bin/psql" \
  --no-psqlrc --tuples-only --no-align \
  --command='SELECT COUNT(*) FROM upload_slots')"
[[ "$rollback_upload_rows" == "0" ]] \
  || { echo "database compensation retained upload rows from the rejected backup" >&2; exit 1; }
[[ "$(<"$rollback_restore/$rollback_sentinel_id")" == "rollback upload sentinel" ]] \
  || { echo "upload compensation did not restore the pre-cutover object" >&2; exit 1; }
[[ ! -e "$rollback_restore/$upload_id" ]] \
  || { echo "upload compensation retained an object from the rejected backup" >&2; exit 1; }

# The backup producer must not publish READY when its exact dump references an
# upload object that is absent from the immutable archive.
missing_upload_id="44444444-4444-4444-8444-444444444444"
PGPASSWORD="$database_password" PGHOST="$socket_dir" PGUSER="$database_role" \
  PGDATABASE=northstar_backup_source "$postgres_bin/psql" \
  --no-psqlrc --set ON_ERROR_STOP=1 \
  --command="INSERT INTO upload_slots(id,user_id,filename,content_type,size,token_hash,expires_at,uploaded,uploading,content_sha256,completed_at,put_expires_at,storage_backend,storage_state,storage_object_key,storage_sha256,storage_size) VALUES ('$missing_upload_id','11111111-1111-4111-8111-111111111111','missing.bin','application/octet-stream',17,decode(repeat('44',32),'hex'),clock_timestamp()+INTERVAL '1 day',TRUE,FALSE,decode(repeat('55',32),'hex'),clock_timestamp(),clock_timestamp()+INTERVAL '15 minutes','local','committed','$missing_upload_id',decode(repeat('55',32),'hex'),17);" >/dev/null
inconsistent_backup_root="$work_dir/inconsistent-backups"
mkdir "$inconsistent_backup_root"
if DATABASE_URL="$source_database" bash "$project_dir/scripts/backup.sh" \
  --output "$inconsistent_backup_root" --upload-dir "$source_uploads" >/dev/null 2>&1; then
  echo "backup published a dump whose referenced upload was absent" >&2
  exit 1
fi
[[ -z "$(find "$inconsistent_backup_root" -mindepth 1 -maxdepth 1 -type d -name 'northstar-*' -print -quit)" ]] \
  || { echo "inconsistent backup published a canonical directory" >&2; exit 1; }
# Keep the deliberately inconsistent row until the disposable PostgreSQL
# cluster is removed. Deleting a committed physical projection correctly
# requires the normal cleanup-debt/outbox workflow; bypassing that authority
# merely to tidy a short-lived negative fixture would invalidate the test.

restore_scratch="$work_dir/restore-scratch"
mkdir -m 0700 "$restore_scratch"

# Exact-journal regression: the old and incoming objects deliberately share a
# UUID but have different bytes. Failing immediately after the first old-object
# rename must restore the old bytes; compensation must never infer ownership by
# scanning the complete incoming set.
same_uuid_restore="$work_dir/same-uuid-restore"
same_uuid_rollback="$work_dir/same-uuid-rollback"
mkdir "$same_uuid_restore" "$same_uuid_rollback"
mark_upload_root "$same_uuid_restore"
mark_rollback_root "$same_uuid_rollback"
same_uuid_old_body='pre-restore bytes for the same UUID'
printf '%s' "$same_uuid_old_body" >"$same_uuid_restore/$upload_id"
chmod 0600 "$same_uuid_restore/$upload_id"
create_restore_database northstar_same_uuid_target
apply_repository_migrations northstar_same_uuid_target
same_uuid_probe_user_id="60000000-0000-4000-8000-000000000002"
same_uuid_probe_marker="same-uuid-database-restored"
seed_canonical_probe northstar_same_uuid_target "$same_uuid_probe_user_id" \
  same-uuid-probe "$same_uuid_probe_marker"
reconcile_repository_grants northstar_same_uuid_target
same_uuid_database="postgresql://$migrator_role:$migrator_password@/northstar_same_uuid_target?host=$encoded_socket"
if NORTHSTAR_RESTORE_TEST_FAIL_POINT=after-first-old \
   RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$same_uuid_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$same_uuid_restore" \
   --rollback-dir "$same_uuid_rollback" >/dev/null 2>&1; then
  echo "same-UUID first-old fault injection unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(<"$same_uuid_restore/$upload_id")" == "$same_uuid_old_body" ]] \
  || { echo "exact journal confused old and new objects with the same UUID" >&2; exit 1; }
same_uuid_value="$(read_canonical_probe northstar_same_uuid_target \
  "$same_uuid_probe_user_id")"
[[ "$same_uuid_value" == "$same_uuid_probe_marker|$same_uuid_probe_marker" ]] \
  || { echo "same-UUID database compensation failed" >&2; exit 1; }
[[ -z "$(find "$same_uuid_restore" -mindepth 1 -maxdepth 1 -name '.northstar-restore-cutover-*' -print -quit)" ]] \
  || { echo "successful same-UUID compensation left cutover state" >&2; exit 1; }

# Fail after the first incoming object is activated. The exact new-intent must
# move only that activated object back before restoring the previous object.
new_activation_restore="$work_dir/new-activation-restore"
new_activation_rollback="$work_dir/new-activation-rollback"
mkdir "$new_activation_restore" "$new_activation_rollback"
mark_upload_root "$new_activation_restore"
mark_rollback_root "$new_activation_rollback"
new_activation_old_body='old bytes before first new activation'
printf '%s' "$new_activation_old_body" >"$new_activation_restore/$upload_id"
chmod 0600 "$new_activation_restore/$upload_id"
create_restore_database northstar_new_activation_target
apply_repository_migrations northstar_new_activation_target
new_activation_probe_user_id="60000000-0000-4000-8000-000000000003"
new_activation_probe_marker="new-activation-database-restored"
seed_canonical_probe northstar_new_activation_target \
  "$new_activation_probe_user_id" new-activation-probe \
  "$new_activation_probe_marker"
reconcile_repository_grants northstar_new_activation_target
new_activation_database="postgresql://$migrator_role:$migrator_password@/northstar_new_activation_target?host=$encoded_socket"
if NORTHSTAR_RESTORE_TEST_FAIL_POINT=after-first-new \
   RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$new_activation_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$new_activation_restore" \
   --rollback-dir "$new_activation_rollback" >/dev/null 2>&1; then
  echo "first-new activation fault injection unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(<"$new_activation_restore/$upload_id")" == "$new_activation_old_body" ]] \
  || { echo "first-new compensation did not restore the previous object" >&2; exit 1; }
new_activation_value="$(read_canonical_probe northstar_new_activation_target \
  "$new_activation_probe_user_id")"
[[ "$new_activation_value" == "$new_activation_probe_marker|$new_activation_probe_marker" ]] \
  || { echo "first-new database compensation failed" >&2; exit 1; }

# SIGTERM uses the same unified EXIT compensation path. A clean retry on the
# same roots proves that successful compensation removed the durable cutover
# journal and re-enabled the database rather than leaving a false recovery lock.
signal_restore="$work_dir/signal-restore"
signal_rollback="$work_dir/signal-rollback"
mkdir "$signal_restore" "$signal_rollback"
mark_upload_root "$signal_restore"
mark_rollback_root "$signal_rollback"
signal_old_body='old bytes before SIGTERM'
printf '%s' "$signal_old_body" >"$signal_restore/$upload_id"
chmod 0600 "$signal_restore/$upload_id"
create_restore_database northstar_signal_target
apply_repository_migrations northstar_signal_target
signal_probe_user_id="60000000-0000-4000-8000-000000000004"
signal_probe_marker="signal-database-restored"
seed_canonical_probe northstar_signal_target "$signal_probe_user_id" \
  signal-probe "$signal_probe_marker"
reconcile_repository_grants northstar_signal_target
signal_database="postgresql://$migrator_role:$migrator_password@/northstar_signal_target?host=$encoded_socket"
signal_status=0
RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" \
NORTHSTAR_RESTORE_TEST_SIGNAL_POINT=after-first-new DATABASE_URL="$signal_database" \
  bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE --upload-dir "$signal_restore" \
  --rollback-dir "$signal_rollback" >/dev/null 2>&1 || signal_status=$?
[[ "$signal_status" == 143 ]] \
  || { echo "SIGTERM restore returned unexpected status: $signal_status" >&2; exit 1; }
[[ "$(<"$signal_restore/$upload_id")" == "$signal_old_body" ]] \
  || { echo "SIGTERM compensation did not restore the previous object" >&2; exit 1; }
signal_value="$(read_canonical_probe northstar_signal_target \
  "$signal_probe_user_id")"
[[ "$signal_value" == "$signal_probe_marker|$signal_probe_marker" ]] \
  || { echo "SIGTERM database compensation failed or remained fenced" >&2; exit 1; }
RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$signal_database" \
  bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
  --confirm-restore NORTHSTAR-RESTORE --upload-dir "$signal_restore" \
  --rollback-dir "$signal_rollback" >/dev/null
[[ "$(<"$signal_restore/$upload_id")" == "$upload_body" ]] \
  || { echo "retry after SIGTERM did not activate the backup object" >&2; exit 1; }
signal_restored_value="$(read_canonical_probe northstar_signal_target \
  "$source_probe_user_id")"
[[ "$signal_restored_value" == "$source_probe_marker|$source_probe_marker" ]] \
  || { echo "retry after SIGTERM did not activate the backup database" >&2; exit 1; }
[[ -z "$(find "$restore_scratch" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
  || { echo "successful compensation/retry left plaintext staging" >&2; exit 1; }

# Archive expansion is bounded before tar extraction or cutover. Both a
# per-object and aggregate refusal must leave a fresh target untouched.
budget_restore="$work_dir/budget-restore"
budget_rollback="$work_dir/budget-rollback"
mkdir "$budget_restore" "$budget_rollback"
mark_upload_root "$budget_restore"
mark_rollback_root "$budget_rollback"
budget_sentinel_id="55555555-5555-4555-8555-555555555555"
printf '%s' budget-sentinel >"$budget_restore/$budget_sentinel_id"
chmod 0600 "$budget_restore/$budget_sentinel_id"
create_restore_database northstar_budget_target
apply_repository_migrations northstar_budget_target
budget_probe_user_id="60000000-0000-4000-8000-000000000006"
budget_probe_marker="budget-target-unchanged"
seed_canonical_probe northstar_budget_target "$budget_probe_user_id" \
  budget-probe "$budget_probe_marker"
reconcile_repository_grants northstar_budget_target
budget_database="postgresql://$migrator_role:$migrator_password@/northstar_budget_target?host=$encoded_socket"
if RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$budget_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$budget_restore" \
   --rollback-dir "$budget_rollback" --max-upload-object-bytes "$((upload_size - 1))" \
   >/dev/null 2>&1; then
  echo "restore accepted an upload object above its expansion limit" >&2
  exit 1
fi
if RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$budget_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$budget_restore" \
   --rollback-dir "$budget_rollback" --max-upload-total-bytes "$((upload_size - 1))" \
   >/dev/null 2>&1; then
  echo "restore accepted an archive above its aggregate expansion limit" >&2
  exit 1
fi
budget_value="$(read_canonical_probe northstar_budget_target "$budget_probe_user_id")"
[[ "$budget_value" == "$budget_probe_marker|$budget_probe_marker" \
   && -f "$budget_restore/$budget_sentinel_id" ]] \
  || { echo "archive budget refusal changed a target data plane" >&2; exit 1; }

# Opening a trusted-floor lock must never truncate an existing safe lock file.
floor_state_dir="$work_dir/restore-floor-state"
mkdir -m 0700 "$floor_state_dir"
printf '%s' 'lock-sentinel-must-survive' >"$floor_state_dir/floor.lock"
chmod 0600 "$floor_state_dir/floor.lock"
if RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$budget_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$budget_restore" \
   --rollback-dir "$budget_rollback" --rollback-state-file "$floor_state_dir/floor" \
   --max-upload-object-bytes "$((upload_size - 1))" >/dev/null 2>&1; then
  echo "trusted-floor lock fixture unexpectedly restored" >&2
  exit 1
fi
[[ "$(<"$floor_state_dir/floor.lock")" == lock-sentinel-must-survive ]] \
  || { echo "trusted-floor lock was truncated while being acquired" >&2; exit 1; }
unsafe_floor_state_dir="$work_dir/unsafe-restore-floor-state"
mkdir "$unsafe_floor_state_dir"
chmod 0755 "$unsafe_floor_state_dir"
if RESTORE_PLAINTEXT_STAGING_DIR="$restore_scratch" DATABASE_URL="$budget_database" \
   bash "$project_dir/scripts/restore-backup.sh" "$backup_dir" \
   --confirm-restore NORTHSTAR-RESTORE --upload-dir "$budget_restore" \
   --rollback-dir "$budget_rollback" --rollback-state-file "$unsafe_floor_state_dir/floor" \
   --max-upload-object-bytes "$((upload_size - 1))" >/dev/null 2>&1; then
  echo "restore accepted a non-private trusted-floor parent" >&2
  exit 1
fi
[[ ! -e "$unsafe_floor_state_dir/floor.lock" ]] \
  || { echo "unsafe trusted-floor parent was mutated before rejection" >&2; exit 1; }

echo "backup/restore: production signing+age+role separation, private validation PostgreSQL, non-terminating peer fence, atomic ACL convergence, shared maintenance fence, dump-to-upload validation, strict paths and budgets, same-filesystem journaled cutover, same-UUID/first-old/first-new/SIGTERM compensation, retry recovery, separate rollback retention and durable READY publication passed"
