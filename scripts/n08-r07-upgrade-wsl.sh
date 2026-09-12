#!/usr/bin/env bash
# N08-R07 only: construct a genuine embedded 0137 baseline, prove that a
# current ordinary runtime fails closed before 0138, then use the candidate's
# explicit migrator to append 0138 and prove the ledger-driven rerun is a
# no-op.  The parent private-loopback fixture owns the only database instance.

set -Eeuo pipefail
set +x
umask 077

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

fail() {
  printf 'N08-R07 failed: %s\n' "$1" >&2
  exit 1
}

for variable in \
  NORTHSTAR_PRIVATE_PG_HOST \
  NORTHSTAR_PRIVATE_PG_PORT \
  NORTHSTAR_PRIVATE_PG_DATABASE \
  NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE; do
  [[ -n "${!variable:-}" ]] || fail "private fixture did not supply $variable"
done
[[ "$NORTHSTAR_PRIVATE_PG_HOST" == '127.0.0.1' ]] \
  || fail 'private fixture host is not IPv4 loopback'
[[ "$NORTHSTAR_PRIVATE_PG_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
  && ((10#$NORTHSTAR_PRIVATE_PG_PORT <= 65535)) \
  || fail 'private fixture port is invalid'
[[ "$NORTHSTAR_PRIVATE_PG_DATABASE" == 'xmpp' ]] \
  || fail 'private fixture database identity is invalid'
for secret_file in \
  "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE"; do
  [[ -f "$secret_file" && ! -L "$secret_file" && -r "$secret_file" ]] \
    || fail 'private fixture supplied an unsafe secret file'
done

for command in cargo curl install mktemp openssl psql python3 rm sed sha256sum sha384sum sleep tail; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
readonly binary="$target_dir/debug/rust-xmpp-server"
[[ -x "$binary" ]] || fail "current candidate binary is missing: $binary"
binary_version="$($binary --version)" || fail 'candidate binary did not report its version'
[[ "$binary_version" == 'xmpp-server '* ]] || fail 'candidate binary reported an unexpected version format'

evidence_dir="${NORTHSTAR_N08_EVIDENCE_DIR:-$project_dir/logs/northstar-n08-2026-09-08}"
mkdir -p -- "$evidence_dir" || fail 'could not create N08 evidence directory'
chmod 0700 -- "$evidence_dir" || fail 'could not protect N08 evidence directory'
attempt_id="${NORTHSTAR_N08_RUN_ID:-$(date -u +%Y%m%dT%H%M%S-%N)}"
[[ "$attempt_id" =~ ^[A-Za-z0-9._-]{8,96}$ ]] || fail 'N08 evidence attempt identity is invalid'
readonly evidence_log="$evidence_dir/r07-db08-db03-db04-$attempt_id.log"
readonly evidence_summary="$evidence_dir/r07-db08-db03-db04-$attempt_id.summary"

runtime_root="$(mktemp -d /tmp/northstar-n08-r07.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-n08-r07\.[A-Za-z0-9]{6}$ ]] \
  || fail "refusing unsafe R07 runtime directory: $runtime_root"
readonly runtime_root
readonly runtime_log="$runtime_root/stale-runtime.log"
readonly runtime_cert="$runtime_root/server.crt"
readonly runtime_key="$runtime_root/server.key"
readonly fast_secret="$runtime_root/fast-token.secret"
readonly dummy_scram_secret="$runtime_root/dummy-scram.secret"
readonly abuse_secret="$runtime_root/abuse-state.secret"
readonly api_control_secret="$runtime_root/api-control.secret"
readonly upload_dir="$runtime_root/uploads"
readonly readiness_file="$runtime_root/ready.json"
server_pid=''

redact() {
  sed -E 's#(postgres(ql)?://[^:[:space:]]+:)[^@[:space:]]+@#\1[REDACTED]@#g' \
    | sed -E 's#(password=)[^[:space:]]+#\1[REDACTED]#gi'
}

append_redacted_diagnostic() {
  local source="$1"
  [[ -f "$source" ]] || return 0
  redact <"$source" >>"$evidence_log"
}

stop_owned_server() {
  local deadline
  [[ "$server_pid" =~ ^[1-9][0-9]*$ ]] || return 0
  if kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || return 1
    deadline=$((SECONDS + 10))
    while kill -0 "$server_pid" 2>/dev/null && ((SECONDS < deadline)); do
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      echo 'N08-R07 owned stale-runtime child did not terminate within 10 seconds' >&2
      return 1
    fi
  fi
  wait "$server_pid" 2>/dev/null || true
  server_pid=''
}

cleanup() {
  local original_status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  stop_owned_server || cleanup_status=1
  case "$runtime_root" in
    /tmp/northstar-n08-r07.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
      rm -rf -- "$runtime_root" || cleanup_status=1
      ;;
    *)
      echo "refusing cleanup of unexpected R07 directory: $runtime_root" >&2
      cleanup_status=1
      ;;
  esac
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_as() {
  local url_file="$1"
  shift
  python3 "$project_dir/scripts/run-postgres.py" \
    --database-url-file "$url_file" -- \
    psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 "$@"
}

run_bootstrap_psql() {
  run_as "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE" "$@"
}

run_migrator_psql() {
  run_as "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" "$@"
}

sql_hash() {
  run_migrator_psql --tuples-only --no-align --command "$1" \
    | sha256sum | awk '{print $1}'
}

ledger_state() {
  run_migrator_psql --tuples-only --no-align --command \
    "SELECT count(*) || '|' || min(version) || '|' || max(version) || '|' || bool_and(success) FROM public._sqlx_migrations"
}

runtime_acl_state() {
  run_bootstrap_psql --tuples-only --no-align --command \
    "SELECT has_database_privilege('northstar_runtime','xmpp','CONNECT')::text || '|' || has_schema_privilege('northstar_runtime','public','USAGE')::text || '|' || has_table_privilege('northstar_runtime','public._sqlx_migrations','SELECT')::text || '|' || coalesce(array_to_string((SELECT relacl FROM pg_catalog.pg_class WHERE oid='public._sqlx_migrations'::pg_catalog.regclass),','),'')"
}

historical_count="$(find "$project_dir/migrations" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' -printf '%f\n' \
  | awk -F_ '{version=$1+0; if (version <= 137) count++} END {print count+0}')"
candidate_count="$(find "$project_dir/migrations" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' | wc -l | tr -d '[:space:]')"
[[ "$historical_count" =~ ^[1-9][0-9]*$ && "$candidate_count" =~ ^[1-9][0-9]*$ ]] \
  || fail 'could not determine migration counts'

{
  printf 'case=N08-R07-DB08-DB03-DB04\n'
  printf 'binary_version=%s\n' "$binary_version"
  printf 'binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
  printf 'database_endpoint=127.0.0.1:%s\n' "$NORTHSTAR_PRIVATE_PG_PORT"
  printf 'historical_migration_count=%s\n' "$historical_count"
  printf 'candidate_migration_count=%s\n' "$candidate_count"
  printf 'historical_baseline_source=embedded-sqlx-migrator-through-0137\n'
} >"$evidence_summary"

# The ignored test runs `migrator_through(137)` over the exact compiled
# migration bytes.  It therefore cannot fake an old state by applying 0138
# and deleting a ledger row.  Cargo receives the URL only through its process
# environment; no password-bearing value is written to evidence.
set +e
historical_output="$(TEST_DATABASE_URL="$(<"$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE")" \
  NORTHSTAR_N08_HISTORICAL_0137_FIXTURE=true \
  CARGO_TARGET_DIR="$target_dir" \
  cargo test --locked --offline \
    'db::migration_upgrade_test::historical_0137_baseline_is_built_from_the_embedded_migration_chain' \
    -- --ignored --exact --nocapture 2>&1)"
historical_status=$?
set -e
printf '%s\n' "$historical_output" | redact >>"$evidence_log"
[[ "$historical_status" == 0 ]] || fail 'embedded historical-0137 baseline test failed'
grep -Fq 'test result: ok. 1 passed; 0 failed' <<<"$historical_output" \
  || fail 'historical-0137 baseline test did not execute exactly one test'

ledger_before="$(ledger_state)"
[[ "$ledger_before" == "$historical_count|1|137|true" ]] \
  || fail "historical baseline ledger is not exact: $ledger_before"
ledger_before_hash="$(sql_hash "SELECT version,description,success,encode(checksum,'hex') FROM public._sqlx_migrations ORDER BY version")"
representative_before="$(sql_hash "SELECT action,target,details::text FROM public.audit_log WHERE action='n08.migration.fixture' AND target='historical-0137' ORDER BY id")"
fixture_rows="$(run_migrator_psql --tuples-only --no-align --command "SELECT count(*) FROM public.audit_log WHERE action='n08.migration.fixture' AND target='historical-0137'")"
[[ "$fixture_rows" == 1 ]] || fail 'historical representative record is missing or duplicated'

# A real 0137 database has no current-version runtime grant reconciler in this
# candidate tree.  The fixture adds only enough read-only access to reach the
# first runtime gate (the immutable migration ledger).  It deliberately does
# not grant DML, routine execution, ownership, or DDL.  The exact current ACL
# policy is applied only after the explicit current migrator succeeds.
run_bootstrap_psql <<'SQL' >/dev/null
GRANT CONNECT ON DATABASE xmpp TO northstar_runtime;
GRANT USAGE ON SCHEMA public TO northstar_runtime;
GRANT SELECT ON TABLE public._sqlx_migrations TO northstar_runtime;
SQL
stale_acl_before="$(runtime_acl_state)"
[[ "$stale_acl_before" == true\|true\|true\|* ]] \
  || fail 'stale-runtime fixture did not receive the documented minimal ledger-read access'

install -d -m 0700 "$upload_dir"
for secret_file in "$fast_secret" "$dummy_scram_secret" "$abuse_secret" "$api_control_secret"; do
  install -m 0600 /dev/null "$secret_file"
  openssl rand -hex 32 >"$secret_file"
done
openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
  -subj '/CN=localhost' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -addext 'subjectAltName=DNS:localhost' \
  -keyout "$runtime_key" -out "$runtime_cert" >/dev/null 2>&1
chmod 0600 "$runtime_key"

readiness_nonce="$(openssl rand -hex 16)"
# northstar-runtime-migration-negative-precheck: immutable-ledger-drift
# DB08 deliberately starts the historical 0137 database once to prove that a
# runtime cannot publish readiness before the current immutable ledger exists.
# The bounded rejection assertions immediately below are part of this fixture's
# contract; DB03 is the sole path that subsequently performs the upgrade.
env NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE" \
  ADMIN_COMMAND_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE" \
  XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 \
  S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 COMPONENT_BIND=127.0.0.1:0 \
  METRICS_BIND=127.0.0.1:0 WEB_ADMIN_ENABLED=false \
  TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
  PUBLIC_URL=http://localhost:18080 \
  TLS_CERT_PATH="$runtime_cert" TLS_KEY_PATH="$runtime_key" UPLOAD_DIR="$upload_dir" \
  FAST_TOKEN_SECRET_FILE="$fast_secret" DUMMY_SCRAM_SECRET_FILE="$dummy_scram_secret" \
  ABUSE_STATE_HMAC_KEY_FILE="$abuse_secret" API_CONTROL_SECRET_FILE="$api_control_secret" \
  OPEN_REGISTRATION=false INVITATION_REQUIRED=false FEDERATION_ENABLED=false DIALBACK_ENABLED=false \
  LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info \
  "$binary" >"$runtime_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 100); do
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$server_pid" 2>/dev/null; then
  append_redacted_diagnostic "$runtime_log"
  stop_owned_server || true
  fail 'stale runtime exceeded the 10-second bounded rejection window'
fi
set +e
wait "$server_pid"
stale_status=$?
set -e
server_pid=''
append_redacted_diagnostic "$runtime_log"
[[ "$stale_status" != 0 ]] || fail 'stale runtime unexpectedly exited successfully'
[[ ! -e "$readiness_file" ]] || fail 'stale runtime published readiness despite missing migration 0138'
grep -Fq 'PostgreSQL migration ledger drifted:' "$runtime_log" \
  || fail 'stale runtime failed before the expected immutable migration-ledger rejection'

ledger_after_stale="$(ledger_state)"
stale_acl_after="$(runtime_acl_state)"
[[ "$ledger_after_stale" == "$ledger_before" ]] \
  || fail 'stale runtime altered the historical migration ledger'
[[ "$stale_acl_after" == "$stale_acl_before" ]] \
  || fail 'stale runtime altered the fixture ACLs'

# DB03: explicit DDL is available solely through the migrator identity and the
# current executable.  This is the first operation allowed to append 0138.
if ! NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$binary" migrate >"$runtime_root/migrate-0138.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/migrate-0138.log"
  fail 'explicit current migrator could not upgrade the 0137 baseline'
fi

ledger_after_upgrade="$(ledger_state)"
[[ "$ledger_after_upgrade" == "$candidate_count|1|138|true" ]] \
  || fail "explicit migration did not append the complete candidate ledger: $ledger_after_upgrade"
ledger_after_upgrade_hash="$(sql_hash "SELECT version,description,success,encode(checksum,'hex') FROM public._sqlx_migrations ORDER BY version")"
stored_0138_checksum="$(run_migrator_psql --tuples-only --no-align --command "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=138")"
expected_0138_checksum="$(sha384sum "$project_dir/migrations/0138_sm_mix_teardown_catalog.sql" | awk '{print $1}')"
[[ "$stored_0138_checksum" == "$expected_0138_checksum" ]] \
  || fail 'migration 0138 ledger checksum differs from the candidate source'
[[ "$(run_migrator_psql --tuples-only --no-align --command "SELECT count(*) FROM public._sqlx_migrations WHERE version=138")" == 1 ]] \
  || fail 'migration 0138 ledger row was not appended exactly once'
[[ "$(run_migrator_psql --tuples-only --no-align --command "SELECT count(*) FROM pg_catalog.pg_trigger AS trigger WHERE trigger.tgrelid='public.sm_resume_sessions'::pg_catalog.regclass AND trigger.tgname='sm_resume_sessions_release_mix_delivery_owners' AND NOT trigger.tgisinternal")" == 1 ]] \
  || fail 'SM-to-MIX lease-release trigger is absent or duplicated after upgrade'
representative_after_upgrade="$(sql_hash "SELECT action,target,details::text FROM public.audit_log WHERE action='n08.migration.fixture' AND target='historical-0137' ORDER BY id")"
[[ "$representative_after_upgrade" == "$representative_before" ]] \
  || fail 'explicit migration rewrote the historical representative record'

# Once the full immutable ledger exists, reconcile the canonical exact ACLs.
# This removes the fixture-only ledger read grant and makes the upgraded
# database eligible for ordinary strict-runtime validation in subsequent work.
if ! MIGRATOR_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  bash "$project_dir/scripts/reconcile-database-grants.sh" \
    --database-url-file "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
    >"$runtime_root/grants.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/grants.log"
  fail 'exact grant reconciliation failed after migration 0138'
fi

# DB04: a second candidate migrator invocation must be a ledger-validated
# no-op; do not substitute a direct SQL rerun.
if ! NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$binary" migrate >"$runtime_root/migrate-repeat.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/migrate-repeat.log"
  fail 'idempotent candidate migrator rerun failed'
fi
ledger_after_repeat="$(ledger_state)"
ledger_after_repeat_hash="$(sql_hash "SELECT version,description,success,encode(checksum,'hex') FROM public._sqlx_migrations ORDER BY version")"
representative_after_repeat="$(sql_hash "SELECT action,target,details::text FROM public.audit_log WHERE action='n08.migration.fixture' AND target='historical-0137' ORDER BY id")"
[[ "$ledger_after_repeat" == "$ledger_after_upgrade" ]] \
  || fail 'idempotent candidate migration changed ledger shape'
[[ "$ledger_after_repeat_hash" == "$ledger_after_upgrade_hash" ]] \
  || fail 'idempotent candidate migration changed a ledger row or checksum'
[[ "$representative_after_repeat" == "$representative_before" ]] \
  || fail 'idempotent candidate migration rewrote the historical representative record'
[[ "$(run_migrator_psql --tuples-only --no-align --command "SELECT count(*) FROM pg_catalog.pg_trigger AS trigger WHERE trigger.tgrelid='public.sm_resume_sessions'::pg_catalog.regclass AND trigger.tgname='sm_resume_sessions_release_mix_delivery_owners' AND NOT trigger.tgisinternal")" == 1 ]] \
  || fail 'idempotent migration duplicated or removed the SM-to-MIX lease-release trigger'

{
  printf 'db08_stale_runtime=expected-ledger-rejection-no-readiness\n'
  printf 'db08_ledger_before=%s\n' "$ledger_before"
  printf 'db08_ledger_after=%s\n' "$ledger_after_stale"
  printf 'db08_acl_unchanged=true\n'
  printf 'db03_ledger_after_upgrade=%s\n' "$ledger_after_upgrade"
  printf 'db03_0138_checksum=%s\n' "$stored_0138_checksum"
  printf 'db04_ledger_after_repeat=%s\n' "$ledger_after_repeat"
  printf 'db04_ledger_hash_unchanged=true\n'
  printf 'representative_data_preserved=true\n'
  printf 'sm_mix_release_trigger_count=1\n'
  printf 'fixture_runtime_ledger_read_acl=temporary-minimal-precheck-only\n'
} >>"$evidence_summary"
cat "$evidence_summary" >>"$evidence_log"
printf 'N08-R07 PASS: DB08 rejected missing 0138, DB03 upgraded through the current migrator, DB04 reran idempotently\n'
