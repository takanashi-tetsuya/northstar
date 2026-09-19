#!/usr/bin/env bash
# N08-R06 only: run the candidate's explicit migration, strict runtime
# attestation, bounded loopback startup and readiness check.  The parent
# `private-loopback-postgres-wsl.sh` creates the PostgreSQL instance and gives
# this script the protected connection-file paths; this script never accepts a
# caller-provided host, port, password, or database name.

set -Eeuo pipefail
set +x
umask 077

# The shared listener-readiness helpers use a function-local `project_dir`.
# Keep this caller binding mutable so Bash can establish that local shadow.
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

fail() {
  printf 'N08-R06 DB01 failed: %s\n' "$1" >&2
  exit 1
}

for variable in \
  NORTHSTAR_PRIVATE_PG_HOST \
  NORTHSTAR_PRIVATE_PG_PORT \
  NORTHSTAR_PRIVATE_PG_DATABASE \
  NORTHSTAR_PRIVATE_PG_BOOTSTRAP_PASSWORD_FILE \
  NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE; do
  [[ -n "${!variable:-}" ]] || fail "private fixture did not supply $variable"
done
[[ "$NORTHSTAR_PRIVATE_PG_HOST" == 127.0.0.1 ]] \
  || fail 'private fixture host is not IPv4 loopback'
[[ "$NORTHSTAR_PRIVATE_PG_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
  && ((10#$NORTHSTAR_PRIVATE_PG_PORT <= 65535)) \
  || fail 'private fixture port is invalid'
[[ "$NORTHSTAR_PRIVATE_PG_DATABASE" == xmpp ]] \
  || fail 'private fixture database identity is invalid'
for secret_file in \
  "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_PASSWORD_FILE" \
  "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE"; do
  [[ -f "$secret_file" && ! -L "$secret_file" && -r "$secret_file" ]] \
    || fail 'private fixture supplied an unsafe secret file'
done

for command in curl install mktemp openssl psql python3 rm sed sha256sum sleep tail; do
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
readonly evidence_log="$evidence_dir/r06-db01-private-loopback-$attempt_id.log"
readonly evidence_summary="$evidence_dir/r06-db01-private-loopback-$attempt_id.summary"
runtime_root="$(mktemp -d /tmp/northstar-n08-db01.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-n08-db01\.[A-Za-z0-9]{6}$ ]] \
  || fail "refusing unsafe DB01 runtime directory: $runtime_root"
readonly runtime_root
readonly runtime_log="$runtime_root/server.log"
readonly runtime_cert="$runtime_root/server.crt"
readonly runtime_key="$runtime_root/server.key"
readonly fast_secret="$runtime_root/fast-token.secret"
readonly dummy_scram_secret="$runtime_root/dummy-scram.secret"
readonly abuse_secret="$runtime_root/abuse-state.secret"
readonly api_control_secret="$runtime_root/api-control.secret"
readonly upload_dir="$runtime_root/uploads"
readonly readiness_file="$runtime_root/ready.json"
server_pid=''
declare -a fixture_listener_ports=()

redacted_tail() {
  [[ -f "$runtime_log" ]] || return 0
  tail -n 160 -- "$runtime_log" \
    | sed -E 's#(postgres(ql)?://[^:[:space:]]+:)[^@[:space:]]+@#\1[REDACTED]@#g' \
    | sed -E 's#(password=)[^[:space:]]+#\1[REDACTED]#gi' \
    >&2 || true
}

append_redacted_diagnostic() {
  local source="$1"
  [[ -f "$source" ]] || return 0
  sed -E 's#(postgres(ql)?://[^:[:space:]]+:)[^@[:space:]]+@#\1[REDACTED]@#g' "$source" \
    | sed -E 's#(password=)[^[:space:]]+#\1[REDACTED]#gi' \
    >>"$evidence_log"
}

cleanup() {
  local original_status=$? cleanup_status=0 deadline
  trap - EXIT INT TERM
  set +e
  if [[ "$server_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || cleanup_status=1
    deadline=$((SECONDS + 15))
    while kill -0 "$server_pid" 2>/dev/null && ((SECONDS < deadline)); do
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      echo 'N08-R06 bounded server shutdown timed out; retaining diagnostics' >&2
      cleanup_status=1
    fi
  fi
  [[ -z "$server_pid" ]] || wait "$server_pid" 2>/dev/null || true
  if ! fixture_assert_no_listeners; then
    echo 'N08-R06 detected a listener owned by its candidate child after shutdown' >&2
    cleanup_status=1
  fi
  case "$runtime_root" in
    /tmp/northstar-n08-db01.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
      rm -rf -- "$runtime_root" || cleanup_status=1
      ;;
    *)
      echo "refusing cleanup of unexpected DB01 directory: $runtime_root" >&2
      cleanup_status=1
      ;;
  esac
  if ((original_status != 0)); then
    redacted_tail
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

source "$project_dir/scripts/lib/test-listener-readiness.sh"

run_migrator_psql() {
  python3 "$project_dir/scripts/run-postgres.py" \
    --database-url-file "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" -- \
    psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 "$@"
}

migration_count="$(find "$project_dir/migrations" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' | wc -l | tr -d '[:space:]')"
[[ "$migration_count" =~ ^[1-9][0-9]*$ ]] || fail 'could not determine the candidate migration count'

{
  printf 'case=N08-R06-DB01\n'
  printf 'binary_version=%s\n' "$binary_version"
  printf 'binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
  printf 'expected_migration_count=%s\n' "$migration_count"
  printf 'database_endpoint=127.0.0.1:%s\n' "$NORTHSTAR_PRIVATE_PG_PORT"
} >"$evidence_summary"

# Explicit DDL must run through the current candidate's migrate command, never
# through handwritten copies of the SQL files.
if ! NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$binary" migrate >"$runtime_root/migrate.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/migrate.log"
  fail 'explicit current-binary migration failed'
fi

# Runtime capabilities are not implicitly granted by the migrator.  Use the
# repository reconciliation entry point before testing the dedicated runtime
# and command identities.
if ! MIGRATOR_DATABASE_URL_FILE="$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  bash "$project_dir/scripts/reconcile-database-grants.sh" \
    --database-url-file "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
    >"$runtime_root/grants.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/grants.log"
  fail 'post-migration grant reconciliation failed'
fi

if ! POSTGRES_CONNECTION_PASSWORD_FILE="$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_PASSWORD_FILE" \
  bash "$project_dir/scripts/reconcile-database-roles.sh" --audit \
    --host 127.0.0.1 --port "$NORTHSTAR_PRIVATE_PG_PORT" \
    --connect-as northstar_bootstrap \
    --connection-password-file "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_PASSWORD_FILE" \
    >"$runtime_root/role-audit.log" 2>&1; then
  append_redacted_diagnostic "$runtime_root/role-audit.log"
  fail 'strict runtime role and capability audit failed'
fi

ledger_before="$(run_migrator_psql --tuples-only --no-align --command \
  "SELECT count(*) || '|' || min(version) || '|' || max(version) || '|' || bool_and(success) FROM public._sqlx_migrations")"
[[ "$ledger_before" == "$migration_count|1|138|true" ]] \
  || fail "candidate migration ledger differs from expected complete set: $ledger_before"
canonicalizer_marker="$(run_migrator_psql --tuples-only --no-align --command \
  "SELECT count(*) FROM public.jid_identity_migrations WHERE canonicalizer_version > 0")"
[[ "$canonicalizer_marker" =~ ^[1-9][0-9]*$ ]] \
  || fail 'domain canonicalizer marker is absent after migration'

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
fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid" \
  || {
    append_redacted_diagnostic "$runtime_log"
    fail 'strict runtime did not publish a valid readiness record'
  }
http_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)" \
  || fail 'strict runtime did not publish an HTTP listener'
curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null \
  || fail 'strict runtime readiness endpoint did not answer'

ledger_after="$(run_migrator_psql --tuples-only --no-align --command \
  "SELECT count(*) || '|' || min(version) || '|' || max(version) || '|' || bool_and(success) FROM public._sqlx_migrations")"
[[ "$ledger_after" == "$ledger_before" ]] \
  || fail "runtime startup altered the migration ledger: before=$ledger_before after=$ledger_after"

{
  printf 'migration_ledger=%s\n' "$ledger_before"
  printf 'canonicalizer_markers=%s\n' "$canonicalizer_marker"
  printf 'runtime_attestation=strict-role-audit-passed\n'
  printf 'runtime_start=readyz-passed\n'
  printf 'runtime_ddl=ledger-unchanged\n'
} >>"$evidence_summary"
cat "$evidence_summary" >"$evidence_log"
printf 'N08-R06 DB01 PASS: explicit migration, strict role audit, runtime readiness, and ledger immutability verified\n'
