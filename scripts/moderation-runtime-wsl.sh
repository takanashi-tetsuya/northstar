#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"

test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "moderation runtime tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
run_id="$(openssl rand -hex 16)"
schema="northstar_moderation_rt_${run_id}"
if [[ ! "$schema" =~ ^northstar_moderation_rt_[0-9a-f]{32}$ ]]; then
  echo "refusing an unexpected moderation runtime schema" >&2
  exit 2
fi
read -r xmpp_port xmpps_port s2s_port s2s_tls_port http_port < <(
  python3 "$project_dir/scripts/allocate-test-ports.py" 52000 53999 5
)
ports=("$xmpp_port" "$xmpps_port" "$s2s_port" "$s2s_tls_port" "$http_port")
if [[ "$(printf '%s\n' "${ports[@]}" | sort -u | wc -l)" -ne 5 ]]; then
  echo "moderation runtime ports were not unique" >&2
  exit 2
fi
for port in "${ports[@]}"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
    echo "invalid moderation runtime port: $port" >&2
    exit 2
  fi
done

runtime_dir="$(mktemp -d /tmp/northstar-moderation.XXXXXX)"
chmod 0700 "$runtime_dir"
server_pid=""
schema_created=false
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
log_contains_value() {
  local needle="$1" file
  [[ -n "$needle" ]] || return 1
  if [[ -f "$runtime_dir/server.log" ]] \
     && grep -Fq -- "$needle" "$runtime_dir/server.log"; then
    return 0
  fi
  if [[ -d "$runtime_dir/logs" ]]; then
    while IFS= read -r -d '' file; do
      grep -Fq -- "$needle" "$file" && return 0
    done < <(find "$runtime_dir/logs" -mindepth 1 -maxdepth 1 -type f -name 'server.log*' -print0)
  fi
  return 1
}
log_contains_sensitive_value() {
  local value
  [[ -f "$runtime_dir/server.log" ]] || return 1
  for value in \
    "${MODERATION_USER_PASSWORD:-}" \
    "${MODERATION_ADMIN_PASSWORD:-}" \
    "$(tr -d '\r\n' <"$runtime_dir/api-control.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/fast-token.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/dummy-scram.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/abuse-state.secret" 2>/dev/null || true)"; do
    log_contains_value "$value" && return 0
  done
  if [[ -n "${MODERATION_RUNTIME_STATE:-}" && -f "$MODERATION_RUNTIME_STATE" ]]; then
    while IFS= read -r value; do
      log_contains_value "$value" && return 0
    done < <(python3 -c 'import json,sys; state=json.load(open(sys.argv[1], encoding="utf-8")); print(*[state.get(key, "") for key in ("evidence_marker", "reporter_token", "target_token", "intruder_token", "admin_token", "expired_token")], sep="\n")' "$MODERATION_RUNTIME_STATE" 2>/dev/null || true)
  fi
  log_contains_value 'moderation-evidence-'
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  if [[ "$status" -ne 0 && -f "$runtime_dir/server.log" ]]; then
    if log_contains_sensitive_value; then
      echo "moderation runtime log contains sensitive test data; raw failure tail suppressed" >&2
    else
      echo "moderation runtime server log after failure:" >&2
      tail -n 200 "$runtime_dir/server.log" >&2 || true
    fi
  fi
  if [[ "$schema_created" == true ]]; then
    if ! PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
      --dbname "$test_database" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA \"$schema\" CASCADE;" >/dev/null 2>&1; then
      echo "moderation runtime schema cleanup failed" >&2
      status=1
    fi
    remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
      --dbname "$test_database" --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
      2>/dev/null || printf unknown)"
    remains="${remains//[[:space:]]/}"
    if [[ "$remains" != "f" ]]; then
      echo "moderation runtime schema remained after cleanup: ${remains:-unknown}" >&2
      status=1
    fi
  fi
  for port in "${ports[@]}"; do
    if port_is_listening "$port"; then
      echo "moderation runtime listener remained on port $port" >&2
      status=1
    fi
  done
  case "$runtime_dir" in
    /tmp/northstar-moderation.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected runtime directory: $runtime_dir" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for port in "${ports[@]}"; do
  if port_is_listening "$port"; then
    echo "allocated moderation runtime port is already in use: $port" >&2
    exit 1
  fi
done

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
  --dbname "$test_database" --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$schema\";" >/dev/null
schema_created=true

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
openssl rand -hex 32 >"$runtime_dir/api-control.secret"
openssl rand -hex 32 >"$runtime_dir/fast-token.secret"
openssl rand -hex 32 >"$runtime_dir/dummy-scram.secret"
openssl rand -hex 32 >"$runtime_dir/abuse-state.secret"
chmod 0600 "$runtime_dir/server.key" "$runtime_dir/api-control.secret" \
  "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret" \
  "$runtime_dir/abuse-state.secret"
chmod 0644 "$runtime_dir/server.crt"

short_id="${run_id:0:12}"
export MODERATION_REPORTER_USERNAME="modreporter_$short_id"
export MODERATION_TARGET_USERNAME="modtarget_$short_id"
export MODERATION_INTRUDER_USERNAME="modintruder_$short_id"
export MODERATION_ADMIN_USERNAME="modadmin_$short_id"
export MODERATION_USER_PASSWORD="Northstar-user-${run_id}A9!"
export MODERATION_ADMIN_PASSWORD="Northstar-admin-${run_id}B8!"
export MODERATION_RUNTIME_STATE="$runtime_dir/state.json"

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then cargo_args+=(--offline); fi
cargo build "${cargo_args[@]}"
binary="${CARGO_TARGET_DIR:-$project_dir/target}/debug/rust-xmpp-server"
database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$binary" migrate

env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  XMPP_BIND="127.0.0.1:$xmpp_port" \
  XMPPS_BIND="127.0.0.1:$xmpps_port" \
  S2S_BIND="127.0.0.1:$s2s_port" \
  S2S_TLS_BIND="127.0.0.1:$s2s_tls_port" \
  HTTP_BIND="127.0.0.1:$http_port" \
  PUBLIC_URL="http://127.0.0.1:$http_port" \
  API_CONTROL_SECRET_FILE="$runtime_dir/api-control.secret" \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
  ABUSE_STATE_HMAC_KEY_FILE="$runtime_dir/abuse-state.secret" \
  TRUSTED_PROXY_IPS=127.0.0.1,::1 \
  WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
  UPLOAD_DIR="$runtime_dir/uploads" \
  LOG_DIR="$runtime_dir/logs" \
  TLS_CERT_PATH="$runtime_dir/server.crt" \
  TLS_KEY_PATH="$runtime_dir/server.key" \
  OPEN_REGISTRATION=true \
  INVITATION_REQUIRED=false \
  REQUIRE_ENCRYPTED_ARCHIVE=false \
  FEDERATION_ENABLED=false \
  REGISTRATION_RATE_PER_HOUR=100 \
  MAX_CLIENT_CONNECTIONS=100 \
  MAX_CONNECTIONS_PER_IP=100 \
  POW_BASE_WORK_FACTOR=32 \
  POW_MAX_WORK_FACTOR=4096 \
  POW_MAX_DEVICE_SECONDS=8 \
  ABUSE_MESSAGE_FREE_BURST=20 \
  ABUSE_WINDOW_SECONDS=60 \
  ABUSE_COOLDOWN_SECONDS=60 \
  ABUSE_MAX_WAIT_SECONDS=120 \
  BOOTSTRAP_ADMIN_USERNAME="$MODERATION_ADMIN_USERNAME" \
  BOOTSTRAP_ADMIN_PASSWORD="$MODERATION_ADMIN_PASSWORD" \
  LOG_FORMAT=json \
  RUST_LOG=rust_xmpp_server=info \
  "$binary" >"$runtime_dir/server.log" 2>&1 &
server_pid=$!

export XMPP_TEST_HOST=127.0.0.1
export XMPP_TEST_HTTP_PORT="$http_port"
export XMPP_TEST_CLIENT_PORT="$xmpp_port"
export XMPP_TEST_XMPPS_PORT="$xmpps_port"
export XMPP_TEST_DOMAIN=localhost
python3 scripts/moderation-runtime-wsl.py workflow

state_value() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' \
    "$MODERATION_RUNTIME_STATE" "$1"
}
uuid_keys=(report_id appeal_id report_create_request report_review_request report_final_request \
  appeal_create_request appeal_review_request appeal_final_request)
for key in "${uuid_keys[@]}"; do
  value="$(state_value "$key")"
  if [[ ! "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "moderation state contained an invalid UUID for $key" >&2
    exit 1
  fi
  printf -v "$key" '%s' "$value"
done
expired_token_hash="$(state_value expired_token_hash)"
if [[ ! "$expired_token_hash" =~ ^[0-9a-f]{64}$ ]]; then
  echo "moderation state contained an invalid session digest" >&2
  exit 1
fi

psql_scalar() {
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
    --dbname "$test_database" --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --command "SET search_path TO \"$schema\"; $1" | tail -n 1
}
[[ "$(psql_scalar "SELECT status || ':' || COALESCE(resolution,'') FROM abuse_reports WHERE id='$report_id'")" \
  == "actioned:Confirmed spam; moderation action recorded." ]]
[[ "$(psql_scalar "SELECT status || ':' || COALESCE(resolution,'') FROM abuse_appeals WHERE id='$appeal_id'")" \
  == "denied:Independent review confirmed the original decision." ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM abuse_report_evidence WHERE report_id='$report_id' AND evidence_source='server_verified_plaintext'")" == "1" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM audit_log WHERE action='abuse.report.create' AND target='$report_id' AND request_id='$report_create_request'")" == "1" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM audit_log WHERE action='abuse.appeal.create' AND target='$appeal_id' AND request_id='$appeal_create_request'")" == "1" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM audit_log WHERE action='admin.report.update' AND target='$report_id' AND request_id IN ('$report_review_request','$report_final_request')")" == "2" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM audit_log WHERE action='admin.appeal.update' AND target='$appeal_id' AND request_id IN ('$appeal_review_request','$appeal_final_request')")" == "2" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM abuse_reports WHERE id='$report_id'")" == "1" ]]
[[ "$(psql_scalar "SELECT COUNT(*) FROM abuse_appeals WHERE id='$appeal_id'")" == "1" ]]

expired_rows="$(psql_scalar "WITH expired AS (UPDATE api_sessions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE token_hash=decode('$expired_token_hash','hex') RETURNING 1) SELECT COUNT(*) FROM expired")"
if [[ "$expired_rows" != "1" ]]; then
  echo "could not expire exactly one moderation runtime bearer" >&2
  exit 1
fi
python3 scripts/moderation-runtime-wsl.py expired-token

kill "$server_pid"
wait "$server_pid"
server_pid=""
if ! grep -q 'shutdown complete' "$runtime_dir/server.log"; then
  echo "moderation runtime server did not complete graceful shutdown" >&2
  exit 1
fi
for forbidden_log_value in \
  "$MODERATION_USER_PASSWORD" \
  "$MODERATION_ADMIN_PASSWORD" \
  "$(state_value evidence_marker)" \
  "$(state_value reporter_token)" \
  "$(state_value target_token)" \
  "$(state_value intruder_token)" \
  "$(state_value admin_token)" \
  "$(state_value expired_token)" \
  "$(tr -d '\r\n' <"$runtime_dir/api-control.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/fast-token.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/dummy-scram.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/abuse-state.secret")"; do
  if log_contains_value "$forbidden_log_value"; then
    echo "moderation runtime server log exposed a credential, bearer, secret or message body" >&2
    exit 1
  fi
done
for port in "${ports[@]}"; do
  if port_is_listening "$port"; then
    echo "moderation runtime listener remained after shutdown on port $port" >&2
    exit 1
  fi
done
echo "moderation runtime: report, administration, appeal, audit, idempotency, authorization and expiry passed"
