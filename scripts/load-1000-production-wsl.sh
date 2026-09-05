#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
[[ "$test_database" == "xmpp_test" ]] \
  || { echo "production-envelope load tests are restricted to xmpp_test" >&2; exit 2; }
run_id="$(openssl rand -hex 16)"
schema="northstar_load_envelope_${run_id}"
[[ "$schema" =~ ^northstar_load_envelope_[0-9a-f]{32}$ ]] \
  || { echo "refusing an unexpected load schema" >&2; exit 2; }
ulimit -n 8192

runtime_dir="$(mktemp -d /tmp/northstar-load-envelope.XXXXXX)"
chmod 0700 "$runtime_dir"
server_pid=""
http_relay_pid=""
http_relay_port=""
http_relay_target="$runtime_dir/http.target"
schema_created=false
xmpp_port=""
xmpps_port=""
http_port=""
metrics_port=""
declare -a fixture_listener_ports=()
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
    "${XMPP_LOAD_PASSWORD:-}" \
    "$(tr -d '\r\n' <"$runtime_dir/api-control.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/fast-token.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/dummy-scram.secret" 2>/dev/null || true)" \
    "$(tr -d '\r\n' <"$runtime_dir/abuse-state.secret" 2>/dev/null || true)"; do
    log_contains_value "$value" && return 0
  done
  return 1
}
cleanup() {
  local status=$?
  local cleanup_pid="$server_pid"
  trap - EXIT INT TERM
  if [[ -n "$cleanup_pid" ]]; then
    kill "$cleanup_pid" 2>/dev/null || true
    wait "$cleanup_pid" 2>/dev/null || true
    server_pid=""
  fi
  if [[ -n "$http_relay_pid" ]]; then
    kill "$http_relay_pid" 2>/dev/null || true
    wait "$http_relay_pid" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 && -f "$runtime_dir/server.log" ]]; then
    if log_contains_sensitive_value; then
      echo "production-envelope log contains a password or mounted secret; raw failure tail suppressed" >&2
    else
      echo "production-envelope load server log after failure:" >&2
      tail -n 200 "$runtime_dir/server.log" >&2 || true
    fi
  fi
  if [[ "$schema_created" == true ]]; then
    PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
      --dbname "$test_database" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA \"$schema\" CASCADE;" >/dev/null 2>&1 || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test \
      --dbname "$test_database" --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
      2>/dev/null || printf unknown)"
    remains="${remains//[[:space:]]/}"
    [[ "$remains" == "f" ]] || { echo "load schema cleanup failed: $remains" >&2; status=1; }
  fi
  listener_count=0
  if ! fixture_assert_no_listeners; then listener_count=1; status=1; fi
  if [[ -n "$cleanup_pid" && -d "/proc/$cleanup_pid" ]]; then
    echo "load test server process remained after cleanup" >&2
    status=1
  fi
  case "$runtime_dir" in
    /tmp/northstar-load-envelope.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected load runtime directory" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
export XMPP_LOAD_USERNAME="load_$short_id"
export XMPP_LOAD_SENDER_USERNAME="sender_$short_id"
export XMPP_LOAD_PASSWORD="Northstar-load-${run_id}A9!"
export XMPP_LOAD_SESSIONS=1000
export XMPP_LOAD_MAX_CONNECTIONS=1005

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then cargo_args+=(--offline); fi
cargo build --release "${cargo_args[@]}"
binary="${CARGO_TARGET_DIR:-$project_dir/target}/release/rust-xmpp-server"
database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$binary" migrate

# The advertised HTTP origin must stay owned by this fixture even though the
# server itself binds an ephemeral child-owned listener.  A stable relay lets
# generated upload/BOSH URLs remain routable without reintroducing a released
# numeric port allocation.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" load-http load-http "$http_relay_target" \
  "$runtime_dir/http-relay.log" http_relay_pid http_relay_port

readiness_file="$runtime_dir/server.ready.json"
readiness_nonce="$(openssl rand -hex 16)"
rm -f -- "$readiness_file"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  DATABASE_MAX_CONNECTIONS=32 \
  DATABASE_MIN_CONNECTIONS=2 \
  XMPP_BIND="127.0.0.1:0" \
  XMPPS_BIND="127.0.0.1:0" \
  S2S_BIND="127.0.0.1:0" \
  S2S_TLS_BIND="127.0.0.1:0" \
  HTTP_BIND="127.0.0.1:0" \
  METRICS_BIND="127.0.0.1:0" \
  TEST_LISTENER_ACTIVATION=true \
  TEST_READINESS_FILE="$readiness_file" \
  TEST_READINESS_NONCE="$readiness_nonce" \
  PUBLIC_URL="http://127.0.0.1:$http_relay_port" \
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
  REQUIRE_ENCRYPTED_ARCHIVE=false \
  FEDERATION_ENABLED=false \
  REGISTRATION_RATE_PER_HOUR=100 \
  MAX_CLIENT_CONNECTIONS="$XMPP_LOAD_MAX_CONNECTIONS" \
  MAX_CONNECTIONS_PER_IP="$XMPP_LOAD_MAX_CONNECTIONS" \
  MAX_SESSIONS_PER_ACCOUNT=1100 \
  POW_BASE_WORK_FACTOR=32 \
  POW_MAX_WORK_FACTOR=4096 \
  ABUSE_MESSAGE_FREE_BURST=10000 \
  LOG_FORMAT=json \
  RUST_LOG=rust_xmpp_server=info \
  "$binary" >"$runtime_dir/server.log" 2>&1 &
server_pid=$!

# Use only the nonce- and PID-bound record published after the child owns the
# sockets; do not turn a free numeric port into a later bind request.
fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid"
xmpp_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
xmpps_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
http_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
metrics_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" metrics)"
http_target_tmp="$runtime_dir/.http.target.$server_pid.tmp"
printf '127.0.0.1:%s\n' "$http_port" >"$http_target_tmp"
mv -- "$http_target_tmp" "$http_relay_target"
curl --silent --fail "http://127.0.0.1:$http_relay_port/readyz" >/dev/null

export XMPP_TEST_HOST=127.0.0.1
export XMPP_TEST_HTTP_PORT="$http_relay_port"
export XMPP_TEST_METRICS_PORT="$metrics_port"
export XMPP_TEST_CLIENT_PORT="$xmpp_port"
export XMPP_TEST_XMPPS_PORT="$xmpps_port"
export XMPP_TEST_DOMAIN=localhost
export XMPP_LOAD_SERVER_PID="$server_pid"
export XMPP_LOAD_CA_CERT="$runtime_dir/server.crt"
python3 scripts/load-1000-production-wsl.py

kill "$server_pid"
wait "$server_pid"
finished_pid="$server_pid"
server_pid=""
[[ ! -d "/proc/$finished_pid" ]] || { echo "load server PID remained after wait" >&2; exit 1; }
kill "$http_relay_pid"
wait "$http_relay_pid"
http_relay_pid=""
grep -q 'shutdown complete' "$runtime_dir/server.log" \
  || { echo "load server did not complete graceful shutdown" >&2; exit 1; }
for forbidden_log_value in \
  "$XMPP_LOAD_PASSWORD" \
  "$(tr -d '\r\n' <"$runtime_dir/api-control.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/fast-token.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/dummy-scram.secret")" \
  "$(tr -d '\r\n' <"$runtime_dir/abuse-state.secret")"; do
  if log_contains_value "$forbidden_log_value"; then
    echo "load server log exposed a password or mounted secret" >&2
    exit 1
  fi
done
fixture_assert_no_listeners

echo "production-envelope load validation passed (design evidence, not an SLA guarantee)"
