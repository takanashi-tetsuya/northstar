#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$project_dir/scripts/lib/test-listener-readiness.sh"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
run_id="$(openssl rand -hex 8)"
test_schema="northstar_message_pow_wire_${run_id}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "message PoW wire tests are restricted to the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_message_pow_wire_[0-9a-f]{16}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unexpected message PoW schema: $test_schema" >&2
  exit 2
fi

runtime_dir="$(mktemp -d /tmp/northstar-message-pow-wire.XXXXXX)"
mkdir -p "$runtime_dir/logs"
server_pid=""
created=0
server_generation=0
http_port=""
http_backend_port=""
client_port=""
xmpps_port=""
http_relay_pid=""
http_relay_port=""
http_relay_target="$runtime_dir/message-pow-http.target"
public_url=""
declare -a fixture_listener_ports=()
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$http_relay_pid" ]]; then
    kill "$http_relay_pid" 2>/dev/null || true
    wait "$http_relay_pid" 2>/dev/null || true
  fi
  if (( status != 0 )) && [[ -f "$runtime_dir/server.log" ]]; then
    echo "--- message PoW server log (last 160 lines) ---" >&2
    tail -n 160 "$runtime_dir/server.log" >&2 || true
    if [[ -d "$runtime_dir/logs" ]]; then
      echo "--- message PoW application log (last 160 lines) ---" >&2
      find "$runtime_dir/logs" -maxdepth 1 -type f -name 'server.log*' \
        -exec tail -n 160 {} + >&2 || true
    fi
  fi
  if [[ "$created" == "1" ]]; then
    PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    if [[ "$remains" != "f" ]]; then
      echo "isolated message PoW wire schema remains: $test_schema (exists=$remains)" >&2
      status=1
    fi
  fi
  if ! fixture_assert_no_listeners; then
    status=1
  fi
  case "$runtime_dir" in
    /tmp/northstar-message-pow-wire.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected runtime directory: $runtime_dir" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
openssl rand -base64 -out "$runtime_dir/api-control.secret" 48
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
openssl rand -base64 -out "$runtime_dir/abuse-state.secret" 48
chmod 0600 "$runtime_dir/server.key" "$runtime_dir/api-control.secret" \
  "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret" \
  "$runtime_dir/abuse-state.secret"
chmod 0644 "$runtime_dir/server.crt"

if [[ "$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing schema: $test_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created=1

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${MESSAGE_POW_WIRE_TARGET_DIR:-$project_dir/target/message-pow-wire-wsl}"
fi
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
cargo build --locked --offline

database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema"
resolved_schema="$(psql "$database_url" --tuples-only --no-align --command 'SELECT current_schema()')"
if [[ "$resolved_schema" != "$test_schema" ]]; then
  echo "message PoW DATABASE_URL resolved unexpected schema: $resolved_schema" >&2
  exit 2
fi
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$target_dir/debug/rust-xmpp-server" migrate
: >"$runtime_dir/server.log"

# HTTP now belongs to each Northstar child as an ephemeral listener.  Keep the
# advertised authority owned by this fixture instead: the relay stays at one
# loopback endpoint through the restart while each verified child generation
# atomically publishes only its private target after nonce/PID readiness.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" message-pow-http message-pow-http \
  "$http_relay_target" "$runtime_dir/message-pow-http-relay.log" \
  http_relay_pid http_relay_port
public_url="https://127.0.0.1:$http_relay_port"

publish_http_target() {
  local temporary="$runtime_dir/.message-pow-http.target.$server_generation.$server_pid.tmp"
  printf '127.0.0.1:%s\n' "$http_backend_port" >"$temporary"
  mv -- "$temporary" "$http_relay_target"
}

assert_advertised_public_url() {
  curl --silent --fail "http://127.0.0.1:$http_relay_port/api/v1/config" |
    python3 -c '
import json
import sys

expected = sys.argv[1]
actual = json.load(sys.stdin).get("public_url")
if actual != expected:
    raise SystemExit(
        f"message PoW fixture advertised {actual!r}, expected stable relay {expected!r}"
    )
' "$public_url"
}

start_server() {
  server_generation=$((server_generation + 1))
  local readiness_file="$runtime_dir/server-${server_generation}.ready.json"
  local readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$http_relay_target"
  (
    trap - EXIT INT TERM
    export \
    NORTHSTAR_DISABLE_DOTENV=true \
    XMPP_DOMAIN=localhost \
    DATABASE_URL="$database_url" \
    XMPP_BIND=127.0.0.1:0 \
    XMPPS_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 \
    S2S_TLS_BIND=127.0.0.1:0 \
    HTTP_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true \
    TEST_READINESS_FILE="$readiness_file" \
    TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="$public_url" \
    API_CONTROL_SECRET_FILE="$runtime_dir/api-control.secret" \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
    DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
    ABUSE_STATE_HMAC_KEY_FILE="$runtime_dir/abuse-state.secret" \
    WEBSOCKET_ALLOWED_ORIGINS="http://localhost,$public_url" \
    TRUSTED_PROXY_IPS=127.0.0.1,::1 \
    TLS_CERT_PATH="$runtime_dir/server.crt" \
    TLS_KEY_PATH="$runtime_dir/server.key" \
    UPLOAD_DIR="$runtime_dir/uploads" \
    OPEN_REGISTRATION=true \
    REQUIRE_ENCRYPTED_ARCHIVE=false \
    REGISTRATION_RATE_PER_HOUR=100 \
    POW_BASE_WORK_FACTOR=2 \
    POW_MAX_WORK_FACTOR=64 \
    POW_MAX_DEVICE_SECONDS=8 \
    ABUSE_MESSAGE_FREE_BURST=100 \
    ABUSE_MAX_WAIT_SECONDS=8 \
    OFFLINE_MESSAGE_TTL_DAYS=365 \
    S2S_OUTBOX_TTL_SECONDS=3600 \
    S2S_OUTBOX_RETRY_BASE_SECONDS=300 \
    S2S_OUTBOX_RETRY_MAX_SECONDS=300 \
    S2S_OUTBOX_MAX_ATTEMPTS=200 \
    LOG_DIR="$runtime_dir/logs" \
    LOG_FORMAT=json \
    RUST_LOG=rust_xmpp_server=info
    exec "$target_dir/debug/rust-xmpp-server"
  ) >>"$runtime_dir/server.log" 2>&1 &
  server_pid=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid" || {
    echo "message PoW server failed before publishing readiness" >&2
    return 1
  }
  client_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
  xmpps_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
  http_backend_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  publish_http_target
  http_port="$http_relay_port"
  curl --silent --fail "http://127.0.0.1:$http_backend_port/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null
  assert_advertised_public_url
}

export PGOPTIONS="-c search_path=$test_schema"
export XMPP_TEST_HOST=127.0.0.1
export XMPP_TEST_HTTP_PORT="$http_port"
export XMPP_TEST_CLIENT_PORT="$client_port"
export XMPP_TEST_XMPPS_PORT="$xmpps_port"
export XMPP_TEST_DOMAIN=localhost
export XMPP_TEST_DATABASE="$test_database"
export XMPP_TEST_RUN_ID="$run_id"
export XMPP_TEST_MESSAGE_POW_STATE="$runtime_dir/message-pow-state.json"

start_server
export XMPP_TEST_HTTP_PORT="$http_port"
export XMPP_TEST_CLIENT_PORT="$client_port"
export XMPP_TEST_XMPPS_PORT="$xmpps_port"
python3 scripts/message-pow-wire-wsl.py prepare

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
start_server
export XMPP_TEST_HTTP_PORT="$http_port"
export XMPP_TEST_CLIENT_PORT="$client_port"
export XMPP_TEST_XMPPS_PORT="$xmpps_port"
python3 scripts/message-pow-wire-wsl.py verify

echo "message PoW isolated wire/restart validation passed"
