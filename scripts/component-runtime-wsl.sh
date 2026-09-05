#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

nonce="$(date +%s%N)_$$"
schema="component_runtime_${nonce}"
[[ "$schema" =~ ^component_runtime_[0-9_]+$ ]] || { echo "unsafe component test schema" >&2; exit 1; }
runtime_dir="$(mktemp -d /tmp/northstar-component.XXXXXX)"
pid=""
mock_pid=""
component_http_relay_pid=""
component_http_relay_port=""
component_http_relay_target="$runtime_dir/component-http.target"
server_generation=0
mock_generation=0
test_xmpp_port=""
test_http_port=""
test_component_port=""
test_connect_port=""
declare -a fixture_listener_ports=()
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  if [[ -n "$mock_pid" ]]; then kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true; fi
  if [[ -n "$component_http_relay_pid" ]]; then
    kill "$component_http_relay_pid" 2>/dev/null || true
    wait "$component_http_relay_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "component runtime server log after failure:" >&2
    tail -n 200 "$runtime_dir/server.log" >&2 || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/component-mock.log" ]]; then
    echo "component connect mock log after failure:" >&2
    tail -n 200 "$runtime_dir/component-mock.log" >&2 || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/component-disabled-mock.log" ]]; then
    echo "federation-disabled component connect mock log after failure:" >&2
    tail -n 200 "$runtime_dir/component-disabled-mock.log" >&2 || true
  fi
  if ! PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE;" >/dev/null 2>&1; then
    status=1
  fi
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
    2>/dev/null || printf unknown)"
  remains="${remains//[[:space:]]/}"
  if [[ "$remains" != "f" ]]; then
    echo "component runtime schema cleanup failed: $schema=${remains:-unknown}" >&2
    status=1
  fi
  listener_count=0
  if ! fixture_assert_no_listeners; then listener_count=1; status=1; fi
  case "$runtime_dir" in
    /tmp/northstar-component.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected component runtime directory: $runtime_dir" >&2; status=1 ;;
  esac
  runtime_remains=0
  if [[ -e "$runtime_dir" ]]; then
    runtime_remains=1
    echo "component runtime directory remained: $runtime_dir" >&2
    status=1
  fi
  echo "component cleanup: schema=$schema:${remains:-unknown} listeners=$listener_count runtime_dirs=$runtime_remains"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 \
  --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null

openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=Northstar Component Runtime CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$runtime_dir/component-ca.key" -out "$runtime_dir/component-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "subjectAltName=DNS:localhost,DNS:gateway.localhost" \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$runtime_dir/server.csr" \
  -CA "$runtime_dir/component-ca.crt" -CAkey "$runtime_dir/component-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$runtime_dir/server-leaf.crt" >/dev/null 2>&1
cp "$runtime_dir/server-leaf.crt" "$runtime_dir/server.crt"
openssl x509 -in "$runtime_dir/component-ca.crt" -outform PEM >>"$runtime_dir/server.crt"
chmod 600 "$runtime_dir/server.key" "$runtime_dir/component-ca.key"
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
chmod 600 "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret"
component_secret="$(openssl rand -hex 32)"
outbound_component_secret="$(openssl rand -hex 32)"
wrong_outbound_component_secret="$(openssl rand -hex 32)"
printf '%s\n' "$wrong_outbound_component_secret" >"$runtime_dir/outbound-component.secret"
chmod 600 "$runtime_dir/outbound-component.secret"

# The connect-mode mock owns its loopback socket before the server can be
# configured with its address.  This deliberately writes configuration only
# after the mock's nonce/PID-bound readiness record proves that ownership.
write_components_config() {
  [[ "$test_connect_port" =~ ^[1-9][0-9]*$ ]] && (( test_connect_port <= 65535 )) || {
    echo "component connect mock did not publish a valid port" >&2
    return 1
  }
  cat >"$runtime_dir/components.json" <<EOF
{"components":[{"jid":"gateway.localhost","aliases":["alias.gateway.localhost"],"secret":"$component_secret","connection":"accept","legacy_0114":true,"modern_0225":true},{"jid":"outbound.localhost","aliases":[],"secret_file":"$runtime_dir/outbound-component.secret","connection":"connect","connect_endpoint":"127.0.0.1:$test_connect_port","legacy_0114":true,"modern_0225":false}]}
EOF
  chmod 600 "$runtime_dir/components.json"
}

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then cargo_args+=(--offline); fi
cargo build "${cargo_args[@]}"
binary="${CARGO_TARGET_DIR:-$project_dir/target}/debug/rust-xmpp-server"
component_database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"

# Runtime startup is verification-only. This suite owns its random schema, so
# apply migrations explicitly with the test role before starting the server.
env NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$component_database_url" \
  "$binary" migrate

# The configured public URL must remain an endpoint owned by this fixture even
# as the server is intentionally crashed and restarted below.  The relay owns
# its loopback port for the whole suite; each verified server generation
# atomically replaces only the relay target.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" component-http component-http \
  "$component_http_relay_target" "$runtime_dir/component-http-relay.log" \
  component_http_relay_pid component_http_relay_port

publish_component_http_target() {
  local temporary="$runtime_dir/.component-http.target.$server_generation.tmp"
  printf '127.0.0.1:%s\n' "$test_http_port" >"$temporary"
  mv -f -- "$temporary" "$component_http_relay_target"
}

start_server() {
  local federation_enabled="${1:-true}"
  local readiness_file="$runtime_dir/server-$((server_generation + 1)).ready.json"
  local readiness_nonce
  server_generation=$((server_generation + 1))
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$component_http_relay_target"
  env XMPP_DOMAIN=localhost \
    NORTHSTAR_DISABLE_DOTENV=true \
    DATABASE_URL="$component_database_url" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 METRICS_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 COMPONENT_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$component_http_relay_port" UPLOAD_DIR="$runtime_dir/uploads" \
    TLS_CERT_PATH="$runtime_dir/server.crt" TLS_KEY_PATH="$runtime_dir/server.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=false REGISTRATION_RATE_PER_HOUR=20 \
    FEDERATION_ENABLED="$federation_enabled" FEDERATION_ALLOWLIST=allowed.remote.invalid \
    DIALBACK_ENABLED=false S2S_SASL_EXTERNAL_ENABLED=true \
    DIALBACK_SECRET_FILE= DIALBACK_SECRET= \
    COMPONENTS_ENABLED=true COMPONENTS_CONFIG_FILE="$runtime_dir/components.json" \
    COMPONENT_HANDSHAKE_TIMEOUT_SECONDS=5 \
    API_CONTROL_ALLOW_EPHEMERAL=true \
    ABUSE_STATE_ALLOW_EPHEMERAL=true \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
    DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
    LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
    "$binary" >"$runtime_dir/server.log" 2>&1 &
  pid=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid" || return 1
  test_xmpp_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
  test_http_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  test_component_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" component)"
  publish_component_http_target
  export XMPP_TEST_CLIENT_PORT="$test_xmpp_port"
  # The Python fixture is an external HTTP/WebSocket client.  Keep it on the
  # stable public relay rather than leaking knowledge of a generation-specific
  # server listener into test traffic.
  export XMPP_TEST_HTTP_PORT="$component_http_relay_port"
  export COMPONENT_RUNTIME_PORT="$test_component_port"
  curl --silent --fail "http://127.0.0.1:$test_http_port/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$component_http_relay_port/readyz" >/dev/null
}

start_connect_mock() {
  local mode="$1" log_file="$2"
  local readiness_file="$runtime_dir/component-connect-$((mock_generation + 1)).ready.json"
  local readiness_nonce
  mock_generation=$((mock_generation + 1))
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  env COMPONENT_CONNECT_RUNTIME_PORT=0 \
    COMPONENT_CONNECT_READINESS_FILE="$readiness_file" \
    COMPONENT_CONNECT_READINESS_NONCE="$readiness_nonce" \
    python3 scripts/component-runtime-wsl.py "$mode" >"$log_file" 2>&1 &
  mock_pid=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$mock_pid" || return 1
  test_connect_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" component-connect)"
  export COMPONENT_CONNECT_RUNTIME_PORT="$test_connect_port"
  write_components_config
}

export COMPONENT_RUNTIME_SECRET="$component_secret"
export COMPONENT_CONNECT_RUNTIME_SECRET="$outbound_component_secret"
export COMPONENT_RUNTIME_CA_FILE="$runtime_dir/component-ca.crt"
python3 scripts/component-runtime-wsl.py reader-selftest
echo "component runtime schema: $schema"

# A configured connect-mode component is local authority only.  Even an
# allowlisted remote domain must remain unreachable while federation itself is
# disabled.  Use the correct mounted secret for this isolated negative phase.
printf '%s\n' "$outbound_component_secret" >"$runtime_dir/outbound-component.secret"
start_connect_mock connect-disabled-federation-mock "$runtime_dir/component-disabled-mock.log"
start_server false
echo "component runtime ports: xmpp=$test_xmpp_port http=$test_http_port component=$test_component_port connect-mock=$test_connect_port"
for _ in $(seq 1 100); do
  if ! kill -0 "$mock_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$mock_pid" 2>/dev/null; then
  echo "federation-disabled outbound component mock did not finish" >&2
  exit 1
fi
if ! wait "$mock_pid"; then
  echo "federation-disabled outbound component mock failed:" >&2
  cat "$runtime_dir/component-disabled-mock.log" >&2
  exit 1
fi
mock_pid=""
kill "$pid"
wait "$pid" 2>/dev/null || true
pid=""

# Restore the deliberately wrong initial credential used by the crash/restart
# durability phase below.  The second startup explicitly enables federation
# and proves that only the configured allowlist can be handed to S2S.
printf '%s\n' "$wrong_outbound_component_secret" >"$runtime_dir/outbound-component.secret"
start_connect_mock connect-mock "$runtime_dir/component-mock.log"
start_server true
python3 scripts/component-runtime-wsl.py enqueue
queued="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --tuples-only --no-align --command "SET search_path TO \"$schema\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='gateway.localhost';" | tail -n 1)"
echo "component outbox rows before crash: $queued"
[[ "$queued" == "1" ]] || { echo "expected one durable component row before crash" >&2; exit 1; }
outbound_queued="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --tuples-only --no-align --command "SET search_path TO \"$schema\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='outbound.localhost';" | tail -n 1)"
echo "outbound connect outbox rows before credential correction: $outbound_queued"
[[ "$outbound_queued" == "1" ]] || { echo "expected one durable outbound component row before restart" >&2; exit 1; }
kill -9 "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""
printf '%s\n' "$outbound_component_secret" >"$runtime_dir/outbound-component.secret"
chmod 600 "$runtime_dir/outbound-component.secret"
start_server
python3 scripts/component-runtime-wsl.py component
for _ in $(seq 1 100); do
  if ! kill -0 "$mock_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$mock_pid" 2>/dev/null; then
  echo "outbound component mock did not finish" >&2
  exit 1
fi
if ! wait "$mock_pid"; then
  echo "outbound component mock failed:" >&2
  cat "$runtime_dir/component-mock.log" >&2
  exit 1
fi
mock_pid=""
remaining="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --tuples-only --no-align --command "SET search_path TO \"$schema\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain IN ('gateway.localhost', 'outbound.localhost');" | tail -n 1)"
echo "component outbox rows after accept, modern and connect transports: $remaining"
[[ "$remaining" == "0" ]] || { echo "component outbox did not drain" >&2; exit 1; }
federation_queued="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --tuples-only --no-align --command "SET search_path TO \"$schema\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='allowed.remote.invalid';" | tail -n 1)"
echo "allowed federation rows durably handed off by component: $federation_queued"
[[ "$federation_queued" == "1" ]] || { echo "allowed component federation handoff was not persisted" >&2; exit 1; }
