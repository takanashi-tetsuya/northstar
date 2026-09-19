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
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

nonce="$(date +%s%N)_$$"
schema="mix_runtime_${nonce}"
[[ "$schema" =~ ^mix_runtime_[0-9_]+$ ]] || { echo "unsafe MIX runtime schema" >&2; exit 2; }
runtime_dir="$(mktemp -d /tmp/northstar-mix.XXXXXX)"
mkdir -p "$runtime_dir/logs"
server_pid=""
mix_http_relay_pid=""
mix_http_relay_port=""
mix_http_relay_target="$runtime_dir/mix-http.target"
declare -a fixture_listener_ports=()
xmpp_port=""
xmpps_port=""
http_port=""
http_backend_port=""
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$mix_http_relay_pid" ]]; then
    kill "$mix_http_relay_pid" 2>/dev/null || true
    wait "$mix_http_relay_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "MIX runtime server log after failure:" >&2
    tail -n 200 "$runtime_dir/server.log" >&2 || true
  fi
  if [[ $status -ne 0 && -d "$runtime_dir/logs" ]]; then
    while IFS= read -r -d '' log_file; do
      echo "MIX runtime rolling log after failure: $log_file" >&2
      tail -n 200 "$log_file" >&2 || true
    done < <(find "$runtime_dir/logs" -mindepth 1 -maxdepth 1 -type f -name 'server.log*' -print0)
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE;" >/dev/null 2>&1 || true
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test --tuples-only --no-align --command "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='$schema';" 2>/dev/null | tail -n 1 || true)"
  listener_count=0
  if ! fixture_assert_no_listeners; then
    listener_count=1
    status=1
  fi
  case "$runtime_dir" in
    /tmp/northstar-mix.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected MIX runtime directory: $runtime_dir" >&2; status=1 ;;
  esac
  echo "MIX cleanup: pid=$server_pid stopped; schema=$schema remains=${remains:-unknown}; listeners=$listener_count"
  exit "$status"
}
trap cleanup EXIT

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
chmod 0600 "$runtime_dir/server.key"
openssl rand -base64 -out "$runtime_dir/api-control.secret" 48
openssl rand -base64 -out "$runtime_dir/abuse-state.secret" 48
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
chmod 0600 "$runtime_dir/api-control.secret" "$runtime_dir/abuse-state.secret" \
  "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret"

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then cargo_args+=(--offline); fi
cargo build "${cargo_args[@]}"
binary="${CARGO_TARGET_DIR:-$project_dir/target}/debug/rust-xmpp-server"
mix_database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"

# The runtime identity is verification-only. Apply the random schema with the
# explicit migrator capability before any listener is configured or started.
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$mix_database_url" "$binary" migrate

# The client-facing public URL must name a listener owned throughout this
# suite, while the Northstar child retains ownership of its ephemeral backend
# HTTP port.  This avoids recreating the old bind-close-launch lease and keeps
# any advertised URL usable by the real wire client.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" mix-http mix-http "$mix_http_relay_target" \
  "$runtime_dir/mix-http-relay.log" mix_http_relay_pid mix_http_relay_port

readiness_file="$runtime_dir/server.ready.json"
readiness_nonce="$(openssl rand -hex 16)"
rm -f -- "$readiness_file" "$mix_http_relay_target"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  DATABASE_URL="$mix_database_url" \
  XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 \
  S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
  TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
  PUBLIC_URL="https://127.0.0.1:$mix_http_relay_port" WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
  API_CONTROL_SECRET_FILE="$runtime_dir/api-control.secret" \
  ABUSE_STATE_HMAC_KEY_FILE="$runtime_dir/abuse-state.secret" \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
  UPLOAD_DIR="$runtime_dir/uploads" LOG_DIR="$runtime_dir/logs" \
  TLS_CERT_PATH="$runtime_dir/server.crt" TLS_KEY_PATH="$runtime_dir/server.key" \
  OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=false REGISTRATION_RATE_PER_HOUR=20 \
  BOOTSTRAP_ADMIN_USERNAME=mix_runtime_admin BOOTSTRAP_ADMIN_PASSWORD=mix-runtime-admin-password-123 \
  FEDERATION_ENABLED=false LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
  "$binary" >"$runtime_dir/server.log" 2>&1 &
server_pid=$!

fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid" || {
  cat "$runtime_dir/server.log" >&2
  exit 1
}
xmpp_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
xmpps_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
http_backend_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
fixture_publish_relay_target "$mix_http_relay_target" "$http_backend_port"
http_port="$mix_http_relay_port"
curl --silent --fail "http://127.0.0.1:$http_backend_port/readyz" >/dev/null
curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null
fixture_assert_public_url "$http_port" "https://127.0.0.1:$mix_http_relay_port"

echo "MIX runtime schema: $schema"
echo "MIX runtime ports: xmpp=$xmpp_port xmpps=$xmpps_port http=$http_port pid=$server_pid"
XMPP_TEST_HOST=127.0.0.1 XMPP_TEST_HTTP_PORT="$http_port" XMPP_TEST_CLIENT_PORT="$xmpp_port" \
  XMPP_TEST_XMPPS_PORT="$xmpps_port" XMPP_TEST_DOMAIN=localhost python3 scripts/mix-runtime-wsl.py
