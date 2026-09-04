#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
cd "$project_dir"

test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
run_id="$(openssl rand -hex 8)"
schema="northstar_load_1000_${run_id}"
pick_port() {
  python3 "$project_dir/scripts/allocate-test-ports.py" 64000 65530 1
}
http_port="${XMPP_LOAD_HTTP_PORT:-$(pick_port)}"
metrics_port="${XMPP_LOAD_METRICS_PORT:-$(pick_port)}"
xmpp_port="${XMPP_LOAD_CLIENT_PORT:-$(pick_port)}"
s2s_port="${XMPP_LOAD_S2S_PORT:-$(pick_port)}"
[[ "$test_database" == "xmpp_test" ]] \
  || { echo "load tests are restricted to the dedicated xmpp_test database" >&2; exit 2; }
[[ "$schema" =~ ^northstar_load_1000_[0-9a-f]{16}$ ]] \
  || { echo "refusing an unexpected load-test schema name" >&2; exit 2; }
ulimit -n 8192

runtime_dir="$(mktemp -d /tmp/northstar-load-1000.XXXXXX)"
server_pid=""
schema_created=false
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if (( status != 0 )) && [[ -f "$runtime_dir/server.log" ]]; then
    echo "load-test server log after failure:" >&2
    tail -n 200 "$runtime_dir/server.log" >&2 || true
  fi
  if [[ "$schema_created" == true ]]; then
    PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1 \
      || status=1
  fi
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
    --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
    2>/dev/null || printf unknown)"
  for port in "$http_port" "$metrics_port" "$xmpp_port" "$s2s_port"; do
    if port_is_listening "$port"; then
      echo "load-test listener remained on port $port" >&2
      status=1
    fi
  done
  case "$runtime_dir" in
    /tmp/northstar-load-1000.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to clean unexpected load-test path: $runtime_dir" >&2; status=1 ;;
  esac
  echo "load cleanup: schema=$schema remains=${remains:-unknown} listeners=0"
  exit "$status"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
chmod 0600 "$runtime_dir/server.key"
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
chmod 0600 "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret"

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$schema\"" >/dev/null
schema_created=true

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" == "true" ]]; then cargo_args+=(--offline); fi
cargo build "${cargo_args[@]}"

database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$target_dir/debug/rust-xmpp-server" migrate

env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  XMPP_BIND="127.0.0.1:$xmpp_port" \
  XMPPS_BIND="127.0.0.1:0" \
  HTTP_BIND="127.0.0.1:$http_port" \
  METRICS_BIND="127.0.0.1:$metrics_port" \
  S2S_BIND="127.0.0.1:$s2s_port" \
  S2S_TLS_BIND="127.0.0.1:0" \
  PUBLIC_URL="http://127.0.0.1:$http_port" \
  API_CONTROL_ALLOW_EPHEMERAL=true \
  ABUSE_STATE_ALLOW_EPHEMERAL=true \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
  UPLOAD_DIR="$runtime_dir/uploads" \
  TLS_CERT_PATH="$runtime_dir/server.crt" \
  TLS_KEY_PATH="$runtime_dir/server.key" \
  OPEN_REGISTRATION=true \
  REQUIRE_ENCRYPTED_ARCHIVE=true \
  REGISTRATION_RATE_PER_HOUR=20 \
  FEDERATION_ENABLED=false \
  MAX_CONNECTIONS_PER_IP=1200 \
  MAX_SESSIONS_PER_ACCOUNT=1200 \
  LOG_FORMAT=json \
  RUST_LOG=rust_xmpp_server=warn \
  "$target_dir/debug/rust-xmpp-server" >"$runtime_dir/server.log" 2>&1 &
server_pid=$!

XMPP_TEST_HTTP_PORT="$http_port" \
XMPP_TEST_METRICS_PORT="$metrics_port" \
XMPP_TEST_CLIENT_PORT="$xmpp_port" \
XMPP_LOAD_SESSIONS="${XMPP_LOAD_SESSIONS:-1000}" \
XMPP_LOAD_WORKERS="${XMPP_LOAD_WORKERS:-64}" \
python3 scripts/load-1000-wsl.py
