#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_profile_storage_${suffix}"
[[ "$schema" =~ ^northstar_profile_storage_[a-f0-9]{32}$ ]] || {
  echo "unsafe profile-storage schema" >&2
  exit 2
}
read -r xmpp_port xmpps_port http_port < <(
  python3 -c "import socket; s=[socket.socket() for _ in range(3)]; [x.bind(('127.0.0.1',0)) for x in s]; print(*(x.getsockname()[1] for x in s)); [x.close() for x in s]"
)
runtime_dir="$(mktemp -d /tmp/northstar-profile-storage.XXXXXX)"
server_pid=""
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "profile-storage server log after failure:" >&2
    tail -n 200 "$runtime_dir/server.log" >&2 || true
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1 || status=1
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" 2>/dev/null || printf unknown)"
  case "$runtime_dir" in
    /tmp/northstar-profile-storage.*) rm -rf -- "$runtime_dir" ;;
    *) status=1 ;;
  esac
  echo "profile-storage cleanup: schema=$schema remains=${remains:-unknown}"
  exit "$status"
}
trap cleanup EXIT INT TERM

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$schema\"" >/dev/null
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
chmod 0600 "$runtime_dir/server.key"
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
chmod 0600 "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret"
cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then cargo_args+=(--offline); fi
cargo build "${cargo_args[@]}"
binary="$target_dir/debug/rust-xmpp-server"
database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$binary" migrate

start_server() {
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
    DATABASE_URL="$database_url" \
    XMPP_BIND="127.0.0.1:$xmpp_port" XMPPS_BIND="127.0.0.1:$xmpps_port" \
    HTTP_BIND="127.0.0.1:$http_port" S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    PUBLIC_URL="https://127.0.0.1:$http_port" WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
    API_CONTROL_ALLOW_EPHEMERAL=true ABUSE_STATE_ALLOW_EPHEMERAL=true FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" UPLOAD_DIR="$runtime_dir/uploads" \
    TLS_CERT_PATH="$runtime_dir/server.crt" TLS_KEY_PATH="$runtime_dir/server.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=false REGISTRATION_RATE_PER_HOUR=20 \
    PEP_MAX_NODES_PER_ACCOUNT=20 PEP_MAX_STORAGE_BYTES_PER_ACCOUNT=16777216 \
    FEDERATION_ENABLED=false LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info \
    "$binary" >>"$runtime_dir/server.log" 2>&1 &
  server_pid=$!
}
run_phase() {
  XMPP_TEST_HOST=127.0.0.1 XMPP_TEST_HTTP_PORT="$http_port" XMPP_TEST_CLIENT_PORT="$xmpp_port" \
    XMPP_TEST_DOMAIN=localhost python3 scripts/profile-storage-runtime-wsl.py "$1"
}

start_server
run_phase setup
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
start_server
run_phase finish
kill "$server_pid"
wait "$server_pid"
server_pid=""
shutdowns="$(grep -c 'shutdown complete' "$runtime_dir/server.log" || true)"
if (( shutdowns < 2 )); then
  echo "profile-storage server did not complete both graceful shutdowns" >&2
  exit 1
fi
