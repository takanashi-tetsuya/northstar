#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_omemo_runtime_${suffix}"
[[ "$schema" =~ ^northstar_omemo_runtime_[a-f0-9]{32}$ ]] || {
  echo "unsafe OMEMO runtime schema" >&2
  exit 2
}
runtime_dir="$(mktemp -d /tmp/northstar-omemo-runtime.XXXXXX)"
server_pid=""
server_generation=0
xmpp_port=""
xmpps_port=""
http_port=""
http_backend_port=""
http_relay_pid=""
http_relay_port=""
http_relay_target="$runtime_dir/omemo-http.target"
public_url=""
declare -a fixture_listener_ports=()

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$http_relay_pid" ]]; then
    kill "$http_relay_pid" 2>/dev/null || true
    wait "$http_relay_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "OMEMO runtime server log after failure:" >&2
    tail -n 240 "$runtime_dir/server.log" >&2 || true
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1 || status=1
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" 2>/dev/null || printf unknown)"
  listener_count=0
  if ! fixture_assert_no_listeners; then
    listener_count=1
    status=1
  fi
  case "$runtime_dir" in
    /tmp/northstar-omemo-runtime.*) rm -rf -- "$runtime_dir" ;;
    *) status=1 ;;
  esac
  echo "OMEMO runtime cleanup: schema=$schema remains=${remains:-unknown} listeners=$listener_count"
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

# Preserve one fixture-owned public authority across the restart.  The relay
# never guesses a server port; it forwards only after this child generation
# has authenticated its dynamic listener through the readiness record.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" omemo-http omemo-http \
  "$http_relay_target" "$runtime_dir/omemo-http-relay.log" \
  http_relay_pid http_relay_port
public_url="https://127.0.0.1:$http_relay_port"

publish_http_target() {
  fixture_publish_relay_target "$http_relay_target" "$http_backend_port"
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
        f"OMEMO fixture advertised {actual!r}, expected stable relay {expected!r}"
    )
' "$public_url"
}

start_server() {
  server_generation=$((server_generation + 1))
  local readiness_file="$runtime_dir/server-${server_generation}.ready.json"
  local readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$http_relay_target"
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
    DATABASE_URL="$database_url" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 \
    HTTP_BIND=127.0.0.1:0 S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="$public_url" WEBSOCKET_ALLOWED_ORIGINS="http://localhost,$public_url" \
    API_CONTROL_ALLOW_EPHEMERAL=true ABUSE_STATE_ALLOW_EPHEMERAL=true FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" UPLOAD_DIR="$runtime_dir/uploads" \
    TLS_CERT_PATH="$runtime_dir/server.crt" TLS_KEY_PATH="$runtime_dir/server.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
    PEP_MAX_NODES_PER_ACCOUNT=20 PEP_MAX_STORAGE_BYTES_PER_ACCOUNT=16777216 \
    FEDERATION_ENABLED=false LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info \
    "$binary" >>"$runtime_dir/server.log" 2>&1 &
  server_pid=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid" || {
    echo "OMEMO runtime server failed before publishing readiness" >&2
    return 1
  }
  xmpp_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
  xmpps_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
  http_backend_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  publish_http_target
  http_port="$http_relay_port"
  curl --silent --fail "http://127.0.0.1:$http_backend_port/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null
  assert_advertised_public_url
}

run_phase() {
  XMPP_TEST_HOST=127.0.0.1 XMPP_TEST_HTTP_PORT="$http_port" XMPP_TEST_CLIENT_PORT="$xmpp_port" \
    XMPP_TEST_DOMAIN=localhost python3 scripts/omemo-runtime-wsl.py "$1"
}

db_scalar() {
  PGOPTIONS="-c search_path=$schema" PGPASSWORD=xmpp-test-password \
    psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command "$1"
}

start_server
run_phase setup

offline_cipher="$(printf %s 'OMEMO-WIRE-OFFLINE-CIPHERTEXT' | base64 -w0)"
muc_cipher="$(printf %s 'OMEMO-WIRE-MUC-CIPHERTEXT' | base64 -w0)"
stored_ciphertexts="$(db_scalar "SELECT
  (SELECT COUNT(*) FROM message_archive WHERE stanza LIKE '%${offline_cipher}%') +
  (SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE '%${offline_cipher}%') +
  (SELECT COUNT(*) FROM muc_messages WHERE stanza LIKE '%${muc_cipher}%');")"
[[ "$stored_ciphertexts" =~ ^[0-9]+$ ]] && (( stored_ciphertexts >= 4 )) || {
  echo "expected durable OMEMO ciphertext projections, found ${stored_ciphertexts:-invalid}" >&2
  exit 1
}
plaintext_rows="$(db_scalar "SELECT
  (SELECT COUNT(*) FROM message_archive WHERE stanza LIKE '%PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST%') +
  (SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE '%PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST%') +
  (SELECT COUNT(*) FROM muc_messages WHERE stanza LIKE '%PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST%') +
  (SELECT COUNT(*) FROM sm_resume_stanzas WHERE stanza LIKE '%PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST%');")"
[[ "$plaintext_rows" == "0" ]] || {
  echo "rejected OMEMO plaintext downgrade reached durable storage" >&2
  exit 1
}

kill "$server_pid"
wait "$server_pid"
server_pid=""
start_server
run_phase finish
kill "$server_pid"
wait "$server_pid"
server_pid=""

archive_after_restart="$(db_scalar "SELECT COUNT(*) FROM message_archive WHERE stanza LIKE '%${offline_cipher}%' AND stanza NOT LIKE '%<body%';")"
[[ "$archive_after_restart" =~ ^[0-9]+$ ]] && (( archive_after_restart >= 2 )) || {
  echo "personal OMEMO MAM archive was missing or gained a fallback body" >&2
  exit 1
}
shutdowns="$(grep -c 'shutdown complete' "$runtime_dir/server.log" || true)"
if (( shutdowns < 2 )); then
  echo "OMEMO runtime server did not complete both graceful shutdowns" >&2
  exit 1
fi
fixture_assert_no_listeners || exit 1
echo "OMEMO runtime: strict PEP/envelope validation, live/Carbons/CSI/MUC/offline/MAM/restart/revocation and no-plaintext DB evidence passed"
