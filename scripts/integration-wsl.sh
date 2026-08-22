#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"

cd "$project_dir"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
test_schema="${XMPP_TEST_SCHEMA:-northstar_integration_it}"
test_http_port="${XMPP_TEST_HTTP_PORT:-18480}"
test_client_port="${XMPP_TEST_CLIENT_PORT:-16422}"
test_s2s_port="${XMPP_TEST_S2S_PORT:-16425}"
if [[ ! "$test_schema" =~ ^[a-z_][a-z0-9_]*$ ]]; then
  echo "XMPP_TEST_SCHEMA must be a simple lowercase PostgreSQL identifier" >&2
  exit 2
fi
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/integration.key -out certs/integration.crt >/dev/null 2>&1

PGOPTIONS="-c search_path=$test_schema" PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 \
  --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE; CREATE SCHEMA \"$test_schema\";" >/dev/null

cargo build --locked --offline

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

env \
  XMPP_DOMAIN=localhost \
  DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema" \
  XMPP_BIND="127.0.0.1:$test_client_port" \
  S2S_BIND="127.0.0.1:$test_s2s_port" \
  HTTP_BIND="127.0.0.1:$test_http_port" \
  PUBLIC_URL="http://127.0.0.1:$test_http_port" \
  UPLOAD_DIR="$project_dir/data/integration-$test_schema" \
  TLS_CERT_PATH="$project_dir/certs/integration.crt" \
  TLS_KEY_PATH="$project_dir/certs/integration.key" \
  OPEN_REGISTRATION=true \
  REQUIRE_ENCRYPTED_ARCHIVE=true \
  REGISTRATION_RATE_PER_HOUR=20 \
  BOOTSTRAP_ADMIN_USERNAME=admin_it \
  BOOTSTRAP_ADMIN_PASSWORD=integration-admin-password-123 \
  LOG_FORMAT=json \
  RUST_LOG="${RUST_LOG:-rust_xmpp_server=info}" \
  "$CARGO_TARGET_DIR/debug/rust-xmpp-server" >integration-server.log 2>&1 &
server_pid=$!

XMPP_TEST_HOST=127.0.0.1 \
XMPP_TEST_HTTP_PORT="$test_http_port" \
XMPP_TEST_CLIENT_PORT="$test_client_port" \
XMPP_TEST_DOMAIN=localhost \
python3 scripts/integration-wsl.py
