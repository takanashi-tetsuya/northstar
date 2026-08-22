#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"
cd "$project_dir"

schema="northstar_load_1000"
http_port="${XMPP_LOAD_HTTP_PORT:-18280}"
xmpp_port="${XMPP_LOAD_CLIENT_PORT:-16222}"
s2s_port="${XMPP_LOAD_S2S_PORT:-16269}"
ulimit -n 8192

mkdir -p certs data/load-1000
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/load-1000.key -out certs/load-1000.crt >/dev/null 2>&1

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 \
  --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null

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
  DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema" \
  XMPP_BIND="127.0.0.1:$xmpp_port" \
  HTTP_BIND="127.0.0.1:$http_port" \
  S2S_BIND="127.0.0.1:$s2s_port" \
  PUBLIC_URL="http://127.0.0.1:$http_port" \
  UPLOAD_DIR="$project_dir/data/load-1000" \
  TLS_CERT_PATH="$project_dir/certs/load-1000.crt" \
  TLS_KEY_PATH="$project_dir/certs/load-1000.key" \
  OPEN_REGISTRATION=true \
  REQUIRE_ENCRYPTED_ARCHIVE=true \
  REGISTRATION_RATE_PER_HOUR=20 \
  FEDERATION_ENABLED=false \
  LOG_FORMAT=json \
  RUST_LOG=rust_xmpp_server=warn \
  "$CARGO_TARGET_DIR/debug/rust-xmpp-server" >load-1000-server.log 2>&1 &
server_pid=$!

XMPP_TEST_HTTP_PORT="$http_port" \
XMPP_TEST_CLIENT_PORT="$xmpp_port" \
XMPP_LOAD_SESSIONS="${XMPP_LOAD_SESSIONS:-1000}" \
XMPP_LOAD_WORKERS="${XMPP_LOAD_WORKERS:-64}" \
python3 scripts/load-1000-wsl.py
