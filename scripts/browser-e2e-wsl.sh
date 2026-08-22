#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"
cd "$project_dir"

schema="${NORTHSTAR_BROWSER_SCHEMA:-northstar_browser_e2e_it}"
http_port="${NORTHSTAR_BROWSER_HTTP_PORT:-18380}"
xmpp_port="${NORTHSTAR_BROWSER_XMPP_PORT:-16322}"
s2s_port="${NORTHSTAR_BROWSER_S2S_PORT:-16326}"
browser_host="${NORTHSTAR_BROWSER_HOST:-127.0.0.1}"
if [[ ! "$schema" =~ ^[a-z_][a-z0-9_]*$ ]]; then
  echo "NORTHSTAR_BROWSER_SCHEMA must be a simple lowercase PostgreSQL identifier" >&2
  exit 2
fi

mkdir -p certs "data/browser-$schema"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/browser-e2e.key -out certs/browser-e2e.crt >/dev/null 2>&1

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
  HTTP_BIND="0.0.0.0:$http_port" \
  S2S_BIND="127.0.0.1:$s2s_port" \
  PUBLIC_URL="http://$browser_host:$http_port" \
  UPLOAD_DIR="$project_dir/data/browser-$schema" \
  TLS_CERT_PATH="$project_dir/certs/browser-e2e.crt" \
  TLS_KEY_PATH="$project_dir/certs/browser-e2e.key" \
  OPEN_REGISTRATION=true \
  REQUIRE_ENCRYPTED_ARCHIVE=true \
  REGISTRATION_RATE_PER_HOUR=20 \
  BOOTSTRAP_ADMIN_USERNAME=admin_it \
  BOOTSTRAP_ADMIN_PASSWORD=integration-admin-password-123 \
  FEDERATION_ENABLED=false \
  LOG_FORMAT=json \
  RUST_LOG="${RUST_LOG:-rust_xmpp_server=info}" \
  "$CARGO_TARGET_DIR/debug/rust-xmpp-server" >browser-e2e-server.log 2>&1 &
server_pid=$!

for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null

windows_curl="/mnt/c/Windows/System32/curl.exe"
for _ in $(seq 1 150); do
  if "$windows_curl" --silent --fail --output NUL "http://$browser_host:$http_port/readyz"; then break; fi
  sleep 0.1
done
"$windows_curl" --silent --fail --output NUL "http://$browser_host:$http_port/readyz"

node_exe="/mnt/c/Users/Admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe"
if [[ ! -x "$node_exe" ]]; then
  echo "Windows Node.js runtime not found at $node_exe" >&2
  exit 2
fi

"$node_exe" \
  "$(wslpath -w "$project_dir/scripts/web-e2e.cjs")" \
  "http://$browser_host:$http_port"
