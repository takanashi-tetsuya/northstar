#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"

schema="${NORTHSTAR_BROWSER_SCHEMA:-northstar_browser_e2e_it}"
http_port="${NORTHSTAR_BROWSER_HTTP_PORT:-18380}"
xmpp_port="${NORTHSTAR_BROWSER_XMPP_PORT:-16322}"
s2s_port="${NORTHSTAR_BROWSER_S2S_PORT:-16326}"
browser_host="${NORTHSTAR_BROWSER_HOST:-127.0.0.1}"
browser_http_bind="127.0.0.1"
if [[ "${NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND:-false}" == "true" ]]; then
  browser_http_bind="0.0.0.0"
elif [[ "${NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND:-false}" != "false" ]]; then
  echo "NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND must be true or false" >&2
  exit 2
fi
if [[ "$browser_host" != "127.0.0.1" && "$browser_host" != "localhost" \
   && "$browser_host" != "::1" && "$browser_http_bind" == "127.0.0.1" ]]; then
  echo "a non-loopback NORTHSTAR_BROWSER_HOST requires NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND=true" >&2
  exit 2
fi
pid_file="$project_dir/browser-e2e-server.pid"
binary="$CARGO_TARGET_DIR/debug/rust-xmpp-server"

if [[ ! "$schema" =~ ^[a-z_][a-z0-9_]*$ ]]; then
  echo "NORTHSTAR_BROWSER_SCHEMA must be a simple lowercase PostgreSQL identifier" >&2
  exit 2
fi
for port in "$http_port" "$xmpp_port" "$s2s_port"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "browser E2E ports must be integers between 1 and 65535" >&2
    exit 2
  fi
done

stop_server() {
  if [[ ! -f "$pid_file" ]]; then
    return
  fi
  local server_pid actual_binary resolved_binary
  server_pid="$(cat "$pid_file")"
  if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
    echo "invalid browser-e2e-server.pid" >&2
    exit 1
  fi
  if kill -0 "$server_pid" 2>/dev/null; then
    actual_binary="$(readlink "/proc/$server_pid/exe" 2>/dev/null || true)"
    resolved_binary="$(readlink -f "$binary")"
    if [[ "$actual_binary" != "$resolved_binary" && "$actual_binary" != "$resolved_binary (deleted)" ]]; then
      echo "refusing to stop PID $server_pid because it is not the browser E2E server" >&2
      exit 1
    fi
    kill "$server_pid"
    for _ in $(seq 1 100); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      echo "browser E2E server did not stop cleanly" >&2
      exit 1
    fi
  fi
  rm -f "$pid_file"
}

case "${1:-}" in
  stop)
    stop_server
    exit 0
    ;;
  start)
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac

stop_server
cd "$project_dir"
mkdir -p certs "data/browser-$schema" "data/browser-$schema/secrets"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/browser-e2e.key -out certs/browser-e2e.crt >/dev/null 2>&1
for secret in api-control abuse-state fast-token dummy-scram; do
  openssl rand -base64 -out "data/browser-$schema/secrets/$secret.secret" 48
  chmod 0600 "data/browser-$schema/secrets/$secret.secret"
done

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 \
  --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null

cargo build --locked --offline
database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$binary" migrate
nohup env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  XMPP_BIND="127.0.0.1:$xmpp_port" \
  XMPPS_BIND="127.0.0.1:0" \
  HTTP_BIND="$browser_http_bind:$http_port" \
  S2S_BIND="127.0.0.1:$s2s_port" \
  S2S_TLS_BIND="127.0.0.1:0" \
  PUBLIC_URL="http://$browser_host:$http_port" \
  API_CONTROL_SECRET_FILE="$project_dir/data/browser-$schema/secrets/api-control.secret" \
  ABUSE_STATE_HMAC_KEY_FILE="$project_dir/data/browser-$schema/secrets/abuse-state.secret" \
  FAST_TOKEN_SECRET_FILE="$project_dir/data/browser-$schema/secrets/fast-token.secret" \
  DUMMY_SCRAM_SECRET_FILE="$project_dir/data/browser-$schema/secrets/dummy-scram.secret" \
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
  "$binary" >browser-e2e-server.log 2>&1 </dev/null &
server_pid=$!
echo "$server_pid" >"$pid_file"

cleanup_on_error() {
  stop_server || true
}
trap cleanup_on_error ERR
for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null; then
    trap - ERR
    echo "$server_pid"
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat browser-e2e-server.log >&2
    exit 1
  fi
  sleep 0.1
done
echo "browser E2E server did not become ready" >&2
exit 1
