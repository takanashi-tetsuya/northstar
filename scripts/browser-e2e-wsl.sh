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
schema="northstar_browser_e2e_${suffix}"
[[ "$schema" =~ ^northstar_browser_e2e_[a-f0-9]{32}$ ]] || {
  echo "unsafe browser E2E schema" >&2
  exit 2
}
read -r xmpp_port xmpps_port http_port s2s_port < <(
  python3 "$project_dir/scripts/allocate-test-ports.py" 60000 61999 4
)
browser_host="${NORTHSTAR_BROWSER_HOST:-127.0.0.1}"
[[ "$browser_host" =~ ^[A-Za-z0-9.:-]+$ ]] || {
  echo "unsafe browser E2E host" >&2
  exit 2
}
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
browser_mode="${NORTHSTAR_BROWSER_MODE:-interop}"
control_dir="${NORTHSTAR_BROWSER_CONTROL_DIR:-}"
browser_timeout_seconds="${NORTHSTAR_BROWSER_TIMEOUT_SECONDS:-900}"
windows_curl="/mnt/c/Windows/System32/curl.exe"
node_exe="${NORTHSTAR_NODE_EXE:-/mnt/c/Users/Admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe}"
if [[ "$browser_mode" == "external" ]]; then
  [[ -n "$control_dir" && "$control_dir" == "$project_dir"/target/browser-e2e-control-* ]] || {
    echo "external browser mode requires a repository-local one-time control directory" >&2
    exit 2
  }
  [[ "$browser_timeout_seconds" =~ ^[0-9]+$ ]] \
    && (( browser_timeout_seconds >= 600 && browser_timeout_seconds <= 3600 )) || {
      echo "external browser timeout must be between 600 and 3600 seconds" >&2
      exit 2
    }
  mkdir -p -- "$control_dir"
elif [[ "$browser_mode" == "interop" ]]; then
  if [[ "$node_exe" =~ ^[A-Za-z]:\\ ]]; then node_exe="$(wslpath -u "$node_exe")"; fi
  if ! "$windows_curl" --version >/dev/null 2>&1; then
    echo "WSL cannot execute Windows programs in this environment; use browser-e2e-windows.ps1" >&2
    exit 2
  fi
  if [[ ! -x "$node_exe" ]]; then
    echo "Windows Node.js runtime not found: $node_exe" >&2
    exit 2
  fi
else
  echo "NORTHSTAR_BROWSER_MODE must be interop or external" >&2
  exit 2
fi

runtime_dir="$(mktemp -d /tmp/northstar-browser-e2e.XXXXXX)"
server_pid=""
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "browser E2E server log after failure:" >&2
    tail -n 240 "$runtime_dir/server.log" >&2 || true
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1 || status=1
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" 2>/dev/null || printf unknown)"
  for port in "$xmpp_port" "$xmpps_port" "$http_port" "$s2s_port"; do
    if port_is_listening "$port"; then
      echo "browser E2E listener remained on port $port" >&2
      status=1
    fi
  done
  case "$runtime_dir" in
    /tmp/northstar-browser-e2e.*) rm -rf -- "$runtime_dir" ;;
    *) status=1 ;;
  esac
  echo "browser E2E cleanup: schema=$schema remains=${remains:-unknown} listeners=0"
  exit "$status"
}
trap cleanup EXIT INT TERM

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$schema\"" >/dev/null
openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
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
database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url" \
  "$target_dir/debug/rust-xmpp-server" migrate
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  XMPP_BIND="127.0.0.1:$xmpp_port" XMPPS_BIND="127.0.0.1:$xmpps_port" \
  HTTP_BIND="$browser_http_bind:$http_port" S2S_BIND="127.0.0.1:$s2s_port" S2S_TLS_BIND=127.0.0.1:0 \
  PUBLIC_URL="http://$browser_host:$http_port" WEBSOCKET_ALLOWED_ORIGINS="http://$browser_host:$http_port" \
  API_CONTROL_SECRET_FILE="$runtime_dir/api-control.secret" \
  ABUSE_STATE_HMAC_KEY_FILE="$runtime_dir/abuse-state.secret" \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
  UPLOAD_DIR="$runtime_dir/uploads" TLS_CERT_PATH="$runtime_dir/server.crt" \
  TLS_KEY_PATH="$runtime_dir/server.key" OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true \
  REGISTRATION_RATE_PER_HOUR=20 BOOTSTRAP_ADMIN_USERNAME=admin_it \
  BOOTSTRAP_ADMIN_PASSWORD=integration-admin-password-123 FEDERATION_ENABLED=false \
  LOG_FORMAT=json RUST_LOG="${RUST_LOG:-rust_xmpp_server=debug}" \
  "$target_dir/debug/rust-xmpp-server" >"$runtime_dir/server.log" 2>&1 &
server_pid=$!

for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null
if [[ "$browser_mode" == "external" ]]; then
  state_tmp="$control_dir/state.json.tmp"
  printf '{"url":"http://%s:%s","schema":"%s"}\n' "$browser_host" "$http_port" "$schema" >"$state_tmp"
  mv -- "$state_tmp" "$control_dir/state.json"
  for _ in $(seq 1 $((browser_timeout_seconds * 10))); do
    [[ -f "$control_dir/result.status" ]] && break
    kill -0 "$server_pid" 2>/dev/null || {
      echo "browser E2E server exited while awaiting the external browser" >&2
      exit 1
    }
    sleep 0.1
  done
  [[ -f "$control_dir/result.status" ]] || {
    echo "external browser did not return a result within $browser_timeout_seconds seconds" >&2
    exit 1
  }
  browser_status="$(tr -d '\r\n ' <"$control_dir/result.status")"
  [[ "$browser_status" == "0" ]] || {
    echo "external browser E2E failed with exit code ${browser_status:-unknown}" >&2
    exit 1
  }
else
  for _ in $(seq 1 150); do
    if "$windows_curl" --silent --fail --output NUL "http://$browser_host:$http_port/readyz"; then break; fi
    sleep 0.1
  done
  "$windows_curl" --silent --fail --output NUL "http://$browser_host:$http_port/readyz"
  "$node_exe" "$(wslpath -w "$project_dir/scripts/web-e2e.cjs")" "http://$browser_host:$http_port"
fi
kill "$server_pid"
wait "$server_pid"
server_pid=""
grep -q 'shutdown complete' "$runtime_dir/server.log" || {
  echo "browser E2E server did not stop gracefully" >&2
  exit 1
}
echo "browser E2E: random-schema multi-device OMEMO/SCE lifecycle passed"
