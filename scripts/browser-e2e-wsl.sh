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
schema="northstar_browser_e2e_${suffix}"
[[ "$schema" =~ ^northstar_browser_e2e_[a-f0-9]{32}$ ]] || {
  echo "unsafe browser E2E schema" >&2
  exit 2
}
browser_host="${NORTHSTAR_BROWSER_HOST:-127.0.0.1}"
[[ "$browser_host" == "127.0.0.1" || "$browser_host" == "localhost" ]] || {
  echo "NORTHSTAR_BROWSER_HOST must be 127.0.0.1 or localhost for the loopback browser fixture" >&2
  exit 2
}
if [[ "${NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND:-false}" == "true" ]]; then
  echo "NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND=true is not supported by the nonce-bound loopback browser fixture" >&2
  exit 2
fi
if [[ "${NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND:-false}" != "false" ]]; then
  echo "NORTHSTAR_BROWSER_ALLOW_NON_LOOPBACK_BIND must be true or false" >&2
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
browser_relay_pid=""
browser_relay_port=""
relay_target_file="$runtime_dir/browser-http.target"
xmpp_port=""
xmpps_port=""
http_port=""
s2s_port=""
declare -a fixture_listener_ports=()
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$browser_relay_pid" ]]; then
    kill "$browser_relay_pid" 2>/dev/null || true
    wait "$browser_relay_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -f "$runtime_dir/server.log" ]]; then
    echo "browser E2E server log after failure:" >&2
    tail -n 240 "$runtime_dir/server.log" >&2 || true
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1 || status=1
  remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" 2>/dev/null || printf unknown)"
  remains="${remains//[[:space:]]/}"
  listener_count=0
  if ! fixture_assert_no_listeners; then listener_count=1; status=1; fi
  case "$runtime_dir" in
    /tmp/northstar-browser-e2e.*) rm -rf -- "$runtime_dir" ;;
    *) status=1 ;;
  esac
  echo "browser E2E cleanup: schema=$schema remains=${remains:-unknown} listeners=$listener_count"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# The browser must know its origin before Northstar can bind its own ephemeral
# HTTP listener.  A fixture-owned loopback relay supplies that stable origin;
# it forwards only after the child server publishes its nonce/PID-bound HTTP
# endpoint.  This preserves exact Origin enforcement without reserving a port
# number or exposing a non-loopback test listener.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" browser browser-http "$relay_target_file" \
  "$runtime_dir/browser-http-relay.log" browser_relay_pid browser_relay_port
browser_url="http://$browser_host:$browser_relay_port"

readiness_file="$runtime_dir/server.ready.json"
readiness_nonce="$(openssl rand -hex 16)"
rm -f -- "$readiness_file" "$relay_target_file"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url" \
  XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 METRICS_BIND=127.0.0.1:0 \
  S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
  TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
  PUBLIC_URL="$browser_url" WEBSOCKET_ALLOWED_ORIGINS="$browser_url" \
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

fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$server_pid"
xmpp_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
xmpps_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
http_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
fixture_publish_relay_target "$relay_target_file" "$http_port"
curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null
if [[ "$browser_mode" == "external" ]]; then
  state_tmp="$control_dir/state.json.tmp"
  printf '{"url":"%s","schema":"%s"}\n' "$browser_url" "$schema" >"$state_tmp"
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
  "$windows_curl" --silent --fail --output NUL "$browser_url/readyz"
  "$node_exe" "$(wslpath -w "$project_dir/scripts/web-e2e.cjs")" "$browser_url"
fi
kill "$server_pid"
wait "$server_pid"
server_pid=""
grep -q 'shutdown complete' "$runtime_dir/server.log" || {
  echo "browser E2E server did not stop gracefully" >&2
  exit 1
}
echo "browser E2E: random-schema multi-device OMEMO/SCE lifecycle passed"
