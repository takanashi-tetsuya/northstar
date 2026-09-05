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
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

nonce="$(date +%s%N)_$$"
schema_a="mix_fed_a_${nonce}"
schema_b="mix_fed_b_${nonce}"
[[ "$schema_a" =~ ^mix_fed_a_[0-9_]+$ && "$schema_b" =~ ^mix_fed_b_[0-9_]+$ ]] || exit 2
runtime_dir="$(mktemp -d /tmp/northstar-mix-fed.XXXXXX)"
pid_a=""
pid_b=""
relay_a_pid=""
relay_b_pid=""
relay_a_tls_port=""
relay_b_tls_port=""
relay_a_http_pid=""
relay_b_http_pid=""
relay_a_http_port=""
relay_b_http_port=""
http_a=""
http_b=""
http_a_backend=""
http_b_backend=""
s2s_tls_a=""
s2s_tls_b=""
target_a_tls="$runtime_dir/a.s2s-tls.target"
target_b_tls="$runtime_dir/b.s2s-tls.target"
target_a_http="$runtime_dir/a.http.target"
target_b_http="$runtime_dir/b.http.target"
declare -a fixture_listener_ports=()
cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "$pid_a" "$pid_b" "$relay_a_pid" "$relay_b_pid" "$relay_a_http_pid" "$relay_b_http_pid"; do [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; done
  for pid in "$pid_a" "$pid_b" "$relay_a_pid" "$relay_b_pid" "$relay_a_http_pid" "$relay_b_http_pid"; do [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true; done
  if [[ $status -ne 0 ]]; then
    for log in "$runtime_dir/a.log" "$runtime_dir/b.log" "$runtime_dir/relay-a.log" "$runtime_dir/relay-b.log" "$runtime_dir/relay-a-http.log" "$runtime_dir/relay-b-http.log"; do [[ ! -f "$log" ]] || { echo "--- $log ---" >&2; tail -n 200 "$log" >&2; }; done
  fi
  for schema in "$schema_a" "$schema_b"; do
    if ! PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -U xmpp_test -d xmpp_test --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE;" >/dev/null 2>&1; then
      status=1
    fi
  done
  remains="$(PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -U xmpp_test -d xmpp_test -tAn --command "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name IN ('$schema_a','$schema_b');" 2>/dev/null | tail -n1 || true)"
  listeners=0
  if ! fixture_assert_no_listeners; then
    listeners=1
    status=1
  fi
  if [[ "$remains" != "0" ]]; then
    echo "MIX federation schemas remained: ${remains:-unknown}" >&2
    status=1
  fi
  if [[ "$listeners" != "0" ]]; then
    echo "MIX federation listeners remained: $listeners" >&2
    status=1
  fi
  case "$runtime_dir" in
    /tmp/northstar-mix-fed.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected MIX federation directory: $runtime_dir" >&2; status=1 ;;
  esac
  runtime_remains=0
  if [[ -e "$runtime_dir" ]]; then
    runtime_remains=1
    echo "MIX federation runtime directory remained: $runtime_dir" >&2
    status=1
  fi
  echo "MIX federation cleanup: schemas=${remains:-unknown} listeners=$listeners runtime_dirs=$runtime_remains"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for schema in "$schema_a" "$schema_b"; do
  PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -U xmpp_test -d xmpp_test --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null
done
mkdir -p "$runtime_dir/certs" "$runtime_dir/uploads-a" "$runtime_dir/uploads-b"
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=Northstar MIX Federation CA" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout "$runtime_dir/certs/ca.key" -out "$runtime_dir/certs/ca.crt" >/dev/null 2>&1
for side in a b; do
  if [[ "$side" == a ]]; then domain=localhost; mix=mix.localhost; else domain=remote.localhost; mix=mix.remote.localhost; fi
  openssl req -new -newkey rsa:3072 -nodes -subj "/CN=$domain" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth,clientAuth" -addext "subjectAltName=DNS:$domain,DNS:$mix" -keyout "$runtime_dir/certs/$side.key" -out "$runtime_dir/certs/$side.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -in "$runtime_dir/certs/$side.csr" -CA "$runtime_dir/certs/ca.crt" -CAkey "$runtime_dir/certs/ca.key" -CAcreateserial -copy_extensions copy -out "$runtime_dir/certs/$side.crt" >/dev/null 2>&1
  openssl x509 -in "$runtime_dir/certs/ca.crt" -outform PEM >>"$runtime_dir/certs/$side.crt"
  chmod 0600 "$runtime_dir/certs/$side.key"
  openssl rand -base64 -out "$runtime_dir/api-control-$side.secret" 48
  openssl rand -base64 -out "$runtime_dir/dialback-$side.secret" 48
  openssl rand -base64 -out "$runtime_dir/fast-token-$side.secret" 48
  openssl rand -base64 -out "$runtime_dir/dummy-scram-$side.secret" 48
  chmod 0600 "$runtime_dir/api-control-$side.secret" "$runtime_dir/dialback-$side.secret" \
    "$runtime_dir/fast-token-$side.secret" "$runtime_dir/dummy-scram-$side.secret"
done

# Both Northstar children own their own ephemeral S2S listeners.  Their
# startup-only federation DNS overrides point at relay children which have
# already published a nonce-bound endpoint; each relay then forwards to the
# dynamically discovered Northstar S2S TLS address written below.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" a relay-a-s2s-tls "$target_a_tls" \
  "$runtime_dir/relay-a.log" relay_a_pid relay_a_tls_port
fixture_start_tcp_relay "$project_dir" "$runtime_dir" b relay-b-s2s-tls "$target_b_tls" \
  "$runtime_dir/relay-b.log" relay_b_pid relay_b_tls_port
# The advertised HTTPS authorities remain stable across the intentional B
# restart below.  They are fixture-owned relays; each child only publishes
# the backend target after it has bound and authenticated its readiness file.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" a-http relay-a-http "$target_a_http" \
  "$runtime_dir/relay-a-http.log" relay_a_http_pid relay_a_http_port
fixture_start_tcp_relay "$project_dir" "$runtime_dir" b-http relay-b-http "$target_b_http" \
  "$runtime_dir/relay-b-http.log" relay_b_http_pid relay_b_http_port

cargo_args=(--locked); [[ "${XMPP_TEST_OFFLINE:-true}" == false ]] || cargo_args+=(--offline)
if [[ "${NORTHSTAR_MIX_FEDERATION_SKIP_BUILD:-false}" != true ]]; then
  cargo build "${cargo_args[@]}"
fi
binary="${CARGO_TARGET_DIR:-$project_dir/target}/debug/rust-xmpp-server"
[[ -x "$binary" ]] || { echo "MIX federation runtime binary is missing: $binary" >&2; exit 1; }
database_url_a="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_a"
database_url_b="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_b"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url_a" "$binary" migrate
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
  MIGRATOR_DATABASE_URL="$database_url_b" "$binary" migrate
export ABUSE_STATE_ALLOW_EPHEMERAL=true

start_a() {
  local readiness_file="$runtime_dir/a.ready.json" readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$target_a_tls" "$target_a_http"
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost DATABASE_URL="$database_url_a" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="https://127.0.0.1:$relay_a_http_port" WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
    API_CONTROL_SECRET_FILE="$runtime_dir/api-control-a.secret" FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-a.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-a.secret" \
    UPLOAD_DIR="$runtime_dir/uploads-a" TLS_CERT_PATH="$runtime_dir/certs/a.crt" TLS_KEY_PATH="$runtime_dir/certs/a.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=false REGISTRATION_RATE_PER_HOUR=20 \
    FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true DIALBACK_SECRET_FILE="$runtime_dir/dialback-a.secret" \
    FEDERATION_DNS_OVERRIDES="remote.localhost=xmpps://127.0.0.1:$relay_b_tls_port,mix.remote.localhost=xmpps://127.0.0.1:$relay_b_tls_port" \
    FEDERATION_EXTRA_ROOT_CERT_PATH="$runtime_dir/certs/ca.crt" LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
    "$binary" >"$runtime_dir/a.log" 2>&1 &
  pid_a=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_a" || return 1
  http_a_backend="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  s2s_tls_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s-tls)"
  fixture_publish_relay_target "$target_a_tls" "$s2s_tls_a"
  fixture_publish_relay_target "$target_a_http" "$http_a_backend"
  http_a="$relay_a_http_port"
  curl --silent --fail "http://127.0.0.1:$http_a_backend/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null
  fixture_assert_public_url "$http_a" "https://127.0.0.1:$relay_a_http_port"
}
start_b() {
  local readiness_file="$runtime_dir/b.ready.json" readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$target_b_tls" "$target_b_http"
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost DATABASE_URL="$database_url_b" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="https://127.0.0.1:$relay_b_http_port" WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
    API_CONTROL_SECRET_FILE="$runtime_dir/api-control-b.secret" FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-b.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-b.secret" \
    UPLOAD_DIR="$runtime_dir/uploads-b" TLS_CERT_PATH="$runtime_dir/certs/b.crt" TLS_KEY_PATH="$runtime_dir/certs/b.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=false REGISTRATION_RATE_PER_HOUR=20 \
    FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true DIALBACK_SECRET_FILE="$runtime_dir/dialback-b.secret" \
    FEDERATION_DNS_OVERRIDES="localhost=xmpps://127.0.0.1:$relay_a_tls_port,mix.localhost=xmpps://127.0.0.1:$relay_a_tls_port" \
    FEDERATION_EXTRA_ROOT_CERT_PATH="$runtime_dir/certs/ca.crt" LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
    "$binary" >"$runtime_dir/b.log" 2>&1 &
  pid_b=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_b" || return 1
  http_b_backend="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  s2s_tls_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s-tls)"
  fixture_publish_relay_target "$target_b_tls" "$s2s_tls_b"
  fixture_publish_relay_target "$target_b_http" "$http_b_backend"
  http_b="$relay_b_http_port"
  curl --silent --fail "http://127.0.0.1:$http_b_backend/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$http_b/readyz" >/dev/null
  fixture_assert_public_url "$http_b" "https://127.0.0.1:$relay_b_http_port"
}

export MIX_FED_HTTP_A="$http_a" MIX_FED_HTTP_B="$http_b" XMPP_TEST_HOST=127.0.0.1
start_a
start_b
echo "MIX federation schemas: $schema_a $schema_b"
echo "MIX federation ports: http=$http_a,$http_b s2s-tls=$s2s_tls_a,$s2s_tls_b pids=$pid_a,$pid_b"
python3 scripts/mix-federation-runtime-wsl.py setup
kill "$pid_b"; wait "$pid_b" || true; pid_b=""
python3 scripts/mix-federation-runtime-wsl.py enqueue
queued="$(PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -U xmpp_test -d xmpp_test -tAn --command "SET search_path TO \"$schema_a\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='mix.remote.localhost' AND stanza LIKE '%durable MIX handoff%';" | tail -n1)"
echo "MIX durable outbox rows before remote restart: $queued"
[[ "$queued" == 1 ]] || { echo "expected one durable MIX row" >&2; exit 1; }
start_b
python3 scripts/mix-federation-runtime-wsl.py finish
for _ in $(seq 1 100); do
  remaining="$(PGPASSWORD=xmpp-test-password psql -h 127.0.0.1 -U xmpp_test -d xmpp_test -tAn --command "SET search_path TO \"$schema_a\"; SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='mix.remote.localhost';" | tail -n1)"
  [[ "$remaining" == 0 ]] && break
  sleep .1
done
echo "MIX durable outbox rows after restart: $remaining"
[[ "$remaining" == 0 ]]
if [[ "${S2S_SASL_EXTERNAL_ENABLED:-true}" == true ]]; then
  grep -q "authenticated inbound S2S certificate identity" "$runtime_dir/a.log" "$runtime_dir/b.log"
  echo "MIX federation authentication path: SASL EXTERNAL"
else
  if grep -q "authenticated inbound S2S certificate identity" "$runtime_dir/a.log" "$runtime_dir/b.log"; then
    echo "MIX Dialback-only fixture unexpectedly used SASL EXTERNAL" >&2
    exit 1
  fi
  grep -q "S2S inbound XMPPS federation authenticated" "$runtime_dir/a.log" "$runtime_dir/b.log"
  echo "MIX federation authentication path: XEP-0220 Dialback"
fi
