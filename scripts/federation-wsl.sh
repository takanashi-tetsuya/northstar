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
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
cd "$project_dir"

run_id="$(openssl rand -hex 8)"
schema_a="federation_a_it_${run_id}"
schema_b="federation_b_it_${run_id}"
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
declare -a allocated_ports=()
port_is_allocated() {
  local candidate="$1"
  local allocated=""
  for allocated in "${allocated_ports[@]}"; do
    if [[ "$allocated" == "$candidate" ]]; then
      return 0
    fi
  done
  return 1
}
assign_port() {
  local destination="$1"
  local environment_name="$2"
  local port=""
  if [[ -v "$environment_name" ]]; then
    port="${!environment_name}"
  else
    # The kernel may hand the same recently released ephemeral port to two
    # consecutive probes. Retry automatic allocation instead of turning that
    # harmless collision into a flaky exit-code-2 CI failure. Explicit caller
    # overrides remain strict and must never alias another listener.
    for _ in {1..100}; do
      port="$(pick_port)"
      if ! port_is_allocated "$port"; then
        break
      fi
      port=""
    done
    if [[ -z "$port" ]]; then
      echo "could not allocate a unique federation test port" >&2
      exit 1
    fi
  fi
  if [[ ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
    echo "$environment_name must be a TCP port from 1 through 65535" >&2
    exit 2
  fi
  port="$((port))"
  if port_is_allocated "$port"; then
    echo "$environment_name duplicates federation test port $port" >&2
    exit 2
  fi
  allocated_ports+=("$port")
  printf -v "$destination" '%s' "$port"
}
assign_port http_a FEDERATION_TEST_HTTP_PORT_A
assign_port http_b FEDERATION_TEST_HTTP_PORT_B
assign_port xmpp_a FEDERATION_TEST_CLIENT_PORT_A
assign_port xmpp_b FEDERATION_TEST_CLIENT_PORT_B
assign_port xmpps_a FEDERATION_TEST_CLIENT_DIRECT_TLS_PORT_A
assign_port xmpps_b FEDERATION_TEST_CLIENT_DIRECT_TLS_PORT_B
assign_port s2s_a FEDERATION_TEST_S2S_STARTTLS_PORT_A
assign_port s2s_b FEDERATION_TEST_S2S_STARTTLS_PORT_B
assign_port s2s_tls_a FEDERATION_TEST_S2S_DIRECT_TLS_PORT_A
assign_port s2s_tls_b FEDERATION_TEST_S2S_DIRECT_TLS_PORT_B
runtime_dir="$(mktemp -d /tmp/northstar-federation.XXXXXX)"
cert_dir="$runtime_dir/certs"
upload_a="$runtime_dir/uploads-a"
upload_b="$runtime_dir/uploads-b"
log_a="$runtime_dir/federation-a.log"
log_b="$runtime_dir/federation-b.log"
pid_a=""
pid_b=""
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  for pid in "$pid_a" "$pid_b"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$pid_a" "$pid_b"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  if (( exit_code != 0 )); then
    for log in "$log_a" "$log_b"; do
      if [[ -f "$log" ]]; then
        echo "--- $(basename "$log") (last 120 lines) ---" >&2
        tail -n 120 "$log" >&2 || true
      fi
    done
  fi
  schema_cleanup=""
  for schema in "$schema_a" "$schema_b"; do
    if ! PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE;" >/dev/null 2>&1; then
      exit_code=1
    fi
    remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
      2>/dev/null || printf unknown)"
    remains="${remains//[[:space:]]/}"
    schema_cleanup+="${schema}:${remains:-unknown} "
    if [[ "$remains" != "f" ]]; then
      exit_code=1
    fi
  done
  listener_count=0
  for port in "${allocated_ports[@]}"; do
    if port_is_listening "$port"; then
      echo "federation listener remained on port $port" >&2
      listener_count=$((listener_count + 1))
      exit_code=1
    fi
  done
  case "$runtime_dir" in
    /tmp/northstar-federation.*) rm -rf -- "$runtime_dir" ;;
    *)
      echo "refusing to remove unexpected federation runtime directory: $runtime_dir" >&2
      exit_code=1
      ;;
  esac
  echo "federation cleanup: schemas=${schema_cleanup% } listeners=$listener_count"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for schema in "$schema_a" "$schema_b"; do
  if [[ ! "$schema" =~ ^[a-z][a-z0-9_]{0,62}$ ]]; then
    echo "Refusing unsafe test schema name: $schema" >&2
    exit 2
  fi
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 \
    --command "CREATE SCHEMA \"$schema\";" >/dev/null
done

mkdir -p "$cert_dir" "$upload_a" "$upload_b"
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=Northstar Federation Test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -keyout "$cert_dir/federation-ca.key" -out "$cert_dir/federation-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "subjectAltName=DNS:localhost,DNS:conference.localhost,DNS:pubsub.localhost" -keyout "$cert_dir/federation-a.key" -out "$cert_dir/federation-a.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$cert_dir/federation-a.csr" -CA "$cert_dir/federation-ca.crt" \
  -CAkey "$cert_dir/federation-ca.key" -CAcreateserial -copy_extensions copy \
  -out "$cert_dir/federation-a-leaf.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=remote.localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "subjectAltName=DNS:remote.localhost,DNS:pubsub.remote.localhost" -keyout "$cert_dir/federation-b.key" -out "$cert_dir/federation-b.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$cert_dir/federation-b.csr" -CA "$cert_dir/federation-ca.crt" \
  -CAkey "$cert_dir/federation-ca.key" -CAcreateserial -copy_extensions copy \
  -out "$cert_dir/federation-b-leaf.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=evil.localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "subjectAltName=DNS:evil.localhost" -keyout "$cert_dir/federation-evil.key" -out "$cert_dir/federation-evil.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$cert_dir/federation-evil.csr" -CA "$cert_dir/federation-ca.crt" \
  -CAkey "$cert_dir/federation-ca.key" -CAcreateserial -copy_extensions copy \
  -out "$cert_dir/federation-evil.crt" >/dev/null 2>&1
cp "$cert_dir/federation-a-leaf.crt" "$cert_dir/federation-a.crt"
cp "$cert_dir/federation-b-leaf.crt" "$cert_dir/federation-b.crt"
openssl x509 -in "$cert_dir/federation-ca.crt" -outform PEM >>"$cert_dir/federation-a.crt"
openssl x509 -in "$cert_dir/federation-ca.crt" -outform PEM >>"$cert_dir/federation-b.crt"
chmod 600 "$cert_dir"/*.key
openssl rand -base64 -out "$runtime_dir/fast-token-a.secret" 48
openssl rand -base64 -out "$runtime_dir/fast-token-b.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-a.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-b.secret" 48
chmod 600 "$runtime_dir/fast-token-a.secret" "$runtime_dir/fast-token-b.secret" \
  "$runtime_dir/dummy-scram-a.secret" "$runtime_dir/dummy-scram-b.secret"

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then
  cargo_args+=(--offline)
fi
cargo build "${cargo_args[@]}"
binary="$target_dir/debug/rust-xmpp-server"
database_url_a="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_a"
database_url_b="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_b"

# Runtime identities verify the migration ledger but never apply DDL. Keep the
# two isolated schemas independent and migrate both before opening listeners.
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url_a" "$binary" migrate
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
  MIGRATOR_DATABASE_URL="$database_url_b" "$binary" migrate

env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  DATABASE_URL="$database_url_a" \
  XMPP_BIND="127.0.0.1:$xmpp_a" XMPPS_BIND="127.0.0.1:$xmpps_a" HTTP_BIND="127.0.0.1:$http_a" S2S_BIND="127.0.0.1:$s2s_a" S2S_TLS_BIND="127.0.0.1:$s2s_tls_a" \
  PUBLIC_URL="http://127.0.0.1:$http_a" UPLOAD_DIR="$upload_a" \
  TLS_CERT_PATH="$cert_dir/federation-a.crt" TLS_KEY_PATH="$cert_dir/federation-a.key" \
  OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
  API_CONTROL_ALLOW_EPHEMERAL=true \
  ABUSE_STATE_ALLOW_EPHEMERAL=true \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-a.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-a.secret" \
  FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true \
  S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true \
  DIALBACK_SECRET_FILE= DIALBACK_SECRET= \
  FEDERATION_DNS_OVERRIDES="remote.localhost=xmpps://127.0.0.1:$s2s_tls_b,pubsub.remote.localhost=xmpps://127.0.0.1:$s2s_tls_b" \
  FEDERATION_EXTRA_ROOT_CERT_PATH="$cert_dir/federation-ca.crt" \
  LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
  "$binary" >"$log_a" 2>&1 &
pid_a=$!

# Confirm the first independently migrated runtime is ready before starting
# the second node so failures retain a single, attributable log.
for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null

env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
  DATABASE_URL="$database_url_b" \
  XMPP_BIND="127.0.0.1:$xmpp_b" XMPPS_BIND="127.0.0.1:$xmpps_b" HTTP_BIND="127.0.0.1:$http_b" S2S_BIND="127.0.0.1:$s2s_b" S2S_TLS_BIND="127.0.0.1:$s2s_tls_b" \
  PUBLIC_URL="http://127.0.0.1:$http_b" UPLOAD_DIR="$upload_b" \
  TLS_CERT_PATH="$cert_dir/federation-b.crt" TLS_KEY_PATH="$cert_dir/federation-b.key" \
  OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
  API_CONTROL_ALLOW_EPHEMERAL=true \
  ABUSE_STATE_ALLOW_EPHEMERAL=true \
  FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-b.secret" \
  DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-b.secret" \
  FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true \
  S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true \
  DIALBACK_SECRET_FILE= DIALBACK_SECRET= \
  FEDERATION_DNS_OVERRIDES="localhost=127.0.0.1:$s2s_a,conference.localhost=127.0.0.1:$s2s_a,pubsub.localhost=127.0.0.1:$s2s_a" \
  FEDERATION_EXTRA_ROOT_CERT_PATH="$cert_dir/federation-ca.crt" \
  LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
  "$binary" >"$log_b" 2>&1 &
pid_b=$!

for url in "http://127.0.0.1:$http_a/readyz" "http://127.0.0.1:$http_b/readyz"; do
  for _ in $(seq 1 150); do
    if curl --silent --fail "$url" >/dev/null; then break; fi
    sleep 0.1
  done
  curl --silent --fail "$url" >/dev/null
done

FEDERATION_TEST_CERT_DIR="$cert_dir" \
FEDERATION_TEST_EXTERNAL="${S2S_SASL_EXTERNAL_ENABLED:-true}" \
FEDERATION_TEST_HTTP_PORT_A="$http_a" \
FEDERATION_TEST_HTTP_PORT_B="$http_b" \
FEDERATION_TEST_CLIENT_PORT_A="$xmpp_a" \
FEDERATION_TEST_CLIENT_PORT_B="$xmpp_b" \
FEDERATION_TEST_CLIENT_DIRECT_TLS_PORT_A="$xmpps_a" \
FEDERATION_TEST_S2S_STARTTLS_PORT_A="$s2s_a" \
FEDERATION_TEST_S2S_DIRECT_TLS_PORT_A="$s2s_tls_a" \
FEDERATION_TEST_SCHEMA_A="$schema_a" \
FEDERATION_TEST_SCHEMA_B="$schema_b" \
python3 scripts/federation-wsl.py
