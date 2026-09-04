#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"

cd "$project_dir"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
run_id="$(openssl rand -hex 8)"
test_schema="northstar_integration_it_${run_id}"
pick_port() {
  python3 "$project_dir/scripts/allocate-test-ports.py" 34000 35999 1
}
test_http_port="${XMPP_TEST_HTTP_PORT:-$(pick_port)}"
test_metrics_port="${XMPP_TEST_METRICS_PORT:-$(pick_port)}"
test_client_port="${XMPP_TEST_CLIENT_PORT:-$(pick_port)}"
test_xmpps_port="${XMPP_TEST_XMPPS_PORT:-$(pick_port)}"
test_s2s_port="${XMPP_TEST_S2S_PORT:-$(pick_port)}"
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "integration tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_integration_it_[0-9a-f]{16}$ ]]; then
  echo "refusing an unexpected integration schema name" >&2
  exit 2
fi
runtime_dir="$(mktemp -d /tmp/northstar-integration.XXXXXX)"
mkdir -p "$runtime_dir/logs"
export METRICS_BIND="127.0.0.1:$test_metrics_port"
server_pid=""
cleanup() {
  exit_code=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if (( exit_code != 0 )) && [[ -f "$runtime_dir/integration-server.log" ]]; then
    echo "--- integration-server.log (last 160 lines) ---" >&2
    tail -n 160 "$runtime_dir/integration-server.log" >&2 || true
  fi
  if (( exit_code != 0 )); then
    echo "--- isolated MUC authority/outbox diagnostics (last 20 rows) ---" >&2
    PGOPTIONS="-c search_path=$test_schema" PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 --pset pager=off \
      --command "SELECT operation_kind,operation_id,event_sequence,target_nick,details,created_at FROM cluster_muc_operations ORDER BY created_at DESC LIMIT 20;" \
      --command "SELECT operation_id,event_sequence,target_node_id,recipient_full_jid,recipient_nick,attempt_count,claim_token IS NOT NULL AS claimed,last_error,created_at FROM cluster_muc_event_outbox ORDER BY created_at DESC LIMIT 20;" \
      --command "SELECT room_id,nick,full_jid,role,affiliation,state,owner_node_id,occupancy_epoch,connection_epoch,lease_until>clock_timestamp() AS lease_live FROM cluster_muc_occupancies ORDER BY updated_at DESC LIMIT 20;" \
      >&2 || true
    echo "--- isolated PubSub/PEP outbox diagnostics (last 20 rows) ---" >&2
    PGOPTIONS="-c search_path=$test_schema" PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 --pset pager=off \
      --command "SELECT source_kind,source_node,delivery_kind,recipient_jid,event_sequence,attempt_count,lease_token IS NOT NULL AS claimed,last_error,created_at FROM pubsub_event_outbox ORDER BY created_at DESC LIMIT 20;" \
      --command "SELECT source_kind,source_node,delivery_kind,recipient_jid,event_sequence,attempt_count,terminal_reason,last_error,dead_lettered_at FROM pubsub_event_dead_letters ORDER BY dead_lettered_at DESC LIMIT 20;" \
      --command "SELECT owner_id,node,access_model,max_items,deliver_notifications,send_last_published_item,updated_at FROM pep_nodes WHERE node IN ('urn:xmpp:avatar:data','urn:xmpp:avatar:metadata') ORDER BY updated_at DESC LIMIT 20;" \
      --command "SELECT owner_id,node,item_id,octet_length(payload) AS payload_bytes,updated_at FROM pep_items WHERE node IN ('urn:xmpp:avatar:data','urn:xmpp:avatar:metadata') ORDER BY updated_at DESC LIMIT 20;" \
      >&2 || true
  fi
  PGPASSWORD=xmpp-test-password psql \
    --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
    --set ON_ERROR_STOP=1 \
    --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE;" >/dev/null 2>&1 || true
  case "$runtime_dir" in
    /tmp/northstar-integration.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected runtime directory: $runtime_dir" >&2; exit_code=1 ;;
  esac
  exit "$exit_code"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$runtime_dir/integration.key" -out "$runtime_dir/integration.crt" >/dev/null 2>&1
chmod 0600 "$runtime_dir/integration.key"
chmod 0644 "$runtime_dir/integration.crt"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj '/CN=Northstar C2S integration root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$runtime_dir/client-ca.key" -out "$runtime_dir/client-ca.crt" >/dev/null 2>&1
make_c2s_client() {
  local name="$1"
  local common_name="$2"
  local san="$3"
  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -subj "/CN=$common_name" \
    -keyout "$runtime_dir/$name.key" -out "$runtime_dir/$name.csr" >/dev/null 2>&1
  {
    echo 'basicConstraints=critical,CA:FALSE'
    echo 'keyUsage=critical,digitalSignature'
    echo 'extendedKeyUsage=critical,clientAuth'
    if [[ -n "$san" ]]; then echo "subjectAltName=$san"; fi
  } > "$runtime_dir/$name.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "$runtime_dir/$name.csr" \
    -CA "$runtime_dir/client-ca.crt" -CAkey "$runtime_dir/client-ca.key" -CAcreateserial \
    -extfile "$runtime_dir/$name.ext" -out "$runtime_dir/$name.crt" >/dev/null 2>&1
}
make_c2s_client client-alice ignored-cn \
  'otherName:1.3.6.1.5.5.7.8.5;UTF8:Alice_IT@LOCALHOST'
make_c2s_client client-wrong-domain ignored-cn \
  'otherName:1.3.6.1.5.5.7.8.5;UTF8:alice@other.test'
make_c2s_client client-cn-only alice@localhost ''
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -subj '/CN=Untrusted Northstar C2S integration root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$runtime_dir/untrusted-client-ca.key" \
  -out "$runtime_dir/untrusted-client-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=ignored-untrusted-cn' \
  -keyout "$runtime_dir/client-untrusted.key" \
  -out "$runtime_dir/client-untrusted.csr" >/dev/null 2>&1
{
  echo 'basicConstraints=critical,CA:FALSE'
  echo 'keyUsage=critical,digitalSignature'
  echo 'extendedKeyUsage=critical,clientAuth'
  echo 'subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:Alice_IT@LOCALHOST'
} > "$runtime_dir/client-untrusted.ext"
openssl x509 -req -sha256 -days 1 \
  -in "$runtime_dir/client-untrusted.csr" \
  -CA "$runtime_dir/untrusted-client-ca.crt" \
  -CAkey "$runtime_dir/untrusted-client-ca.key" -CAcreateserial \
  -extfile "$runtime_dir/client-untrusted.ext" \
  -out "$runtime_dir/client-untrusted.crt" >/dev/null 2>&1
chmod 0600 "$runtime_dir/client-ca.key" "$runtime_dir/client-alice.key" \
  "$runtime_dir/client-wrong-domain.key" "$runtime_dir/client-cn-only.key" \
  "$runtime_dir/untrusted-client-ca.key" "$runtime_dir/client-untrusted.key"
chmod 0644 "$runtime_dir/client-ca.crt" "$runtime_dir/client-alice.crt" \
  "$runtime_dir/client-wrong-domain.crt" "$runtime_dir/client-cn-only.crt" \
  "$runtime_dir/untrusted-client-ca.crt" "$runtime_dir/client-untrusted.crt"
openssl rand -base64 -out "$runtime_dir/api-control.secret" 48
chmod 0600 "$runtime_dir/api-control.secret"
openssl rand -base64 -out "$runtime_dir/fast-token.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram.secret" 48
chmod 0600 "$runtime_dir/fast-token.secret" "$runtime_dir/dummy-scram.secret"

PGOPTIONS="-c search_path=$test_schema" PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$test_schema\";" >/dev/null

cargo_args=(--locked)
if [[ "${XMPP_TEST_OFFLINE:-true}" == "true" ]]; then
  cargo_args+=(--offline)
fi
cargo build "${cargo_args[@]}"

# Production startup is deliberately verification-only: schema changes must be
# applied by the explicit migrator command before the runtime process starts.
# This hermetic suite owns its random schema, so the dedicated xmpp_test role
# safely serves as both migrator and runtime identity inside that schema.
integration_database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema"
env \
  NORTHSTAR_DISABLE_DOTENV=true \
  XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$integration_database_url" \
  "$target_dir/debug/rust-xmpp-server" migrate

: >"$runtime_dir/integration-server.log"
start_server() {
  env \
    NORTHSTAR_DISABLE_DOTENV=true \
    XMPP_DOMAIN=localhost \
    DATABASE_URL="$integration_database_url" \
    XMPP_BIND="127.0.0.1:$test_client_port" \
    XMPPS_BIND="127.0.0.1:$test_xmpps_port" \
    S2S_BIND="127.0.0.1:$test_s2s_port" \
    S2S_TLS_BIND="127.0.0.1:0" \
    HTTP_BIND="127.0.0.1:$test_http_port" \
    PUBLIC_URL="https://127.0.0.1:$test_http_port" \
    API_CONTROL_ALLOW_EPHEMERAL=true \
    ABUSE_STATE_ALLOW_EPHEMERAL=true \
    API_CONTROL_SECRET_FILE="$runtime_dir/api-control.secret" \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token.secret" \
    DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram.secret" \
    BOSH_ENABLED=true \
    TRUSTED_PROXY_IPS=127.0.0.1,::1 \
    WEBSOCKET_ALLOWED_ORIGINS=http://localhost \
    UPLOAD_DIR="$runtime_dir/uploads" \
    TLS_CERT_PATH="$runtime_dir/integration.crt" \
    TLS_KEY_PATH="$runtime_dir/integration.key" \
    C2S_CLIENT_TRUST_ROOT_CERT_PATH="$runtime_dir/client-ca.crt" \
    OPEN_REGISTRATION=true \
    REQUIRE_ENCRYPTED_ARCHIVE=true \
    SCRAM_ITERATIONS=4096 \
    SCRAM_SHA1_ENABLED=true \
    SM_REQUIRE_SAME_DEVICE=false \
    REGISTRATION_RATE_PER_HOUR=20 \
    RESOURCE_BIND_TIMEOUT_SECONDS=5 \
    ADMIN_ADDRESSES=mailto:admin@example.test \
    SECURITY_ADDRESSES=xmpp:security@localhost \
    STUN_SERVER=stun.example.test:3478 \
    TURN_SERVER=turn.example.test:5349 \
    TURN_SHARED_SECRET=integration-turn-shared-secret-32-bytes-minimum-12345 \
    TURN_CREDENTIALS_TTL_SECONDS=3600 \
    PUBSUB_MAX_NODES_PER_OWNER=2 \
    BOOTSTRAP_ADMIN_USERNAME=admin_it \
    BOOTSTRAP_ADMIN_PASSWORD=integration-admin-password-123 \
    LOG_DIR="$runtime_dir/logs" \
    LOG_FORMAT=json \
    RUST_LOG="${RUST_LOG:-rust_xmpp_server=info}" \
    "$target_dir/debug/rust-xmpp-server" >>"$runtime_dir/integration-server.log" 2>&1 &
  server_pid=$!
}
start_server

if [[ "${XMPP_TEST_ONLY_JINGLE_GATE:-false}" == "true" ]]; then
  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  python3 scripts/test-jingle-full-jid-gate.py
  exit 0
fi

if [[ "${XMPP_TEST_ONLY_SASL:-false}" != "true" && "${XMPP_TEST_ONLY_ATOMIC_REGISTRATION:-false}" != "true" && "${XMPP_TEST_ONLY_MODERN_MESSAGES:-false}" != "true" && "${XMPP_TEST_ONLY_LOGIN_IDEMPOTENCY:-false}" != "true" && "${XMPP_TEST_ONLY_CHALLENGE_CAPACITY:-false}" != "true" ]]; then
  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  python3 scripts/test-roster-removal.py

  if [[ "${XMPP_TEST_ONLY_ROSTER_REMOVAL:-false}" == "true" ]]; then
    exit 0
  fi

  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  python3 scripts/test-muc-phase7.py

  if [[ "${XMPP_TEST_ONLY_MUC:-false}" == "true" ]]; then
    exit 0
  fi
fi

fast_restart_file=""
if [[ "${XMPP_TEST_ONLY_SASL:-false}" == "true" ]]; then
  fast_restart_file="$runtime_dir/fast-restart.json"
fi
XMPP_TEST_HOST=127.0.0.1 \
XMPP_TEST_HTTP_PORT="$test_http_port" \
XMPP_TEST_METRICS_PORT="$test_metrics_port" \
XMPP_TEST_CLIENT_PORT="$test_client_port" \
XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
XMPP_TEST_DOMAIN=localhost \
XMPP_TEST_FAST_RESTART_FILE="$fast_restart_file" \
XMPP_TEST_C2S_CLIENT_CERT="$runtime_dir/client-alice.crt" \
XMPP_TEST_C2S_CLIENT_KEY="$runtime_dir/client-alice.key" \
XMPP_TEST_C2S_WRONG_DOMAIN_CERT="$runtime_dir/client-wrong-domain.crt" \
XMPP_TEST_C2S_WRONG_DOMAIN_KEY="$runtime_dir/client-wrong-domain.key" \
XMPP_TEST_C2S_CN_ONLY_CERT="$runtime_dir/client-cn-only.crt" \
XMPP_TEST_C2S_CN_ONLY_KEY="$runtime_dir/client-cn-only.key" \
XMPP_TEST_C2S_UNTRUSTED_CERT="$runtime_dir/client-untrusted.crt" \
XMPP_TEST_C2S_UNTRUSTED_KEY="$runtime_dir/client-untrusted.key" \
python3 scripts/integration-wsl.py

if [[ "${XMPP_TEST_ONLY_SASL:-false}" != "true" && "${XMPP_TEST_ONLY_ATOMIC_REGISTRATION:-false}" != "true" && "${XMPP_TEST_ONLY_MODERN_MESSAGES:-false}" != "true" && "${XMPP_TEST_ONLY_LOGIN_IDEMPOTENCY:-false}" != "true" && "${XMPP_TEST_ONLY_CHALLENGE_CAPACITY:-false}" != "true" ]]; then
  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  python3 scripts/message-family-restart-wsl.py prepare

  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
  start_server
  for _ in $(seq 1 150); do
    if curl --silent --fail "http://127.0.0.1:$test_http_port/readyz" >/dev/null; then break; fi
    sleep 0.1
  done
  curl --silent --fail "http://127.0.0.1:$test_http_port/readyz" >/dev/null

  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  python3 scripts/message-family-restart-wsl.py verify
fi

if [[ "${XMPP_TEST_ONLY_SASL:-false}" == "true" ]]; then
  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
  start_server
  XMPP_TEST_HOST=127.0.0.1 \
  XMPP_TEST_HTTP_PORT="$test_http_port" \
  XMPP_TEST_METRICS_PORT="$test_metrics_port" \
  XMPP_TEST_CLIENT_PORT="$test_client_port" \
  XMPP_TEST_XMPPS_PORT="$test_xmpps_port" \
  XMPP_TEST_DOMAIN=localhost \
  XMPP_TEST_FAST_RESTART_FILE="$fast_restart_file" \
  XMPP_TEST_SASL_RESTART_VERIFY=true \
  XMPP_TEST_C2S_CLIENT_CERT="$runtime_dir/client-alice.crt" \
  XMPP_TEST_C2S_CLIENT_KEY="$runtime_dir/client-alice.key" \
  XMPP_TEST_C2S_WRONG_DOMAIN_CERT="$runtime_dir/client-wrong-domain.crt" \
  XMPP_TEST_C2S_WRONG_DOMAIN_KEY="$runtime_dir/client-wrong-domain.key" \
  XMPP_TEST_C2S_CN_ONLY_CERT="$runtime_dir/client-cn-only.crt" \
  XMPP_TEST_C2S_CN_ONLY_KEY="$runtime_dir/client-cn-only.key" \
  XMPP_TEST_C2S_UNTRUSTED_CERT="$runtime_dir/client-untrusted.crt" \
  XMPP_TEST_C2S_UNTRUSTED_KEY="$runtime_dir/client-untrusted.key" \
  python3 scripts/integration-wsl.py
fi

if [[ "${XMPP_TEST_ONLY_SASL:-false}" != "true" && "${XMPP_TEST_ONLY_ATOMIC_REGISTRATION:-false}" != "true" && "${XMPP_TEST_ONLY_MODERN_MESSAGES:-false}" != "true" && "${XMPP_TEST_ONLY_LOGIN_IDEMPOTENCY:-false}" != "true" && "${XMPP_TEST_ONLY_CHALLENGE_CAPACITY:-false}" != "true" ]]; then
  python3 scripts/transport-conformance.py \
    --bosh "http://127.0.0.1:$test_http_port/http-bind" \
    --websocket "ws://127.0.0.1:$test_http_port/xmpp-websocket" \
    --domain localhost
fi
