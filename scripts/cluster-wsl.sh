#!/usr/bin/env bash
set -euo pipefail
export DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true
export METRICS_BIND=127.0.0.1:0

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# WSL bootstrap keeps its own rustup/cargo layout; system-toolchain callers
# (CI) reuse the installed rustup and the repository target directory.
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
else
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target}"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

schema="${XMPP_TEST_SCHEMA:-cluster_it_$(openssl rand -hex 6)}"
if [[ ! "$schema" =~ ^cluster_it_[0-9a-f]{12,48}$ ]]; then
  echo "XMPP_TEST_SCHEMA must use the isolated cluster_it_ prefix followed by 12-48 lowercase hexadecimal characters" >&2
  exit 2
fi
redis_tmp="$(mktemp -d /tmp/northstar-redis.XXXXXX)"
chmod 700 "$redis_tmp"
if [[ "$(stat -c '%a' "$redis_tmp")" != "700" ]]; then
  echo "cluster Redis runtime directory must be private: $redis_tmp" >&2
  exit 1
fi
redis_socket="$redis_tmp/redis.sock"

redis_pid=""
redis_required_tls_pid=""
redis_optional_tls_pid=""
optional_pid=""
pid_a=""
pid_b=""
relay_a_http_pid=""
relay_b_http_pid=""
relay_probe_http_pid=""
relay_a_http_port=""
relay_b_http_port=""
relay_probe_http_port=""
target_a_http="$redis_tmp/cluster-a.http.target"
target_b_http="$redis_tmp/cluster-b.http.target"
target_probe_http="$redis_tmp/cluster-probe.http.target"
declare -a fixture_listener_ports=()
cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  # The fault matrix deliberately SIGSTOPs the exact Redis process that this
  # script created.  If the test runner is interrupted inside that window,
  # Redis cannot act on SIGTERM until it is continued.  Resume only the two
  # recorded child PIDs before terminating any owned processes.
  for pid in "$redis_pid" "$redis_required_tls_pid" "$redis_optional_tls_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -CONT "$pid" 2>/dev/null || true
    fi
  done
  for pid in "$pid_a" "$pid_b" "$relay_a_http_pid" "$relay_b_http_pid" "$relay_probe_http_pid" \
    "$redis_required_tls_pid" "$redis_optional_tls_pid" "$redis_pid" "$optional_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$pid_a" "$pid_b" "$relay_a_http_pid" "$relay_b_http_pid" "$relay_probe_http_pid" \
    "$redis_required_tls_pid" "$redis_optional_tls_pid" "$redis_pid" "$optional_pid"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  if (( exit_code != 0 )); then
    for log in "$redis_tmp/cluster-a.log" "$redis_tmp/cluster-b.log" \
      "$redis_tmp/cluster-redis.log" "$redis_tmp/redis-required-mtls.log" \
      "$redis_tmp/redis-optional-mtls.log" "$redis_tmp/cluster-a-http-relay.log" \
      "$redis_tmp/cluster-b-http-relay.log" "$redis_tmp/cluster-probe-http-relay.log"; do
      if [[ -f "$log" ]]; then
        echo "--- $(basename "$log") (last 160 lines) ---" >&2
        tail -n 160 "$log" >&2 || true
      fi
    done
  fi
  if ! PGPASSWORD=xmpp-test-password psql \
    --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 \
    --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null 2>&1; then
    exit_code=1
  fi
  remains="$(PGPASSWORD=xmpp-test-password psql \
    --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
    2>/dev/null || printf unknown)"
  remains="${remains//[[:space:]]/}"
  if [[ "$remains" != "f" ]]; then
    echo "cluster schema cleanup failed: $schema=${remains:-unknown}" >&2
    exit_code=1
  fi
  listener_count=0
  if ! fixture_assert_no_listeners; then
    listener_count=1
    exit_code=1
  fi
  if [[ -e "$redis_socket" || -L "$redis_socket" ]]; then
    echo "cluster Redis Unix socket remained after its owned process stopped: $redis_socket" >&2
    exit_code=1
  fi
  case "$redis_tmp" in
    /tmp/northstar-redis.*) rm -rf -- "$redis_tmp" ;;
    *) echo "refusing to remove unexpected cluster runtime directory: $redis_tmp" >&2; exit_code=1 ;;
  esac
  runtime_remains=0
  if [[ -e "$redis_tmp" ]]; then
    runtime_remains=1
    echo "cluster runtime directory remained: $redis_tmp" >&2
    exit_code=1
  fi
  echo "cluster cleanup: schema=$schema:${remains:-unknown} listeners=$listener_count runtime_dirs=$runtime_remains"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
  --set ON_ERROR_STOP=1 \
  --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null

if [[ "${NORTHSTAR_CLUSTER_SKIP_BUILD:-false}" != "true" ]]; then
  cargo build --locked --offline
fi
binary="$CARGO_TARGET_DIR/debug/rust-xmpp-server"
[[ -x "$binary" ]] || { echo "cluster runtime binary is missing: $binary" >&2; exit 1; }
cluster_database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=cluster.localhost \
  MIGRATOR_DATABASE_URL="$cluster_database_url" "$binary" migrate
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=cluster.localhost" \
  -addext "subjectAltName=DNS:cluster.localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$redis_tmp/cluster.key" -out "$redis_tmp/cluster.crt" >/dev/null 2>&1
chmod 600 "$redis_tmp/cluster.key"
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=Northstar Redis Runtime CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$redis_tmp/redis-ca.key" -out "$redis_tmp/redis-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$redis_tmp/redis-tls.key" -out "$redis_tmp/redis-tls.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$redis_tmp/redis-tls.csr" \
  -CA "$redis_tmp/redis-ca.crt" -CAkey "$redis_tmp/redis-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$redis_tmp/redis-tls.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=northstar-cluster-client" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=clientAuth" \
  -keyout "$redis_tmp/redis-client.key" -out "$redis_tmp/redis-client.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$redis_tmp/redis-client.csr" \
  -CA "$redis_tmp/redis-ca.crt" -CAkey "$redis_tmp/redis-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$redis_tmp/redis-client.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj "/CN=Northstar Rogue Redis CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$redis_tmp/redis-rogue-ca.key" -out "$redis_tmp/redis-rogue-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -nodes -subj "/CN=rogue-cluster-client" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=clientAuth" \
  -keyout "$redis_tmp/redis-rogue-client.key" -out "$redis_tmp/redis-rogue-client.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$redis_tmp/redis-rogue-client.csr" \
  -CA "$redis_tmp/redis-rogue-ca.crt" -CAkey "$redis_tmp/redis-rogue-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$redis_tmp/redis-rogue-client.crt" >/dev/null 2>&1
chmod 600 "$redis_tmp/cluster.crt" "$redis_tmp/redis-ca.key" "$redis_tmp/redis-ca.crt" \
  "$redis_tmp/redis-tls.key" "$redis_tmp/redis-tls.crt" \
  "$redis_tmp/redis-client.key" "$redis_tmp/redis-client.crt" \
  "$redis_tmp/redis-rogue-ca.key" "$redis_tmp/redis-rogue-ca.crt" \
  "$redis_tmp/redis-rogue-client.key" "$redis_tmp/redis-rogue-client.crt"
openssl rand -hex 32 >"$redis_tmp/dialback_secret"
openssl rand -hex 32 >"$redis_tmp/api_control_secret"
openssl rand -hex 32 >"$redis_tmp/abuse_state_hmac_key"
openssl rand -hex 32 >"$redis_tmp/fast_token_secret"
openssl rand -hex 32 >"$redis_tmp/dummy_scram_secret"
chmod 600 \
  "$redis_tmp/dialback_secret" \
  "$redis_tmp/api_control_secret" \
  "$redis_tmp/abuse_state_hmac_key" \
  "$redis_tmp/fast_token_secret" \
  "$redis_tmp/dummy_scram_secret"
redis_binary="$(command -v redis-server)"
redis_cli="$(command -v redis-cli)"
redis_password="$(openssl rand -hex 32)"
cat >"$redis_tmp/redis.conf" <<EOF
port 0
tls-port 0
unixsocket $redis_socket
unixsocketperm 700
save ""
appendonly no
protected-mode yes
user default off
user northstar on >$redis_password ~northstar:cluster.localhost:* &northstar:cluster.localhost:* +ping +time +get +set +setex +expire +ttl +exists +del +sadd +srem +smembers +zadd +zrem +zrangebyscore +zremrangebyscore +scan +publish +subscribe +unsubscribe +psubscribe +punsubscribe +eval +evalsha +script|load +hget +hset +hdel +hexists +hlen +hvals +hgetall +hkeys +hincrby
EOF
chmod 600 "$redis_tmp/redis.conf"

"$redis_binary" "$redis_tmp/redis.conf" >"$redis_tmp/cluster-redis.log" 2>&1 &
redis_pid=$!

for _ in $(seq 1 100); do
  if REDISCLI_AUTH="$redis_password" "$redis_cli" --socket "$redis_socket" \
    --user northstar ping 2>/dev/null | grep -q PONG; then
    break
  fi
  if ! kill -0 "$redis_pid" 2>/dev/null; then
    echo "cluster Redis exited before publishing its private Unix socket" >&2
    tail -n 160 "$redis_tmp/cluster-redis.log" >&2 || true
    exit 1
  fi
  sleep 0.05
done
REDISCLI_AUTH="$redis_password" "$redis_cli" --socket "$redis_socket" \
  --user northstar ping | grep -q PONG
[[ -S "$redis_socket" ]] || {
  echo "cluster Redis readiness succeeded without a Unix-domain socket: $redis_socket" >&2
  exit 1
}
if [[ "$(stat -c '%a' "$redis_socket")" != "700" ]]; then
  echo "cluster Redis Unix socket must remain private: $redis_socket" >&2
  exit 1
fi

# Redis itself owns no TCP listener.  The two short-lived TLS frontends own
# their own ephemeral ports and readiness records, preserving the required
# and optional mTLS test boundary while Northstar uses the private Unix socket
# behind them.
start_redis_tls_frontend() {
  local label="$1" client_auth="$2" purpose="$3" pid_variable="$4" port_variable="$5"
  local readiness_file="$redis_tmp/$label.ready.json" readiness_nonce relay_pid relay_port
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  python3 "$project_dir/scripts/test-redis-tls-unix-relay.py" \
    --readiness-file "$readiness_file" --nonce "$readiness_nonce" --purpose "$purpose" \
    --unix-socket "$redis_socket" --certificate "$redis_tmp/redis-tls.crt" \
    --private-key "$redis_tmp/redis-tls.key" --ca-certificate "$redis_tmp/redis-ca.crt" \
    --client-auth "$client_auth" >"$redis_tmp/$label.log" 2>&1 &
  relay_pid=$!
  if ! fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$relay_pid"; then
    kill "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
    return 1
  fi
  relay_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" "$purpose")" || return 1
  printf -v "$pid_variable" '%s' "$relay_pid"
  printf -v "$port_variable" '%s' "$relay_port"
}

start_redis_tls_frontend redis-required-mtls required redis-required-mtls \
  redis_required_tls_pid redis_required_tls_port
start_redis_tls_frontend redis-optional-mtls optional redis-optional-mtls \
  redis_optional_tls_pid redis_optional_tls_port
printf 'rediss://northstar:%s@localhost:%s/\n' "$redis_password" "$redis_required_tls_port" >"$redis_tmp/redis.url"
chmod 600 "$redis_tmp/redis.url"

REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --cert "$redis_tmp/redis-client.crt" --key "$redis_tmp/redis-client.key" \
  --user northstar -h localhost -p "$redis_required_tls_port" ping | grep -q PONG
unauthorized="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
  --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
  --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_required_tls_port" \
  flushall 2>&1 || true)"
if ! grep -q 'NOPERM' <<<"$unauthorized"; then
  echo "Redis ACL did not reject an ungranted administrative command" >&2
  exit 1
fi
REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --user northstar -h localhost -p "$redis_optional_tls_port" ping | grep -q PONG
if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --user northstar -h localhost -p "$redis_required_tls_port" ping >/dev/null 2>&1; then
  echo "Redis required-mTLS endpoint accepted a client without a certificate" >&2
  exit 1
fi
if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --cert "$redis_tmp/redis-rogue-client.crt" --key "$redis_tmp/redis-rogue-client.key" \
  --user northstar -h localhost -p "$redis_required_tls_port" ping >/dev/null 2>&1; then
  echo "Redis required-mTLS endpoint accepted an untrusted client certificate" >&2
  exit 1
fi
echo "Redis ACL and optional/required mTLS endpoint configuration probes passed"

node scripts/generate-cluster-signing-key.mjs \
  "$redis_tmp/node-a.pkcs8.b64" "$redis_tmp/node-a.public.b64" >/dev/null
node scripts/generate-cluster-signing-key.mjs \
  "$redis_tmp/node-b.pkcs8.b64" "$redis_tmp/node-b.public.b64" >/dev/null
node scripts/generate-cluster-signing-key.mjs \
  "$redis_tmp/node-probe.pkcs8.b64" "$redis_tmp/node-probe.public.b64" >/dev/null
node -e 'const fs=require("node:fs"); fs.writeFileSync(process.argv[2], Buffer.from(fs.readFileSync(process.argv[1], "utf8").trim(), "base64url"), {mode: 0o600, flag: "wx"});' \
  "$redis_tmp/node-b.pkcs8.b64" "$redis_tmp/node-b.pkcs8.der"
cluster_public_a="$(tr -d '\r\n' <"$redis_tmp/node-a.public.b64")"
cluster_public_b="$(tr -d '\r\n' <"$redis_tmp/node-b.public.b64")"
cluster_kinds='["ack","direct_delivery","blocking_presence","presence_probe","session_teardown","account_generation_teardown","user_agent_replacement","sm_session_teardown","sm_muc_teardown","muc_broadcast","muc_private","muc_presence","muc_nickname_change","muc_role_change","muc_evict","muc_destroy","muc_operation_wake"]'
printf '{"namespace":"cluster.localhost","nodes":[{"node_id":"node-b","key_epoch":1,"current_public_key":"%s","allowed_kinds":%s}]}\n' \
  "$cluster_public_b" "$cluster_kinds" >"$redis_tmp/node-a-peers.json"
printf '{"namespace":"cluster.localhost","nodes":[{"node_id":"node-a","key_epoch":1,"current_public_key":"%s","allowed_kinds":%s}]}\n' \
  "$cluster_public_a" "$cluster_kinds" >"$redis_tmp/node-b-peers.json"
printf '{"namespace":"cluster.localhost","nodes":[{"node_id":"node-a","key_epoch":1,"current_public_key":"%s","allowed_kinds":%s}]}\n' \
  "$cluster_public_a" "$cluster_kinds" >"$redis_tmp/node-probe-peers.json"
chmod 600 "$redis_tmp"/*.pkcs8.b64 "$redis_tmp"/*.pkcs8.der \
  "$redis_tmp"/*.public.b64 "$redis_tmp"/*-peers.json

common_env=(
  NORTHSTAR_DISABLE_DOTENV=true
  XMPP_DOMAIN=cluster.localhost
  DATABASE_URL="$cluster_database_url"
  REDIS_URL_FILE="$redis_tmp/redis.url"
  REDIS_TLS_CA_CERT_PATH="$redis_tmp/redis-ca.crt"
  REDIS_TLS_CLIENT_CERT_PATH="$redis_tmp/redis-client.crt"
  REDIS_TLS_CLIENT_KEY_PATH="$redis_tmp/redis-client.key"
  CLUSTER_NODE_ID=node-probe
  CLUSTER_SIGNING_PRIVATE_KEY_FILE="$redis_tmp/node-probe.pkcs8.b64"
  CLUSTER_PEER_KEYS_FILE="$redis_tmp/node-probe-peers.json"
  CLUSTER_SIGNING_KEY_EPOCH=1
  CLUSTER_FAILURE_POLICY=fail_closed
  CLUSTER_SAFETY_LEASE_SECONDS=120
  TLS_CERT_PATH="$redis_tmp/cluster.crt"
  TLS_KEY_PATH="$redis_tmp/cluster.key"
  OPEN_REGISTRATION=true
  REQUIRE_ENCRYPTED_ARCHIVE=false
  REGISTRATION_RATE_PER_HOUR=20
  FEDERATION_ENABLED=false
  DIALBACK_SECRET_FILE="$redis_tmp/dialback_secret"
  API_CONTROL_SECRET_FILE="$redis_tmp/api_control_secret"
  ABUSE_STATE_HMAC_KEY_FILE="$redis_tmp/abuse_state_hmac_key"
  FAST_TOKEN_SECRET_FILE="$redis_tmp/fast_token_secret"
  DUMMY_SCRAM_SECRET_FILE="$redis_tmp/dummy_scram_secret"
  LOG_FORMAT=json
  RUST_LOG=rust_xmpp_server=info,rust_xmpp_server::cluster=debug,rust_xmpp_server::xmpp::protocol::messaging=debug,rust_xmpp_server::db::replay=debug
)

# PUBLIC_URL is consumed while each node starts, before that node can publish
# its own dynamic HTTP listener.  A fixture-owned relay supplies that stable
# externally visible origin and follows the child-written target across the
# deliberate node-A restart later in this scenario.
publish_relay_target() {
  local target="$1" port="$2" temporary
  # The runtime directory is private.  The caller retires the old target only
  # after reaping the old child; publication below then creates the target
  # exactly once through a hard link.  A relay can therefore observe only an
  # absent target (and wait), or a complete immutable HOST:PORT record --
  # never a partial write or a stale endpoint being overwritten in place.
  temporary="$(mktemp "$redis_tmp/.cluster-http-target.XXXXXX")"
  printf '127.0.0.1:%s\n' "$port" >"$temporary"
  chmod 600 "$temporary"
  if ! ln -- "$temporary" "$target"; then
    rm -f -- "$temporary"
    echo "refusing to replace an existing relay target: $target" >&2
    return 1
  fi
  rm -f -- "$temporary"
}

retire_relay_target() {
  local target="$1"
  # This is deliberately a two-phase target lifecycle: callers invoke it
  # only after the child which owned the prior endpoint has exited.  The
  # relay will wait for a replacement instead of connecting a new request to
  # a dead or superseded endpoint.
  rm -f -- "$target"
}

fixture_start_tcp_relay "$project_dir" "$redis_tmp" cluster-a cluster-a-http-relay \
  "$target_a_http" "$redis_tmp/cluster-a-http-relay.log" relay_a_http_pid relay_a_http_port
fixture_start_tcp_relay "$project_dir" "$redis_tmp" cluster-b cluster-b-http-relay \
  "$target_b_http" "$redis_tmp/cluster-b-http-relay.log" relay_b_http_pid relay_b_http_port
fixture_start_tcp_relay "$project_dir" "$redis_tmp" cluster-probe cluster-probe-http-relay \
  "$target_probe_http" "$redis_tmp/cluster-probe-http-relay.log" relay_probe_http_pid relay_probe_http_port

start_optional_cluster_probe() {
  local readiness_file="$redis_tmp/cluster-optional.ready.json" readiness_nonce optional_http
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  retire_relay_target "$target_probe_http"
  env "${common_env[@]}" REDIS_URL_FILE= \
    REDIS_URL="rediss://northstar:$redis_password@localhost:$redis_optional_tls_port/" \
    REDIS_TLS_CLIENT_CERT_PATH= REDIS_TLS_CLIENT_KEY_PATH= \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 METRICS_BIND=127.0.0.1:0 \
    HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_probe_http_port" UPLOAD_DIR="$redis_tmp/cluster-optional" \
    "$binary" >"$redis_tmp/cluster-optional.log" 2>&1 &
  optional_pid=$!
  if ! fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$optional_pid"; then
    cat "$redis_tmp/cluster-optional.log" >&2 || true
    return 1
  fi
  optional_http="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)" || return 1
  publish_relay_target "$target_probe_http" "$optional_http"
  curl --silent --fail "http://127.0.0.1:$optional_http/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$relay_probe_http_port/readyz" >/dev/null
}

start_optional_cluster_probe
kill "$optional_pid"
wait "$optional_pid" || true
optional_pid=""
kill "$redis_optional_tls_pid"
wait "$redis_optional_tls_pid"
redis_optional_tls_pid=""
retire_relay_target "$target_probe_http"
echo "Northstar rediss custom-CA optional-mTLS connection passed"

expect_redis_tls_rejected() {
  local label="$1" url="$2" ca="$3" cert="$4" key="$5"
  local log="$redis_tmp/rejected-$label.log" readiness_file="$redis_tmp/rejected-$label.ready.json"
  local readiness_nonce probe_pid published=0 exited=0 nodes_before nodes_after
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  retire_relay_target "$target_probe_http"
  nodes_before="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
    --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
    --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_required_tls_port" \
    --scan --pattern 'northstar:cluster.localhost:node:*:alive' | wc -l | tr -d '[:space:]')"
  env "${common_env[@]}" REDIS_URL_FILE= REDIS_URL="$url" \
    REDIS_TLS_CA_CERT_PATH="$ca" REDIS_TLS_CLIENT_CERT_PATH="$cert" \
    REDIS_TLS_CLIENT_KEY_PATH="$key" XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 \
    METRICS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_probe_http_port" UPLOAD_DIR="$redis_tmp/rejected-$label" \
    "$binary" >"$log" 2>&1 &
  probe_pid=$!
  for _ in $(seq 1 50); do
    if [[ -e "$readiness_file" ]]; then
      if fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$probe_pid"; then
        published=1
        break
      fi
    fi
    if ! kill -0 "$probe_pid" 2>/dev/null; then
      exited=1
      break
    fi
    sleep 0.1
  done
  if (( published != 0 )); then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    echo "Northstar accepted rejected Redis TLS fixture: $label" >&2
    exit 1
  fi
  if (( exited == 0 )); then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    echo "Northstar did not reject the Redis TLS fixture within its bounded startup window: $label" >&2
    exit 1
  fi
  if wait "$probe_pid"; then
    echo "Northstar exited successfully without readiness for rejected Redis TLS fixture: $label" >&2
    exit 1
  fi
  if grep -Fq "$redis_password" "$log" || grep -Fq "$url" "$log"; then
    echo "Northstar leaked Redis credentials or URL in $label failure log" >&2
    exit 1
  fi
  nodes_after="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
    --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
    --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_required_tls_port" \
    --scan --pattern 'northstar:cluster.localhost:node:*:alive' | wc -l | tr -d '[:space:]')"
  if [[ "$nodes_before" != "$nodes_after" ]]; then
    echo "rejected Redis TLS fixture changed cluster liveness leases: $label" >&2
    exit 1
  fi
  echo "Northstar rejected Redis TLS fixture without URL/credential log leakage: $label"
}

expect_redis_tls_rejected wrong-hostname \
  "rediss://northstar:$redis_password@127.0.0.1:$redis_required_tls_port/" \
  "$redis_tmp/redis-ca.crt" "$redis_tmp/redis-client.crt" "$redis_tmp/redis-client.key"
expect_redis_tls_rejected wrong-ca \
  "rediss://northstar:$redis_password@localhost:$redis_required_tls_port/" \
  "$redis_tmp/redis-rogue-ca.crt" "$redis_tmp/redis-client.crt" "$redis_tmp/redis-client.key"
expect_redis_tls_rejected wrong-client-cert \
  "rediss://northstar:$redis_password@localhost:$redis_required_tls_port/" \
  "$redis_tmp/redis-ca.crt" "$redis_tmp/redis-rogue-client.crt" "$redis_tmp/redis-rogue-client.key"

http_a=""
http_b=""
xmpp_a=""
xmpp_b=""
metrics_a=""
metrics_b=""

start_a() {
  local readiness_file="$redis_tmp/cluster-a.ready.json" readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  retire_relay_target "$target_a_http"
  env "${common_env[@]}" \
    CLUSTER_NODE_ID=node-a \
    CLUSTER_SIGNING_PRIVATE_KEY_FILE="$redis_tmp/node-a.pkcs8.b64" \
    CLUSTER_PEER_KEYS_FILE="$redis_tmp/node-a-peers.json" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 METRICS_BIND=127.0.0.1:0 \
    HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_a_http_port" UPLOAD_DIR="$redis_tmp/cluster-a" \
    "$binary" >"$redis_tmp/cluster-a.log" 2>&1 &
  pid_a=$!
  if ! fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_a"; then
    cat "$redis_tmp/cluster-a.log" >&2 || true
    return 1
  fi
  http_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)" || return 1
  xmpp_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)" || return 1
  metrics_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" metrics)" || return 1
  publish_relay_target "$target_a_http" "$http_a"
  curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$relay_a_http_port/readyz" >/dev/null
}

start_b() {
  local readiness_file="$redis_tmp/cluster-b.ready.json" readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  retire_relay_target "$target_b_http"
  env "${common_env[@]}" \
    CLUSTER_NODE_ID=node-b \
    CLUSTER_SIGNING_PRIVATE_KEY_FILE="$redis_tmp/node-b.pkcs8.b64" \
    CLUSTER_PEER_KEYS_FILE="$redis_tmp/node-b-peers.json" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 METRICS_BIND=127.0.0.1:0 \
    HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_b_http_port" UPLOAD_DIR="$redis_tmp/cluster-b" \
    "$binary" >"$redis_tmp/cluster-b.log" 2>&1 &
  pid_b=$!
  if ! fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_b"; then
    cat "$redis_tmp/cluster-b.log" >&2 || true
    return 1
  fi
  http_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)" || return 1
  xmpp_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)" || return 1
  metrics_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" metrics)" || return 1
  publish_relay_target "$target_b_http" "$http_b"
  curl --silent --fail "http://127.0.0.1:$http_b/readyz" >/dev/null
  curl --silent --fail "http://127.0.0.1:$relay_b_http_port/readyz" >/dev/null
}

start_a
start_b

# The protocol driver deliberately reaches node-specific public origins via
# the stable relays.  It retains the exact dynamically published XMPP and
# metrics addresses because those are internal node-specific test surfaces.
NORTHSTAR_CLUSTER_HTTP_A="$relay_a_http_port" NORTHSTAR_CLUSTER_HTTP_B="$relay_b_http_port" \
NORTHSTAR_CLUSTER_XMPP_A="$xmpp_a" NORTHSTAR_CLUSTER_XMPP_B="$xmpp_b" \
NORTHSTAR_CLUSTER_METRICS_A="$metrics_a" NORTHSTAR_CLUSTER_METRICS_B="$metrics_b" \
NORTHSTAR_CLUSTER_PID_A="$pid_a" NORTHSTAR_CLUSTER_SCHEMA="$schema" \
python3 scripts/cluster-wsl.py
wait "$pid_a" || true
pid_a=""
start_a
NORTHSTAR_CLUSTER_HTTP_A="$relay_a_http_port" NORTHSTAR_CLUSTER_HTTP_B="$relay_b_http_port" \
NORTHSTAR_CLUSTER_XMPP_A="$xmpp_a" NORTHSTAR_CLUSTER_XMPP_B="$xmpp_b" \
NORTHSTAR_CLUSTER_METRICS_A="$metrics_a" NORTHSTAR_CLUSTER_METRICS_B="$metrics_b" \
NORTHSTAR_CLUSTER_PID_A="$pid_a" NORTHSTAR_CLUSTER_REDIS_PID="$redis_pid" \
NORTHSTAR_CLUSTER_PID_B="$pid_b" \
NORTHSTAR_CLUSTER_NODE_B_PRIVATE_KEY_DER="$redis_tmp/node-b.pkcs8.der" \
NORTHSTAR_CLUSTER_REDIS_PORT="$redis_required_tls_port" NORTHSTAR_CLUSTER_REDIS_PASSWORD="$redis_password" \
NORTHSTAR_CLUSTER_REDIS_CA="$redis_tmp/redis-ca.crt" \
NORTHSTAR_CLUSTER_REDIS_CERT="$redis_tmp/redis-client.crt" \
NORTHSTAR_CLUSTER_REDIS_KEY="$redis_tmp/redis-client.key" \
NORTHSTAR_CLUSTER_LOG_B="$redis_tmp/cluster-b.log" \
NORTHSTAR_CLUSTER_SCHEMA="$schema" \
python3 scripts/cluster-wsl.py faults
while IFS= read -r -d '' log; do
  if grep -Fq "$redis_password" "$log" || grep -Fq "rediss://northstar:$redis_password" "$log"; then
    echo "Redis URL or credential leaked into runtime log: $log" >&2
    exit 1
  fi
done < <(find "$redis_tmp" -type f -name '*.log*' -print0)
echo "cluster logs contain neither Redis URL nor ACL password"
