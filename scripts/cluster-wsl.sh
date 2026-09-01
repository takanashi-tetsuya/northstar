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

schema="${XMPP_TEST_SCHEMA:-cluster_it_$(openssl rand -hex 6)}"
if [[ ! "$schema" =~ ^cluster_it_[0-9a-f]{12,48}$ ]]; then
  echo "XMPP_TEST_SCHEMA must use the isolated cluster_it_ prefix followed by 12-48 lowercase hexadecimal characters" >&2
  exit 2
fi
redis_tmp="$(mktemp -d /tmp/northstar-redis.XXXXXX)"
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
declare -a allocated_ports=()
assign_port() {
  local destination="$1"
  local port=""
  while :; do
    port="$(pick_port)"
    if [[ ! " ${allocated_ports[*]} " =~ " $port " ]]; then
      break
    fi
  done
  allocated_ports+=("$port")
  printf -v "$destination" '%s' "$port"
}
assign_port redis_port
assign_port redis_tls_port
assign_port xmpp_a
assign_port xmpp_b
assign_port http_a
assign_port http_b
assign_port metrics_a
assign_port metrics_b
assign_port http_probe

redis_pid=""
redis_tls_pid=""
optional_pid=""
pid_a=""
pid_b=""
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  # The fault matrix deliberately SIGSTOPs the exact Redis process that this
  # script created.  If the test runner is interrupted inside that window,
  # Redis cannot act on SIGTERM until it is continued.  Resume only the two
  # recorded child PIDs before terminating any owned processes.
  for pid in "$redis_pid" "$redis_tls_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -CONT "$pid" 2>/dev/null || true
    fi
  done
  for pid in "$pid_a" "$pid_b" "$redis_pid" "$redis_tls_pid" "$optional_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$pid_a" "$pid_b" "$redis_pid" "$redis_tls_pid" "$optional_pid"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  if (( exit_code != 0 )); then
    for log in "$redis_tmp/cluster-a.log" "$redis_tmp/cluster-b.log" "$redis_tmp/cluster-redis.log"; do
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
  for port in "${allocated_ports[@]}"; do
    if port_is_listening "$port"; then
      echo "cluster listener remained on port $port" >&2
      listener_count=$((listener_count + 1))
      exit_code=1
    fi
  done
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
bind 127.0.0.1
port 0
tls-port $redis_port
save ""
appendonly no
protected-mode yes
tls-cert-file $redis_tmp/redis-tls.crt
tls-key-file $redis_tmp/redis-tls.key
tls-ca-cert-file $redis_tmp/redis-ca.crt
tls-auth-clients yes
user default off
user northstar on >$redis_password ~northstar:cluster.localhost:* &northstar:cluster.localhost:* +ping +time +get +set +setex +expire +ttl +exists +del +sadd +srem +smembers +zadd +zrem +zrangebyscore +zremrangebyscore +scan +publish +subscribe +unsubscribe +psubscribe +punsubscribe +eval +evalsha +script|load +hget +hset +hdel +hexists +hlen +hvals +hgetall +hkeys +hincrby
EOF
chmod 600 "$redis_tmp/redis.conf"
cat >"$redis_tmp/redis-tls.conf" <<EOF
bind 127.0.0.1
port 0
tls-port $redis_tls_port
save ""
appendonly no
protected-mode yes
tls-cert-file $redis_tmp/redis-tls.crt
tls-key-file $redis_tmp/redis-tls.key
tls-ca-cert-file $redis_tmp/redis-ca.crt
tls-auth-clients optional
user default off
user northstar on >$redis_password ~northstar:cluster.localhost:* &northstar:cluster.localhost:* +ping +time +get +set +setex +expire +ttl +exists +del +sadd +srem +smembers +zadd +zrem +zrangebyscore +zremrangebyscore +scan +publish +subscribe +unsubscribe +psubscribe +punsubscribe +eval +evalsha +script|load +hget +hset +hdel +hexists +hlen +hvals +hgetall +hkeys +hincrby
EOF
chmod 600 "$redis_tmp/redis-tls.conf"
printf 'rediss://northstar:%s@localhost:%s/\n' "$redis_password" "$redis_port" >"$redis_tmp/redis.url"
chmod 600 "$redis_tmp/redis.url"

"$redis_binary" "$redis_tmp/redis.conf" >"$redis_tmp/cluster-redis.log" 2>&1 &
redis_pid=$!

"$redis_binary" "$redis_tmp/redis-tls.conf" >"$redis_tmp/cluster-redis-tls.log" 2>&1 &
redis_tls_pid=$!

for _ in $(seq 1 100); do
  if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
    --cert "$redis_tmp/redis-client.crt" --key "$redis_tmp/redis-client.key" \
    --user northstar -h localhost -p "$redis_port" ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 0.05
done
REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --cert "$redis_tmp/redis-client.crt" --key "$redis_tmp/redis-client.key" \
  --user northstar -h localhost -p "$redis_port" ping | grep -q PONG
unauthorized="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
  --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
  --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_port" \
  flushall 2>&1 || true)"
if ! grep -q 'NOPERM' <<<"$unauthorized"; then
  echo "Redis ACL did not reject an ungranted administrative command" >&2
  exit 1
fi
for _ in $(seq 1 100); do
  if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
    --user northstar -h localhost -p "$redis_tls_port" ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 0.05
done
REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --user northstar -h localhost -p "$redis_tls_port" ping | grep -q PONG
if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --user northstar -h localhost -p "$redis_port" ping >/dev/null 2>&1; then
  echo "Redis required-mTLS endpoint accepted a client without a certificate" >&2
  exit 1
fi
if REDISCLI_AUTH="$redis_password" "$redis_cli" --tls --cacert "$redis_tmp/redis-ca.crt" \
  --cert "$redis_tmp/redis-rogue-client.crt" --key "$redis_tmp/redis-rogue-client.key" \
  --user northstar -h localhost -p "$redis_port" ping >/dev/null 2>&1; then
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

env "${common_env[@]}" REDIS_URL_FILE= \
  REDIS_URL="rediss://northstar:$redis_password@localhost:$redis_tls_port/" \
  REDIS_TLS_CLIENT_CERT_PATH= REDIS_TLS_CLIENT_KEY_PATH= \
  XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 \
  HTTP_BIND="127.0.0.1:$http_probe" S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
  PUBLIC_URL="http://127.0.0.1:$http_probe" UPLOAD_DIR="$redis_tmp/cluster-optional" \
  "$binary" >"$redis_tmp/cluster-optional.log" 2>&1 &
optional_pid=$!
for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_probe/readyz" >/dev/null; then break; fi
  if ! kill -0 "$optional_pid" 2>/dev/null; then cat "$redis_tmp/cluster-optional.log" >&2; exit 1; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$http_probe/readyz" >/dev/null
kill "$optional_pid"
wait "$optional_pid" || true
optional_pid=""
kill "$redis_tls_pid"
wait "$redis_tls_pid"
redis_tls_pid=""
echo "Northstar rediss custom-CA optional-mTLS connection passed"

expect_redis_tls_rejected() {
  local label="$1" url="$2" ca="$3" cert="$4" key="$5"
  local log="$redis_tmp/rejected-$label.log" probe_pid ready=0 nodes_before nodes_after
  nodes_before="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
    --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
    --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_port" \
    --scan --pattern 'northstar:cluster.localhost:node:*:alive' | wc -l | tr -d '[:space:]')"
  env "${common_env[@]}" REDIS_URL_FILE= REDIS_URL="$url" \
    REDIS_TLS_CA_CERT_PATH="$ca" REDIS_TLS_CLIENT_CERT_PATH="$cert" \
    REDIS_TLS_CLIENT_KEY_PATH="$key" XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 \
    HTTP_BIND="127.0.0.1:$http_probe" S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    PUBLIC_URL="http://127.0.0.1:$http_probe" UPLOAD_DIR="$redis_tmp/rejected-$label" \
    "$binary" >"$log" 2>&1 &
  probe_pid=$!
  for _ in $(seq 1 50); do
    if curl --silent --fail "http://127.0.0.1:$http_probe/readyz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    kill -0 "$probe_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill "$probe_pid" 2>/dev/null || true
  wait "$probe_pid" 2>/dev/null || true
  if (( ready != 0 )); then
    echo "Northstar accepted rejected Redis TLS fixture: $label" >&2
    exit 1
  fi
  if grep -Fq "$redis_password" "$log" || grep -Fq "$url" "$log"; then
    echo "Northstar leaked Redis credentials or URL in $label failure log" >&2
    exit 1
  fi
  if port_is_listening "$http_probe"; then
    echo "rejected Redis TLS fixture retained an HTTP listener: $label" >&2
    exit 1
  fi
  nodes_after="$(REDISCLI_AUTH="$redis_password" "$redis_cli" --tls \
    --cacert "$redis_tmp/redis-ca.crt" --cert "$redis_tmp/redis-client.crt" \
    --key "$redis_tmp/redis-client.key" --user northstar -h localhost -p "$redis_port" \
    --scan --pattern 'northstar:cluster.localhost:node:*:alive' | wc -l | tr -d '[:space:]')"
  if [[ "$nodes_before" != "$nodes_after" ]]; then
    echo "rejected Redis TLS fixture changed cluster liveness leases: $label" >&2
    exit 1
  fi
  echo "Northstar rejected Redis TLS fixture without URL/credential log leakage: $label"
}

expect_redis_tls_rejected wrong-hostname \
  "rediss://northstar:$redis_password@127.0.0.1:$redis_port/" \
  "$redis_tmp/redis-ca.crt" "$redis_tmp/redis-client.crt" "$redis_tmp/redis-client.key"
expect_redis_tls_rejected wrong-ca \
  "rediss://northstar:$redis_password@localhost:$redis_port/" \
  "$redis_tmp/redis-rogue-ca.crt" "$redis_tmp/redis-client.crt" "$redis_tmp/redis-client.key"
expect_redis_tls_rejected wrong-client-cert \
  "rediss://northstar:$redis_password@localhost:$redis_port/" \
  "$redis_tmp/redis-ca.crt" "$redis_tmp/redis-rogue-client.crt" "$redis_tmp/redis-rogue-client.key"

start_a() {
  env "${common_env[@]}" \
    CLUSTER_NODE_ID=node-a \
    CLUSTER_SIGNING_PRIVATE_KEY_FILE="$redis_tmp/node-a.pkcs8.b64" \
    CLUSTER_PEER_KEYS_FILE="$redis_tmp/node-a-peers.json" \
    XMPP_BIND="127.0.0.1:$xmpp_a" XMPPS_BIND=127.0.0.1:0 \
    METRICS_BIND="127.0.0.1:$metrics_a" \
    HTTP_BIND="127.0.0.1:$http_a" S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    PUBLIC_URL="http://127.0.0.1:$http_a" UPLOAD_DIR="$redis_tmp/cluster-a" \
    "$binary" >"$redis_tmp/cluster-a.log" 2>&1 &
  pid_a=$!
  for _ in $(seq 1 150); do
    if curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null; then return; fi
    sleep 0.1
  done
  return 1
}

start_a

env "${common_env[@]}" \
  CLUSTER_NODE_ID=node-b \
  CLUSTER_SIGNING_PRIVATE_KEY_FILE="$redis_tmp/node-b.pkcs8.b64" \
  CLUSTER_PEER_KEYS_FILE="$redis_tmp/node-b-peers.json" \
  XMPP_BIND="127.0.0.1:$xmpp_b" XMPPS_BIND=127.0.0.1:0 \
  METRICS_BIND="127.0.0.1:$metrics_b" \
  HTTP_BIND="127.0.0.1:$http_b" S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
  PUBLIC_URL="http://127.0.0.1:$http_b" UPLOAD_DIR="$redis_tmp/cluster-b" \
  "$binary" >"$redis_tmp/cluster-b.log" 2>&1 &
pid_b=$!

for _ in $(seq 1 150); do
  if curl --silent --fail "http://127.0.0.1:$http_b/readyz" >/dev/null; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$http_b/readyz" >/dev/null

NORTHSTAR_CLUSTER_HTTP_A="$http_a" NORTHSTAR_CLUSTER_HTTP_B="$http_b" \
NORTHSTAR_CLUSTER_XMPP_A="$xmpp_a" NORTHSTAR_CLUSTER_XMPP_B="$xmpp_b" \
NORTHSTAR_CLUSTER_METRICS_A="$metrics_a" NORTHSTAR_CLUSTER_METRICS_B="$metrics_b" \
NORTHSTAR_CLUSTER_PID_A="$pid_a" NORTHSTAR_CLUSTER_SCHEMA="$schema" \
python3 scripts/cluster-wsl.py
wait "$pid_a" || true
pid_a=""
start_a
NORTHSTAR_CLUSTER_HTTP_A="$http_a" NORTHSTAR_CLUSTER_HTTP_B="$http_b" \
NORTHSTAR_CLUSTER_XMPP_A="$xmpp_a" NORTHSTAR_CLUSTER_XMPP_B="$xmpp_b" \
NORTHSTAR_CLUSTER_METRICS_A="$metrics_a" NORTHSTAR_CLUSTER_METRICS_B="$metrics_b" \
NORTHSTAR_CLUSTER_PID_A="$pid_a" NORTHSTAR_CLUSTER_REDIS_PID="$redis_pid" \
NORTHSTAR_CLUSTER_PID_B="$pid_b" \
NORTHSTAR_CLUSTER_NODE_B_PRIVATE_KEY_DER="$redis_tmp/node-b.pkcs8.der" \
NORTHSTAR_CLUSTER_REDIS_PORT="$redis_port" NORTHSTAR_CLUSTER_REDIS_PASSWORD="$redis_password" \
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
