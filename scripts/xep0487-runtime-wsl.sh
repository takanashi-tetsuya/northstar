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
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
cd "$project_dir"

run_id="$(openssl rand -hex 6)"
schema_a="xep0487_a_${run_id}"
schema_b="xep0487_b_${run_id}"
[[ "$schema_a" =~ ^[a-z][a-z0-9_]{0,62}$ && "$schema_b" =~ ^[a-z][a-z0-9_]{0,62}$ ]] || exit 2
declare -a allocated_ports=(443)
http_a=""
http_b=""
s2s_tls_a=""
s2s_tls_b=""
s2s_port_file=""
if ss -H -ltn 'sport = :443' 2>/dev/null | grep -q .; then
  echo "XEP-0487 fixture requires an unused local TCP port 443" >&2
  exit 2
fi

runtime_dir="$(mktemp -d /tmp/northstar-xep0487.XXXXXX)"
export PYTHONPYCACHEPREFIX="$runtime_dir/pycache"
mkdir -p "$PYTHONPYCACHEPREFIX"
pid_a=""
pid_b=""
https_pid=""
residual_probe_pid=""
port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}
readiness_port() {
  local record="$1" purpose="$2" address
  address="$(awk -F= -v purpose="$purpose" '$1 == purpose { print $2; exit }' <<<"$record")"
  [[ -n "$address" ]] || { echo "test readiness did not publish $purpose" >&2; return 1; }
  printf '%s' "${address##*:}"
}
track_readiness_ports() {
  local record="$1" purpose address port
  while IFS='=' read -r purpose address; do
    [[ -n "$purpose" && -n "$address" ]] || continue
    port="${address##*:}"
    [[ "$port" =~ ^[1-9][0-9]*$ ]] || { echo "invalid readiness address: $address" >&2; return 1; }
    allocated_ports+=("$port")
  done <<<"$record"
}
assert_no_fixture_listeners() {
  local port listener_count=0
  for port in "${allocated_ports[@]}"; do
    if port_is_listening "$port"; then
      echo "XEP-0487 listener remained on port $port" >&2
      listener_count=$((listener_count + 1))
    fi
  done
  (( listener_count == 0 ))
}
wait_for_readiness() {
  local record_path="$1" nonce="$2" pid="$3"
  readiness_output="$(python3 "$project_dir/scripts/wait-test-readiness.py" "$record_path" "$nonce" "$pid" 15)" || return 1
  # Command substitution would run registration in a subshell and discard the
  # parent fixture's port ledger before cleanup can inspect it.
  track_readiness_ports "$readiness_output"
}
exercise_non_443_residual_detection() {
  local probe_port_file="$runtime_dir/residual-probe.port" probe_port
  python3 -c 'import socket,time; listener=socket.socket(); listener.bind(("127.0.0.1",0)); listener.listen(); print(listener.getsockname()[1],flush=True); time.sleep(30)' \
    >"$probe_port_file" 2>&1 &
  residual_probe_pid=$!
  for _ in $(seq 1 50); do [[ -s "$probe_port_file" ]] && break; sleep .1; done
  probe_port="$(head -n 1 "$probe_port_file")"
  [[ "$probe_port" =~ ^[1-9][0-9]*$ && "$probe_port" != 443 ]] || {
    echo "failed to create a non-443 residual-listener counterexample" >&2; return 1;
  }
  allocated_ports+=("$probe_port")
  if assert_no_fixture_listeners >/dev/null 2>&1; then
    echo "residual-listener detector accepted a live non-443 listener" >&2; return 1
  fi
  kill "$residual_probe_pid" 2>/dev/null || true
  wait "$residual_probe_pid" 2>/dev/null || true
  residual_probe_pid=""
  assert_no_fixture_listeners
}
cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "$pid_a" "$pid_b" "$https_pid" "$residual_probe_pid"; do
    [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
  done
  for pid in "$pid_a" "$pid_b" "$https_pid" "$residual_probe_pid"; do
    [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  done
  if (( status != 0 )); then
    for log in "$runtime_dir"/*.log; do
      [[ ! -f "$log" ]] || { echo "--- $(basename "$log") ---" >&2; tail -n 180 "$log" >&2 || true; }
    done
  fi
  schema_cleanup=""
  for schema in "$schema_a" "$schema_b"; do
    if ! PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --set ON_ERROR_STOP=1 --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE;" >/dev/null 2>&1; then
      status=1
    fi
    remains="$(PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
      2>/dev/null || printf unknown)"
    remains="${remains//[[:space:]]/}"
    schema_cleanup+="$schema:${remains:-unknown} "
    [[ "$remains" == f ]] || status=1
  done
  listener_count=0
  if ! assert_no_fixture_listeners; then listener_count=1; status=1; fi
  case "$runtime_dir" in
    /tmp/northstar-xep0487.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected XEP-0487 directory: $runtime_dir" >&2; status=1 ;;
  esac
  runtime_remains=0
  if [[ -e "$runtime_dir" ]]; then runtime_remains=1; status=1; fi
  echo "XEP-0487 cleanup: schemas=${schema_cleanup% } listeners=$listener_count runtime_dirs=$runtime_remains"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

exercise_non_443_residual_detection

for schema in "$schema_a" "$schema_b"; do
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$schema\";" >/dev/null
done
mkdir -p "$runtime_dir/certs" "$runtime_dir/uploads-a" "$runtime_dir/uploads-b"
if (( EUID != 0 )); then
  echo "XEP-0487 fixture must be launched as WSL root solely to bind its temporary HTTPS listener to 127.0.0.1:443" >&2
  exit 2
fi
runtime_uid="${XEP0487_RUNTIME_UID:-1000}"
[[ "$runtime_uid" =~ ^[1-9][0-9]*$ ]] || { echo "XEP0487_RUNTIME_UID must be a non-root numeric uid" >&2; exit 2; }
runtime_user="$(getent passwd "$runtime_uid" | cut -d: -f1)"
[[ -n "$runtime_user" ]] || { echo "XEP-0487 non-root runtime uid does not exist: $runtime_uid" >&2; exit 2; }
runtime_gid="$(id -g "$runtime_user")"
runtime_prefix=(setpriv --reuid="$runtime_uid" --regid="$runtime_gid" --init-groups --)

openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj '/CN=Northstar XEP-0487 Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$runtime_dir/certs/ca.key" -out "$runtime_dir/certs/ca.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj '/CN=Northstar XEP-0487 Untrusted Endpoint CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$runtime_dir/certs/endpoint-ca.key" -out "$runtime_dir/certs/endpoint-ca.crt" >/dev/null 2>&1
make_trusted_leaf() {
  local name="$1" san="$2"
  openssl req -new -newkey rsa:3072 -nodes -subj "/CN=$name" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth,clientAuth' \
    -addext "subjectAltName=$san" \
    -keyout "$runtime_dir/certs/$name.key" -out "$runtime_dir/certs/$name.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -in "$runtime_dir/certs/$name.csr" \
    -CA "$runtime_dir/certs/ca.crt" -CAkey "$runtime_dir/certs/ca.key" \
    -CAcreateserial -copy_extensions copy -out "$runtime_dir/certs/$name-leaf.crt" >/dev/null 2>&1
  cp "$runtime_dir/certs/$name-leaf.crt" "$runtime_dir/certs/$name.crt"
  openssl x509 -in "$runtime_dir/certs/ca.crt" -outform PEM >>"$runtime_dir/certs/$name.crt"
}
make_trusted_leaf a 'DNS:localhost'
make_trusted_leaf https 'DNS:remote.localhost,DNS:redirect.remote.localhost'
openssl req -new -newkey rsa:3072 -nodes -subj '/CN=remote.localhost' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth,clientAuth' \
  -addext 'subjectAltName=DNS:remote.localhost' \
  -keyout "$runtime_dir/certs/b.key" -out "$runtime_dir/certs/b.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$runtime_dir/certs/b.csr" \
  -CA "$runtime_dir/certs/endpoint-ca.crt" -CAkey "$runtime_dir/certs/endpoint-ca.key" \
  -CAcreateserial -copy_extensions copy -out "$runtime_dir/certs/b-leaf.crt" >/dev/null 2>&1
cp "$runtime_dir/certs/b-leaf.crt" "$runtime_dir/certs/b.crt"
openssl x509 -in "$runtime_dir/certs/endpoint-ca.crt" -outform PEM >>"$runtime_dir/certs/b.crt"
chmod 0600 "$runtime_dir/certs"/*.key
openssl rand -base64 -out "$runtime_dir/fast-token-a.secret" 48
openssl rand -base64 -out "$runtime_dir/fast-token-b.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-a.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-b.secret" 48
chmod 0600 "$runtime_dir/fast-token-a.secret" "$runtime_dir/fast-token-b.secret" \
  "$runtime_dir/dummy-scram-a.secret" "$runtime_dir/dummy-scram-b.secret"
b_pin="$(openssl x509 -in "$runtime_dir/certs/b-leaf.crt" -pubkey -noout | \
  openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)"
[[ "$b_pin" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "failed to calculate endpoint SPKI pin" >&2; exit 1; }
mode_file="$runtime_dir/mode"
echo valid >"$mode_file"
chown -R "$runtime_uid:$runtime_gid" "$runtime_dir"

if [[ "${NORTHSTAR_XEP0487_SKIP_BUILD:-false}" != true ]]; then
  cargo_args=(--locked)
  [[ "${XMPP_TEST_OFFLINE:-true}" == false ]] || cargo_args+=(--offline)
  cargo build "${cargo_args[@]}"
fi
binary="$CARGO_TARGET_DIR/debug/rust-xmpp-server"
[[ -x "$binary" ]] || { echo "XEP-0487 runtime binary is missing: $binary" >&2; exit 1; }
database_url_a="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_a"
database_url_b="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_b"
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
  MIGRATOR_DATABASE_URL="$database_url_a" "$binary" migrate
env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
  MIGRATOR_DATABASE_URL="$database_url_b" "$binary" migrate

common_env=(
  NORTHSTAR_DISABLE_DOTENV=true
  XMPP_BIND=127.0.0.1:0
  XMPPS_BIND=127.0.0.1:0
  HTTP_BIND=127.0.0.1:0
  S2S_BIND=127.0.0.1:0
  S2S_TLS_BIND=127.0.0.1:0
  METRICS_BIND=127.0.0.1:0
  WEB_ADMIN_BIND=127.0.0.1:0
  OPEN_REGISTRATION=true
  REQUIRE_ENCRYPTED_ARCHIVE=false
  REGISTRATION_RATE_PER_HOUR=20
  API_CONTROL_ALLOW_EPHEMERAL=true
  ABUSE_STATE_ALLOW_EPHEMERAL=true
  FEDERATION_ENABLED=true
  S2S_SASL_EXTERNAL_ENABLED=true
  DIALBACK_ENABLED=true
  FEDERATION_EXTRA_ROOT_CERT_PATH="$runtime_dir/certs/ca.crt"
  LOG_FORMAT=json
  RUST_LOG=rust_xmpp_server=debug
)

start_a() {
  local scenario="$1" allow_private="$2" readiness_file readiness_nonce readiness
  log_a="$runtime_dir/a-$scenario.log"
  readiness_file="$runtime_dir/a-$scenario.ready.json"
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  env "${common_env[@]}" XMPP_DOMAIN=localhost FEDERATION_ALLOW_PRIVATE_IPS="$allow_private" \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-a.secret" \
    DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-a.secret" \
    DATABASE_URL="$database_url_a" \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1" UPLOAD_DIR="$runtime_dir/uploads-a" \
    TLS_CERT_PATH="$runtime_dir/certs/a.crt" TLS_KEY_PATH="$runtime_dir/certs/a.key" \
    FEDERATION_DNS_OVERRIDES= \
    "${runtime_prefix[@]}" "$binary" >"$log_a" 2>&1 &
  pid_a=$!
  wait_for_readiness "$readiness_file" "$readiness_nonce" "$pid_a" || {
    cat "$log_a" >&2
    return 1
  }
  readiness="$readiness_output"
  printf '%s\n' "$readiness" >"$runtime_dir/a-$scenario.readiness"
  http_a="$(readiness_port "$readiness" http)"
  s2s_tls_a="$(readiness_port "$readiness" s2s-tls)"
  curl --silent --fail "http://127.0.0.1:$http_a/readyz" >/dev/null
  [[ "$(ps -o euid= -p "$pid_a" | tr -d '[:space:]')" == "$runtime_uid" ]] || {
    echo "Northstar A did not run as the non-root fixture uid" >&2; exit 1;
  }
}
stop_a() {
  [[ -z "$pid_a" ]] || kill "$pid_a" 2>/dev/null || true
  [[ -z "$pid_a" ]] || wait "$pid_a" 2>/dev/null || true
  pid_a=""
  for _ in $(seq 1 50); do port_is_listening "$http_a" || break; sleep .1; done
}
clear_outbox() {
  PGPASSWORD=xmpp-test-password PGOPTIONS="-c search_path=$schema_a" \
    psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 --command 'DELETE FROM s2s_outbox;' >/dev/null
}
outbox_marker_count() {
  local marker="$1"
  PGPASSWORD=xmpp-test-password PGOPTIONS="-c search_path=$schema_a" \
    psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test --tuples-only --no-align \
    --set ON_ERROR_STOP=1 --command "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE '%$marker%';" | tr -d '[:space:]'
}
client_probe() {
  env XEP0487_HTTP_A="$http_a" XEP0487_HTTP_B="$http_b" XEP0487_MODE_FILE="$mode_file" \
    XMPP_TEST_HOST=127.0.0.1 "${runtime_prefix[@]}" python3 scripts/xep0487-runtime-wsl.py "$@"
}

start_b() {
  local readiness_file readiness_nonce readiness
  readiness_file="$runtime_dir/b.ready.json"
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  env "${common_env[@]}" XMPP_DOMAIN=remote.localhost \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-b.secret" \
    DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-b.secret" \
    FEDERATION_ALLOW_PRIVATE_IPS=true \
    DATABASE_URL="$database_url_b" \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1" UPLOAD_DIR="$runtime_dir/uploads-b" \
    TLS_CERT_PATH="$runtime_dir/certs/b.crt" TLS_KEY_PATH="$runtime_dir/certs/b.key" \
    FEDERATION_DNS_OVERRIDES= \
    "${runtime_prefix[@]}" "$binary" >>"$runtime_dir/b.log" 2>&1 &
  pid_b=$!
  wait_for_readiness "$readiness_file" "$readiness_nonce" "$pid_b" || {
    cat "$runtime_dir/b.log" >&2
    return 1
  }
  readiness="$readiness_output"
  printf '%s\n' "$readiness" >"$runtime_dir/b.readiness"
  http_b="$(readiness_port "$readiness" http)"
  s2s_tls_b="$(readiness_port "$readiness" s2s-tls)"
  # Discovery is served by the independently restarted HTTPS fixture.  Keep
  # the port source current for every B lifecycle, not just the one restart
  # exercised below.
  if [[ -n "$s2s_port_file" ]]; then
    printf '%s\n' "$s2s_tls_b" >"$s2s_port_file"
  fi
  curl --silent --fail "http://127.0.0.1:$http_b/readyz" >/dev/null
  [[ "$(ps -o euid= -p "$pid_b" | tr -d '[:space:]')" == "$runtime_uid" ]] || {
    echo "Northstar B did not run as the non-root fixture uid" >&2; exit 1;
  }
}
stop_b() {
  [[ -z "$pid_b" ]] || kill "$pid_b" 2>/dev/null || true
  [[ -z "$pid_b" ]] || wait "$pid_b" 2>/dev/null || true
  pid_b=""
  for _ in $(seq 1 50); do
    if ! port_is_listening "$http_b" && ! port_is_listening "$s2s_tls_b"; then break; fi
    sleep .1
  done
  ! port_is_listening "$http_b" || { echo "Northstar B HTTP listener did not stop" >&2; exit 1; }
  ! port_is_listening "$s2s_tls_b" || { echo "Northstar B S2S listener did not stop" >&2; exit 1; }
}

start_b

s2s_port_file="$runtime_dir/s2s-tls-b.port"
printf '%s\n' "$s2s_tls_b" >"$s2s_port_file"
takeover_ack="$runtime_dir/https.takeover.json"
takeover_nonce="$(openssl rand -hex 16)"
XEP0487_HTTPS_PORT=443 XEP0487_S2S_PORT_FILE="$s2s_port_file" \
XEP0487_HTTPS_CERT="$runtime_dir/certs/https.crt" XEP0487_HTTPS_KEY="$runtime_dir/certs/https.key" \
XEP0487_MODE_FILE="$mode_file" XEP0487_PUBLIC_KEY_PIN="$b_pin" \
XEP0487_RUNTIME_UID="$runtime_uid" XEP0487_RUNTIME_GID="$runtime_gid" \
XEP0487_TAKEOVER_ACK="$takeover_ack" XEP0487_TAKEOVER_NONCE="$takeover_nonce" \
python3 scripts/xep0487-socket-activation.py >"$runtime_dir/https.log" 2>&1 &
https_pid=$!
for _ in $(seq 1 100); do
  if curl --silent --fail --noproxy '*' --cacert "$runtime_dir/certs/ca.crt" \
    --resolve remote.localhost:443:127.0.0.1 \
    https://remote.localhost/.well-known/host-meta.json >/dev/null; then break; fi
  kill -0 "$https_pid" 2>/dev/null || { cat "$runtime_dir/https.log" >&2; exit 1; }
  sleep .1
done
curl --silent --fail --noproxy '*' --cacert "$runtime_dir/certs/ca.crt" \
  --resolve remote.localhost:443:127.0.0.1 \
  https://remote.localhost/.well-known/host-meta.json >/dev/null

echo valid >"$mode_file"
start_a valid true
client_probe bootstrap
grep -q "takeover-ack pid=.* uid=$runtime_uid listener=127.0.0.1:443" "$runtime_dir/https.log"
grep -q "host=remote.localhost mode=valid uid=$runtime_uid" "$runtime_dir/https.log"
grep -q 'authenticated outbound S2S certificate identity' "$log_a"
grep -q 'authenticated inbound S2S certificate identity' "$runtime_dir/b.log"
stop_a
clear_outbox

run_rejection() {
  local scenario="$1" mode="$2" allow_private="$3" timeout="$4"
  echo "$mode" >"$mode_file"
  start_a "$scenario" "$allow_private"
  client_probe reject "$scenario" "$timeout"
  [[ "$(outbox_marker_count "$scenario")" == 1 ]] || {
    echo "XEP-0487 rejection did not retain exactly one durable outbox row: $scenario" >&2; exit 1;
  }
  if grep -q 'authenticated outbound S2S certificate identity' "$log_a"; then
    echo "XEP-0487 rejection unexpectedly authenticated an endpoint: $scenario" >&2; exit 1
  fi
  stop_a
  clear_outbox
}

run_rejection wrong-pin wrong-pin true 5
grep -q 'host=remote.localhost mode=wrong-pin' "$runtime_dir/https.log"
run_rejection missing-pin missing-pin true 5
grep -q 'host=remote.localhost mode=missing-pin' "$runtime_dir/https.log"

echo redirect >"$mode_file"
start_a redirect true
client_probe deliver redirect 30
grep -q 'host=remote.localhost mode=redirect' "$runtime_dir/https.log"
grep -q 'host=redirect.remote.localhost mode=redirect' "$runtime_dir/https.log"
grep -q 'authenticated outbound S2S certificate identity' "$log_a"
stop_a
clear_outbox

run_rejection downgrade downgrade true 5
grep -q 'XEP-0487 redirects must retain HTTPS' "$runtime_dir/a-downgrade.log"
run_rejection private-ip valid false 5
grep -q 'XEP-0487 HTTPS host has no policy-compliant address' "$runtime_dir/a-private-ip.log"
run_rejection oversize oversize true 5
grep -q 'XEP-0487 HTTPS response exceeds its size limit' "$runtime_dir/a-oversize.log"
run_rejection timeout timeout true 15
grep -q 'XEP-0487 HTTPS response read timed out' "$runtime_dir/a-timeout.log"

echo stale-valid >"$mode_file"
# Restart B before seeding the short-lived cache. This exercises B's dynamic
# listener ownership while ensuring that the cached endpoint is the new one
# which remains usable during the later discovery timeout.
stop_b
start_b
start_a stale-cache true
client_probe deliver stale-seed 30
sleep 1.3
# Assert timeout discovery from the calling server's structured result, not
# the independently supervised HTTPS handler's buffered access log.  The
# latter may not have flushed while the assertion is evaluated.
timeout_hits_before="$(grep -c 'XEP-0487 HTTPS response read timed out' "$log_a" || true)"
echo timeout >"$mode_file"
client_probe deliver stale-recovery 30
timeout_hits_after="$(grep -c 'XEP-0487 HTTPS response read timed out' "$log_a" || true)"
(( timeout_hits_after > timeout_hits_before )) || {
  echo "stale-cache probe did not observe a fresh XEP-0487 discovery timeout" >&2; exit 1;
}
grep -q 'host=remote.localhost mode=stale-valid' "$runtime_dir/https.log"
grep -q 'XEP-0487 discovery unavailable; trying cached and DNS connection methods' "$log_a"
grep -q 'authenticated outbound S2S certificate identity' "$log_a"
stop_a
clear_outbox

echo "XEP-0487 evidence: WebPKI HTTPS, required SPKI pin, wrong/missing pin rejection, HTTPS-only redirect, downgrade/private-IP/oversize/timeout rejection, stale-cache recovery, TLS identity and bidirectional delivery PASS"
