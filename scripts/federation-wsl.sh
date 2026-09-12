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
source "$project_dir/scripts/lib/test-listener-readiness.sh"
source "$project_dir/scripts/lib/runtime-test-profile.sh"
source "$project_dir/scripts/lib/test-fixture-certificates.sh"
fixture_select_runtime_profile "${NORTHSTAR_RUNTIME_TEST_PROFILE:-dev}"

stress_database_a="${NORTHSTAR_LISTENER_STRESS_DATABASE_A:-}"
stress_database_b="${NORTHSTAR_LISTENER_STRESS_DATABASE_B:-}"
stress_database_host="${NORTHSTAR_LISTENER_STRESS_DATABASE_HOST:-127.0.0.1}"
stress_database_port="${NORTHSTAR_LISTENER_STRESS_DATABASE_PORT:-5432}"
if [[ -n "$stress_database_a" || -n "$stress_database_b" ]]; then
  [[ -n "$stress_database_a" && -n "$stress_database_b" ]] || {
    echo "listener stress preprovisioning requires both database names" >&2
    exit 2
  }
  [[ "$stress_database_a" =~ ^northstar_listener_[a-z0-9_]{1,42}$ \
     && "$stress_database_b" =~ ^northstar_listener_[a-z0-9_]{1,42}$ \
     && "$stress_database_a" != "$stress_database_b" ]] || {
    echo "listener stress preprovisioned database names are invalid" >&2
    exit 2
  }
  [[ "$stress_database_host" == 127.0.0.1 ]] || {
    echo "listener stress preprovisioned database host must be 127.0.0.1" >&2
    exit 2
  }
  [[ "$stress_database_port" =~ ^[1-9][0-9]{0,4}$ ]] \
    && ((10#$stress_database_port <= 65535)) || {
    echo "listener stress preprovisioned database port must be an integer from 1 through 65535" >&2
    exit 2
  }
  fixture_preprovisioned=true
  schema_a=public
  schema_b=public
  database_name_a="$stress_database_a"
  database_name_b="$stress_database_b"
else
  fixture_preprovisioned=false
  run_id="$(openssl rand -hex 8)"
  schema_a="federation_a_it_${run_id}"
  schema_b="federation_b_it_${run_id}"
  database_name_a=xmpp_test
  database_name_b=xmpp_test
fi
database_host=127.0.0.1
database_port=5432
if [[ "$fixture_preprovisioned" == true ]]; then
  database_host="$stress_database_host"
  database_port="$stress_database_port"
fi
runtime_dir="$(mktemp -d /tmp/northstar-federation.XXXXXX)"
cert_dir="$runtime_dir/certs"
upload_a="$runtime_dir/uploads-a"
upload_b="$runtime_dir/uploads-b"
log_a="$runtime_dir/federation-a.log"
log_b="$runtime_dir/federation-b.log"
pid_a=""
pid_b=""
relay_a_s2s_pid=""
relay_b_s2s_tls_pid=""
relay_a_s2s_port=""
relay_b_s2s_tls_port=""
relay_a_http_pid=""
relay_b_http_pid=""
relay_a_http_port=""
relay_b_http_port=""
target_a_s2s="$runtime_dir/a.s2s.target"
target_b_s2s_tls="$runtime_dir/b.s2s-tls.target"
target_a_http="$runtime_dir/a.http.target"
target_b_http="$runtime_dir/b.http.target"
http_a_backend=""
http_b_backend=""
http_a=""
http_b=""
xmpp_a=""
xmpp_b=""
xmpps_a=""
xmpps_b=""
s2s_a=""
s2s_b=""
s2s_tls_a=""
s2s_tls_b=""
declare -a fixture_listener_ports=()
fixture_print_log_excerpt() {
  # Server processes are already reaped. Redact complete bounded records before
  # truncating output; the outer CI wrapper redacts the transcript again.
  python3 - "$project_dir" "$1" "${2:-warnings}" <<'PY_WARNING_EXCERPT'
from collections import deque
import json
import os
from pathlib import Path
import stat
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
from github_ci_summary import redact_diagnostic_log
mode = sys.argv[3] if len(sys.argv) > 3 else "warnings"
if mode not in ("head", "tail", "warnings"):
    raise ValueError("unsupported log excerpt mode")
scan_limit = 8 * 1024 * 1024
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
with os.fdopen(os.open(sys.argv[2], flags), "rb") as source:
    metadata = os.fstat(source.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("excerpt requires a regular log file")
    if mode == "tail" and metadata.st_size > scan_limit:
        # Seeking into a PEM block loses its BEGIN marker. Fail closed rather
        # than echo a suffix whose preceding redaction context is unknown.
        print("tail_excerpt omitted=redaction_context_exceeds_scan_limit scan_truncated=true max_rows=120 max_payload_bytes=131072")
        sys.exit(0)
    data = source.read(min(metadata.st_size, scan_limit))
truncated = metadata.st_size > len(data)
if truncated and not data.endswith(b"\n"):
    data = data.rsplit(b"\n", 1)[0] if b"\n" in data else b""
if mode in ("head", "tail"):
    max_rows, byte_limit = (60, 65536) if mode == "head" else (120, 131072)
    # Redact the complete bounded context before selecting physical rows.
    # Per-line redaction would erase BEGIN while exposing later PEM contents.
    redacted = redact_diagnostic_log(data.decode("utf-8", errors="replace"))
    raw_lines = redacted.splitlines()
    raw_lines = raw_lines[:max_rows] if mode == "head" else raw_lines[-max_rows:]
    lines, oversized = [], 0
    for line in raw_lines:
        encoded = line.encode("utf-8")
        if len(encoded) > 8192:
            oversized += 1
            continue
        lines.append(encoded)
    print(f"{mode}_excerpt scanned_bytes={len(data)} scan_truncated={str(truncated).lower()} oversized_lines_omitted={oversized} max_rows={max_rows} max_payload_bytes={byte_limit}", flush=True)
else:
    first, latest, matched, oversized = [], deque(maxlen=32), 0, 0
    for number, raw in enumerate(data.splitlines()):
        if len(raw) > 8192:
            oversized += 1
            continue
        try:
            line = raw.decode("utf-8")
            record = json.loads(line)
        except (UnicodeError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("level") not in ("WARN", "ERROR"):
            continue
        matched += 1
        item = (number, redact_diagnostic_log(line).encode("utf-8"))
        if len(first) < 32:
            first.append(item)
        latest.append(item)
    lines = [line for _, line in sorted(dict(first + list(latest)).items())]
    byte_limit = 65536
    print(f"warning_excerpt scanned_bytes={len(data)} scan_truncated={str(truncated).lower()} matched={matched} oversized_lines_omitted={oversized} max_rows=64 max_payload_bytes={byte_limit}", flush=True)
remaining = byte_limit
for line in lines:
    if remaining <= 1:
        break
    line = line[:min(2048, remaining - 1)].decode("utf-8", errors="ignore").encode("utf-8")
    sys.stdout.buffer.write(line + b"\n")
    remaining -= len(line) + 1
PY_WARNING_EXCERPT
}

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  for pid in "$pid_a" "$pid_b" "$relay_a_s2s_pid" "$relay_b_s2s_tls_pid" "$relay_a_http_pid" "$relay_b_http_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$pid_a" "$pid_b" "$relay_a_s2s_pid" "$relay_b_s2s_tls_pid" "$relay_a_http_pid" "$relay_b_http_pid"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  if (( exit_code != 0 )); then
    for log in "$log_a" "$log_b" "$runtime_dir/relay-a-s2s.log" "$runtime_dir/relay-b-s2s-tls.log" "$runtime_dir/relay-a-http.log" "$runtime_dir/relay-b-http.log"; do
      if [[ -f "$log" ]]; then
        # Preserve startup evidence before frequent worker debug messages can
        # push a missing-readiness failure out of the bounded ending excerpt.
        echo "--- $(basename "$log") (first 60 lines, at most 65536 bytes) ---" >&2
        fixture_print_log_excerpt "$log" head >&2 || true
        echo "--- $(basename "$log") (last 120 lines, at most 131072 bytes) ---" >&2
        fixture_print_log_excerpt "$log" tail >&2 || true
        if [[ "$log" == "$log_a" || "$log" == "$log_b" ]]; then
          echo "--- $(basename "$log") (bounded WARN/ERROR excerpt) ---" >&2
          fixture_print_log_excerpt "$log" warnings >&2 || true
        fi
      fi
    done
  fi
  schema_cleanup=""
  if [[ "$fixture_preprovisioned" == true ]]; then
    # The stress driver owns these disposable databases.  A fixture must not
    # drop `public`, because the parent validates and removes the whole
    # database only after every server and relay in this private worker exits.
    schema_cleanup="preprovisioned:${database_name_a},${database_name_b}"
  else
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
  fi
  listener_count=0
  if ! fixture_assert_no_listeners; then
    listener_count=1
    exit_code=1
  fi
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

if [[ "$fixture_preprovisioned" != true ]]; then
  for schema in "$schema_a" "$schema_b"; do
    if [[ ! "$schema" =~ ^[a-z][a-z0-9_]{0,62}$ ]]; then
      echo "Refusing unsafe test schema name: $schema" >&2
      exit 2
    fi
    PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --set ON_ERROR_STOP=1 \
      --command "CREATE SCHEMA \"$schema\";" >/dev/null
  done
fi

mkdir -p "$cert_dir" "$upload_a" "$upload_b" "$runtime_dir/logs-a" "$runtime_dir/logs-b"
fixture_certificates_restore federation "$cert_dir"
if [[ "$fixture_certificates_reused" == false ]]; then
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
  chmod 600 "$cert_dir"/*
fi
fixture_certificates_save federation "$cert_dir"
openssl rand -base64 -out "$runtime_dir/fast-token-a.secret" 48
openssl rand -base64 -out "$runtime_dir/fast-token-b.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-a.secret" 48
openssl rand -base64 -out "$runtime_dir/dummy-scram-b.secret" 48
chmod 600 "$runtime_dir/fast-token-a.secret" "$runtime_dir/fast-token-b.secret" \
  "$runtime_dir/dummy-scram-a.secret" "$runtime_dir/dummy-scram-b.secret"

# The relays are child-owned ephemeral listeners with the standard readiness
# record.  They make peer addresses available to the two server startup
# configurations without reserving, releasing, and re-binding a numeric port.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" a relay-a-s2s "$target_a_s2s" \
  "$runtime_dir/relay-a-s2s.log" relay_a_s2s_pid relay_a_s2s_port
fixture_start_tcp_relay "$project_dir" "$runtime_dir" b relay-b-s2s-tls "$target_b_s2s_tls" \
  "$runtime_dir/relay-b-s2s-tls.log" relay_b_s2s_tls_pid relay_b_s2s_tls_port
# PUBLIC_URL is observable protocol output (not only a local bind option).
# Keep a fixture-owned HTTP authority stable while both server children choose
# their own backend ports, exactly as the S2S relay above stabilizes startup
# DNS overrides.
fixture_start_tcp_relay "$project_dir" "$runtime_dir" a-http relay-a-http "$target_a_http" \
  "$runtime_dir/relay-a-http.log" relay_a_http_pid relay_a_http_port
fixture_start_tcp_relay "$project_dir" "$runtime_dir" b-http relay-b-http "$target_b_http" \
  "$runtime_dir/relay-b-http.log" relay_b_http_pid relay_b_http_port

cargo_args=(--locked --profile "$fixture_cargo_profile")
if [[ "${XMPP_TEST_OFFLINE:-true}" != "false" ]]; then
  cargo_args+=(--offline)
fi
if [[ "${NORTHSTAR_FEDERATION_SKIP_BUILD:-false}" != true ]]; then
  cargo build "${cargo_args[@]}"
fi
binary="$target_dir/$fixture_cargo_profile_directory/rust-xmpp-server"
[[ -x "$binary" ]] || { echo "federation runtime binary is missing: $binary" >&2; exit 1; }
database_url_a="postgres://xmpp_test:xmpp-test-password@$database_host:$database_port/$database_name_a?options=-csearch_path%3D$schema_a"
database_url_b="postgres://xmpp_test:xmpp-test-password@$database_host:$database_port/$database_name_b?options=-csearch_path%3D$schema_b"

# Direct fixture runs migrate two isolated schemas before opening listeners.
# Listener stress workers receive two parent-owned, domain-specific migrated
# database copies instead; runtime startup still verifies the same ledger and
# canonicalizer state before it binds any listener.
if [[ "$fixture_preprovisioned" != true ]]; then
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
    MIGRATOR_DATABASE_URL="$database_url_a" "$binary" migrate
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
    MIGRATOR_DATABASE_URL="$database_url_b" "$binary" migrate
fi

start_a() {
  local readiness_file="$runtime_dir/a.ready.json" readiness_nonce startup_deadline
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$target_a_s2s" "$target_a_http"
  startup_deadline="$(fixture_startup_deadline "$project_dir")"
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=localhost \
    DATABASE_URL="$database_url_a" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_a_http_port" UPLOAD_DIR="$upload_a" LOG_DIR="$runtime_dir/logs-a" \
    TLS_CERT_PATH="$cert_dir/federation-a.crt" TLS_KEY_PATH="$cert_dir/federation-a.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
    API_CONTROL_ALLOW_EPHEMERAL=true ABUSE_STATE_ALLOW_EPHEMERAL=true \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-a.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-a.secret" \
    FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true \
    DIALBACK_SECRET_FILE= DIALBACK_SECRET= \
    FEDERATION_DNS_OVERRIDES="remote.localhost=xmpps://127.0.0.1:$relay_b_s2s_tls_port,pubsub.remote.localhost=xmpps://127.0.0.1:$relay_b_s2s_tls_port" \
    FEDERATION_EXTRA_ROOT_CERT_PATH="$cert_dir/federation-ca.crt" LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info,rust_xmpp_server::s2s::inbound=debug \
    "$binary" >"$log_a" 2>&1 &
  pid_a=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_a" "$startup_deadline" || return 1
  http_a_backend="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  xmpp_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
  xmpps_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
  s2s_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s)"
  s2s_tls_a="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s-tls)"
  fixture_publish_relay_target "$target_a_s2s" "$s2s_a"
  fixture_publish_relay_target "$target_a_http" "$http_a_backend"
  http_a="$relay_a_http_port"
  fixture_wait_for_http_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_a" "$startup_deadline" \
    "http://127.0.0.1:$http_a_backend/readyz" "http://127.0.0.1:$http_a/readyz" || return 1
  fixture_assert_public_url "$http_a" "http://127.0.0.1:$relay_a_http_port"
}

start_b() {
  local readiness_file="$runtime_dir/b.ready.json" readiness_nonce startup_deadline
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file" "$target_b_s2s_tls" "$target_b_http"
  startup_deadline="$(fixture_startup_deadline "$project_dir")"
  env NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=remote.localhost \
    DATABASE_URL="$database_url_b" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 WEB_ADMIN_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness_file" TEST_READINESS_NONCE="$readiness_nonce" \
    PUBLIC_URL="http://127.0.0.1:$relay_b_http_port" UPLOAD_DIR="$upload_b" LOG_DIR="$runtime_dir/logs-b" \
    TLS_CERT_PATH="$cert_dir/federation-b.crt" TLS_KEY_PATH="$cert_dir/federation-b.key" \
    OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
    API_CONTROL_ALLOW_EPHEMERAL=true ABUSE_STATE_ALLOW_EPHEMERAL=true \
    FAST_TOKEN_SECRET_FILE="$runtime_dir/fast-token-b.secret" DUMMY_SCRAM_SECRET_FILE="$runtime_dir/dummy-scram-b.secret" \
    FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true S2S_SASL_EXTERNAL_ENABLED="${S2S_SASL_EXTERNAL_ENABLED:-true}" DIALBACK_ENABLED=true \
    DIALBACK_SECRET_FILE= DIALBACK_SECRET= \
    FEDERATION_DNS_OVERRIDES="localhost=127.0.0.1:$relay_a_s2s_port,conference.localhost=127.0.0.1:$relay_a_s2s_port,pubsub.localhost=127.0.0.1:$relay_a_s2s_port" \
    FEDERATION_EXTRA_ROOT_CERT_PATH="$cert_dir/federation-ca.crt" LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info,rust_xmpp_server::s2s::inbound=debug \
    "$binary" >"$log_b" 2>&1 &
  pid_b=$!
  fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_b" "$startup_deadline" || return 1
  http_b_backend="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)"
  xmpp_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpp)"
  xmpps_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" xmpps)"
  s2s_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s)"
  s2s_tls_b="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" s2s-tls)"
  fixture_publish_relay_target "$target_b_s2s_tls" "$s2s_tls_b"
  fixture_publish_relay_target "$target_b_http" "$http_b_backend"
  http_b="$relay_b_http_port"
  fixture_wait_for_http_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$pid_b" "$startup_deadline" \
    "http://127.0.0.1:$http_b_backend/readyz" "http://127.0.0.1:$http_b/readyz" || return 1
  fixture_assert_public_url "$http_b" "http://127.0.0.1:$relay_b_http_port"
}

# Confirm each independently migrated runtime after its own authenticated
# readiness handoff.  No polling loop treats an assumed numeric port as
# listener ownership.
fixture_stress_phase_barrier "$project_dir" prepared
start_a
start_b

# Keep transport probes and credential setup outside every other pair's
# cold-start window; all pairs still execute their full protocol matrix.
fixture_stress_phase_barrier "$project_dir" live "$pid_a" "$pid_b"

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
FEDERATION_TEST_DATABASE_A="$database_name_a" \
FEDERATION_TEST_DATABASE_B="$database_name_b" \
python3 scripts/federation-wsl.py
