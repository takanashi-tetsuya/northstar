#!/usr/bin/env bash
# N08-R08 only: provision two current, domain-specific template databases in
# the parent-owned loopback PostgreSQL cluster, clone each once, then prove
# strict runtime startup and a concrete no-DDL boundary in each clone.  This
# intentionally does not use the listener stress driver: that driver exercises
# a separate development-role contract and is not evidence for strict roles.

set -Eeuo pipefail
set +x
umask 077

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

fail() {
  printf 'N08-R08 DB05 failed: %s\n' "$1" >&2
  exit 1
}

for variable in \
  NORTHSTAR_PRIVATE_PG_HOST \
  NORTHSTAR_PRIVATE_PG_PORT \
  NORTHSTAR_PRIVATE_PG_DATABASE \
  NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE \
  NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE; do
  [[ -n "${!variable:-}" ]] || fail "private fixture did not supply $variable"
done
[[ "$NORTHSTAR_PRIVATE_PG_HOST" == '127.0.0.1' ]] \
  || fail 'private fixture host is not IPv4 loopback'
[[ "$NORTHSTAR_PRIVATE_PG_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
  && ((10#$NORTHSTAR_PRIVATE_PG_PORT <= 65535)) \
  || fail 'private fixture port is invalid'
[[ "$NORTHSTAR_PRIVATE_PG_DATABASE" == 'xmpp' ]] \
  || fail 'private fixture database identity is invalid'
for secret_file in \
  "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE" \
  "$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE"; do
  [[ -f "$secret_file" && ! -L "$secret_file" && -r "$secret_file" ]] \
    || fail 'private fixture supplied an unsafe secret file'
done
for command in curl install mktemp openssl psql python3 rm sed sha256sum sleep tail; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
readonly binary="$target_dir/debug/rust-xmpp-server"
[[ -x "$binary" ]] || fail "current candidate binary is missing: $binary"
binary_version="$($binary --version)" || fail 'candidate binary did not report its version'
[[ "$binary_version" == 'xmpp-server '* ]] || fail 'candidate binary reported an unexpected version format'

evidence_dir="${NORTHSTAR_N08_EVIDENCE_DIR:-$project_dir/logs/northstar-n08-2026-09-08}"
mkdir -p -- "$evidence_dir" || fail 'could not create N08 evidence directory'
chmod 0700 -- "$evidence_dir" || fail 'could not protect N08 evidence directory'
attempt_id="${NORTHSTAR_N08_RUN_ID:-$(date -u +%Y%m%dT%H%M%S-%N)}"
[[ "$attempt_id" =~ ^[A-Za-z0-9._-]{8,96}$ ]] || fail 'N08 evidence attempt identity is invalid'
readonly evidence_log="$evidence_dir/r08-db05-template-clone-$attempt_id.log"
readonly evidence_summary="$evidence_dir/r08-db05-template-clone-$attempt_id.summary"

runtime_root="$(mktemp -d /tmp/northstar-n08-r08.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-n08-r08\.[A-Za-z0-9]{6}$ ]] \
  || fail "refusing unsafe R08 runtime directory: $runtime_root"
readonly runtime_root
readonly urls_dir="$runtime_root/urls"
readonly cert_dir="$runtime_root/certs"
readonly uploads_dir="$runtime_root/uploads"
declare -a owned_databases=()
declare -a server_pids=()
declare -a fixture_listener_ports=()

source "$project_dir/scripts/lib/test-listener-readiness.sh"

redact() {
  sed -E 's#(postgres(ql)?://[^:[:space:]]+:)[^@[:space:]]+@#\1[REDACTED]@#g' \
    | sed -E 's#(password=)[^[:space:]]+#\1[REDACTED]#gi'
}

append_redacted_diagnostic() {
  local source="$1"
  [[ -f "$source" ]] || return 0
  redact <"$source" >>"$evidence_log"
}

run_as() {
  local url_file="$1"
  shift
  python3 "$project_dir/scripts/run-postgres.py" \
    --database-url-file "$url_file" -- \
    psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 "$@"
}

run_bootstrap_psql() {
  run_as "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE" "$@"
}

safe_database_name() {
  [[ "$1" =~ ^northstar_n08_r08_[a-f0-9]{16}_(template|clone)_[ab]$ ]]
}

database_exists() {
  local database_name="$1" value
  safe_database_name "$database_name" || return 1
  value="$(run_bootstrap_psql --tuples-only --no-align --command \
    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='$database_name')")" || return 1
  [[ "$value" == t || "$value" == true ]]
}

wait_template_quiescent() {
  local database_name="$1" active
  safe_database_name "$database_name" || return 1
  active="$(run_bootstrap_psql --tuples-only --no-align --command \
    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname='$database_name' AND pid<>pg_backend_pid()")" || return 1
  [[ "$active" == 0 ]]
}

stop_owned_servers() {
  local pid deadline status=0
  for pid in "${server_pids[@]}"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { status=1; continue; }
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || status=1
      deadline=$((SECONDS + 15))
      while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        echo "N08-R08 owned runtime PID $pid did not terminate within 15 seconds" >&2
        status=1
      fi
    fi
    wait "$pid" 2>/dev/null || true
  done
  server_pids=()
  fixture_assert_no_listeners || status=1
  return "$status"
}

drop_owned_databases() {
  local database_name status=0
  for database_name in "${owned_databases[@]}"; do
    safe_database_name "$database_name" || { status=1; continue; }
    if database_exists "$database_name"; then
      # The database names contain an invocation nonce and no fixture child
      # remains connected.  Do not use FORCE: an unexpected connection is a
      # failed cleanup condition, not authority to disconnect another actor.
      if ! run_bootstrap_psql --command "DROP DATABASE \"$database_name\"" >/dev/null; then
        printf 'N08-R08 retained owned database after cleanup failure: %s\n' "$database_name" >&2
        status=1
      fi
    fi
  done
  return "$status"
}

cleanup() {
  local original_status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  stop_owned_servers || cleanup_status=1
  drop_owned_databases || cleanup_status=1
  case "$runtime_root" in
    /tmp/northstar-n08-r08.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
      rm -rf -- "$runtime_root" || cleanup_status=1
      ;;
    *)
      echo "refusing cleanup of unexpected R08 directory: $runtime_root" >&2
      cleanup_status=1
      ;;
  esac
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0700 "$urls_dir" "$cert_dir" "$uploads_dir"
run_nonce="$(openssl rand -hex 8)"
[[ "$run_nonce" =~ ^[0-9a-f]{16}$ ]] || fail 'could not create template/clone nonce'
template_a="northstar_n08_r08_${run_nonce}_template_a"
template_b="northstar_n08_r08_${run_nonce}_template_b"
clone_a="northstar_n08_r08_${run_nonce}_clone_a"
clone_b="northstar_n08_r08_${run_nonce}_clone_b"
for database_name in "$template_a" "$template_b" "$clone_a" "$clone_b"; do
  safe_database_name "$database_name" || fail 'generated database name is unsafe'
  database_exists "$database_name" && fail "refusing to reuse existing database $database_name"
done
owned_databases=("$clone_a" "$clone_b" "$template_a" "$template_b")

url_for_database() {
  local base_url_file="$1" database_name="$2" output_file="$3" base_url
  safe_database_name "$database_name" || return 1
  base_url="$(<"$base_url_file")"
  [[ "$base_url" == postgres://*@127.0.0.1:*'/xmpp' ]] || return 1
  install -m 0600 /dev/null "$output_file"
  printf '%s/%s\n' "${base_url%/xmpp}" "$database_name" >"$output_file"
}

template_url_file() {
  local role="$1" database_name="$2"
  printf '%s/%s-%s.url' "$urls_dir" "$role" "$database_name"
}

create_database() {
  local database_name="$1" bootstrap_url
  safe_database_name "$database_name" || return 1
  run_bootstrap_psql --command \
    "CREATE DATABASE \"$database_name\" OWNER northstar_migrator TEMPLATE template0" >/dev/null
  # PostgreSQL 15+ creates the default public schema with the special
  # `pg_database_owner` owner even when CREATE DATABASE specifies a concrete
  # owner.  Northstar's strict migrator contract intentionally requires the
  # durable schema owner itself to be northstar_migrator, exactly as the fresh
  # volume initializer does for `xmpp`.
  bootstrap_url="$(template_url_file bootstrap "$database_name")"
  url_for_database "$NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE" \
    "$database_name" "$bootstrap_url" || return 1
  run_as "$bootstrap_url" --command \
    'ALTER SCHEMA public OWNER TO northstar_migrator' >/dev/null
}

clone_database() {
  local source_database="$1" clone_database_name="$2"
  safe_database_name "$source_database" && safe_database_name "$clone_database_name" || return 1
  wait_template_quiescent "$source_database" || {
    echo "template has active connections and will not be cloned: $source_database" >&2
    return 1
  }
  run_bootstrap_psql --command \
    "CREATE DATABASE \"$clone_database_name\" TEMPLATE \"$source_database\"" >/dev/null
  # CREATE DATABASE ... TEMPLATE copies the template contents but assigns the
  # new database to the issuing bootstrap role unless an owner is explicitly
  # restored.  The cloned public schema retains the template's migrator owner;
  # make the database owner match before a runtime ever sees the clone.
  run_bootstrap_psql --command \
    "ALTER DATABASE \"$clone_database_name\" OWNER TO northstar_migrator" >/dev/null
}

reconcile_exact_grants() {
  local url_file="$1" database_name="$2"
  safe_database_name "$database_name" || return 1
  run_as "$url_file" \
    --set=database_name="$database_name" \
    --set=migrator_role=northstar_migrator \
    --set=runtime_role=northstar_runtime \
    --set=command_role=northstar_commands \
    --set=backup_role=northstar_backup \
    --set=allow_bootstrap=false \
    --set=grant_phase=exact \
    --file "$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
}

identity_record() {
  local url_file="$1"
  run_as "$url_file" --tuples-only --no-align --command \
    "SELECT current_database() || '|' || current_user || '|' || pg_catalog.pg_get_userbyid((SELECT datdba FROM pg_catalog.pg_database WHERE datname=current_database())) || '|' || pg_catalog.pg_get_userbyid((SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='public'))"
}

runtime_forbidden_ddl() {
  local runtime_url="$1" database_name="$2" output status remains
  safe_database_name "$database_name" || return 1
  set +e
  output="$(run_as "$runtime_url" --command \
    "CREATE TABLE public.northstar_n08_r08_forbidden_probe(id integer)" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" | redact >>"$evidence_log"
  [[ "$status" != 0 ]] || return 1
  grep -Eqi 'permission denied|must be owner' <<<"$output" || return 1
  remains="$(run_bootstrap_psql --tuples-only --no-align --command \
    "SELECT pg_catalog.to_regclass('public.northstar_n08_r08_forbidden_probe') IS NULL")" || return 1
  [[ "$remains" == t || "$remains" == true ]]
}

start_runtime() {
  local label="$1" domain="$2" runtime_url="$3" command_url="$4"
  local cert="$cert_dir/$label.crt" key="$cert_dir/$label.key"
  local readiness="$runtime_root/$label.ready.json" nonce log upload_dir
  local fast="$runtime_root/$label.fast.secret" dummy="$runtime_root/$label.dummy-scram.secret"
  local abuse="$runtime_root/$label.abuse.secret" api="$runtime_root/$label.api.secret"
  nonce="$(openssl rand -hex 16)"
  log="$runtime_root/$label.server.log"
  upload_dir="$uploads_dir/$label"
  install -d -m 0700 "$upload_dir"
  for secret_file in "$fast" "$dummy" "$abuse" "$api"; do
    install -m 0600 /dev/null "$secret_file"
    openssl rand -hex 32 >"$secret_file"
  done
  openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
    -subj "/CN=$domain" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext "subjectAltName=DNS:$domain" \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
  chmod 0600 "$key"
  env NORTHSTAR_DISABLE_DOTENV=true \
    XMPP_DOMAIN="$domain" \
    DATABASE_URL_FILE="$runtime_url" \
    ADMIN_COMMAND_DATABASE_URL_FILE="$command_url" \
    XMPP_BIND=127.0.0.1:0 XMPPS_BIND=127.0.0.1:0 HTTP_BIND=127.0.0.1:0 \
    S2S_BIND=127.0.0.1:0 S2S_TLS_BIND=127.0.0.1:0 COMPONENT_BIND=127.0.0.1:0 \
    METRICS_BIND=127.0.0.1:0 WEB_ADMIN_ENABLED=false \
    TEST_LISTENER_ACTIVATION=true TEST_READINESS_FILE="$readiness" TEST_READINESS_NONCE="$nonce" \
    PUBLIC_URL="http://$domain:18080" \
    TLS_CERT_PATH="$cert" TLS_KEY_PATH="$key" UPLOAD_DIR="$upload_dir" \
    FAST_TOKEN_SECRET_FILE="$fast" DUMMY_SCRAM_SECRET_FILE="$dummy" \
    ABUSE_STATE_HMAC_KEY_FILE="$abuse" API_CONTROL_SECRET_FILE="$api" \
    OPEN_REGISTRATION=false INVITATION_REQUIRED=false FEDERATION_ENABLED=false DIALBACK_ENABLED=false \
    LOG_FORMAT=json RUST_LOG=rust_xmpp_server=info \
    "$binary" >"$log" 2>&1 &
  local pid=$!
  server_pids+=("$pid")
  if ! fixture_wait_for_readiness "$project_dir" "$readiness" "$nonce" "$pid"; then
    append_redacted_diagnostic "$log"
    return 1
  fi
  local http_port
  http_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" http)" || return 1
  curl --silent --fail "http://127.0.0.1:$http_port/readyz" >/dev/null || return 1
}

create_database "$template_a"
create_database "$template_b"

migrator_template_a="$(template_url_file migrator "$template_a")"
migrator_template_b="$(template_url_file migrator "$template_b")"
url_for_database "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" "$template_a" "$migrator_template_a" \
  || fail 'could not create template A migrator URL file'
url_for_database "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE" "$template_b" "$migrator_template_b" \
  || fail 'could not create template B migrator URL file'

for mapping in \
  "localhost|$template_a|$migrator_template_a" \
  "remote.localhost|$template_b|$migrator_template_b"; do
  domain="${mapping%%|*}"
  remainder="${mapping#*|}"
  database_name="${remainder%%|*}"
  url_file="${remainder#*|}"
  if ! NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN="$domain" \
    MIGRATOR_DATABASE_URL_FILE="$url_file" "$binary" migrate >"$runtime_root/migrate-$domain.log" 2>&1; then
    append_redacted_diagnostic "$runtime_root/migrate-$domain.log"
    fail "current migrator failed for $domain template"
  fi
  reconcile_exact_grants "$url_file" "$database_name" \
    >"$runtime_root/grants-$domain.log" 2>&1 || {
      append_redacted_diagnostic "$runtime_root/grants-$domain.log"
      fail "exact grants failed for $domain template"
    }
done

clone_database "$template_a" "$clone_a"
clone_database "$template_b" "$clone_b"

runtime_clone_a="$(template_url_file runtime "$clone_a")"
runtime_clone_b="$(template_url_file runtime "$clone_b")"
command_clone_a="$(template_url_file command "$clone_a")"
command_clone_b="$(template_url_file command "$clone_b")"
migrator_clone_a="$(template_url_file migrator "$clone_a")"
migrator_clone_b="$(template_url_file migrator "$clone_b")"
for item in \
  "$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE|$clone_a|$runtime_clone_a" \
  "$NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE|$clone_b|$runtime_clone_b" \
  "$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE|$clone_a|$command_clone_a" \
  "$NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE|$clone_b|$command_clone_b" \
  "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE|$clone_a|$migrator_clone_a" \
  "$NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE|$clone_b|$migrator_clone_b"; do
  source_file="${item%%|*}"
  remainder="${item#*|}"
  database_name="${remainder%%|*}"
  output_file="${remainder#*|}"
  url_for_database "$source_file" "$database_name" "$output_file" \
    || fail 'could not derive an owned clone URL file'
done

# A physical PostgreSQL clone copies object ACLs, but a database-level owner
# transition is a separate catalog operation.  Re-apply the repository's
# exact, manifest-backed grant reconciliation to each clone before testing a
# runtime identity; never treat template inheritance as proof that the new
# database's ACL grantors and database-level entries remain canonical.
for mapping in "$clone_a|$migrator_clone_a" "$clone_b|$migrator_clone_b"; do
  database_name="${mapping%%|*}"
  url_file="${mapping#*|}"
  if ! reconcile_exact_grants "$url_file" "$database_name" \
    >"$runtime_root/grants-$database_name.log" 2>&1; then
    append_redacted_diagnostic "$runtime_root/grants-$database_name.log"
    fail "exact clone grant reconciliation failed for $database_name"
  fi
done

identity_template_a="$(identity_record "$migrator_template_a")"
identity_template_b="$(identity_record "$migrator_template_b")"
identity_clone_a="$(identity_record "$migrator_clone_a")"
identity_clone_b="$(identity_record "$migrator_clone_b")"
[[ "$identity_template_a" == "$template_a|northstar_migrator|northstar_migrator|northstar_migrator" ]] \
  || fail 'template A ownership attestation failed'
[[ "$identity_template_b" == "$template_b|northstar_migrator|northstar_migrator|northstar_migrator" ]] \
  || fail 'template B ownership attestation failed'
[[ "$identity_clone_a" == "$clone_a|northstar_migrator|northstar_migrator|northstar_migrator" ]] \
  || fail 'clone A ownership attestation failed'
[[ "$identity_clone_b" == "$clone_b|northstar_migrator|northstar_migrator|northstar_migrator" ]] \
  || fail 'clone B ownership attestation failed'

runtime_forbidden_ddl "$runtime_clone_a" "$clone_a" \
  || fail 'runtime clone A did not reject forbidden DDL'
runtime_forbidden_ddl "$runtime_clone_b" "$clone_b" \
  || fail 'runtime clone B did not reject forbidden DDL'

start_runtime a localhost "$runtime_clone_a" "$command_clone_a" \
  || fail 'strict runtime did not become ready from clone A'
start_runtime b remote.localhost "$runtime_clone_b" "$command_clone_b" \
  || fail 'strict runtime did not become ready from clone B'

{
  printf 'case=N08-R08-DB05\n'
  printf 'binary_version=%s\n' "$binary_version"
  printf 'binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
  printf 'database_endpoint=127.0.0.1:%s\n' "$NORTHSTAR_PRIVATE_PG_PORT"
  printf 'template_a=owned-migrated-domain-localhost\n'
  printf 'template_b=owned-migrated-domain-remote.localhost\n'
  printf 'clone_a=strict-runtime-ready\n'
  printf 'clone_b=strict-runtime-ready\n'
  printf 'runtime_ddl_negative=permission-denied-on-both-clones\n'
  printf 'template_clone_identity=distinct-database-owner-schema-attested\n'
  printf 'cleanup=normal-drop-only-no-force\n'
} >"$evidence_summary"
cat "$evidence_summary" >>"$evidence_log"
printf 'N08-R08 PASS: templates/clones, strict runtime identity, and no-DDL boundary verified\n'
