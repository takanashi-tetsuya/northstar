#!/usr/bin/env bash
#
# Run one explicitly supplied local test command against a disposable,
# loopback-only PostgreSQL instance.  This is deliberately a *parent*
# lifecycle wrapper: it owns the data directory, the PostgreSQL postmaster,
# the private role-password files, and the child command.  It never contacts
# a developer's 5432 instance and it never uses Docker.
#
# The wrapper supplies both the normal Northstar role boundary (for migration
# and runtime-attestation fixtures) and the deliberately fixed xmpp_test
# role required by listener-readiness-stress-wsl.sh.  The latter is restricted
# by that driver to the loopback endpoint exported below.

set -Eeuo pipefail
set +x
umask 077

readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

usage() {
  cat >&2 <<'EOF'
usage: scripts/private-loopback-postgres-wsl.sh [--max-connections N] [--with-listener-stress-role] -- COMMAND [ARG ...]

Creates a one-command, disposable PostgreSQL fixture bound only to 127.0.0.1.
The child receives NORTHSTAR_PRIVATE_PG_* connection-file variables and the
NORTHSTAR_LISTENER_STRESS_DATABASE_{HOST,PORT} endpoint variables only when
--with-listener-stress-role is selected.  It must not be used against a shared
database or as a long-lived database service.
EOF
}

max_connections="${NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS:-64}"
with_listener_stress_role=false
while (($#)); do
  case "$1" in
    --max-connections)
      max_connections="${2:?missing max-connections value}"
      shift 2
      ;;
    --with-listener-stress-role)
      with_listener_stress_role=true
      shift
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

(($# > 0)) || { usage; exit 2; }
[[ "$max_connections" =~ ^[1-9][0-9]*$ ]] \
  && ((10#$max_connections >= 16 && 10#$max_connections <= 768)) || {
  echo 'max-connections must be an integer from 16 through 768' >&2
  exit 2
}
max_connections=$((10#$max_connections))

[[ "$(id -u)" -ne 0 ]] || {
  echo 'run the private loopback PostgreSQL fixture as an ordinary WSL user' >&2
  exit 2
}
[[ "${CI:-}" != true && "${GITHUB_ACTIONS:-}" != true ]] || {
  echo 'the private loopback PostgreSQL fixture is for an owner-approved local WSL run, not CI' >&2
  exit 2
}

for command in bash chmod id install mktemp openssl pg_config psql realpath rm shuf tail; do
  command -v "$command" >/dev/null || {
    echo "private loopback PostgreSQL fixture requires: $command" >&2
    exit 2
  }
done

readonly pg_bin="$(pg_config --bindir)"
for command in createdb initdb pg_ctl postgres; do
  [[ -x "$pg_bin/$command" ]] || {
    echo "PostgreSQL server tool is unavailable: $pg_bin/$command" >&2
    exit 2
  }
done

runtime_root="$(mktemp -d /tmp/northstar-private-loopback-pg.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-private-loopback-pg\.[A-Za-z0-9]{6}$ ]] || {
  echo "refusing unsafe PostgreSQL fixture directory: $runtime_root" >&2
  exit 2
}
readonly runtime_root
readonly data_dir="$runtime_root/data"
readonly secrets_dir="$runtime_root/secrets"
readonly socket_dir="$runtime_root/socket"
readonly postgres_log="$runtime_root/postgres.log"
readonly bootstrap_role='northstar_bootstrap'
readonly migrator_role='northstar_migrator'
readonly runtime_role='northstar_runtime'
readonly command_role='northstar_commands'
readonly backup_role='northstar_backup'
readonly database_name='xmpp'
readonly listener_role='xmpp_test'
readonly listener_password='xmpp-test-password'
postgres_started=false
postgres_port=''

cleanup() {
  local original_status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  if [[ "$postgres_started" == true ]]; then
    "$pg_bin/pg_ctl" -D "$data_dir" -m fast -w stop >/dev/null 2>&1 \
      || cleanup_status=1
    postgres_started=false
  fi
  if [[ "$runtime_root" =~ ^/tmp/northstar-private-loopback-pg\.[A-Za-z0-9]{6}$ ]]; then
    rm -rf -- "$runtime_root" || cleanup_status=1
  else
    echo "refusing cleanup of unexpected PostgreSQL fixture: $runtime_root" >&2
    cleanup_status=1
  fi
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0700 "$secrets_dir"
install -d -m 0700 "$socket_dir"
write_secret() {
  local path="$1" value="$2"
  install -m 0600 /dev/null "$path"
  printf '%s\n' "$value" >"$path"
}

readonly bootstrap_password="$(openssl rand -hex 32)"
readonly migrator_password="$(openssl rand -hex 32)"
readonly runtime_password="$(openssl rand -hex 32)"
readonly command_password="$(openssl rand -hex 32)"
readonly backup_password="$(openssl rand -hex 32)"
readonly bootstrap_password_file="$secrets_dir/bootstrap-password"
readonly migrator_password_file="$secrets_dir/migrator-password"
readonly runtime_password_file="$secrets_dir/runtime-password"
readonly command_password_file="$secrets_dir/command-password"
readonly backup_password_file="$secrets_dir/backup-password"
readonly bootstrap_url_file="$secrets_dir/bootstrap-database-url"
readonly migrator_url_file="$secrets_dir/migrator-database-url"
readonly runtime_url_file="$secrets_dir/runtime-database-url"
readonly command_url_file="$secrets_dir/command-database-url"
write_secret "$bootstrap_password_file" "$bootstrap_password"
write_secret "$migrator_password_file" "$migrator_password"
write_secret "$runtime_password_file" "$runtime_password"
write_secret "$command_password_file" "$command_password"
write_secret "$backup_password_file" "$backup_password"

"$pg_bin/initdb" \
  --pgdata="$data_dir" \
  --username="$bootstrap_role" \
  --pwfile="$bootstrap_password_file" \
  --auth-local=scram-sha-256 \
  --auth-host=scram-sha-256 \
  --no-instructions >/dev/null

# PostgreSQL does not provide an inherited file descriptor mode for an
# ephemeral TCP port.  Retry a bounded set of random high ports, but never
# kill, replace, or inspect any listener which already owns one.
for attempt in $(seq 1 16); do
  candidate_port="$(shuf -i 20000-45000 -n 1)"
  if "$pg_bin/pg_ctl" -D "$data_dir" -l "$postgres_log" -w start \
    -o "-c listen_addresses=127.0.0.1 -c port=$candidate_port -c unix_socket_directories=$socket_dir -c unix_socket_permissions=0700 -c max_connections=$max_connections -c password_encryption=scram-sha-256" \
    >/dev/null 2>&1; then
    postgres_started=true
    postgres_port="$candidate_port"
    break
  fi
done
[[ "$postgres_started" == true && "$postgres_port" =~ ^[1-9][0-9]*$ ]] || {
  echo 'private loopback PostgreSQL fixture failed to bind a bounded ephemeral port' >&2
  tail -n 80 "$postgres_log" >&2 || true
  exit 1
}

control_psql() {
  PGPASSWORD="$bootstrap_password" "$pg_bin/psql" \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host 127.0.0.1 --port "$postgres_port" \
    --username "$bootstrap_role" "$@"
}

control_psql --dbname=postgres --command "CREATE DATABASE $database_name OWNER $bootstrap_role;" >/dev/null

# Reuse the repository's fresh-volume role policy instead of copying role
# definitions or grants into this test wrapper.  This gives DB01 the same
# roles, ownership and bootstrap grant phase as a new production volume.
PGHOST=127.0.0.1 \
PGPORT="$postgres_port" \
POSTGRES_USER="$bootstrap_role" \
POSTGRES_DB="$database_name" \
POSTGRES_PASSWORD_FILE="$bootstrap_password_file" \
NORTHSTAR_MIGRATOR_PASSWORD_FILE="$migrator_password_file" \
NORTHSTAR_RUNTIME_PASSWORD_FILE="$runtime_password_file" \
NORTHSTAR_COMMAND_PASSWORD_FILE="$command_password_file" \
NORTHSTAR_BACKUP_PASSWORD_FILE="$backup_password_file" \
  bash "$project_dir/deploy/postgres-init/010-northstar-roles.sh" >/dev/null

if [[ "$with_listener_stress_role" == true ]]; then
  control_psql --dbname=postgres \
    --set=listener_password="$listener_password" <<'PSQL' >/dev/null
SELECT pg_catalog.format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOINHERIT NOSUPERUSER CREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
  'xmpp_test', :'listener_password'
) \gexec
GRANT CONNECT ON DATABASE postgres TO xmpp_test;
PSQL
fi

write_secret "$bootstrap_url_file" "postgres://$bootstrap_role:$bootstrap_password@127.0.0.1:$postgres_port/$database_name"
write_secret "$migrator_url_file" "postgres://$migrator_role:$migrator_password@127.0.0.1:$postgres_port/$database_name"
write_secret "$runtime_url_file" "postgres://$runtime_role:$runtime_password@127.0.0.1:$postgres_port/$database_name"
write_secret "$command_url_file" "postgres://$command_role:$command_password@127.0.0.1:$postgres_port/$database_name"

fixture_identity="$(control_psql --dbname=postgres --tuples-only --no-align --command \
  "SELECT pg_catalog.host(pg_catalog.inet_server_addr()) || '|' || current_user || '|' || current_setting('max_connections')")"
[[ "$fixture_identity" == "127.0.0.1|$bootstrap_role|$max_connections" ]] || {
  echo 'private loopback PostgreSQL identity attestation failed' >&2
  exit 1
}
if [[ "$with_listener_stress_role" == true ]]; then
  listener_identity="$(PGPASSWORD="$listener_password" "$pg_bin/psql" --no-psqlrc --no-password \
    --host 127.0.0.1 --port "$postgres_port" --username "$listener_role" --dbname postgres \
    --tuples-only --no-align --set=ON_ERROR_STOP=1 --command \
    "SELECT pg_catalog.host(pg_catalog.inet_server_addr()) || '|' || current_user || '|' || (SELECT rolcreatedb::text FROM pg_catalog.pg_roles WHERE rolname=current_user)")"
  [[ "$listener_identity" == '127.0.0.1|xmpp_test|true' ]] || {
    echo 'listener-readiness PostgreSQL identity attestation failed' >&2
    exit 1
  }
fi

echo "private loopback PostgreSQL fixture ready host=127.0.0.1 port=$postgres_port max_connections=$max_connections listener_stress_role=$with_listener_stress_role"

child_environment=(
  NORTHSTAR_PRIVATE_PG_HOST=127.0.0.1
  NORTHSTAR_PRIVATE_PG_PORT="$postgres_port"
  NORTHSTAR_PRIVATE_PG_DATABASE="$database_name"
  NORTHSTAR_PRIVATE_PG_BOOTSTRAP_PASSWORD_FILE="$bootstrap_password_file"
  NORTHSTAR_PRIVATE_PG_BOOTSTRAP_DATABASE_URL_FILE="$bootstrap_url_file"
  NORTHSTAR_PRIVATE_PG_MIGRATOR_DATABASE_URL_FILE="$migrator_url_file"
  NORTHSTAR_PRIVATE_PG_RUNTIME_DATABASE_URL_FILE="$runtime_url_file"
  NORTHSTAR_PRIVATE_PG_COMMAND_DATABASE_URL_FILE="$command_url_file"
)
# The wrapper intentionally starts the child with a closed environment so a
# host credential or proxy setting cannot leak into a private fixture.  These
# four controls are non-secret execution metadata needed by the repository's
# bounded WSL drivers: they select the already-built target, keep Cargo
# offline, and place their redacted diagnostics outside the removable runtime
# directory.  Do not replace this whitelist with `env` passthrough.
for forwarded_variable in \
  CARGO_TARGET_DIR \
  XMPP_TEST_SYSTEM_TOOLCHAIN \
  XMPP_TEST_OFFLINE \
  NORTHSTAR_CI_DIAGNOSTICS_DIR; do
  if [[ -v "$forwarded_variable" ]]; then
    child_environment+=("$forwarded_variable=${!forwarded_variable}")
  fi
done
if [[ "$with_listener_stress_role" == true ]]; then
  child_environment+=(
    NORTHSTAR_LISTENER_STRESS_DATABASE_HOST=127.0.0.1
    NORTHSTAR_LISTENER_STRESS_DATABASE_PORT="$postgres_port"
    NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS="$max_connections"
  )
fi
env "${child_environment[@]}" "$@"
