#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Focused, disposable PostgreSQL proof for migrations 0133/0134. It does not
# use a shared developer database or Docker: PostgreSQL listens only on a
# private Unix socket beneath the directory this script created.

readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

fail() {
  printf 'MIX delivery wake trigger validation failed: %s\n' "$1" >&2
  exit 1
}

for command in bash chmod grep id install mktemp pg_config realpath rm sleep; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

[[ "$(id -u)" -ne 0 ]] || fail 'run the private PostgreSQL fixture as an ordinary WSL user'

readonly pg_bin="$(pg_config --bindir)"
for command in initdb pg_ctl psql; do
  [[ -x "$pg_bin/$command" ]] || fail "PostgreSQL server tool is unavailable: $pg_bin/$command"
done

runtime_root="$(mktemp -d /tmp/northstar-mix-delivery-wake-wsl.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-mix-delivery-wake-wsl\.[A-Za-z0-9]{6}$ ]] \
  || fail "refusing unexpected fixture path: $runtime_root"
readonly runtime_root
readonly data_dir="$runtime_root/data"
readonly socket_dir="$runtime_root/socket"
readonly control_password_file="$runtime_root/control-password"
readonly postgres_log="$runtime_root/postgres.log"
readonly control_password='northstar-mix-wake-control-password-00000001'
readonly migrator_password='northstar-mix-wake-migrator-password-00000001'
readonly runtime_password='northstar-mix-wake-runtime-password-00000001'
readonly database_name='northstar_mix_wake'
readonly wake_notification_migration="$project_dir/migrations/0133_mix_delivery_wake_notifications.sql"
readonly route_generation_migration="$project_dir/migrations/0134_mix_delivery_route_wake_generation.sql"
readonly schema="northstar_mix_wake_${RANDOM}_$$"
postgres_started=false
listener_pid=''

cleanup() {
  local original_status=$?
  trap - EXIT
  set +e
  if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then
    # This is only the psql listener process created by this script.
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  if [[ "$postgres_started" == true ]]; then
    "$pg_bin/pg_ctl" -D "$data_dir" -m fast -w stop >/dev/null 2>&1 || true
  fi
  case "$runtime_root" in
    /tmp/northstar-mix-delivery-wake-wsl.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
      rm -rf -- "$runtime_root" || true
      ;;
    *)
      printf 'refusing cleanup of unexpected fixture path: %s\n' "$runtime_root" >&2
      ;;
  esac
  exit "$original_status"
}
trap cleanup EXIT

install -m 0600 /dev/null "$control_password_file"
printf '%s\n' "$control_password" >"$control_password_file"
install -d -m 0700 "$socket_dir"

"$pg_bin/initdb" \
  --pgdata="$data_dir" \
  --username=northstar_mix_wake_control \
  --pwfile="$control_password_file" \
  --auth-local=scram-sha-256 \
  --auth-host=scram-sha-256 \
  --no-instructions >/dev/null

"$pg_bin/pg_ctl" -D "$data_dir" -l "$postgres_log" -w start \
  -o "-c listen_addresses='' -c unix_socket_directories=$socket_dir -c unix_socket_permissions=0700 -c password_encryption=scram-sha-256" \
  >/dev/null || {
    tail -n 80 "$postgres_log" >&2 || true
    fail 'private PostgreSQL fixture failed to start'
  }
postgres_started=true

control_psql() {
  PGPASSWORD="$control_password" "$pg_bin/psql" \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host "$socket_dir" --username northstar_mix_wake_control "$@"
}

migrator_psql() {
  PGPASSWORD="$migrator_password" "$pg_bin/psql" \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host "$socket_dir" --username northstar_mix_wake_migrator --dbname "$database_name" "$@"
}

runtime_psql() {
  PGPASSWORD="$runtime_password" "$pg_bin/psql" \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host "$socket_dir" --username northstar_mix_wake_runtime --dbname "$database_name" "$@"
}

control_psql --dbname postgres <<SQL
CREATE ROLE northstar_mix_wake_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD '${migrator_password}';
CREATE ROLE northstar_mix_wake_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD '${runtime_password}';
CREATE DATABASE ${database_name} OWNER northstar_mix_wake_migrator;
SQL

# The fixture is deliberately a non-public schema.  Migration 0133 must use
# TG_TABLE_SCHEMA/current_schema rather than resolving a hard-coded public
# object, and its non-secret payload must equal this exact isolated schema.
migrator_psql <<SQL
CREATE SCHEMA ${schema} AUTHORIZATION northstar_mix_wake_migrator;
CREATE TABLE ${schema}.mix_delivery_recipients (marker pg_catalog.text PRIMARY KEY);
GRANT USAGE ON SCHEMA ${schema} TO northstar_mix_wake_runtime;
GRANT INSERT, DELETE ON ${schema}.mix_delivery_recipients TO northstar_mix_wake_runtime;
SET search_path TO ${schema}, pg_catalog;
\i ${wake_notification_migration}
\i ${route_generation_migration}
GRANT UPDATE(route_wake_generation) ON mix_delivery_recipients TO northstar_mix_wake_runtime;
SQL

runtime_direct_execute=$(runtime_psql --tuples-only --no-align --command \
  "SELECT pg_catalog.has_function_privilege(current_user, '${schema}.northstar_mix_delivery_notify()', 'EXECUTE')")
[[ "$runtime_direct_execute" == f ]] \
  || fail 'runtime role can directly execute the migration 0133 trigger helper'

start_listener() {
  local label=$1
  local listener_log="$runtime_root/${label}.listener.log"
  listener_pid=''
  PGPASSWORD="$control_password" "$pg_bin/psql" \
    --no-psqlrc --no-password --quiet --tuples-only --no-align \
    --host "$socket_dir" --username northstar_mix_wake_control --dbname "$database_name" \
    >"$listener_log" 2>&1 <<'SQL' &
LISTEN northstar_mix_delivery_v1;
SELECT 'listener-ready';
SELECT pg_catalog.pg_sleep(3);
SQL
  listener_pid=$!
  for _ in $(seq 1 150); do
    if grep -Fxq 'listener-ready' "$listener_log"; then
      return 0
    fi
    if ! kill -0 "$listener_pid" 2>/dev/null; then
      cat "$listener_log" >&2 || true
      fail "listener exited before readiness for ${label}"
    fi
    sleep 0.02
  done
  cat "$listener_log" >&2 || true
  fail "listener did not become ready for ${label}"
}

expect_notification() {
  local label=$1
  local listener_log="$runtime_root/${label}.listener.log"
  wait "$listener_pid" || {
    cat "$listener_log" >&2 || true
    fail "listener failed for ${label}"
  }
  listener_pid=''
  grep -Fq "Asynchronous notification \"northstar_mix_delivery_v1\" with payload \"${schema}\"" "$listener_log" \
    || {
      cat "$listener_log" >&2 || true
      fail "${label} did not publish the isolated schema payload"
    }
}

expect_no_notification() {
  local label=$1
  local listener_log="$runtime_root/${label}.listener.log"
  wait "$listener_pid" || {
    cat "$listener_log" >&2 || true
    fail "listener failed for ${label}"
  }
  listener_pid=''
  if grep -Fq 'Asynchronous notification "northstar_mix_delivery_v1"' "$listener_log"; then
    cat "$listener_log" >&2 || true
    fail "${label} leaked a notification from a rolled-back transaction"
  fi
}

start_listener committed_insert
runtime_psql --command "INSERT INTO ${schema}.mix_delivery_recipients(marker) VALUES ('committed');"
expect_notification committed_insert

start_listener rolled_back_insert
runtime_psql <<SQL
BEGIN;
INSERT INTO ${schema}.mix_delivery_recipients(marker) VALUES ('rolled-back');
ROLLBACK;
SQL
expect_no_notification rolled_back_insert

start_listener committed_delete
# Do not grant SELECT merely to test the trigger.  The fixture has exactly one
# committed row at this point, so an unqualified DELETE proves that the
# ordinary DML privilege invokes the SECURITY INVOKER trigger without widening
# the runtime role's read surface.
runtime_psql --command "DELETE FROM ${schema}.mix_delivery_recipients;"
expect_notification committed_delete

runtime_psql --command "INSERT INTO ${schema}.mix_delivery_recipients(marker) VALUES ('route-wake');"
start_listener committed_route_wake
runtime_psql --command "UPDATE ${schema}.mix_delivery_recipients SET route_wake_generation=1;"
expect_notification committed_route_wake

start_listener rolled_back_route_wake
runtime_psql <<SQL
BEGIN;
UPDATE ${schema}.mix_delivery_recipients SET route_wake_generation=2;
ROLLBACK;
SQL
expect_no_notification rolled_back_route_wake

migrator_psql --command "DROP SCHEMA ${schema} CASCADE;"
printf 'MIX delivery wake trigger WSL validation passed: insert/delete and route-epoch commit/rollback, isolated schema payload, and direct-execute boundary\n'
