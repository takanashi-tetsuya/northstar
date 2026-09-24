#!/usr/bin/env bash

# Shared lifecycle for disposable PostgreSQL integration-test schemas.
# Callers provide a fixed prefix and keep their own test commands.

northstar_cleanup_test_schema() {
  local status=$? remains
  trap - EXIT INT TERM
  if [[ "${northstar_schema_created:-0}" == 1 ]]; then
    PGPASSWORD=xmpp-test-password psql "${northstar_schema_database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${northstar_schema_database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    if [[ "$remains" != f ]]; then
      echo "isolated $northstar_schema_label schema was not removed: $test_schema (exists=$remains)" >&2
      status=1
    fi
  fi
  exit "$status"
}

northstar_start_test_schema() {
  local prefix=$1 label=$2 random_suffix
  if [[ ! "$prefix" =~ ^northstar_[a-z0-9_]+_$ ]]; then
    echo "invalid isolated test schema prefix: $prefix" >&2
    return 2
  fi
  if [[ "${XMPP_TEST_DATABASE:-xmpp_test}" != xmpp_test ]]; then
    echo "refusing to run $label tests outside the disposable xmpp_test database" >&2
    return 2
  fi

  random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  test_schema="${XMPP_TEST_SCHEMA:-$prefix$random_suffix}"
  if [[ ! "$test_schema" =~ ^${prefix}[a-f0-9]{32}$ ]] || (( ${#test_schema} > 63 )); then
    echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
    return 2
  fi

  northstar_schema_label=$label
  northstar_schema_database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
  northstar_schema_created=0
  trap northstar_cleanup_test_schema EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [[ "$(PGPASSWORD=xmpp-test-password psql "${northstar_schema_database_args[@]}" \
    --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == t ]]; then
    echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
    return 2
  fi
  PGPASSWORD=xmpp-test-password psql "${northstar_schema_database_args[@]}" \
    --set ON_ERROR_STOP=1 \
    --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
  northstar_schema_created=1
}

northstar_use_test_toolchain() {
  local project_dir=$1
  if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != true ]]; then
    export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export RUSTUP_HOME="$project_dir/.rustup-linux"
    export CARGO_HOME="$project_dir/.cargo-local"
    export CARGO_TARGET_DIR="$project_dir/target-wsl"
  fi
}
