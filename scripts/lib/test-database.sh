#!/usr/bin/env bash

# One loopback connection for both schema management and Rust database tests.
# These fixtures must never inherit the application's database/user/host.
northstar_test_database_config() {
  if [[ "${XMPP_TEST_DATABASE:-xmpp_test}" != xmpp_test ]]; then
    echo 'database tests require the disposable xmpp_test database' >&2
    return 2
  fi
  local port=${PGPORT:-5432}
  if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    echo 'database tests require a single PostgreSQL port between 1 and 65535' >&2
    return 2
  fi
  export PGPORT=$((10#$port))
  northstar_test_database_args=(--host 127.0.0.1 --port "$PGPORT" --username xmpp_test --dbname xmpp_test)
  northstar_test_database_url="postgres://xmpp_test:xmpp-test-password@127.0.0.1:$PGPORT/xmpp_test"
}

northstar_test_database_url_for_schema() {
  local schema=$1
  if [[ ! "$schema" =~ ^[a-z][a-z0-9_]{0,62}$ ]]; then
    echo 'refusing an unsafe test schema in the database URL' >&2
    return 2
  fi
  printf '%s?options=-csearch_path%%3D%s' "$northstar_test_database_url" "$schema"
}
