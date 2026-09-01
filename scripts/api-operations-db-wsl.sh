#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
test_schema="northstar_api_operations_it_$random_suffix"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "API operation tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_api_operations_it_[a-f0-9]{32}$ ]]; then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

created=0
cleanup() {
  if [[ "$created" == "1" ]]; then
    PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created=1

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema"

test_output="$(cargo test --locked --offline 'db::api_operations::tests::' \
  -- --ignored --nocapture --test-threads=1 2>&1)" || {
  printf '%s\n' "$test_output"
  exit 1
}
printf '%s\n' "$test_output"
if ! grep -Eq 'test result: ok\. 8 passed; 0 failed' <<<"$test_output"; then
  echo "expected exactly eight ignored API operation tests to execute" >&2
  exit 1
fi

cleanup
created=0
schema_remains="$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")"
if [[ "$schema_remains" != "f" ]]; then
  echo "isolated API operation schema was not removed" >&2
  exit 1
fi
trap - EXIT
