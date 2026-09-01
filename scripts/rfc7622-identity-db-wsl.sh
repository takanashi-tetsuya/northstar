#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
test_schema="northstar_rfc7622_it_$random_suffix"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "RFC 7622 tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_rfc7622_it_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing an unsafe RFC 7622 test schema name" >&2
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

existing="$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")"
if [[ "$existing" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi

PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created=1

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema"

test_name="db::identity_migration::tests::global_ulabel_migration_rolls_back_every_subsystem_then_retries_idempotently"
if ! output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture --test-threads=1 2>&1)"; then
  printf '%s\n' "$output"
  exit 1
fi
printf '%s\n' "$output"
if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output"; then
  echo "expected exactly one ignored RFC 7622 database test to execute" >&2
  exit 1
fi

cleanup
created=0
remaining="$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT COUNT(*) FROM pg_namespace WHERE nspname='$test_schema'")"
if [[ "$remaining" != "0" ]]; then
  echo "isolated RFC 7622 schema was not removed" >&2
  exit 1
fi
trap - EXIT
