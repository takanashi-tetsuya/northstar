#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
test_schema="northstar_upload_it_$random_suffix"
fixture_schema="${test_schema}_upgrade"
recovery_schema="${test_schema}_recovery"

if [[ ! "$test_schema" =~ ^northstar_upload_it_[a-f0-9]{32}$ ]] ||
   [[ ! "$fixture_schema" =~ ^northstar_upload_it_[a-f0-9]{32}_upgrade$ ]] ||
   [[ ! "$recovery_schema" =~ ^northstar_upload_it_[a-f0-9]{32}_recovery$ ]] ||
   (( ${#test_schema} > 63 || ${#fixture_schema} > 63 || ${#recovery_schema} > 63 )); then
  echo "refusing an unsafe upload test schema name" >&2
  exit 2
fi
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "upload DB tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi

created_schema=false
created_fixture_schema=false
created_recovery_schema=false
cleanup() {
  if [[ "$created_schema" == "true" ]]; then
    PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null
  fi
  if [[ "$created_fixture_schema" == "true" ]]; then
    PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$fixture_schema\" CASCADE" >/dev/null
  fi
  if [[ "$created_recovery_schema" == "true" ]]; then
    PGPASSWORD=xmpp-test-password psql \
      --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$recovery_schema\" CASCADE" >/dev/null
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
if [[ "$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$fixture_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $fixture_schema" >&2
  exit 2
fi
if [[ "$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$recovery_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $recovery_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created_schema=true
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$fixture_schema\"" >/dev/null
created_fixture_schema=true
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --command "CREATE SCHEMA \"$recovery_schema\"" >/dev/null
created_recovery_schema=true

PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --set "fixture_schema=$fixture_schema" \
  --file "$project_dir/scripts/upload-migration-0061-fixture.sql" >/dev/null
PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --set ON_ERROR_STOP=1 --set "recovery_schema=$recovery_schema" \
  --file "$project_dir/scripts/upload-migration-0109-fixture.sql" >/dev/null

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$test_database?options=-csearch_path%3D$test_schema"
cargo test --locked --offline db::upload::tests -- --ignored --nocapture --test-threads=1
cargo test --locked --offline \
  db::upload_admin::tests::postgres_retry_idempotency_replay_target_generation_and_not_found_contract \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::upload_admin::tests::postgres_retry_authorization_pagination_concurrency_and_fencing \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::users::tests::account_deletion_atomically_cancels_local_reverse_rosters \
  -- --ignored --nocapture --test-threads=1

cleanup
created_schema=false
created_fixture_schema=false
created_recovery_schema=false
remaining="$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT COUNT(*) FROM pg_namespace WHERE nspname IN ('$test_schema','$fixture_schema','$recovery_schema')")"
if [[ "$remaining" != "0" ]]; then
  echo "isolated upload schemas were not removed" >&2
  exit 1
fi
trap - EXIT
