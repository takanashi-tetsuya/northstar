#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_retention_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run retention tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_retention_it_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
created=0

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$created" == 1 ]]; then
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    [[ "$remains" == "f" ]] || {
      echo "isolated retention schema was not removed: $test_schema (exists=$remains)" >&2
      status=1
    }
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
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
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::bounded_concurrent_cleanup_is_restart_safe_and_preserves_evidence \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::asymmetric_mam_retention_preserves_admission_until_the_last_projection_ends \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::offline_retention_and_admin_clear_respect_sm_and_bosh_owners \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::data_lifecycle::tests::postgres_hold_cleanup_delete_release_and_audit_invariants \
  -- --ignored --exact --nocapture
