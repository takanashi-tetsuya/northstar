#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
test_schema="northstar_auth_admin_it_$random_suffix"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "authentication/admin tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_auth_admin_it_[a-f0-9]{32}$ ]]; then
  echo "refusing an unsafe authentication/admin schema name" >&2
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

scope="${AUTH_ADMIN_TEST_SCOPE:-all}"
run_exact_ignored() {
  local test_name="$1"
  local test_output
  if ! test_output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$test_output"
    return 1
  fi
  printf '%s\n' "$test_output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$test_output"; then
    echo "expected exactly one ignored test to execute: $test_name" >&2
    return 1
  fi
}
if [[ "$scope" == "all" || "$scope" == "users" ]]; then
  run_exact_ignored \
    db::users::tests::scram_families_hide_unknown_and_disabled_accounts_but_surface_corruption
  run_exact_ignored \
    db::users::tests::rest_password_cas_and_admin_authorization_are_atomic
fi
if [[ "$scope" == "all" || "$scope" == "password-api" ]]; then
  run_exact_ignored \
    db::users::tests::rest_password_idempotency_logout_and_lock_order_are_atomic
fi
if [[ "$scope" == "all" || "$scope" == "api-control" ]]; then
  run_exact_ignored \
    db::api_control::tests::capacity_lock_contention_fails_fast_without_starving_pool
  run_exact_ignored \
    db::api_control::tests::yielded_lease_preserves_guard_marker_and_fences_old_worker
  run_exact_ignored \
    db::api_control::tests::postgres_idempotency_is_atomic_rotatable_and_tamper_evident
  run_exact_ignored \
    db::api_control::tests::concurrent_register_and_login_execute_once_per_idempotency_key
fi
if [[ "$scope" == "all" || "$scope" == "admin-sync" ]]; then
  run_exact_ignored \
    db::api_control::tests::admin_sync_mutations_are_authorized_atomic_replay_safe_and_queue_serialized
fi
if [[ "$scope" == "all" || "$scope" == "fast" ]]; then
  run_exact_ignored \
    db::fast::tests::durable_fast_tokens_support_optional_counts_replay_and_status_revocation
  run_exact_ignored \
    db::fast::tests::bind2_fast_side_effects_rollback_with_route_sql_and_commit_failures
fi
if [[ "$scope" == "all" || "$scope" == "commands" ]]; then
  run_exact_ignored \
    services::admin_commands::read_authorization_tests::admin_read_snapshot_blocks_post_authorization_demotion_until_commit
  run_exact_ignored \
    services::admin_commands::read_authorization_tests::admin_reads_reject_demotion_and_rotation_that_win_the_authorization_race
  run_exact_ignored \
    xmpp::protocol::commands::tests::postgres_command_sessions_are_cross_node_atomic
fi

cleanup
created=0
schema_remains="$(PGPASSWORD=xmpp-test-password psql \
  --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")"
if [[ "$schema_remains" != "f" ]]; then
  echo "isolated authentication/admin schema was not removed" >&2
  exit 1
fi
trap - EXIT
