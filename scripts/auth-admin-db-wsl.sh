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
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/$test_database?options=-csearch_path%3D$test_schema"

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
# These two read the whole schema, so they run before any test leaves state: the
# last-administrator refusal needs no other enabled administrator, and the login
# penalty sums every abuse actor state.
if [[ "$scope" == "all" || "$scope" == "users" ]]; then
  run_exact_ignored \
    db::users_tests::api_session_cap_and_disable_revocation_are_atomic
fi
if [[ "$scope" == "all" || "$scope" == "api-control" ]]; then
  run_exact_ignored \
    db::api_control_tests::failed_login_penalty_and_replay_are_one_transaction
fi
if [[ "$scope" == "all" || "$scope" == "users" ]]; then
  run_exact_ignored \
    db::users_tests::concurrent_registration_cannot_exceed_the_global_hourly_limit
  run_exact_ignored \
    db::users_tests::guarded_registration_rolls_back_and_replays_proof_invitation_user_and_audit
  run_exact_ignored \
    db::users_tests::scram_families_hide_unknown_and_disabled_accounts_but_surface_corruption
  run_exact_ignored \
    db::users_tests::rest_password_cas_and_admin_authorization_are_atomic
  run_exact_ignored \
    db::users_tests::login_publication_preserves_each_scram_family_across_rolling_configuration
  run_exact_ignored \
    db::account_repository_registration_guard_tests::http_registration_overload_preserves_committed_proof_marker_for_exact_retry
  run_exact_ignored \
    db::account_repository_registration_guard_tests::http_registration_replays_exact_created_and_rejected_responses_after_policy_closure
  run_exact_ignored \
    db::account_repository_registration_guard_tests::registration_guard_consumes_v2_proof_with_marker_and_fences_old_worker
fi
if [[ "$scope" == "all" || "$scope" == "password-api" ]]; then
  run_exact_ignored \
    db::users_tests::rest_password_idempotency_logout_and_lock_order_are_atomic
  run_exact_ignored \
    db::password_change_repository_tests::password_change_replays_committed_response_after_bearer_revocation
fi
if [[ "$scope" == "all" || "$scope" == "api-control" ]]; then
  run_exact_ignored \
    db::api_control_tests::capacity_lock_contention_fails_fast_without_starving_pool
  run_exact_ignored \
    db::api_control_tests::yielded_lease_preserves_guard_marker_and_fences_old_worker
  run_exact_ignored \
    db::api_control_tests::postgres_idempotency_is_atomic_rotatable_and_tamper_evident
  run_exact_ignored \
    db::api_control_tests::concurrent_register_and_login_execute_once_per_idempotency_key
fi
if [[ "$scope" == "all" || "$scope" == "admin-sync" ]]; then
  run_exact_ignored \
    db::api_control_tests::admin_sync_mutations_are_authorized_atomic_replay_safe_and_queue_serialized
fi
if [[ "$scope" == "all" || "$scope" == "fast" ]]; then
  run_exact_ignored \
    db::fast_tests::durable_fast_tokens_support_optional_counts_replay_and_status_revocation
  run_exact_ignored \
    db::fast_tests::bind2_fast_side_effects_rollback_with_route_sql_and_commit_failures
fi
if [[ "$scope" == "all" || "$scope" == "commands" ]]; then
  run_exact_ignored \
    db::admin_read_authorization_tests::admin_read_snapshot_blocks_post_authorization_demotion_until_commit
  run_exact_ignored \
    db::admin_read_authorization_tests::admin_reads_reject_demotion_and_rotation_that_win_the_authorization_race
  run_exact_ignored \
    db::admin_command_sessions_tests::postgres_command_sessions_are_cross_node_atomic
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
