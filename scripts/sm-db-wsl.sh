#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_sm_it_$random_suffix}"
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run Stream Management integration tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_sm_it_[a-f0-9]{32}$ ]]; then
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
    if [[ "$remains" != "f" ]]; then
      echo "isolated Stream Management schema was not removed: $test_schema (exists=$remains)" >&2
      status=1
    fi
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
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema"

run_exact_ignored() {
  local test_name="$1"
  local output
  output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
    echo "expected exactly one ignored SM test to execute: $test_name" >&2
    exit 1
  }
}

run_exact_ignored \
  db::sm::tests::owner_only_session_catalog_is_strict_and_development_safe
run_exact_ignored \
  db::sm::tests::strict_same_device_claim_rejects_legacy_and_null_claimant
run_exact_ignored \
  db::sm::tests::durable_claim_is_single_consumer_and_revocable
run_exact_ignored \
  db::sm::tests::durable_delivery_fence_survives_checkpoint_resume_and_revocation
run_exact_ignored \
  db::sm::tests::authorization_mutations_retain_sm_presence_and_muc_teardown_state
run_exact_ignored \
  db::sm::tests::every_teardown_scope_preserves_the_active_privacy_list
run_exact_ignored \
  db::sm::tests::account_deletion_quiesce_closes_all_sm_race_barriers
run_exact_ignored \
  db::account_deletion::tests::deletion_recovery_is_delayed_single_owner_and_cascading
run_exact_ignored \
  services::sm::tests::binding_reservation_is_bounded_leased_and_rechecks_auth_generation
run_exact_ignored \
  services::sm::tests::sm_activation_and_privacy_selection_commit_or_roll_back_together
run_exact_ignored \
  services::sm::tests::resumable_binding_lease_transfers_only_after_transport_publication
