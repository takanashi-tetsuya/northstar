#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_sm_it_" "Stream Management integration"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema"

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
