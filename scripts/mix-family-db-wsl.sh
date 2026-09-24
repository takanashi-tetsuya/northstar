#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_mix_family_" "MIX family"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"

run_exact_ignored() {
  local test_name="$1" output
  output="$(TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
    cargo test --locked --offline "$test_name" \
    -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  printf '%s\n' "$output"
  grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
    echo "expected exactly one ignored MIX test to execute: $test_name" >&2
    return 1
  }
}

run_exact_ignored \
  db::mix::pam_durability_integration_tests::pam_restart_and_result_claims_preserve_authority_and_token_fencing

run_exact_ignored \
  db::mix::delivery_sequence_retention_integration_tests::sequence_gc_preserves_a_producer_committed_after_its_snapshot

run_exact_ignored \
  db::mix::delivery_sequence_retention_integration_tests::event_gc_preserves_a_requeue_committed_after_its_snapshot

run_exact_ignored \
  db::mix::delivery_sequence_retention_integration_tests::empty_delivery_claim_avoids_the_event_lock_and_recovers_after_insert

run_exact_ignored \
  db::mix::delivery_sequence_retention_integration_tests::empty_delivery_claim_preserves_database_authority_errors

run_exact_ignored \
  db::mix::delivery_route_wake_integration_tests::an_expired_unowned_head_blocks_until_terminalized

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::mam_integration_tests::mix_anon_misc_permissions_are_atomic_and_private \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::delivery_capacity_integration_tests::delivery_ack_is_independent_of_the_producer_fence_and_release_is_atomic \
  -- --ignored --nocapture

# A verified recipient route may appear while the ordered head is leased.
# Exercise the persisted wake epoch and recovery ordering against the same
# fully migrated isolated schema used by the other MIX authority tests.
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::delivery_route_wake_integration_tests::leased_route_wake_defeats_defer_and_retry_but_not_unrelated_backoff \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::delivery_route_wake_integration_tests::attempt_limit_route_wake_gets_one_fresh_claim_before_dead_letter \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::delivery_route_wake_integration_tests::dead_letter_requeue_uses_tail_and_preserves_current_head_wake \
  -- --ignored --nocapture
