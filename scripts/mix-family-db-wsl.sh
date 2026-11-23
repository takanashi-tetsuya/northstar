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
    cargo test --locked --offline -p northstar-db-it "$test_name" \
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
  room::mix_pam_durability::pam_restart_and_result_claims_preserve_authority_and_token_fencing

run_exact_ignored \
  room::mix_sequence_retention::sequence_gc_preserves_a_producer_committed_after_its_snapshot

run_exact_ignored \
  room::mix_sequence_retention::event_gc_preserves_a_requeue_committed_after_its_snapshot

run_exact_ignored \
  room::mix_publisher_visibility::locked_visibility_rejects_stale_message_and_retraction_payloads_without_writes

run_exact_ignored \
  room::mix_publisher_visibility::unfiltered_mix_mam_preserves_payload_committed_under_visible_policy

run_exact_ignored \
  room::mix_sequence_retention::empty_delivery_claim_avoids_the_event_lock_and_recovers_after_insert

run_exact_ignored \
  room::mix_sequence_retention::empty_delivery_claim_preserves_database_authority_errors

run_exact_ignored \
  room::mix_delivery_route_wake::an_expired_unowned_head_blocks_until_terminalized

run_exact_ignored \
  room::mix_muc::mirror_link_is_common_owner_only_one_to_one_and_idempotent

run_exact_ignored \
  room::relay_profile_snapshot::local_channel_block_does_not_relay_a_new_vcard

run_exact_ignored \
  room::relay_profile_snapshot::local_requester_block_does_not_relay_a_new_vcard

run_exact_ignored \
  room::relay_profile_snapshot::federated_pam_leave_does_not_relay_a_new_vcard4_item

run_exact_ignored \
  room::relay_profile_snapshot::deleted_vcard4_node_is_missing_for_an_authorized_relay

run_exact_ignored \
  room::relay_profile_snapshot::legacy_non_open_vcard4_relays_latest_or_requested_item

run_exact_ignored \
  room::relay_profile_snapshot::relay_profile_snapshots_work_on_a_read_only_connection

run_exact_ignored \
  room::mix_presence_recovery::startup_sweep_drains_more_than_one_page

run_exact_ignored \
  room::mix_presence_recovery::skipped_locked_rows_are_revisited

run_exact_ignored \
  room::mix_presence_recovery::reensured_resource_before_cutoff_survives_the_sweep

run_exact_ignored \
  room::mix_presence_recovery::fresh_concurrent_publish_survives_the_sweep

run_exact_ignored \
  room::mix_presence_recovery::liveness_refresh_keeps_the_explicit_payload

run_exact_ignored \
  room::mix_presence_recovery::cutoff_uses_the_database_clock_under_process_skew

run_exact_ignored \
  room::mix_pam_ingress::leave_while_blocked_then_unblock_admits_no_reflection

run_exact_ignored \
  room::mix_pam_ingress::pending_rejoin_replacing_subscriptions_is_read_in_one_snapshot

run_exact_ignored \
  room::mix_pam_ingress::denied_reflection_archives_nothing_and_fans_out_nothing

run_exact_ignored \
  room::mix_pam_ingress::reflected_presence_error_reaches_only_eligible_resources

run_exact_ignored \
  room::mix_pam_projection::local_pam_join_then_core_subscribe_keeps_one_subscription_set

run_exact_ignored \
  room::mix_pam_projection::direct_core_leave_removes_pam_and_roster_projection

run_exact_ignored \
  room::mix_pam_projection::repeated_pam_cleanup_is_idempotent

run_exact_ignored \
  room::mix_pam_projection::destroy_racing_join_returns_a_removal_for_every_committed_member

run_exact_ignored \
  room::mix_pam_projection::ban_then_rejoin_pairs_each_roster_version_with_its_annotation

run_exact_ignored \
  room::mix_pam_projection::account_disable_before_roster_write_rejects_the_membership_change

run_exact_ignored \
  room::mix_pam_projection::channel_destroyed_after_lookup_is_typed_not_found

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline -p northstar-db-it \
  room::mix_mam::mix_anon_misc_permissions_are_atomic_and_private \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline -p northstar-db-it \
  room::mix_delivery_capacity::delivery_ack_is_independent_of_the_producer_fence_and_release_is_atomic \
  -- --ignored --nocapture

# A verified recipient route may appear while the ordered head is leased.
# Exercise the persisted wake epoch and recovery ordering against the same
# fully migrated isolated schema used by the other MIX authority tests.
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline -p northstar-db-it \
  room::mix_delivery_route_wake::leased_route_wake_defeats_defer_and_retry_but_not_unrelated_backoff \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline -p northstar-db-it \
  room::mix_delivery_route_wake::attempt_limit_route_wake_gets_one_fresh_claim_before_dead_letter \
  -- --ignored --nocapture

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline -p northstar-db-it \
  room::mix_delivery_route_wake::dead_letter_requeue_uses_tail_and_preserves_current_head_wake \
  -- --ignored --nocapture
