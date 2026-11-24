#!/usr/bin/env bash
set -euo pipefail

# S50 one-to-one message authority suites (C5 audit): clustered Live
# handoff, Push claim authority, processing-policy admission, commit
# authorization, replay authority, retraction lifecycle and the Carbon
# audience. Every test runs exactly once against one fully migrated
# isolated schema.

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_message_authority_" "message authority"

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
    echo "expected exactly one ignored message authority test to execute: $test_name" >&2
    return 1
  }
}

run_exact_ignored \
  message::cluster_live_handoff::committed_live_reservation_verifies_and_fences_exactly_once

run_exact_ignored \
  message::cluster_live_handoff::replay_takeover_after_verification_prevents_the_stale_socket_fence

run_exact_ignored \
  message::cluster_live_handoff::released_reservation_refuses_live_verification_and_remains_replayable

run_exact_ignored \
  message::push_authority::claim_counts_and_targets_share_a_snapshot

run_exact_ignored \
  message::push_authority::replacement_revokes_claim_before_handoff_even_for_identical_options

run_exact_ignored \
  message::push_authority::owner_disable_and_response_serialize_on_the_account_before_rows

run_exact_ignored \
  message::push_authority::expired_cleanup_skips_locked_attempts_without_blocking_a_claim

run_exact_ignored \
  message::push_authority::password_rotation_while_enable_waits_rejects_the_session_generation

run_exact_ignored \
  message::push_authority::request_timestamps_and_expiry_follow_the_database_clock_under_skew

run_exact_ignored \
  message::processing_policy::processing_policy_restricts_outbox_spool_and_history_admission

run_exact_ignored \
  message::commit_authorization::actor_generation_changes_refuse_without_projections

run_exact_ignored \
  message::commit_authorization::policy_changes_before_commit_cannot_leave_mixed_projections

run_exact_ignored \
  message::commit_authorization::offline_fallback_rechecks_default_policy_and_actor_before_inserting

run_exact_ignored \
  message::commit_authorization::volatile_history_keeps_its_pre_route_archive_selection

run_exact_ignored \
  roster::privacy_decision::session_privacy_is_read_only_even_with_the_lease_row_locked

run_exact_ignored \
  roster::privacy_decision::session_privacy_honors_switches_and_does_not_resurrect_a_lost_selection

run_exact_ignored \
  session::replay_authority::bind2_delivers_when_retention_wins_before_claim_or_suppression

run_exact_ignored \
  session::replay_authority::bind2_requires_recipient_projection_and_delivers_temporary_spool

run_exact_ignored \
  session::replay_authority::replay_revalidates_block_active_default_roster_and_password

run_exact_ignored \
  session::replay_authority::sm_resume_suffix_refuses_a_replaced_connection

run_exact_ignored \
  message::retraction_lifecycle::paired_admission_during_locked_scan_is_not_partially_retracted

run_exact_ignored \
  message::retraction_lifecycle::exact_unowned_spool_cancellation_commits_and_rolls_back_with_tombstones

run_exact_ignored \
  message::retraction_lifecycle::sender_only_archive_cancels_spool_row_linked_by_origin_admission

run_exact_ignored \
  message::retraction_lifecycle::retraction_preserves_replay_socket_sm_and_bosh_ownership

run_exact_ignored \
  message::retraction_lifecycle::retraction_leaves_held_archive_and_offline_evidence

run_exact_ignored \
  message::retraction_lifecycle::local_action_id_is_reusable_after_sender_recreation_but_remote_replay_survives

run_exact_ignored \
  message::retraction_lifecycle::migration_backfills_only_proven_local_sender_commitments

run_exact_ignored \
  message::retraction_lifecycle::stale_retraction_actor_cannot_write_or_replay_as_current_generation

run_exact_ignored \
  message::retraction_lifecycle::no_store_federated_retraction_has_no_durable_effects

run_exact_ignored \
  message::retraction_lifecycle::paired_tombstones_share_the_retraction_transaction_timestamp

run_exact_ignored \
  message::carbon_audience::block_after_primary_acceptance_suppresses_sent_and_received_carbons

run_exact_ignored \
  message::carbon_audience::active_list_deny_after_primary_acceptance_suppresses_sent_and_received_carbons
